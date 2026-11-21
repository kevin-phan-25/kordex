// Package connectivitycheck provides a read-only, credential-safe diagnostic
// for the agent-to-private-relay path. It uses the agent's actual mTLS client
// and Ed25519 identity request rather than a weaker transport-only probe.
package connectivitycheck

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"kordex.local/agent/internal/client"
	"kordex.local/agent/internal/state"
	"kordex.local/api/protocol"
)

const identityRoute = "GET /v1/agent/identity"

type Config struct {
	Endpoint                       string
	ClusterID                      string
	Identity                       state.State
	MTLS                           client.MTLSConfig
	AllowedCIDRs                   []string
	GatewayAccessHeadersConfigured bool
	Timeout                        time.Duration
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Dependencies struct {
	Resolver    Resolver
	DialContext func(context.Context, string, string) (net.Conn, error)
}

// Result contains only endpoint and verification status metadata. It never
// contains request headers, response bodies, certificate data, or identity
// keys. A successful response proves the relay route and Kordex identity API
// accepted this cluster's signed request.
type Result struct {
	Endpoint                  string   `json:"endpoint,omitempty"`
	ResolvedAddresses         []string `json:"resolvedAddresses,omitempty"`
	PrivateDNSVerified        bool     `json:"privateDNSVerified"`
	RelayReachable            bool     `json:"relayReachable"`
	AgentRouteAvailable       bool     `json:"agentRouteAvailable"`
	Route                     string   `json:"route"`
	TLSIdentityVerified       bool     `json:"tlsIdentityVerified"`
	ClientCertificateAccepted bool     `json:"clientCertificateAccepted"`
	CertificateMapping        string   `json:"certificateMapping"`
	APIResponse               string   `json:"apiResponse"`
	ClusterIdentityMatches    bool     `json:"clusterIdentityMatches"`
	AgentIdentityMatches      bool     `json:"agentIdentityMatches"`
	Status                    string   `json:"status"`
}

func Check(ctx context.Context, cfg Config, deps Dependencies) Result {
	result := Result{Route: identityRoute, CertificateMapping: "not_verified", APIResponse: "not_reached", Status: "configuration_invalid"}
	endpoint, host, port, err := validateEndpoint(cfg)
	if err != nil {
		return result
	}
	result.Endpoint = endpoint.String()
	prefixes, err := parsePrivateCIDRs(cfg.AllowedCIDRs)
	if err != nil || cfg.GatewayAccessHeadersConfigured || cfg.Identity.Validate() != nil || !protocol.ValidUUID(cfg.ClusterID) || cfg.Identity.ClusterID != cfg.ClusterID || len(cfg.Identity.PrivateKey) != ed25519.PrivateKeySize {
		return result
	}
	if deps.Resolver == nil {
		deps.Resolver = net.DefaultResolver
	}
	addresses, err := deps.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		result.Status = "dns_resolution_failed"
		return result
	}
	addresses = uniqueAddresses(addresses)
	for _, address := range addresses {
		if address.Zone() != "" || address.Is4In6() || !address.IsPrivate() || !insidePrefixes(address, prefixes) {
			result.Status = "endpoint_outside_approved_private_cidrs"
			return result
		}
		result.ResolvedAddresses = append(result.ResolvedAddresses, address.String())
	}
	result.PrivateDNSVerified = true

	remote, err := client.NewWithMTLS(endpoint.String(), cfg.ClusterID, cfg.MTLS)
	if err != nil {
		return result
	}
	transport, ok := remote.HTTP.Transport.(*http.Transport)
	if !ok {
		result.Status = "configuration_invalid"
		return result
	}
	// Pin DNS resolution to an address checked above; environment proxy
	// settings and later DNS changes cannot redirect this diagnostic.
	transport.Proxy = nil
	if deps.DialContext == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		deps.DialContext = dialer.DialContext
	}
	pinned := net.JoinHostPort(addresses[0].String(), port)
	want := net.JoinHostPort(host, port)
	transport.DialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		if address != want {
			return nil, errors.New("unexpected connectivity-check destination")
		}
		return deps.DialContext(dialCtx, network, pinned)
	}
	defer transport.CloseIdleConnections()

	timeout := cfg.Timeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 15 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var connected atomic.Bool
	var handshakeDone atomic.Bool
	var handshakeFailed atomic.Bool
	trace := &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, err error) { connected.Store(err == nil) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			handshakeDone.Store(true)
			handshakeFailed.Store(err != nil)
		},
	}
	requestCtx = httptrace.WithClientTrace(requestCtx, trace)
	identity, err := remote.Identity(requestCtx, cfg.Identity.PrivateKey)
	result.RelayReachable = connected.Load()
	if err != nil {
		result.APIResponse = classifyAPIError(err)
		if _, ok := err.(*client.APIError); ok {
			result.AgentRouteAvailable = result.APIResponse != "route_unavailable"
		}
		if handshakeDone.Load() && !handshakeFailed.Load() {
			result.TLSIdentityVerified = true
			result.ClientCertificateAccepted = true
			if result.APIResponse != "relay_authorization_rejected" {
				result.CertificateMapping = "accepted"
			}
		}
		switch {
		case handshakeDone.Load() && handshakeFailed.Load():
			result.Status = "tls_identity_rejected"
		case !connected.Load():
			result.Status = "relay_unreachable"
		case !handshakeDone.Load():
			result.Status = "tls_handshake_incomplete"
		case result.APIResponse == "relay_authorization_rejected":
			result.Status = "relay_authorization_rejected"
		case result.APIResponse == "api_unavailable":
			result.Status = "api_unavailable"
		default:
			result.Status = result.APIResponse
		}
		return result
	}
	result.TLSIdentityVerified = true
	result.ClientCertificateAccepted = true
	result.CertificateMapping = "accepted"
	result.AgentRouteAvailable = true
	result.APIResponse = "identity_accepted"
	result.ClusterIdentityMatches = identity.ClusterID == cfg.ClusterID
	privateKey := ed25519.PrivateKey(cfg.Identity.PrivateKey)
	result.AgentIdentityMatches = identity.KeyID == protocol.KeyID(privateKey.Public().(ed25519.PublicKey)) && time.Now().Before(identity.ExpiresAt)
	if !result.ClusterIdentityMatches {
		result.Status = "cluster_identity_mismatch"
		return result
	}
	if !result.AgentIdentityMatches {
		result.Status = "agent_identity_mismatch_or_expired"
		return result
	}
	result.Status = "verified"
	return result
}

func validateEndpoint(cfg Config) (*url.URL, string, string, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, "", "", errors.New("invalid endpoint")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || !validDNSName(host) || !strings.EqualFold(u.Hostname(), cfg.MTLS.ServerName) {
		return nil, "", "", errors.New("invalid endpoint identity")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, "", "", errors.New("invalid endpoint port")
	}
	u.Host = net.JoinHostPort(host, port)
	return u, host, port, nil
}

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func parsePrivateCIDRs(raw []string) ([]netip.Prefix, error) {
	if len(raw) == 0 {
		return nil, errors.New("private endpoint CIDRs required")
	}
	var prefixes []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, item := range raw {
		p, err := netip.ParsePrefix(item)
		if err != nil || p != p.Masked() || !validPrivatePrefix(p) {
			return nil, errors.New("invalid private CIDR")
		}
		if p.Addr().Is4In6() || seen[p] {
			return nil, errors.New("ambiguous private CIDR")
		}
		seen[p] = true
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

func validPrivatePrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if !address.IsValid() || address.Is4In6() {
		return false
	}
	if address.Is4() {
		if prefix.Bits() < 24 {
			return false
		}
		for _, private := range []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
		} {
			if private.Contains(address) {
				return true
			}
		}
		return false
	}
	return prefix.Bits() >= 64 && netip.MustParsePrefix("fc00::/7").Contains(address)
}

func insidePrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func uniqueAddresses(input []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	result := make([]netip.Addr, 0, len(input))
	for _, address := range input {
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result
}

func classifyAPIError(err error) string {
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return "transport_or_api_error"
	}
	switch apiErr.Status {
	case http.StatusForbidden:
		if apiErr.Code == "invalid_error_response" {
			return "relay_authorization_rejected"
		}
		return "api_authorization_rejected"
	case http.StatusUnauthorized:
		return "agent_authentication_rejected"
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return "api_unavailable"
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return "route_unavailable"
	default:
		return "api_rejected"
	}
}
