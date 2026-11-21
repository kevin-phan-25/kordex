// Package client implements outbound HTTPS; it never accesses the management database.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"

	"kordex.local/api/protocol"
)

type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("management API status %d (%s)", e.Status, e.Code)
}

type Client struct {
	BaseURL                  string
	HTTP                     *http.Client
	ClusterID                string
	cloudflareAccessClientID string
	cloudflareAccessSecret   string
}

// MTLSConfig contains customer-provisioned transport trust and identity. It is
// deliberately separate from the agent's Ed25519 identity and authorization.
type MTLSConfig struct {
	ClientCertificatePEM []byte
	ClientKeyPEM         []byte
	ServerCAPEM          []byte
	ServerName           string
}

// LoadMTLSConfig reads customer-mounted certificate files without including
// their contents in errors. Callers should invoke this only when mTLS is
// explicitly enabled; missing files then fail startup rather than downgrade.
func LoadMTLSConfig(clientCertificateFile, clientKeyFile, serverCAFile, serverName string) (MTLSConfig, error) {
	if clientCertificateFile == "" || clientKeyFile == "" || serverCAFile == "" || serverName == "" {
		return MTLSConfig{}, fmt.Errorf("mTLS requires client certificate, client key, server CA, and server DNS name")
	}
	read := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("mTLS certificate file unavailable")
		}
		return b, nil
	}
	cert, err := read(clientCertificateFile)
	if err != nil {
		return MTLSConfig{}, err
	}
	key, err := read(clientKeyFile)
	if err != nil {
		return MTLSConfig{}, err
	}
	ca, err := read(serverCAFile)
	if err != nil {
		return MTLSConfig{}, err
	}
	return MTLSConfig{ClientCertificatePEM: cert, ClientKeyPEM: key, ServerCAPEM: ca, ServerName: serverName}, nil
}

func New(base, cluster string, local bool, caPEM []byte) (*Client, error) {
	return newClient(base, cluster, local, caPEM, nil)
}

// NewWithMTLS creates an HTTPS-only client that authenticates the server with
// the supplied CA bundle and presents the configured client certificate on
// every allowlisted agent request. It never uses system roots as an implicit
// fallback for the customer trust bundle.
func NewWithMTLS(base, cluster string, mtls MTLSConfig) (*Client, error) {
	return newClient(base, cluster, false, nil, &mtls)
}

func newClient(base, cluster string, local bool, caPEM []byte, mtls *MTLSConfig) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("control plane URL must be an origin")
	}
	if !protocol.ValidUUID(cluster) {
		return nil, fmt.Errorf("invalid configured cluster ID")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if mtls != nil || !local || u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("HTTPS required; local HTTP is limited to loopback")
		}
	}
	var tlsConfig *tls.Config
	if mtls != nil {
		if len(mtls.ClientCertificatePEM) == 0 || len(mtls.ClientKeyPEM) == 0 || len(mtls.ServerCAPEM) == 0 {
			return nil, fmt.Errorf("mTLS certificate material is incomplete")
		}
		host := u.Hostname()
		if !validDNSName(mtls.ServerName) || net.ParseIP(host) != nil || !strings.EqualFold(host, mtls.ServerName) {
			return nil, fmt.Errorf("mTLS server DNS name must match the HTTPS control plane hostname")
		}
		roots, err := parseCustomerRoots(mtls.ServerCAPEM)
		if err != nil {
			return nil, err
		}
		if _, err := parseCertificatePEM(mtls.ClientCertificatePEM, false); err != nil {
			return nil, fmt.Errorf("invalid mTLS client certificate")
		}
		if err := validatePrivateKeyPEM(mtls.ClientKeyPEM); err != nil {
			return nil, fmt.Errorf("invalid mTLS client private key")
		}
		pair, err := tls.X509KeyPair(mtls.ClientCertificatePEM, mtls.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("invalid mTLS client certificate or private key")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("invalid mTLS client certificate")
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasClientAuthUsage(leaf) {
			return nil, fmt.Errorf("mTLS client certificate is not currently valid for client authentication")
		}
		pair.Leaf = leaf
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: mtls.ServerName}
	} else {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if len(caPEM) > 0 && !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("invalid management CA bundle")
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	// Never forward signed identity headers across redirects.
	h := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{BaseURL: u.Scheme + "://" + u.Host, HTTP: h, ClusterID: cluster}, nil
}

func parseCustomerRoots(bundle []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	certificates, err := parseCertificatePEM(bundle, true)
	if err != nil {
		return nil, fmt.Errorf("invalid mTLS server CA bundle")
	}
	for _, cert := range certificates {
		if !cert.IsCA {
			return nil, fmt.Errorf("invalid mTLS server CA bundle")
		}
		roots.AddCert(cert)
	}
	return roots, nil
}

func parseCertificatePEM(input []byte, allCAs bool) ([]*x509.Certificate, error) {
	remaining := bytes.TrimSpace(input)
	var certificates []*x509.Certificate
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("malformed PEM certificate bundle")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("malformed PEM certificate bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || (allCAs && !cert.IsCA) || (!allCAs && len(certificates) > 0 && !cert.IsCA) {
			return nil, fmt.Errorf("invalid certificate chain")
		}
		certificates = append(certificates, cert)
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("empty PEM certificate bundle")
	}
	return certificates, nil
}

func validatePrivateKeyPEM(input []byte) error {
	remaining := bytes.TrimSpace(input)
	if !(bytes.HasPrefix(remaining, []byte("-----BEGIN PRIVATE KEY-----")) || bytes.HasPrefix(remaining, []byte("-----BEGIN RSA PRIVATE KEY-----")) || bytes.HasPrefix(remaining, []byte("-----BEGIN EC PRIVATE KEY-----"))) {
		return fmt.Errorf("malformed PEM private key")
	}
	block, rest := pem.Decode(remaining)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("malformed PEM private key")
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return nil
	default:
		return fmt.Errorf("unsupported PEM private key")
	}
}

func hasClientAuthUsage(cert *x509.Certificate) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func validDNSName(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\:*?[]@ \t\r\n") || strings.HasSuffix(name, ".") {
		return false
	}
	if net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// ConfigureCloudflareAccess enables the second, edge-level authentication
// factor used by the lab's Cloudflare Access tunnel. Values are sent only on
// the exact agent routes enforced below and are never logged or traced.
func (c *Client) ConfigureCloudflareAccess(clientID, clientSecret string, required bool) error {
	if (clientID == "") != (clientSecret == "") {
		return fmt.Errorf("Cloudflare Access client ID and secret must be configured together")
	}
	if required && clientID == "" {
		return fmt.Errorf("Cloudflare Access credentials are required but missing")
	}
	if !required && clientID != "" {
		return fmt.Errorf("Cloudflare Access credentials require gateway authentication to be enabled")
	}
	if strings.ContainsAny(clientID+clientSecret, "\r\n") {
		return fmt.Errorf("Cloudflare Access credentials contain invalid line breaks")
	}
	c.cloudflareAccessClientID = clientID
	c.cloudflareAccessSecret = clientSecret
	return nil
}
func (c *Client) Call(ctx context.Context, method, path string, input, output any, key ed25519.PrivateKey) error {
	boundedMethod := boundedHTTPMethod(method)
	route := boundedAgentRoute(method, path)
	ctx, span := otel.Tracer("kordex.agent").Start(ctx, boundedMethod+" "+route)
	statusCode := 0
	failureClass := ""
	defer func() {
		span.SetAttributes(
			attribute.String("http.request.method", boundedMethod),
			attribute.String("http.route", route),
			attribute.String("kordex.agent.call.outcome", agentCallOutcome(failureClass)),
		)
		if statusCode != 0 {
			span.SetAttributes(attribute.Int("http.response.status_code", statusCode))
		}
		if failureClass != "" {
			span.SetAttributes(attribute.String("kordex.agent.call.error_class", failureClass))
			span.SetStatus(codes.Error, "agent_api_call_failed")
		}
		span.End()
	}()
	if route == "unmatched" {
		failureClass = "request_rejected"
		return fmt.Errorf("management API route is not allowed for the agent")
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			failureClass = "request_encode"
			return err
		}
	}
	if len(body) > protocol.MaxReportBytes {
		failureClass = "request_rejected"
		return fmt.Errorf("inventory request exceeds size limit")
	}
	r, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		failureClass = "request_create"
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	if c.cloudflareAccessClientID != "" {
		r.Header.Set("CF-Access-Client-Id", c.cloudflareAccessClientID)
		r.Header.Set("CF-Access-Client-Secret", c.cloudflareAccessSecret)
	}
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))
	if len(key) > 0 {
		protocol.Sign(r, c.ClusterID, key, body, time.Now())
	}
	response, err := c.HTTP.Do(r)
	if err != nil {
		failureClass = "transport"
		return fmt.Errorf("management transport unavailable")
	}
	defer response.Body.Close()
	statusCode = response.StatusCode
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		failureClass = "response_read"
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		failureClass = "http_status"
		var v struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			v.Error = "invalid_error_response"
		}
		return &APIError{Status: response.StatusCode, Code: v.Error}
	}
	if output != nil {
		if err = json.Unmarshal(data, output); err != nil {
			failureClass = "response_decode"
			return fmt.Errorf("invalid management response")
		}
	}
	return nil
}

func boundedHTTPMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func boundedAgentRoute(method, path string) string {
	switch {
	case method == http.MethodGet && path == "/v1/agent/identity":
		return "/v1/agent/identity"
	case method == http.MethodPost && path == "/v1/agent/enroll":
		return "/v1/agent/enroll"
	case method == http.MethodPost && path == "/v1/agent/rotate":
		return "/v1/agent/rotate"
	case method == http.MethodPost && path == "/v1/agent/report":
		return "/v1/agent/report"
	case method == http.MethodPost && path == "/v1/agent/operations/sync":
		return "/v1/agent/operations/sync"
	default:
		return "unmatched"
	}
}

func agentCallOutcome(failureClass string) string {
	if failureClass == "" {
		return "success"
	}
	return "error"
}
func (c *Client) Identity(ctx context.Context, key ed25519.PrivateKey) (protocol.Identity, error) {
	var v protocol.Identity
	err := c.Call(ctx, "GET", "/v1/agent/identity", nil, &v, key)
	return v, err
}
func (c *Client) Enroll(ctx context.Context, uid, token string, key ed25519.PrivateKey) (protocol.Identity, error) {
	e := protocol.Enrollment{ClusterID: c.ClusterID, ClusterUID: uid, Token: token, PublicKey: protocol.EncodeKey(key.Public().(ed25519.PublicKey))}
	e.Proof = protocol.Proof(key, protocol.EnrollmentMessage(e))
	var v protocol.Identity
	err := c.Call(ctx, "POST", "/v1/agent/enroll", e, &v, nil)
	return v, err
}
