// Package agentrelay implements the customer-operated private mTLS ingress for
// Kordex agents. It is a closed route forwarder, not a general reverse proxy.
package agentrelay

import (
	"bytes"
	"context"
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
	"strconv"
	"strings"
	"time"
)

const (
	DefaultListenAddress = "0.0.0.0:8443"
	DefaultMaxRequest    = 4 << 20
	maxResponseBytes     = 64 << 10
	maxMappingBytes      = 1 << 20
)

type Route struct{ Method, Path string }

// Routes returns a copy of the complete supported protocol surface.
func Routes() []Route {
	return []Route{
		{http.MethodGet, "/v1/agent/identity"},
		{http.MethodPost, "/v1/agent/enroll"},
		{http.MethodPost, "/v1/agent/rotate"},
		{http.MethodPost, "/v1/agent/report"},
		{http.MethodPost, "/v1/agent/operations/sync"},
	}
}

// Mapping binds one exact URI SAN from a TLS-verified client leaf to one
// registered Kordex cluster. Multiple distinct certificate identities may map
// to a cluster during rotation; an identity may never map more than once.
type Mapping struct {
	Identity  string `json:"identity"`
	ClusterID string `json:"clusterId"`
	Enabled   bool   `json:"enabled"`
}

type MappingFile struct {
	Mappings []Mapping `json:"mappings"`
}

type Options struct {
	MaxRequestBytes int64
	RequestTimeout  time.Duration
}

type Handler struct {
	inner     http.Handler
	transport *http.Transport
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.inner.ServeHTTP(w, r) }

func (h *Handler) CloseIdleConnections() { h.transport.CloseIdleConnections() }

func LoadMappings(file string) ([]Mapping, error) {
	if file == "" {
		return nil, fmt.Errorf("client identity mapping file is required")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("client identity mapping file unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMappingBytes+1))
	if err != nil || len(data) > maxMappingBytes {
		return nil, fmt.Errorf("client identity mapping file is invalid")
	}
	if err := rejectDuplicateJSON(data); err != nil {
		return nil, fmt.Errorf("invalid client identity mapping file")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m MappingFile
	if err := dec.Decode(&m); err != nil || dec.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("invalid client identity mapping file")
	}
	if err := ValidateMappings(m.Mappings); err != nil {
		return nil, err
	}
	return m.Mappings, nil
}

func ValidateMappings(mappings []Mapping) error {
	if len(mappings) == 0 || len(mappings) > 10000 {
		return fmt.Errorf("at least one bounded client identity mapping is required")
	}
	seen := make(map[string]struct{}, len(mappings))
	for _, m := range mappings {
		if !validIdentity(m.Identity) || !validUUID(m.ClusterID) {
			return fmt.Errorf("client identity mapping is invalid")
		}
		if _, ok := seen[m.Identity]; ok {
			return fmt.Errorf("duplicate client identity mapping")
		}
		seen[m.Identity] = struct{}{}
	}
	return nil
}

func validIdentity(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(value, "\r\n \t") && u.String() == value
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidateUpstream restricts forwarding to an HTTP Kubernetes Service DNS
// name. The destination is startup configuration only and never comes from a
// request. API TLS termination is expected at the customer cluster boundary.
func ValidateUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, fmt.Errorf("API upstream must be a plain internal Kubernetes Service origin")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || !hasServiceDNSLabel(host) {
		return nil, fmt.Errorf("API upstream must use an internal Kubernetes Service DNS name")
	}
	port := u.Port()
	if port == "" {
		return nil, fmt.Errorf("API upstream must specify its service port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("API upstream service port is invalid")
	}
	u.Path, u.RawPath = "", ""
	return u, nil
}

func hasServiceDNSLabel(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) == 3 && labels[2] == "svc" {
		return validDNSLabel(labels[0]) && validDNSLabel(labels[1])
	}
	return len(labels) == 5 && labels[2] == "svc" && labels[3] == "cluster" && labels[4] == "local" && validDNSLabel(labels[0]) && validDNSLabel(labels[1])
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// NewHandler constructs a fixed-upstream handler. TLS must be configured by
// the caller with RequireAndVerifyClientCert; requests without verified chains
// are rejected again here to keep the trust boundary explicit.
func NewHandler(upstream string, mappings []Mapping, opts Options) (*Handler, error) {
	target, err := ValidateUpstream(upstream)
	if err != nil {
		return nil, err
	}
	if err := ValidateMappings(mappings); err != nil {
		return nil, err
	}
	if opts.MaxRequestBytes == 0 {
		opts.MaxRequestBytes = DefaultMaxRequest
	}
	if opts.MaxRequestBytes < 1 || opts.MaxRequestBytes > DefaultMaxRequest {
		return nil, fmt.Errorf("request size limit must be between 1 byte and 4 MiB")
	}
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = 20 * time.Second
	}
	if opts.RequestTimeout < time.Second || opts.RequestTimeout > time.Minute {
		return nil, fmt.Errorf("request timeout must be between 1 and 60 seconds")
	}
	byIdentity := make(map[string]Mapping, len(mappings))
	for _, m := range mappings {
		byIdentity[m.Identity] = m
	}
	return newHandler(target, byIdentity, opts, (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext), nil
}

func newHandler(target *url.URL, byIdentity map[string]Mapping, opts Options, dialContext func(context.Context, string, string) (net.Conn, error)) *Handler {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: opts.RequestTimeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   16,
	}
	client := &http.Client{Transport: transport, Timeout: opts.RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	concurrent := make(chan struct{}, 16)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case concurrent <- struct{}{}:
			defer func() { <-concurrent }()
		default:
			http.Error(w, "relay busy", http.StatusServiceUnavailable)
			return
		}
		if r.URL == nil {
			http.Error(w, "invalid request target", http.StatusBadRequest)
			return
		}
		route, allowed := matchRoute(r)
		if !canonicalTarget(r) {
			http.Error(w, "invalid request target", http.StatusBadRequest)
			return
		}
		if !allowed {
			if method, exists := allowedMethod(r.URL.Path); exists {
				w.Header().Set("Allow", method)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			http.NotFound(w, r)
			return
		}
		clusterID, status := mappedCluster(r, byIdentity)
		if status != 0 {
			http.Error(w, "client identity is not authorized", status)
			return
		}
		if err := validateHeaders(r, route, clusterID); err != nil {
			http.Error(w, "invalid agent request", http.StatusBadRequest)
			return
		}
		if r.ContentLength > opts.MaxRequestBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		var body []byte
		if r.Body != nil {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, opts.MaxRequestBytes+1))
			if err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
		}
		if int64(len(body)) > opts.MaxRequestBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if route.Method == http.MethodGet && len(body) != 0 {
			http.Error(w, "GET body not accepted", http.StatusBadRequest)
			return
		}
		if route.Path == "/v1/agent/enroll" {
			bodyCluster, ok := enrollmentCluster(body)
			if !ok || bodyCluster != clusterID {
				http.Error(w, "client identity is not authorized", http.StatusForbidden)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), opts.RequestTimeout)
		defer cancel()
		out, err := http.NewRequestWithContext(ctx, route.Method, target.String()+route.Path, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		copyProtocolHeaders(out.Header, r.Header, route)
		if route.Method == http.MethodPost {
			out.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(out)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			http.Error(w, "upstream redirect rejected", http.StatusBadGateway)
			return
		}
		responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		if err != nil || len(responseBody) > maxResponseBytes {
			http.Error(w, "upstream response unavailable", http.StatusBadGateway)
			return
		}
		if contentType := response.Header.Values("Content-Type"); len(contentType) == 1 {
			w.Header().Set("Content-Type", contentType[0])
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(responseBody)
	})
	return &Handler{inner: inner, transport: transport}
}

func matchRoute(r *http.Request) (Route, bool) {
	for _, route := range Routes() {
		if route.Method == r.Method && route.Path == r.URL.Path {
			return route, true
		}
	}
	return Route{}, false
}

func allowedMethod(path string) (string, bool) {
	for _, route := range Routes() {
		if route.Path == path {
			return route.Method, true
		}
	}
	return "", false
}

func canonicalTarget(r *http.Request) bool {
	return r.URL != nil && r.RequestURI == r.URL.Path && r.URL.RawQuery == "" && !r.URL.ForceQuery && r.URL.RawPath == "" && r.URL.Opaque == "" && r.URL.Scheme == "" && r.URL.Host == "" && r.URL.User == nil && r.URL.Fragment == "" && r.URL.EscapedPath() == r.URL.Path && !strings.Contains(r.URL.Path, "\\")
}

func mappedCluster(r *http.Request, mappings map[string]Mapping) (string, int) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return "", http.StatusUnauthorized
	}
	leaf := r.TLS.PeerCertificates[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA {
		return "", http.StatusUnauthorized
	}
	var identity string
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return "", http.StatusForbidden
	}
	identity = leaf.URIs[0].String()
	mapping, ok := mappings[identity]
	if !ok || !mapping.Enabled {
		return "", http.StatusForbidden
	}
	return mapping.ClusterID, 0
}

func validateHeaders(r *http.Request, route Route, clusterID string) error {
	for name := range r.Header {
		lower := strings.ToLower(name)
		if isUntrustedIdentityHeader(lower) {
			return fmt.Errorf("untrusted header")
		}
		if strings.HasPrefix(lower, "x-kordex-") && !isProtocolHeader(lower) {
			return fmt.Errorf("unknown Kordex header")
		}
	}
	if route.Method == http.MethodPost {
		values := r.Header.Values("Content-Type")
		if len(values) != 1 || values[0] != "application/json" {
			return fmt.Errorf("content type required")
		}
	}
	if route.Path == "/v1/agent/enroll" {
		for _, name := range protocolHeaders {
			if len(r.Header.Values(name)) != 0 {
				return fmt.Errorf("enrollment must use proof authentication")
			}
		}
		return nil
	}
	for _, name := range protocolHeaders {
		values := r.Header.Values(name)
		if len(values) != 1 || strings.ContainsAny(values[0], "\r\n") {
			return fmt.Errorf("signed request headers required")
		}
	}
	values := r.Header.Values("X-Kordex-Cluster")
	if len(values) != 1 || values[0] != clusterID {
		return fmt.Errorf("signed cluster differs from certificate mapping")
	}
	return nil
}

func isUntrustedIdentityHeader(lower string) bool {
	return strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-remote-") || strings.HasPrefix(lower, "x-envoy-") || strings.HasPrefix(lower, "x-original-") || strings.HasPrefix(lower, "x-rewrite-") || strings.HasPrefix(lower, "x-authenticated-") || strings.HasPrefix(lower, "x-auth-request-") || strings.HasPrefix(lower, "x-client-cert") || strings.HasPrefix(lower, "x-ssl-client-") || strings.HasPrefix(lower, "cf-access-") || lower == "cf-connecting-ip" || lower == "true-client-ip" || lower == "forwarded" || lower == "x-real-ip" || lower == "authorization" || lower == "proxy-authorization" || strings.HasPrefix(lower, "proxy-") || lower == "proxy" || lower == "cookie" || lower == "connection" || lower == "transfer-encoding" || lower == "content-encoding"
}

var protocolHeaders = []string{"X-Kordex-Version", "X-Kordex-Cluster", "X-Kordex-Key", "X-Kordex-Time", "X-Kordex-Nonce", "X-Kordex-Signature"}

func isProtocolHeader(lower string) bool {
	for _, name := range protocolHeaders {
		if strings.ToLower(name) == lower {
			return true
		}
	}
	return false
}

func copyProtocolHeaders(dst, src http.Header, route Route) {
	for _, name := range protocolHeaders {
		if route.Path != "/v1/agent/enroll" {
			dst.Set(name, src.Get(name))
		}
	}
}

func enrollmentCluster(body []byte) (string, bool) {
	if rejectDuplicateJSON(body) != nil {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return "", false
	}
	seen := make(map[string]bool)
	cluster := ""
	for dec.More() {
		token, err = dec.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return "", false
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", false
		}
		if key == "clusterId" {
			if err := json.Unmarshal(value, &cluster); err != nil {
				return "", false
			}
		}
	}
	if _, err := dec.Token(); err != nil || cluster == "" || dec.Decode(new(any)) != io.EOF {
		return "", false
	}
	return cluster, true
}

func rejectDuplicateJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func scanJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, ok := seen[key]; ok {
				return fmt.Errorf("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case json.Delim('['):
		for dec.More() {
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	case json.Delim('}'), json.Delim(']'):
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

// LoadServerTLSConfig loads customer-mounted TLS assets and requires verified
// client certificates. The CA file must contain only CA certificates.
func LoadServerTLSConfig(certFile, keyFile, clientCAFile, serverName string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" || clientCAFile == "" || !validServerName(serverName) {
		return nil, fmt.Errorf("relay server certificate, key, client CA, and DNS name are required")
	}
	info, err := os.Stat(keyFile) // Kubernetes Secret projections use symlinked files.
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 {
		return nil, fmt.Errorf("relay private key file permissions are unsafe")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("relay server certificate or key is invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) || leaf.IsCA || leaf.VerifyHostname(serverName) != nil || !hasUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, fmt.Errorf("relay server certificate is not currently valid for server authentication")
	}
	pair.Leaf = leaf
	caData, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("relay client CA bundle unavailable")
	}
	clientCAs, err := parseCAs(caData)
	if err != nil {
		return nil, fmt.Errorf("relay client CA bundle is invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}, nil
}

func validServerName(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\:*?[]@ \t\r\n") || strings.HasSuffix(name, ".") || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(strings.ToLower(name), ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func parseCAs(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(data)
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("invalid PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil, fmt.Errorf("non-CA certificate")
		}
		pool.AddCert(cert)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, fmt.Errorf("empty CA bundle")
	}
	return pool, nil
}

func hasUsage(cert *x509.Certificate, expected x509.ExtKeyUsage) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == expected || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return len(cert.ExtKeyUsage) == 0
}

func ValidateListenAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || host != "0.0.0.0" && host != "::" {
		return fmt.Errorf("relay must bind an unspecified pod interface and valid port")
	}
	return nil
}
