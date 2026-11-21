// Package agentgateway implements the loopback TLS origin for the optional
// self-managed lab's Cloudflare Access tunnel. It is deliberately not a general
// reverse proxy: the upstream is fixed and the method/path map is closed.
package agentgateway

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultListenAddress = "127.0.0.1:18443"
	upstreamAddress      = "http://127.0.0.1:8080"
	maxRequestBody       = 4 << 20
)

type Route struct {
	Method string
	Path   string
}

// allowedRoutes is the complete public agent surface. Keep synchronized with
// agent/internal/client.boundedAgentRoute and the control-plane agent router.
var allowedRoutes = [...]Route{
	{Method: http.MethodGet, Path: "/v1/agent/identity"},
	{Method: http.MethodPost, Path: "/v1/agent/enroll"},
	{Method: http.MethodPost, Path: "/v1/agent/report"},
	{Method: http.MethodPost, Path: "/v1/agent/rotate"},
	{Method: http.MethodPost, Path: "/v1/agent/operations/sync"},
}

// NewHandler requires the Cloudflare Access service-token pair and always
// forwards to the local Kordex API. The upstream cannot be configured at run
// time, preventing the gateway from becoming an open proxy.
func NewHandler(accessClientID, accessClientSecret string) (http.Handler, error) {
	if accessClientID == "" || accessClientSecret == "" || strings.ContainsAny(accessClientID+accessClientSecret, "\r\n") {
		return nil, fmt.Errorf("Cloudflare Access credentials are required")
	}
	upstream, _ := url.Parse(upstreamAddress)
	return newHandler(accessClientID, accessClientSecret, upstream), nil
}

func newHandler(accessClientID, accessClientSecret string, upstream *url.URL) http.Handler {
	target := *upstream
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 20 * time.Second
	transport.IdleConnTimeout = 30 * time.Second
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(&target)
			request.Out.Host = target.Host
			for _, name := range []string{
				"CF-Access-Client-Id", "CF-Access-Client-Secret", "CF-Access-Jwt-Assertion",
				"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
				"CF-Connecting-IP", "True-Client-IP",
			} {
				request.Out.Header.Del(name)
			}
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			if response.StatusCode >= 300 && response.StatusCode < 400 {
				return fmt.Errorf("unexpected upstream redirect")
			}
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodAllowed := false
		for _, route := range allowedRoutes {
			if r.URL.Path == route.Path && r.Method == route.Method {
				methodAllowed = true
				break
			}
		}
		if !canonicalRequestTarget(r) {
			http.Error(w, "invalid request target", http.StatusBadRequest)
			return
		}
		if !methodAllowed {
			for _, route := range allowedRoutes {
				if r.URL.Path == route.Path {
					w.Header().Set("Allow", route.Method)
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		if !singleHeaderMatches(r.Header, "CF-Access-Client-Id", accessClientID) || !singleHeaderMatches(r.Header, "CF-Access-Client-Secret", accessClientSecret) {
			http.Error(w, "access denied", http.StatusUnauthorized)
			return
		}
		// The Kordex agent authenticates through signed X-Kordex headers. It has
		// no bearer-token contract; do not let unrelated credentials cross this
		// boundary or reach the API.
		if len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Proxy-Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 {
			http.Error(w, "credential header not accepted", http.StatusBadRequest)
			return
		}
		requestBody := r.Body
		if requestBody == nil {
			requestBody = http.NoBody
		}
		body, err := io.ReadAll(io.LimitReader(requestBody, maxRequestBody+1))
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(body) > maxRequestBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Method == http.MethodGet && len(body) != 0 {
			http.Error(w, "GET body not accepted", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
	})
}

func canonicalRequestTarget(r *http.Request) bool {
	return r.URL != nil && r.RequestURI == r.URL.Path && r.URL.RawQuery == "" &&
		!r.URL.ForceQuery && r.URL.RawPath == "" && r.URL.Opaque == "" &&
		r.URL.Scheme == "" && r.URL.Host == "" && r.URL.User == nil && r.URL.Fragment == "" &&
		path.Clean(r.URL.Path) == r.URL.Path
}

func singleHeaderMatches(header http.Header, name, expected string) bool {
	values := header.Values(name)
	if len(values) != 1 {
		return false
	}
	gotHash, expectedHash := sha256.Sum256([]byte(values[0])), sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(gotHash[:], expectedHash[:]) == 1
}

// ValidateListenAddress requires a numeric loopback address; DNS names are
// intentionally rejected so resolver changes cannot turn this into a LAN bind.
func ValidateListenAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("gateway listen address must be an IP loopback and port")
	}
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if ip == nil || !ip.IsLoopback() || portErr != nil || port < 1 || port > 65535 {
		return fmt.Errorf("gateway listen address must be an IP loopback and valid port")
	}
	return nil
}

// LoadOriginCertificate validates the serving certificate and private-key
// permissions, including the DNS name cloudflared must verify via originServerName.
func LoadOriginCertificate(certFile, keyFile, serverName string) (tls.Certificate, error) {
	if certFile == "" || keyFile == "" || serverName == "" || strings.ContainsAny(serverName, "/\\\r\n") {
		return tls.Certificate{}, fmt.Errorf("gateway TLS certificate, key, and server name are required")
	}
	info, err := os.Lstat(keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return tls.Certificate{}, fmt.Errorf("gateway TLS private key must be readable only by its owner")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load gateway TLS key pair")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(serverName) != nil {
		return tls.Certificate{}, fmt.Errorf("gateway TLS certificate does not match configured server name")
	}
	serverUsage := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			serverUsage = true
		}
	}
	if !serverUsage {
		return tls.Certificate{}, fmt.Errorf("gateway TLS certificate is not valid for server authentication")
	}
	now := time.Now()
	if leaf.NotBefore.After(now) || leaf.NotAfter.Before(now) {
		return tls.Certificate{}, fmt.Errorf("gateway TLS certificate is outside its validity period")
	}
	certificate.Leaf = leaf
	return certificate, nil
}
