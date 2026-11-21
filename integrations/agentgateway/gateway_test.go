package agentgateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAccessID     = "test-access-client-id"
	testAccessSecret = "test-access-client-secret-do-not-forward"
)

func TestGatewayRequiresCompleteAccessConfiguration(t *testing.T) {
	for _, pair := range [][2]string{{"", ""}, {testAccessID, ""}, {"", testAccessSecret}, {testAccessID + "\n", testAccessSecret}} {
		if _, err := NewHandler(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted incomplete or malformed Access credentials")
		}
	}
	if _, err := NewHandler(testAccessID, testAccessSecret); err != nil {
		t.Fatalf("rejected configured Access credentials: %v", err)
	}
}

func TestEveryAllowedMethodPathIsForwardedAndAccessHeadersAreRemoved(t *testing.T) {
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("CF-Access-Client-Id") != "" || r.Header.Get("CF-Access-Client-Secret") != "" || r.Header.Get("CF-Access-Jwt-Assertion") != "" {
			t.Error("Cloudflare credential reached Kordex API")
		}
		if r.Header.Get("X-Kordex-Signature") != "signed-agent-request" {
			t.Error("Kordex signed authentication header was not preserved")
		}
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
			t.Error("untrusted forwarding header reached Kordex API")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()
	upstream, _ := url.Parse(api.URL)
	handler := newHandler(testAccessID, testAccessSecret, upstream)
	for _, route := range allowedRoutes {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			body := io.Reader(http.NoBody)
			if route.Method == http.MethodPost {
				body = strings.NewReader(`{"ok":true}`)
			}
			req := httptest.NewRequest(route.Method, route.Path, body)
			req.Header.Set("CF-Access-Client-Id", testAccessID)
			req.Header.Set("CF-Access-Client-Secret", testAccessSecret)
			req.Header.Set("CF-Access-Jwt-Assertion", "edge-jwt")
			req.Header.Set("X-Kordex-Signature", "signed-agent-request")
			req.Header.Set("X-Forwarded-For", "attacker-value")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d body=%q", response.Code, response.Body.String())
			}
		})
	}
	if got := calls.Load(); got != int32(len(allowedRoutes)) {
		t.Fatalf("forwarded requests = %d, want %d", got, len(allowedRoutes))
	}
}

func TestDeniedRoutesMethodsAndCredentialsNeverReachAPI(t *testing.T) {
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer api.Close()
	upstream, _ := url.Parse(api.URL)
	handler := newHandler(testAccessID, testAccessSecret, upstream)
	cases := []struct {
		name, method, target, id, secret string
		want                             int
	}{
		{"unapproved route", http.MethodGet, "/healthz", testAccessID, testAccessSecret, http.StatusNotFound},
		{"admin route", http.MethodPost, "/v1/organizations/org/memberships", testAccessID, testAccessSecret, http.StatusNotFound},
		{"wrong method", http.MethodPost, "/v1/agent/identity", testAccessID, testAccessSecret, http.StatusMethodNotAllowed},
		{"wrong method on write", http.MethodGet, "/v1/agent/report", testAccessID, testAccessSecret, http.StatusMethodNotAllowed},
		{"missing headers", http.MethodPost, "/v1/agent/report", "", "", http.StatusUnauthorized},
		{"wrong client ID", http.MethodPost, "/v1/agent/report", "wrong", testAccessSecret, http.StatusUnauthorized},
		{"wrong secret", http.MethodPost, "/v1/agent/report", testAccessID, "wrong", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, http.NoBody)
			if tc.id != "" {
				req.Header.Set("CF-Access-Client-Id", tc.id)
			}
			if tc.secret != "" {
				req.Header.Set("CF-Access-Client-Secret", tc.secret)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if strings.Contains(response.Body.String(), testAccessSecret) {
				t.Fatal("response disclosed Access secret")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("denied requests reached API %d times", calls.Load())
	}
}

func TestRejectsNonCanonicalTargetsQueriesTraversalAndAuthorization(t *testing.T) {
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer api.Close()
	upstream, _ := url.Parse(api.URL)
	handler := newHandler(testAccessID, testAccessSecret, upstream)
	cases := []struct {
		name    string
		request *http.Request
		want    int
	}{
		{"query", httptest.NewRequest(http.MethodGet, "/v1/agent/identity?x=1", nil), http.StatusBadRequest},
		{"encoded path", rawRequest("/v1/agent/%69dentity", "/v1/agent/identity", "/v1/agent/%69dentity"), http.StatusBadRequest},
		{"traversal", rawRequest("/v1/agent/../healthz", "/v1/agent/../healthz", ""), http.StatusBadRequest},
		{"encoded traversal", rawRequest("/v1/agent/%2e%2e/healthz", "/v1/agent/../healthz", "/v1/agent/%2e%2e/healthz"), http.StatusBadRequest},
		{"absolute form", rawRequest("http://attacker.invalid/v1/agent/identity", "/v1/agent/identity", ""), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.request
			req.Method = http.MethodGet
			req.Header.Set("CF-Access-Client-Id", testAccessID)
			req.Header.Set("CF-Access-Client-Secret", testAccessSecret)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d body=%q", response.Code, tc.want, response.Body.String())
			}
		})
	}
	for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
		credentialReq := httptest.NewRequest(http.MethodGet, "/v1/agent/identity", nil)
		credentialReq.Header.Set("CF-Access-Client-Id", testAccessID)
		credentialReq.Header.Set("CF-Access-Client-Secret", testAccessSecret)
		credentialReq.Header.Set(header, "sensitive-value-must-not-be-forwarded")
		credentialResponse := httptest.NewRecorder()
		handler.ServeHTTP(credentialResponse, credentialReq)
		if credentialResponse.Code != http.StatusBadRequest || strings.Contains(credentialResponse.Body.String(), "sensitive-value-must-not-be-forwarded") {
			t.Fatalf("%s rejection response = %d %q", header, credentialResponse.Code, credentialResponse.Body.String())
		}
	}
	duplicate := httptest.NewRequest(http.MethodGet, "/v1/agent/identity", nil)
	duplicate.Header[http.CanonicalHeaderKey("CF-Access-Client-Id")] = []string{testAccessID, testAccessID}
	duplicate.Header.Set("CF-Access-Client-Secret", testAccessSecret)
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate credential status = %d", duplicateResponse.Code)
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed or unauthorized requests reached API %d times", calls.Load())
	}
}

func rawRequest(requestURI, path, rawPath string) *http.Request {
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: path, RawPath: rawPath}, RequestURI: requestURI, Header: make(http.Header), Body: http.NoBody}
	if strings.HasPrefix(requestURI, "http://") {
		req.URL.Scheme = "http"
		req.URL.Host = "attacker.invalid"
	}
	return req
}

func TestGatewayEndToEndTLSAccessFixtureAndUnavailableUpstream(t *testing.T) {
	var reached atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agent/report" || r.Header.Get("X-Kordex-Signature") != "fixture-signature" {
			t.Errorf("unexpected forwarded request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("CF-Access-Client-Secret") != "" {
			t.Error("Access credential leaked upstream")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	upstream, _ := url.Parse(api.URL)
	accessFixture := httptest.NewTLSServer(newHandler(testAccessID, testAccessSecret, upstream))
	request, _ := http.NewRequest(http.MethodPost, accessFixture.URL+"/v1/agent/report", strings.NewReader(`{"nodes":[]}`))
	request.Header.Set("CF-Access-Client-Id", testAccessID)
	request.Header.Set("CF-Access-Client-Secret", testAccessSecret)
	request.Header.Set("X-Kordex-Signature", "fixture-signature")
	response, err := accessFixture.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted || !reached.Load() {
		t.Fatalf("fixture response=%d upstreamReached=%v", response.StatusCode, reached.Load())
	}
	accessFixture.Close()
	api.Close()

	closed := httptest.NewServer(http.NotFoundHandler())
	deadTarget, _ := url.Parse(closed.URL)
	closed.Close()
	dead := httptest.NewServer(newHandler(testAccessID, testAccessSecret, deadTarget))
	defer dead.Close()
	req, err := http.NewRequest(http.MethodGet, dead.URL+"/v1/agent/identity", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("CF-Access-Client-Id", testAccessID)
	req.Header.Set("CF-Access-Client-Secret", testAccessSecret)
	resp, err := dead.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), deadTarget.Host) {
		t.Fatalf("unavailable API response = %d %q", resp.StatusCode, body)
	}
}

func TestListenerMustBeLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:18443", "[::1]:18443"} {
		if err := ValidateListenAddress(address); err != nil {
			t.Errorf("rejected loopback %q: %v", address, err)
		}
	}
	for _, address := range []string{":18443", "0.0.0.0:18443", "localhost:18443", "192.0.2.1:18443", "127.0.0.1:0", "127.0.0.1:bad"} {
		if err := ValidateListenAddress(address); err == nil {
			t.Errorf("accepted non-loopback/invalid address %q", address)
		}
	}
}

func TestOriginCertificateRequiresValidSANAndPrivateKeyPermissions(t *testing.T) {
	t.TempDir()
	for _, tc := range []struct {
		name     string
		host     string
		notAfter time.Time
		keyMode  os.FileMode
		wantErr  bool
	}{
		{"valid", "gateway.local", time.Now().Add(time.Hour), 0600, false},
		{"wrong hostname", "other.local", time.Now().Add(time.Hour), 0600, true},
		{"expired", "gateway.local", time.Now().Add(-time.Hour), 0600, true},
		{"permissive key", "gateway.local", time.Now().Add(time.Hour), 0644, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certFile, keyFile := writeTestCertificate(t, tc.host, tc.notAfter, tc.keyMode)
			_, err := LoadOriginCertificate(certFile, keyFile, "gateway.local")
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadOriginCertificate error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func writeTestCertificate(t *testing.T, host string, notAfter time.Time, keyMode os.FileMode) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "origin.crt")
	keyFile := filepath.Join(t.TempDir(), "origin.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), keyMode); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
