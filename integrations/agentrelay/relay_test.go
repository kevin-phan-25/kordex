package agentrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testCluster  = "11111111-1111-4111-8111-111111111111"
	otherCluster = "22222222-2222-4222-8222-222222222222"
	testIdentity = "spiffe://customer.example/kordex/clusters/" + testCluster
)

type testPKI struct {
	root       *x509.CertPool
	rootPEM    []byte
	server     tls.Certificate
	client     tls.Certificate
	clientLeaf *x509.Certificate
}

func makePKI(t *testing.T, clientURI string, clientNotAfter time.Time, clientUsage []x509.ExtKeyUsage) testPKI {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	issue := func(serial int64, notAfter time.Time, usages []x509.ExtKeyUsage, dns []string, uris []*url.URL) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: dns, URIs: uris, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, template, rootCert, &key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair
	}
	server := issue(2, now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"}, nil)
	u, _ := url.Parse(clientURI)
	var uris []*url.URL
	if clientURI != "" {
		uris = []*url.URL{u}
	}
	client := issue(3, clientNotAfter, clientUsage, nil, uris)
	clientLeaf, err := x509.ParseCertificate(client.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{root: pool, rootPEM: rootPEM, server: server, client: client, clientLeaf: clientLeaf}
}

func tlsRequestState(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
}

func newTestHandler(t *testing.T, upstream http.Handler, mapping []Mapping, options Options) http.Handler {
	t.Helper()
	api := httptest.NewServer(upstream)
	t.Cleanup(api.Close)
	apiURL, _ := url.Parse("http://api.kordex-system.svc:8080")
	apiAddress := strings.TrimPrefix(api.URL, "http://")
	dialer := &net.Dialer{Timeout: time.Second}
	handler := newHandler(apiURL, func() map[string]Mapping {
		m := map[string]Mapping{}
		for _, entry := range mapping {
			m[entry.Identity] = entry
		}
		return m
	}(), normalizeOptions(options), nil, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, apiAddress)
	})
	return handler
}

func normalizeOptions(o Options) Options {
	if o.MaxRequestBytes == 0 {
		o.MaxRequestBytes = DefaultMaxRequest
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = 3 * time.Second
	}
	return o
}

func validMapping() Mapping {
	return Mapping{Identity: testIdentity, ClusterID: testCluster, Enabled: true}
}

func addSignedHeaders(r *http.Request, cluster string) {
	r.Header.Set("X-Kordex-Version", "1")
	r.Header.Set("X-Kordex-Cluster", cluster)
	r.Header.Set("X-Kordex-Key", "fixture-key")
	r.Header.Set("X-Kordex-Time", "fixture-time")
	r.Header.Set("X-Kordex-Nonce", "fixture-nonce")
	r.Header.Set("X-Kordex-Signature", "fixture-signature")
}

func testRequest(method, path, body string, leaf *x509.Certificate) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.TLS = tlsRequestState(leaf)
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	if path != "/v1/agent/enroll" {
		addSignedHeaders(r, testCluster)
	}
	return r
}

func TestFiveAllowedRoutesPreserveSignedRequestBytesAndStripHeaders(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	var calls atomic.Int32
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Kordex-Signature") != "fixture-signature" && r.URL.Path != "/v1/agent/enroll" {
			t.Errorf("signed header not preserved")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("CF-Access-Client-Secret") != "" {
			t.Errorf("untrusted header forwarded")
		}
		if r.URL.Host != "" && r.Host != "api.kordex-system.svc:8080" {
			t.Errorf("fixed upstream Host not used: %q", r.Host)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	h := newTestHandler(t, api, []Mapping{validMapping()}, Options{})
	routes := Routes()
	for _, route := range routes {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			body := `{"clusterId":"` + testCluster + `","clusterUid":"test-uid","token":"0123456789012345678901234567890123456789012","publicKey":"key","proof":"proof"}`
			if route.Path != "/v1/agent/enroll" {
				body = `{"nodes":[]}`
			}
			req := testRequest(route.Method, route.Path, body, pki.clientLeaf)
			if route.Path != "/v1/agent/enroll" {
				req.Header.Set("X-Forwarded-For", "spoofed")
			}
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if route.Path != "/v1/agent/enroll" { // The spoofed request is deliberately rejected.
				if res.Code != http.StatusBadRequest {
					t.Fatalf("spoofed header status = %d", res.Code)
				}
				return
			}
			if res.Code != http.StatusAccepted {
				t.Fatalf("status = %d, body=%s", res.Code, res.Body.String())
			}
		})
	}
	// Exercise each signed route without untrusted headers and prove exact body forwarding.
	for _, route := range routes {
		if route.Path == "/v1/agent/enroll" {
			continue
		}
		body := `{"nodes":[]}`
		if route.Method == http.MethodGet {
			body = ""
		}
		req := testRequest(route.Method, route.Path, body, pki.clientLeaf)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("%s %s status = %d body=%s", route.Method, route.Path, res.Code, res.Body.String())
		}
	}
	if got := calls.Load(); got != int32(len(routes)) {
		t.Fatalf("upstream call count = %d", got)
	}
}

func TestEnrollmentClusterBindingAndDuplicateFields(t *testing.T) {
	if got, ok := enrollmentCluster([]byte(`{"clusterId":"` + testCluster + `","token":"x"}`)); !ok || got != testCluster {
		t.Fatalf("valid enrollment: %q %v", got, ok)
	}
	for _, body := range []string{
		`{"clusterId":"` + testCluster + `","clusterId":"` + otherCluster + `"}`,
		`{"ClusterID":"` + testCluster + `"}`,
		`{"clusterId":"` + testCluster + `"} {}`,
		`[]`,
	} {
		if _, ok := enrollmentCluster([]byte(body)); ok {
			t.Fatalf("accepted ambiguous enrollment JSON %s", body)
		}
	}
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("mismatched enrollment reached API") }), []Mapping{validMapping()}, Options{})
	req := testRequest(http.MethodPost, "/v1/agent/enroll", `{"clusterId":"`+otherCluster+`"}`, pki.clientLeaf)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("mismatch status = %d", res.Code)
	}
}

func TestUnknownDisabledDuplicateAndUnverifiedCertificateFailClosed(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for name, mappings := range map[string][]Mapping{
		"unknown":  {{Identity: "spiffe://customer.example/other", ClusterID: testCluster, Enabled: true}},
		"disabled": {{Identity: testIdentity, ClusterID: testCluster, Enabled: false}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHandler(t, api, mappings, Options{})
			req := testRequest(http.MethodGet, "/v1/agent/identity", "", pki.clientLeaf)
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != http.StatusForbidden {
				t.Fatalf("status = %d", res.Code)
			}
		})
	}
	if err := ValidateMappings([]Mapping{validMapping(), validMapping()}); err == nil {
		t.Fatal("duplicate identity mappings accepted")
	}
	h := newTestHandler(t, api, []Mapping{validMapping()}, Options{})
	req := httptest.NewRequest(http.MethodGet, "/v1/agent/identity", nil)
	addSignedHeaders(req, testCluster)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("unverified TLS request status = %d", res.Code)
	}
}

func TestMethodsPathsQueriesTraversalAndAbsoluteTargetsAreRejected(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), []Mapping{validMapping()}, Options{})
	requests := []*http.Request{
		testRequest(http.MethodPut, "/v1/agent/report", `{}`, pki.clientLeaf),
		testRequest(http.MethodGet, "/v1/agent/unknown", "", pki.clientLeaf),
		testRequest(http.MethodPost, "/v1/agent/report?x=1", `{}`, pki.clientLeaf),
		testRequest(http.MethodPost, "/v1/agent/../agent/report", `{}`, pki.clientLeaf),
		testRequest(http.MethodPost, "http://attacker.invalid/v1/agent/report", `{}`, pki.clientLeaf),
	}
	for i, req := range requests {
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code < 400 {
			t.Fatalf("request %d accepted", i)
		}
	}
	encoded := testRequest(http.MethodPost, "/v1/agent/report", `{}`, pki.clientLeaf)
	encoded.URL.RawPath = "/v1/agent/%2freport"
	encoded.RequestURI = encoded.URL.RawPath
	res := httptest.NewRecorder()
	h.ServeHTTP(res, encoded)
	if res.Code < 400 {
		t.Fatal("encoded path accepted")
	}
}

func TestSpoofedAndDuplicateAuthenticationHeadersAreRejectedAndNeverForwarded(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	var calls atomic.Int32
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }), []Mapping{validMapping()}, Options{})
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Add("X-Kordex-Cluster", testCluster) },
		func(r *http.Request) { r.Header.Set("X-Kordex-Cluster", otherCluster) },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer forged") },
		func(r *http.Request) { r.Header.Set("X-Remote-User", "forged") },
		func(r *http.Request) { r.Header.Set("X-Envoy-External-Address", "forged") },
		func(r *http.Request) { r.Header.Set("X-Client-Cert", "forged") },
		func(r *http.Request) { r.Header.Set("CF-Access-Client-Secret", "secret") },
	} {
		req := testRequest(http.MethodPost, "/v1/agent/report", `{}`, pki.clientLeaf)
		mutate(req)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code < 400 {
			t.Fatalf("spoofed request accepted: %d", res.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("spoofed request reached API")
	}
}

func TestLimitsTimeoutRedirectAndAPIRecovery(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	tooLarge := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("large body reached API") }), []Mapping{validMapping()}, Options{MaxRequestBytes: 4, RequestTimeout: time.Second})
	req := testRequest(http.MethodPost, "/v1/agent/report", `{"x":1}`, pki.clientLeaf)
	res := httptest.NewRecorder()
	tooLarge.ServeHTTP(res, req)
	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("size status = %d", res.Code)
	}
	var calls atomic.Int32
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Location", "http://attacker.invalid/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	h := newTestHandler(t, api, []Mapping{validMapping()}, Options{})
	for i, want := range []int{http.StatusBadGateway, http.StatusServiceUnavailable} {
		req := testRequest(http.MethodGet, "/v1/agent/identity", "", pki.clientLeaf)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", i, res.Code, want)
		}
	}
	var recoverCalls atomic.Int32
	recoverHandler := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if recoverCalls.Add(1) == 1 {
			http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), []Mapping{validMapping()}, Options{})
	for i, want := range []int{http.StatusServiceUnavailable, http.StatusOK} {
		req := testRequest(http.MethodGet, "/v1/agent/identity", "", pki.clientLeaf)
		res := httptest.NewRecorder()
		recoverHandler.ServeHTTP(res, req)
		if res.Code != want {
			t.Fatalf("recovery attempt %d status = %d", i, res.Code)
		}
	}
}

func TestUpstreamTimeoutAndUnavailableFailBoundedly(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	t.Run("timeout", func(t *testing.T) {
		h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}), []Mapping{validMapping()}, Options{RequestTimeout: time.Second})
		req := testRequest(http.MethodGet, "/v1/agent/identity", "", pki.clientLeaf)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusBadGateway {
			t.Fatalf("timeout status = %d", res.Code)
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		closed, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := closed.Addr().String()
		_ = closed.Close()
		target, _ := url.Parse("http://api.kordex-system.svc:8080")
		h := newHandler(target, map[string]Mapping{testIdentity: validMapping()}, Options{RequestTimeout: time.Second}, nil, func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		})
		req := testRequest(http.MethodGet, "/v1/agent/identity", "", pki.clientLeaf)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusBadGateway {
			t.Fatalf("unavailable status = %d", res.Code)
		}
	})
}

func TestSignedRequestBodyIsForwardedByteForByte(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	payload := []byte("{ \"nodes\" : [ ], \"version\": 1 }\n")
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, payload) {
			t.Errorf("request body changed: %q", got)
		}
		if r.Header.Get("X-Kordex-Signature") != "fixture-signature" {
			t.Error("signature header changed")
		}
		w.WriteHeader(http.StatusAccepted)
	}), []Mapping{validMapping()}, Options{})
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/report", bytes.NewReader(payload))
	req.TLS = tlsRequestState(pki.clientLeaf)
	req.Header.Set("Content-Type", "application/json")
	addSignedHeaders(req, testCluster)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestValidCertificateAloneCannotAuthorizeUnsignedOrInvalidSignedAPIRequest(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This fixture represents the API's independent signature gate; the relay
		// neither creates nor verifies an Ed25519 signature.
		if r.Header.Get("X-Kordex-Signature") != "valid-fixture-signature" || r.Header.Get("X-Kordex-Cluster") != testCluster {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := newTestHandler(t, api, []Mapping{validMapping()}, Options{})
	unsigned := httptest.NewRequest(http.MethodGet, "/v1/agent/identity", nil)
	unsigned.TLS = tlsRequestState(pki.clientLeaf)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, unsigned)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("unsigned status = %d", res.Code)
	}
	invalid := testRequest(http.MethodGet, "/v1/agent/identity", "", pki.clientLeaf)
	invalid.Header.Set("X-Kordex-Signature", "invalid-fixture-signature")
	res = httptest.NewRecorder()
	h.ServeHTTP(res, invalid)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("invalid API signature status = %d", res.Code)
	}
	valid := testRequest(http.MethodGet, "/v1/agent/identity", "", pki.clientLeaf)
	valid.Header.Set("X-Kordex-Signature", "valid-fixture-signature")
	res = httptest.NewRecorder()
	h.ServeHTTP(res, valid)
	if res.Code != http.StatusOK {
		t.Fatalf("valid API authorization status = %d", res.Code)
	}
}

func TestUpstreamMustBeFixedInternalServiceOrigin(t *testing.T) {
	for _, raw := range []string{"https://api.example.com", "http://127.0.0.1:8080", "http://api.example:8080", "http://user@api.ns.svc:8080", "http://api.ns.svc:8080/other", "http://api.ns.svc:8080?x=1", "http://api.ns.svc:8080#fragment", "http://api.ns.svc:99999"} {
		if _, err := ValidateUpstream(raw); err == nil {
			t.Errorf("accepted upstream %q", raw)
		}
	}
	if _, err := ValidateUpstream("http://kordex-api.kordex-system.svc.cluster.local:8080"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadServerTLSConfigRequiresValidCAKeyPairAndServerName(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.server.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(pki.server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for name, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: pki.rootPEM} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(keyFile, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerTLSConfig(certFile, keyFile, caFile, "wrong.example"); err == nil {
		t.Fatal("wrong server name accepted")
	}
	if _, err := LoadServerTLSConfig(certFile, keyFile, filepath.Join(dir, "missing-ca"), "localhost"); err == nil {
		t.Fatal("missing CA accepted")
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(pki.client.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerTLSConfig(certFile, keyFile, caFile, "localhost"); err == nil {
		t.Fatal("mismatched server certificate key accepted")
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, []byte("not a CA"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerTLSConfig(certFile, keyFile, caFile, "localhost"); err == nil {
		t.Fatal("malformed CA accepted")
	}
	if err := os.WriteFile(caFile, pki.rootPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerTLSConfig(certFile, keyFile, caFile, "localhost"); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	if err := os.Chmod(keyFile, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerTLSConfig(certFile, keyFile, caFile, "localhost"); err == nil {
		t.Fatal("unsafe key permissions accepted")
	}
}

func TestRealMutualTLSHandshakeAndClientCertificateRejections(t *testing.T) {
	t.Run("trusted client", func(t *testing.T) {
		pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		server := startMTLSServer(t, pki, []Mapping{validMapping()})
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pki.root, Certificates: []tls.Certificate{pki.client}, ServerName: "localhost"}}}
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/agent/identity", nil)
		addSignedHeaders(req, testCluster)
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("mTLS request failed: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d", response.StatusCode)
		}
	})
	for name, usage := range map[string][]x509.ExtKeyUsage{"wrong usage": {x509.ExtKeyUsageServerAuth}} {
		t.Run(name, func(t *testing.T) {
			pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), usage)
			server := startMTLSServer(t, pki, []Mapping{validMapping()})
			client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.root, Certificates: []tls.Certificate{pki.client}, ServerName: "localhost"}}}
			if _, err := client.Get(server.URL + "/v1/agent/identity"); err == nil {
				t.Fatal("invalid client certificate accepted")
			}
		})
	}
	t.Run("expired client", func(t *testing.T) {
		pki := makePKI(t, testIdentity, time.Now().Add(-time.Minute), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		server := startMTLSServer(t, pki, []Mapping{validMapping()})
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.root, Certificates: []tls.Certificate{pki.client}, ServerName: "localhost"}}}
		if _, err := client.Get(server.URL + "/v1/agent/identity"); err == nil {
			t.Fatal("expired certificate accepted")
		}
	})
	t.Run("missing client", func(t *testing.T) {
		pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		server := startMTLSServer(t, pki, []Mapping{validMapping()})
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.root, ServerName: "localhost"}}}
		if _, err := client.Get(server.URL + "/v1/agent/identity"); err == nil {
			t.Fatal("missing client certificate accepted")
		}
	})
	t.Run("untrusted client", func(t *testing.T) {
		serverPKI := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		clientPKI := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		server := startMTLSServer(t, serverPKI, []Mapping{validMapping()})
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: serverPKI.root, Certificates: []tls.Certificate{clientPKI.client}, ServerName: "localhost"}}}
		if _, err := client.Get(server.URL + "/v1/agent/identity"); err == nil {
			t.Fatal("untrusted client certificate accepted")
		}
	})
	t.Run("wrong server CA", func(t *testing.T) {
		pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		server := startMTLSServer(t, pki, []Mapping{validMapping()})
		wrongRoots := x509.NewCertPool()
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: wrongRoots, Certificates: []tls.Certificate{pki.client}, ServerName: "localhost"}}}
		if _, err := client.Get(server.URL + "/v1/agent/identity"); err == nil {
			t.Fatal("wrong server CA accepted")
		}
	})
	t.Run("wrong server DNS name", func(t *testing.T) {
		pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		server := startMTLSServer(t, pki, []Mapping{validMapping()})
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.root, Certificates: []tls.Certificate{pki.client}, ServerName: "wrong.example"}}}
		if _, err := client.Get(server.URL + "/v1/agent/identity"); err == nil {
			t.Fatal("wrong server DNS name accepted")
		}
	})
}

func startMTLSServer(t *testing.T, pki testPKI, mappings []Mapping) *httptest.Server {
	t.Helper()
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), mappings, Options{})
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.root}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestMappingFileStrictJSONAndListenAddress(t *testing.T) {
	if err := ValidateMappings([]Mapping{{Identity: "spiffe://x/a", ClusterID: "bad", Enabled: true}}); err == nil {
		t.Fatal("invalid UUID accepted")
	}
	if err := ValidateMappings([]Mapping{{Identity: "https://x/a", ClusterID: testCluster, Enabled: true}}); err == nil {
		t.Fatal("non-SPIFFE identity accepted")
	}
	if err := ValidateListenAddress("127.0.0.1:8443"); err == nil {
		t.Fatal("loopback listener accepted; Service cannot reach it")
	}
	if err := ValidateListenAddress("0.0.0.0:8443"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "mappings.json")
	data, _ := json.Marshal(MappingFile{Mappings: []Mapping{validMapping()}})
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMappings(file)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("load mapping: %v", err)
	}
	if err := os.WriteFile(file, []byte(`{"mappings":[],"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMappings(file); err == nil {
		t.Fatal("unknown mapping field accepted")
	}
}

func TestWorkstationModeRequiresPrivateBindingFixedUpstreamAndPrivateAllowlist(t *testing.T) {
	for _, address := range []string{"10.76.0.2:18443", "172.31.4.9:443", "192.168.8.2:8443", "[fd12:3456::2]:443"} {
		if err := ValidateWorkstationListenAddress(address); err != nil {
			t.Errorf("private bind %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8443", "[::]:8443", "127.0.0.1:8443", "localhost:8443", "8.8.8.8:8443", "169.254.1.2:8443", "[fe80::1]:8443", "10.76.0.2", "10.76.0.2:0"} {
		if err := ValidateWorkstationListenAddress(address); err == nil {
			t.Errorf("unsafe workstation bind %q accepted", address)
		}
	}
	if err := ValidateWorkstationUpstream(WorkstationAPIUpstream); err != nil {
		t.Fatalf("fixed loopback API upstream rejected: %v", err)
	}
	for _, upstream := range []string{"", "http://127.0.0.1:8081", "http://localhost:8080", "http://10.0.0.2:8080", "http://api.ns.svc:8080", "http://127.0.0.1:8080/agent", "http://user@127.0.0.1:8080"} {
		if err := ValidateWorkstationUpstream(upstream); err == nil {
			t.Errorf("workstation upstream %q accepted", upstream)
		}
	}

	for _, raw := range []string{"10.76.0.0/24", "172.16.0.0/12", "192.168.1.0/24", "fd12:3456::/48"} {
		if _, err := ParsePrivateClientCIDRs(raw); err != nil {
			t.Errorf("private client range %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "0.0.0.0/0", "11.0.0.0/8", "172.15.0.0/16", "10.0.0.1/24", "10.0.0.0/24,10.0.0.0/24", "vpn.customer.internal"} {
		if _, err := ParsePrivateClientCIDRs(raw); err == nil {
			t.Errorf("unsafe or ambiguous client range %q accepted", raw)
		}
	}
	if _, err := NewWorkstationHandler(WorkstationAPIUpstream, []Mapping{validMapping()}, nil, Options{}); err == nil {
		t.Fatal("workstation handler accepted missing source CIDR allowlist")
	}
	if _, err := NewWorkstationHandler("http://127.0.0.1:8081", []Mapping{validMapping()}, []netip.Prefix{netip.MustParsePrefix("10.76.0.0/24")}, Options{}); err == nil {
		t.Fatal("workstation handler accepted a non-fixed upstream")
	}
}

func TestWorkstationHandlerEnforcesPrivatePeerCIDRAndPreservesKordexAuthorizationHeaders(t *testing.T) {
	pki := makePKI(t, testIdentity, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	var forwarded atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.URL.Path != "/v1/agent/report" || r.Header.Get("X-Kordex-Signature") != "fixture-signature" || r.Header.Get("X-Kordex-Cluster") != testCluster {
			t.Errorf("agent request was not preserved: path=%q signature=%q cluster=%q", r.URL.Path, r.Header.Get("X-Kordex-Signature"), r.Header.Get("X-Kordex-Cluster"))
		}
		if r.Header.Get("X-Forwarded-For") != "" {
			t.Error("forwarded client header reached API")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer api.Close()
	apiAddress := strings.TrimPrefix(api.URL, "http://")
	allowed, err := ParsePrivateClientCIDRs("10.76.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: time.Second}
	h, err := newWorkstationHandler(WorkstationAPIUpstream, []Mapping{validMapping()}, allowed, normalizeOptions(Options{}), func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, apiAddress)
	})
	if err != nil {
		t.Fatal(err)
	}

	denied := testRequest(http.MethodPost, "/v1/agent/report", `{"nodes":[]}`, pki.clientLeaf)
	denied.RemoteAddr = "10.77.0.3:1234"
	denied.Header.Set("X-Forwarded-For", "10.76.0.3")
	deniedResponse := httptest.NewRecorder()
	h.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden || forwarded.Load() != 0 {
		t.Fatalf("out-of-range peer was forwarded: status=%d forwards=%d", deniedResponse.Code, forwarded.Load())
	}

	allowedRequest := testRequest(http.MethodPost, "/v1/agent/report", `{"nodes":[]}`, pki.clientLeaf)
	allowedRequest.RemoteAddr = "10.76.0.3:1234"
	allowedResponse := httptest.NewRecorder()
	h.ServeHTTP(allowedResponse, allowedRequest)
	if allowedResponse.Code != http.StatusAccepted || forwarded.Load() != 1 {
		t.Fatalf("allowed signed request failed: status=%d forwards=%d body=%s", allowedResponse.Code, forwarded.Load(), allowedResponse.Body.String())
	}
}
