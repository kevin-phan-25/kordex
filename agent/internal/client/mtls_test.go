package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kordex.local/api/protocol"
)

const mtlsTestCluster = "80bd80f9-f097-4474-86f4-b80986fd5423"

type mtlsFixture struct {
	caPEM, otherCAPEM               []byte
	serverCert, serverKey           []byte
	clientCert, clientKey           []byte
	otherClientCert, otherClientKey []byte
}

func newMTLSFixture(t *testing.T, serverExpiry, clientExpiry time.Time) mtlsFixture {
	t.Helper()
	caKey, caCert, caPEM := makeTestCA(t, "mTLS fixture CA")
	otherKey, otherCert, otherPEM := makeTestCA(t, "untrusted fixture CA")
	serverCert, serverKey := makeTestLeaf(t, caKey, caCert, "relay.test", []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, serverExpiry)
	clientCert, clientKey := makeTestLeaf(t, caKey, caCert, "agent fixture", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, clientExpiry)
	otherClientCert, otherClientKey := makeTestLeaf(t, otherKey, otherCert, "untrusted agent fixture", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, clientExpiry)
	return mtlsFixture{caPEM: caPEM, otherCAPEM: otherPEM, serverCert: serverCert, serverKey: serverKey, clientCert: clientCert, clientKey: clientKey, otherClientCert: otherClientCert, otherClientKey: otherClientKey}
}

func makeTestCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func makeTestLeaf(t *testing.T, signer *ecdsa.PrivateKey, ca *x509.Certificate, commonName string, dnsNames []string, usages []x509.ExtKeyUsage, expiry time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (f mtlsFixture) config() MTLSConfig {
	return MTLSConfig{ClientCertificatePEM: f.clientCert, ClientKeyPEM: f.clientKey, ServerCAPEM: f.caPEM, ServerName: "relay.test"}
}

func startMTLSServer(t *testing.T, certPEM, keyPEM, clientCA []byte, handler http.Handler) (string, string) {
	t.Helper()
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientCA) {
		t.Fatal("fixture client CA rejected")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientCAs: clientRoots, ClientAuth: tls.RequireAndVerifyClientCert})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close() })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://relay.test:" + port, listener.Addr().String()
}

func clientForMTLSTest(t *testing.T, base, address string, config MTLSConfig) *Client {
	t.Helper()
	c, err := NewWithMTLS(base, mtlsTestCluster, config)
	if err != nil {
		t.Fatal(err)
	}
	transport := c.HTTP.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	c.HTTP.Transport = transport
	return c
}

func TestMTLSSuccessAndEd25519AuthorizationRemainIndependent(t *testing.T) {
	f := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var authorized, sawClientCertificate bool
	base, address := startMTLSServer(t, f.serverCert, f.serverKey, f.caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawClientCertificate = r.TLS != nil && len(r.TLS.PeerCertificates) == 1 && r.TLS.PeerCertificates[0].Subject.CommonName == "agent fixture"
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Error(readErr)
			return
		}
		authorized = protocol.Verify(r, public, body, time.Now())
		if !authorized {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	c := clientForMTLSTest(t, base, address, f.config())
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, private); err != nil {
		t.Fatal(err)
	}
	if !sawClientCertificate || !authorized {
		t.Fatal("mTLS client identity or independent Ed25519 authorization was not verified")
	}
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("mTLS certificate alone authorized an unsigned Kordex request")
	}
}

func TestMTLSAppliesToEveryAllowlistedAgentOperation(t *testing.T) {
	f := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	seen := make(map[string]bool)
	base, address := startMTLSServer(t, f.serverCert, f.serverKey, f.caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Errorf("%s %s did not present a client certificate", r.Method, r.URL.Path)
		}
		seen[r.Method+" "+r.URL.Path] = true
		w.WriteHeader(http.StatusNoContent)
	}))
	c := clientForMTLSTest(t, base, address, f.config())
	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/agent/identity"},
		{http.MethodPost, "/v1/agent/enroll"},
		{http.MethodPost, "/v1/agent/rotate"},
		{http.MethodPost, "/v1/agent/report"},
		{http.MethodPost, "/v1/agent/operations/sync"},
	}
	for _, route := range routes {
		var input any
		if route.method == http.MethodPost {
			input = map[string]string{"fixture": "synthetic"}
		}
		if err := c.Call(context.Background(), route.method, route.path, input, nil, nil); err != nil {
			t.Fatalf("Call(%s %s): %v", route.method, route.path, err)
		}
		if !seen[route.method+" "+route.path] {
			t.Fatalf("mTLS route %s %s was not received", route.method, route.path)
		}
	}
	if err := c.Call(context.Background(), http.MethodGet, "/v1/healthz", nil, nil, nil); err == nil {
		t.Fatal("mTLS client accepted a non-agent health path")
	}
}

func TestMTLSRejectsUntrustedCAAndWrongServerDNSNameWithoutFallback(t *testing.T) {
	f := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	calls := 0
	base, address := startMTLSServer(t, f.serverCert, f.serverKey, f.caPEM, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	badCA := f.config()
	badCA.ServerCAPEM = f.otherCAPEM
	c, err := NewWithMTLS(base, mtlsTestCluster, badCA)
	if err != nil {
		t.Fatal(err)
	}
	transport := c.HTTP.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	c.HTTP.Transport = transport
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("accepted server signed by an untrusted CA")
	}
	wrongName := f.config()
	wrongName.ServerName = "other.relay.test"
	if _, err := NewWithMTLS(base, mtlsTestCluster, wrongName); err == nil {
		t.Fatal("accepted a server DNS name different from the HTTPS origin")
	}
	if calls != 0 {
		t.Fatalf("failed mTLS request reached application handler %d times; fallback occurred", calls)
	}
	if _, err := NewWithMTLS("http://127.0.0.1:8080", mtlsTestCluster, f.config()); err == nil {
		t.Fatal("mTLS allowed plaintext loopback transport")
	}
	wrongSAN := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	altKey, altCA, altCAPEM := makeTestCA(t, "wrong SAN fixture CA")
	wrongSAN.serverCert, wrongSAN.serverKey = makeTestLeaf(t, altKey, altCA, "wrong relay", []string{"wrong.relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Now().Add(time.Hour))
	wrongSAN.caPEM = altCAPEM
	base, address = startMTLSServer(t, wrongSAN.serverCert, wrongSAN.serverKey, f.caPEM, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	c = clientForMTLSTest(t, base, address, wrongSAN.config())
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("accepted server certificate without the configured DNS SAN")
	}
}

func TestMTLSRejectsExpiredServerAndClientCertificates(t *testing.T) {
	clientExpiry := time.Now().Add(time.Hour)
	expiredClient := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(-time.Minute))
	base, address := startMTLSServer(t, expiredClient.serverCert, expiredClient.serverKey, expiredClient.caPEM, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	if _, err := NewWithMTLS(base, mtlsTestCluster, expiredClient.config()); err == nil {
		t.Fatal("accepted expired client certificate")
	}

	expiredServer := newMTLSFixture(t, time.Now().Add(-time.Minute), clientExpiry)
	base, address = startMTLSServer(t, expiredServer.serverCert, expiredServer.serverKey, expiredServer.caPEM, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	c := clientForMTLSTest(t, base, address, expiredServer.config())
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("accepted expired relay server certificate")
	}
}

func TestMTLSRejectsMissingInvalidAndMismatchedClientMaterial(t *testing.T) {
	f := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	cases := []struct {
		name   string
		config MTLSConfig
	}{
		{name: "missing client certificate", config: MTLSConfig{ClientKeyPEM: f.clientKey, ServerCAPEM: f.caPEM, ServerName: "relay.test"}},
		{name: "missing private key", config: MTLSConfig{ClientCertificatePEM: f.clientCert, ServerCAPEM: f.caPEM, ServerName: "relay.test"}},
		{name: "missing CA", config: MTLSConfig{ClientCertificatePEM: f.clientCert, ClientKeyPEM: f.clientKey, ServerName: "relay.test"}},
		{name: "mismatched key", config: MTLSConfig{ClientCertificatePEM: f.clientCert, ClientKeyPEM: f.otherClientKey, ServerCAPEM: f.caPEM, ServerName: "relay.test"}},
		{name: "malformed client certificate", config: MTLSConfig{ClientCertificatePEM: []byte("NOT_A_CERTIFICATE"), ClientKeyPEM: f.clientKey, ServerCAPEM: f.caPEM, ServerName: "relay.test"}},
		{name: "malformed private key", config: MTLSConfig{ClientCertificatePEM: f.clientCert, ClientKeyPEM: []byte("PRIVATE_KEY_FIXTURE_DO_NOT_LOG"), ServerCAPEM: f.caPEM, ServerName: "relay.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewWithMTLS("https://relay.test", mtlsTestCluster, tc.config); err == nil {
				t.Fatal("accepted invalid client material")
			}
		})
	}
	privateFixture := []byte("PRIVATE_KEY_FIXTURE_DO_NOT_LOG")
	invalid := f.config()
	invalid.ClientKeyPEM = privateFixture
	_, err := NewWithMTLS("https://relay.test", mtlsTestCluster, invalid)
	if err == nil || strings.Contains(err.Error(), string(privateFixture)) {
		t.Fatal("invalid-key error did not fail safely or exposed key fixture material")
	}
	if _, err := NewWithMTLS("https://relay.test", mtlsTestCluster, f.config()); err != nil {
		t.Fatal("valid fixture rejected:", err)
	}
	base, address := startMTLSServer(t, f.serverCert, f.serverKey, f.caPEM, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	untrustedClient := f.config()
	untrustedClient.ClientCertificatePEM = f.otherClientCert
	untrustedClient.ClientKeyPEM = f.otherClientKey
	c := clientForMTLSTest(t, base, address, untrustedClient)
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("relay accepted a client certificate outside its trusted client CA")
	}
}

func TestLoadMTLSConfigFailsClosedForMissingOrUnreadableFiles(t *testing.T) {
	dir := t.TempDir()
	for _, paths := range [][]string{{"", "key", "ca"}, {filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"), filepath.Join(dir, "missing.ca")}, {dir, dir, dir}} {
		if _, err := LoadMTLSConfig(paths[0], paths[1], paths[2], "relay.test"); err == nil {
			t.Fatal("accepted missing or unreadable mTLS files")
		}
	}
	f := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	certPath, keyPath, caPath := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"), filepath.Join(dir, "ca.crt")
	for path, data := range map[string][]byte{certPath: f.clientCert, keyPath: f.clientKey, caPath: f.caPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := LoadMTLSConfig(certPath, keyPath, caPath, "relay.test")
	if err != nil || len(loaded.ClientKeyPEM) == 0 {
		t.Fatalf("valid file config failed: %v", err)
	}
	_, missingNameErr := LoadMTLSConfig(certPath, keyPath, caPath, "")
	if missingNameErr == nil {
		t.Fatal("accepted missing expected server DNS name")
	}
	if strings.Contains(missingNameErr.Error(), string(f.clientKey)) {
		t.Fatal("error exposed private-key contents")
	}
}

func TestMTLSRejectsMalformedTrustAndLegacyModeRemainsSeparate(t *testing.T) {
	f := newMTLSFixture(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	for _, bad := range [][]byte{nil, []byte("not a CA"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fixture")})} {
		config := f.config()
		config.ServerCAPEM = bad
		if _, err := NewWithMTLS("https://relay.test", mtlsTestCluster, config); err == nil {
			t.Fatal("accepted malformed or non-CA trust bundle")
		}
	}
	if _, err := New("http://127.0.0.1:8080", mtlsTestCluster, true, nil); err != nil {
		t.Fatalf("legacy explicit local mode changed: %v", err)
	}
}
