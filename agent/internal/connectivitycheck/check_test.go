package connectivitycheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"kordex.local/agent/internal/client"
	"kordex.local/agent/internal/state"
	"kordex.local/api/protocol"
)

const testCluster = "a0f38b4c-2f0a-4477-8a75-27e435c44c29"

type fixedResolver struct {
	addresses []netip.Addr
	err       error
}

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, r.err
}

type testPKI struct {
	caPEM, otherCAPEM     []byte
	serverCert, serverKey []byte
	clientCert, clientKey []byte
}

func makeTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, caCert, caPEM := makeCA(t, "connectivity fixture CA")
	_, _, otherPEM := makeCA(t, "untrusted connectivity fixture CA")
	serverCert, serverKey := makeLeaf(t, caKey, caCert, "relay.test", []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert, clientKey := makeLeaf(t, caKey, caCert, "synthetic agent", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return testPKI{caPEM: caPEM, otherCAPEM: otherPEM, serverCert: serverCert, serverKey: serverKey, clientCert: clientCert, clientKey: clientKey}
}

func makeCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
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

func makeLeaf(t *testing.T, signer *ecdsa.PrivateKey, ca *x509.Certificate, cn string, dns []string, usages []x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: dns, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
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

func fixture(t *testing.T, status int, responseCluster string) (Config, func(context.Context, string, string) (net.Conn, error), *ed25519.PrivateKey) {
	t.Helper()
	pki := makeTestPKI(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(pki.serverCert, pki.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(pki.caPEM)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/agent/identity" || r.URL.RawQuery != "" || !protocol.Verify(r, public, nil, time.Now()) {
			http.Error(w, "agent authorization rejected", http.StatusUnauthorized)
			return
		}
		if status != 0 {
			http.Error(w, "synthetic response", status)
			return
		}
		if responseCluster == "" {
			responseCluster = testCluster
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.Identity{ClusterID: responseCluster, KeyID: protocol.KeyID(public), ExpiresAt: time.Now().Add(time.Hour)})
	})}
	tlsListener := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientCAs: clientRoots, ClientAuth: tls.RequireAndVerifyClientCert})
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close() })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Endpoint: "https://relay.test:" + port, ClusterID: testCluster, Identity: state.State{ClusterID: testCluster, ClusterUID: "synthetic-cluster-uid", PrivateKey: private}, MTLS: client.MTLSConfig{ClientCertificatePEM: pki.clientCert, ClientKeyPEM: pki.clientKey, ServerCAPEM: pki.caPEM, ServerName: "relay.test"}, AllowedCIDRs: []string{"10.76.0.0/24"}}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort("10.76.0.2", port) {
			return nil, errors.New("unexpected pinned address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	return config, dial, &private
}

func TestCheckValidMTLSAndSignedIdentity(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	cfg, dial, _ := fixture(t, 0, "")
	cfg.Endpoint = strings.Replace(cfg.Endpoint, "relay.test", "RELAY.TEST", 1)
	result := Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("10.76.0.2")}}, DialContext: dial})
	if result.Status != "verified" || !result.PrivateDNSVerified || !result.RelayReachable || !result.AgentRouteAvailable || !result.TLSIdentityVerified || !result.ClientCertificateAccepted || result.CertificateMapping != "accepted" || !result.ClusterIdentityMatches || !result.AgentIdentityMatches || result.APIResponse != "identity_accepted" {
		t.Fatalf("connectivity check result = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PrivateKey") || strings.Contains(string(encoded), "synthetic-cluster-uid") {
		t.Fatal("connectivity report exposed identity material")
	}
}

func TestCheckRejectsDNSOutsideApprovedPrivateRangeBeforeDial(t *testing.T) {
	cfg, dial, _ := fixture(t, 0, "")
	dialCalled := false
	result := Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}, DialContext: func(context.Context, string, string) (net.Conn, error) { dialCalled = true; return nil, nil }})
	if result.Status != "endpoint_outside_approved_private_cidrs" || dialCalled || dial == nil {
		t.Fatalf("public DNS answer was not rejected before dialing: %+v", result)
	}
}

func TestCheckClassifiesRelayAPIAndIdentityFailures(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		cluster string
		want    string
	}{
		{name: "certificate mapping or source rejected", status: http.StatusForbidden, want: "relay_authorization_rejected"},
		{name: "agent signature rejected", status: http.StatusUnauthorized, want: "agent_authentication_rejected"},
		{name: "API unavailable behind relay", status: http.StatusBadGateway, want: "api_unavailable"},
		{name: "route unavailable", status: http.StatusNotFound, want: "route_unavailable"},
		{name: "wrong cluster identity", cluster: "b0f38b4c-2f0a-4477-8a75-27e435c44c29", want: "cluster_identity_mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, dial, _ := fixture(t, tc.status, tc.cluster)
			result := Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("10.76.0.2")}}, DialContext: dial})
			if result.Status != tc.want {
				t.Fatalf("status = %q, want %q; result=%+v", result.Status, tc.want, result)
			}
		})
	}
}

func TestCheckFailsClosedForBadTLSAndUnavailableRelay(t *testing.T) {
	cfg, dial, _ := fixture(t, 0, "")
	cfg.MTLS.ServerCAPEM = makeTestPKI(t).otherCAPEM
	result := Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("10.76.0.2")}}, DialContext: dial})
	if result.Status != "tls_identity_rejected" || result.TLSIdentityVerified {
		t.Fatalf("untrusted server certificate accepted: %+v", result)
	}

	cfg, _, _ = fixture(t, 0, "")
	result = Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("10.76.0.2")}}, DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unavailable") }})
	if result.Status != "relay_unreachable" {
		t.Fatalf("unavailable relay status = %+v", result)
	}
}

func TestCheckRejectsMissingCIDRAndNoncanonicalEndpoint(t *testing.T) {
	cfg, dial, _ := fixture(t, 0, "")
	cfg.AllowedCIDRs = nil
	if got := Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("10.76.0.2")}}, DialContext: dial}); got.Status != "configuration_invalid" {
		t.Fatalf("missing approved CIDR accepted: %+v", got)
	}
	cfg.AllowedCIDRs = []string{"0.0.0.0/0"}
	if got := Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("10.76.0.2")}}, DialContext: dial}); got.Status != "configuration_invalid" {
		t.Fatalf("public CIDR accepted: %+v", got)
	}
	cfg.AllowedCIDRs = []string{"10.0.0.0/8"}
	if got := Check(context.Background(), cfg, Dependencies{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("10.76.0.2")}}, DialContext: dial}); got.Status != "configuration_invalid" {
		t.Fatalf("overly broad CIDR accepted: %+v", got)
	}
	cfg.AllowedCIDRs = []string{"10.76.0.0/24"}
	cfg.GatewayAccessHeadersConfigured = true
	if got := Check(context.Background(), cfg, Dependencies{}); got.Status != "configuration_invalid" {
		t.Fatalf("Cloudflare Access headers were allowed on private relay check: %+v", got)
	}
	cfg.GatewayAccessHeadersConfigured = false
	u, _ := url.Parse(cfg.Endpoint)
	u.RawQuery = "unexpected=true"
	cfg.Endpoint = u.String()
	if got := Check(context.Background(), cfg, Dependencies{}); got.Status != "configuration_invalid" {
		t.Fatalf("query string endpoint accepted: %+v", got)
	}
}
