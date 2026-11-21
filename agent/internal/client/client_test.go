package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestHTTPSAndRedirectBoundaries(t *testing.T) {
	const cluster = "80bd80f9-f097-4474-86f4-b80986fd5423"
	for _, origin := range []string{"http://hub.example", "https://user:password@hub.example", "https://hub.example/path", "https://hub.example?secret=x"} {
		if _, err := New(origin, cluster, false, nil); err == nil {
			t.Fatalf("accepted unsafe origin %q", origin)
		}
	}
	if _, err := New("http://127.0.0.1:8080", cluster, true, nil); err != nil {
		t.Fatal(err)
	}
	targetCalled := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalled = true }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	c, err := New(redirect.URL, cluster, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP.Transport = redirect.Client().Transport
	if err = c.Call(context.Background(), "GET", "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("redirect reported as success")
	}
	if targetCalled {
		t.Fatal("followed redirect to another origin")
	}
}

func TestCallContinuesW3CTraceContextWithAllowlistedRoute(t *testing.T) {
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})

	const parentTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const parentSpanID = "00f067aa0ba902b7"
	ctx := propagation.TraceContext{}.Extract(context.Background(), propagation.MapCarrier{
		"traceparent": "00-" + parentTraceID + "-" + parentSpanID + "-01",
	})
	outboundTraceparent := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outboundTraceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c, err := New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = server.Client()
	if err = c.Call(ctx, http.MethodPost, "/v1/agent/report", map[string]string{"private": "request-body"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	outbound := propagation.TraceContext{}.Extract(context.Background(), propagation.MapCarrier{"traceparent": outboundTraceparent})
	outboundSpan := trace.SpanContextFromContext(outbound)
	if !outboundSpan.IsValid() || outboundSpan.TraceID().String() != parentTraceID || outboundSpan.SpanID().String() == parentSpanID {
		t.Fatalf("outbound traceparent = %q; want child span in trace %s", outboundTraceparent, parentTraceID)
	}
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d; want 1", len(spans))
	}
	got := spans[0]
	if got.Name != "POST /v1/agent/report" || got.SpanContext.TraceID().String() != parentTraceID || got.Parent.SpanID().String() != parentSpanID {
		t.Fatalf("agent request span = %+v", got)
	}
	values := make(map[string]any, len(got.Attributes))
	for _, item := range got.Attributes {
		values[string(item.Key)] = item.Value.AsInterface()
		if item.Value.Type() == attribute.STRING && item.Value.AsString() == "request-body" {
			t.Fatal("request data was added to trace attributes")
		}
	}
	if values["http.route"] != "/v1/agent/report" || values["kordex.agent.call.outcome"] != "success" {
		t.Fatalf("agent request attributes = %#v", values)
	}
}

func TestCallErrorTraceOmitsResponseBodyAndUnknownPath(t *testing.T) {
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})

	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"private-response-detail"}`))
	}))
	defer server.Close()
	c, err := New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = server.Client()
	err = c.Call(context.Background(), http.MethodGet, "/v1/agent/clusters/private-id", nil, nil, nil)
	if err == nil {
		t.Fatal("unknown agent route was accepted")
	}
	if strings.Contains(err.Error(), "private-response-detail") || strings.Contains(err.Error(), "private-id") {
		t.Fatal("unknown route error exposed request or response details")
	}
	if serverCalled {
		t.Fatal("unknown route reached the network")
	}
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d; want 1", len(spans))
	}
	got := spans[0]
	if got.Name != "GET unmatched" {
		t.Fatalf("unknown route span name = %q", got.Name)
	}
	values := make(map[string]any, len(got.Attributes))
	for _, item := range got.Attributes {
		values[string(item.Key)] = item.Value.AsInterface()
		if item.Value.Type() == attribute.STRING && (item.Value.AsString() == "private-id" || item.Value.AsString() == "private-response-detail") {
			t.Fatal("raw path or response detail was added to trace attributes")
		}
	}
	if values["http.route"] != "unmatched" || values["kordex.agent.call.error_class"] != "request_rejected" {
		t.Fatalf("agent error span attributes = %#v", values)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("unknown route unexpectedly made an API request: %v", apiErr)
	}
}

func TestCloudflareAccessCredentialsOnlyReachExactAgentRoutes(t *testing.T) {
	const clientID = "edge-client-id"
	const clientSecret = "edge-client-secret-never-log"
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("CF-Access-Client-Id") != clientID || r.Header.Get("CF-Access-Client-Secret") != clientSecret {
			t.Errorf("Cloudflare Access headers missing")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c, err := New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ConfigureCloudflareAccess(clientID, "", false); err == nil {
		t.Fatal("accepted only one gateway credential")
	}
	if err := c.ConfigureCloudflareAccess("", "", true); err == nil {
		t.Fatal("accepted missing required gateway credentials")
	}
	if err := c.ConfigureCloudflareAccess(clientID, clientSecret, false); err == nil {
		t.Fatal("accepted gateway credentials while gateway mode is disabled")
	}
	if err := c.ConfigureCloudflareAccess(clientID, clientSecret, true); err != nil {
		t.Fatal(err)
	}
	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/agent/identity"},
		{http.MethodPost, "/v1/agent/enroll"},
		{http.MethodPost, "/v1/agent/report"},
		{http.MethodPost, "/v1/agent/rotate"},
		{http.MethodPost, "/v1/agent/operations/sync"},
	}
	for _, route := range routes {
		var input any
		if route.method == http.MethodPost {
			input = map[string]string{"ok": "yes"}
		}
		if err := c.Call(context.Background(), route.method, route.path, input, nil, nil); err != nil {
			t.Fatalf("Call(%s %s): %v", route.method, route.path, err)
		}
	}
	if calls != len(routes) {
		t.Fatalf("agent calls = %d, want %d", calls, len(routes))
	}
	if err := c.Call(context.Background(), http.MethodGet, "/healthz", nil, nil, nil); err == nil {
		t.Fatal("agent client accepted non-agent route")
	}
	if calls != len(routes) {
		t.Fatal("disallowed route reached the network")
	}
}

func TestDirectAPIModeSendsNoCloudflareHeaders(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get("CF-Access-Client-Id") != "" || r.Header.Get("CF-Access-Client-Secret") != "" {
			t.Error("direct API mode sent Cloudflare headers")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c, err := New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ConfigureCloudflareAccess("", "", false); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("direct API request did not reach the API")
	}
}

func TestAgentTLSRequiresTrustedCAAndHostnameValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	base := server.URL
	const cluster = "80bd80f9-f097-4474-86f4-b80986fd5423"

	withoutCA, err := New(base, cluster, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := withoutCA.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("TLS succeeded without trusting the origin certificate")
	}
	trustedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	trusted, err := New(base, cluster, false, trustedPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := trusted.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err != nil {
		t.Fatalf("trusted TLS request failed: %v", err)
	}
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wrongHostURL := "https://wrong.invalid:" + port
	wrongHost, err := New(wrongHostURL, cluster, false, trustedPEM)
	if err != nil {
		t.Fatal(err)
	}
	transport := wrongHost.HTTP.Transport.(*http.Transport).Clone()
	originAddress := server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, originAddress)
	}
	wrongHost.HTTP.Transport = transport
	if err := wrongHost.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("TLS succeeded with a hostname absent from the certificate SAN")
	}

	wrongPEM := unrelatedTestCA(t)
	wrongTrust, err := New(base, cluster, false, wrongPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongTrust.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("TLS succeeded with the wrong CA")
	}
}

func unrelatedTestCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "unrelated test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAgentGatewayUnavailableDoesNotExposeCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	c, err := New("http://"+address, "80bd80f9-f097-4474-86f4-b80986fd5423", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := "must-not-appear-in-errors"
	if err := c.ConfigureCloudflareAccess("id", secret, true); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(context.Background(), http.MethodGet, "/v1/agent/identity", nil, nil, nil); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unavailable gateway error = %v", err)
	}
}
