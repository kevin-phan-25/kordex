package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		t.Fatal("HTTP error response reported as success")
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
	if values["http.route"] != "unmatched" || values["kordex.agent.call.error_class"] != "http_status" || values["http.response.status_code"] != int64(http.StatusInternalServerError) {
		t.Fatalf("agent error span attributes = %#v", values)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Call error type = %T; want *APIError", err)
	}
}
