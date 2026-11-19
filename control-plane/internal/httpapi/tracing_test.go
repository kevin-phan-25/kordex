package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestHTTPRequestTraceUsesRouteTemplateAndBoundedAttributes(t *testing.T) {
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(previousPropagator) })
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
	server := &Server{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics: newHTTPMetrics(),
		tracer:  provider.Tracer("test"),
	}
	handler := server.observe(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	request := httptest.NewRequest(http.MethodGet, "/v1/organizations/tenant-secret/sites?token=query-secret", nil)
	request.Pattern = "GET /v1/organizations/{organizationID}/sites"
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d; want 1", len(spans))
	}
	got := spans[0]
	if got.Name != "GET /v1/organizations/{organizationID}/sites" || got.Status.Code != codes.Error || got.Status.Description != "http_server_error" {
		t.Fatalf("HTTP span = %+v", got)
	}
	if got.SpanContext.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" || got.Parent.SpanID().String() != "00f067aa0ba902b7" {
		t.Fatalf("HTTP span lost the inbound trace context: %+v", got)
	}
	values := make(map[string]any, len(got.Attributes))
	for _, item := range got.Attributes {
		values[string(item.Key)] = item.Value.AsInterface()
	}
	if values["http.request.method"] != http.MethodGet || values["http.route"] != "/v1/organizations/{organizationID}/sites" || values["http.response.status_code"] != int64(http.StatusServiceUnavailable) {
		t.Fatalf("HTTP span attributes = %#v", values)
	}
	for _, item := range got.Attributes {
		if item.Value.Type() == attribute.STRING && (item.Value.AsString() == "tenant-secret" || item.Value.AsString() == "query-secret") {
			t.Fatal("raw request identifier or query value was added to trace attributes")
		}
	}
}

func TestTraceHTTPMethodIsBounded(t *testing.T) {
	if got := boundedTraceHTTPMethod("CUSTOM-METHOD-with-secret"); got != "OTHER" {
		t.Fatalf("custom HTTP method = %q", got)
	}
}
