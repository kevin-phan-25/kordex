package observability

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMaintenanceReconcileSpanUsesBoundedAttributes(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	_, span := StartMaintenanceReconcile(context.Background(), provider.Tracer("test"))
	EndMaintenanceReconcile(span, "UnknownPhaseWithSecret", "RunShell", "error", "raw kubernetes error with secret")
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d; want 1", len(spans))
	}
	got := spans[0]
	if got.Name != "operator.maintenance.reconcile" || got.Status.Code != codes.Error || got.Status.Description != "reconcile_error" {
		t.Fatalf("maintenance span = %+v", got)
	}
	values := make(map[string]any, len(got.Attributes))
	for _, item := range got.Attributes {
		values[string(item.Key)] = item.Value.AsInterface()
		if item.Value.Type() == attribute.STRING && strings.Contains(item.Value.AsString(), "secret") {
			t.Fatal("raw operation or error detail was added to trace attributes")
		}
	}
	if values["kordex.maintenance.phase"] != "other" || values["kordex.maintenance.action"] != "other" || values["kordex.reconcile.outcome"] != "error" || values["kordex.reconcile.error_class"] != "other" {
		t.Fatalf("maintenance span attributes = %#v", values)
	}
}

func TestValidateOTLPEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "https://otel.example:4318/v1/traces", "http://127.0.0.1:4318"} {
		if err := ValidateOTLPEndpoint(endpoint); err != nil {
			t.Errorf("valid endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		" https://otel.example:4318",
		"https://user:secret@otel.example:4318",
		"https://otel.example:4318?token=secret",
		"https://otel.example:4318#secret",
		"https://otel.example:4318#",
		"ftp://otel.example:4318",
		"https:///missing-host",
	} {
		if err := ValidateOTLPEndpoint(endpoint); err == nil {
			t.Errorf("unsafe endpoint %q accepted", endpoint)
		}
	}
}

func TestSetupTracingRedactsInvalidEndpoint(t *testing.T) {
	const endpoint = "https://user:private-token@otel.example:4318"
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", endpoint)
	if _, err := SetupTracing(context.Background()); err == nil || strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), endpoint) {
		t.Fatalf("SetupTracing error = %v; want a redacted invalid-endpoint error", err)
	}
}
