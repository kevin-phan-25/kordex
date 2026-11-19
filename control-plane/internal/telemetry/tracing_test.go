package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestSchedulerTickSpanUsesBoundedOutcomeAndErrorAttributes(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	_, span := StartSchedulerTick(context.Background(), provider.Tracer("test"))
	EndSchedulerTick(span, "error", -4, "private SQL details")
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d; want 1", len(spans))
	}
	got := spans[0]
	if got.Name != "scheduler.tick" || got.Status.Code != codes.Error {
		t.Fatalf("scheduler span = %+v", got)
	}
	values := make(map[string]any, len(got.Attributes))
	for _, item := range got.Attributes {
		values[string(item.Key)] = item.Value.AsInterface()
	}
	if values["kordex.scheduler.outcome"] != "error" || values["kordex.scheduler.operations_admitted"] != int64(0) || values["kordex.scheduler.error_class"] != "other" {
		t.Fatalf("bounded scheduler span attributes = %#v", values)
	}
	for _, item := range got.Attributes {
		if item.Value.Type() == attribute.STRING && item.Value.AsString() == "private SQL details" {
			t.Fatal("raw database error was added to the trace")
		}
	}
}
