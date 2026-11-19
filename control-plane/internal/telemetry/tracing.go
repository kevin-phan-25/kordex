package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func StartSchedulerTick(ctx context.Context, tracer trace.Tracer) (context.Context, trace.Span) {
	return tracer.Start(ctx, "scheduler.tick")
}

// EndSchedulerTick adds only bounded scheduler attributes and never records raw
// database or operation payloads in a trace.
func EndSchedulerTick(span trace.Span, outcome string, admitted int, errorClass string) {
	switch outcome {
	case "claimed", "idle", "error":
	default:
		outcome = "other"
	}
	if admitted < 0 {
		admitted = 0
	}
	span.SetAttributes(
		attribute.String("kordex.scheduler.outcome", outcome),
		attribute.Int("kordex.scheduler.operations_admitted", admitted),
	)
	if outcome == "error" {
		if _, ok := schedulerErrorClasses[errorClass]; !ok {
			errorClass = "other"
		}
		span.SetAttributes(attribute.String("kordex.scheduler.error_class", errorClass))
		span.SetStatus(codes.Error, "scheduler_error")
	}
	span.End()
}
