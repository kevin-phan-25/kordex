package observability

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const serviceName = "kordex-operator"

// SetupTracing configures opt-in OTLP/HTTP export. Invalid settings fail startup
// and are rejected before the exporter can include configuration in errors.
func SetupTracing(ctx context.Context) (func(context.Context) error, error) {
	endpoints := []string{os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")}
	for _, endpoint := range endpoints {
		if err := ValidateOTLPEndpoint(endpoint); err != nil {
			return nil, errors.New("invalid operator OTLP endpoint configuration")
		}
	}
	otel.SetTextMapPropagator(propagation.TraceContext{})
	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", serviceName))),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.1))),
	}
	if endpoints[0] != "" || endpoints[1] != "" {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, errors.New("create operator OTLP exporter")
		}
		options = append(options, sdktrace.WithBatcher(exporter))
	}
	provider := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

// ValidateOTLPEndpoint accepts an empty default or a private HTTP(S) endpoint,
// while excluding embedded credentials, query values, and fragments.
func ValidateOTLPEndpoint(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 2048 || strings.TrimSpace(value) != value {
		return errors.New("invalid endpoint")
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(value, "#") {
		return errors.New("invalid endpoint")
	}
	return nil
}

func StartMaintenanceReconcile(ctx context.Context, tracer trace.Tracer) (context.Context, trace.Span) {
	return tracer.Start(ctx, "operator.maintenance.reconcile")
}

// EndMaintenanceReconcile records only bounded state. Object names, UIDs,
// annotations, and error text are deliberately omitted from spans.
func EndMaintenanceReconcile(span trace.Span, phase, action, outcome, errorClass string) {
	span.SetAttributes(
		attribute.String("kordex.maintenance.phase", boundedMaintenancePhase(phase)),
		attribute.String("kordex.maintenance.action", boundedMaintenanceAction(action)),
		attribute.String("kordex.reconcile.outcome", boundedReconcileOutcome(outcome)),
	)
	if outcome == "error" {
		span.SetAttributes(attribute.String("kordex.reconcile.error_class", boundedReconcileErrorClass(errorClass)))
		span.SetStatus(codes.Error, "reconcile_error")
	}
	span.End()
}

func boundedMaintenancePhase(value string) string {
	switch value {
	case "Pending", "Validating", "SafetyChecking", "Blocked", "Preflighting", "Cordoning", "Draining", "Executing", "Rebooting", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "RecoveryRequired", "Succeeded", "Failed", "Cancelled":
		return value
	default:
		return "other"
	}
}

func boundedMaintenanceAction(value string) string {
	switch value {
	case "ValidateOnly", "DrainAndVerify", "UpgradePackages", "UpgradeNodePool":
		return value
	default:
		return "other"
	}
}

func boundedReconcileOutcome(value string) string {
	switch value {
	case "complete", "requeue", "error":
		return value
	default:
		return "other"
	}
}

func boundedReconcileErrorClass(value string) string {
	switch value {
	case "conflict", "not_found", "timeout", "canceled", "other":
		return value
	default:
		return "other"
	}
}
