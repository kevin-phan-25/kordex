package telemetry

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

func Setup(ctx context.Context) (func(context.Context) error, error) {
	for _, endpoint := range []string{os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")} {
		if err := ValidateOTLPEndpoint(endpoint); err != nil {
			return nil, errors.New("invalid OTLP endpoint configuration")
		}
	}
	otel.SetTextMapPropagator(propagation.TraceContext{})
	options := []trace.TracerProviderOption{trace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", "kordex-control-plane"))), trace.WithSampler(trace.ParentBased(trace.TraceIDRatioBased(0.1)))}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, err
		}
		options = append(options, trace.WithBatcher(exporter))
	}
	provider := trace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

// ValidateOTLPEndpoint rejects endpoint strings that could smuggle credentials
// or query values into deployment configuration and telemetry diagnostics.
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
