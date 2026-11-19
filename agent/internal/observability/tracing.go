package observability

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
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// SetupTracing configures opt-in OTLP/HTTP export. Invalid endpoint settings
// fail startup without echoing the configured value into diagnostics.
func SetupTracing(ctx context.Context) (func(context.Context) error, error) {
	endpoints := []string{os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")}
	for _, endpoint := range endpoints {
		if err := ValidateOTLPEndpoint(endpoint); err != nil {
			return nil, errors.New("invalid agent OTLP endpoint configuration")
		}
	}
	otel.SetTextMapPropagator(propagation.TraceContext{})
	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", "kordex-agent"))),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.1))),
	}
	if endpoints[0] != "" || endpoints[1] != "" {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, errors.New("create agent OTLP exporter")
		}
		options = append(options, sdktrace.WithBatcher(exporter))
	}
	provider := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

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
