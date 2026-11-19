package telemetry

import (
	"context"
	"strings"
	"testing"
)

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

func TestSetupRejectsUnsafeEndpointWithoutEchoingIt(t *testing.T) {
	const endpoint = "https://user:private-token@otel.example:4318"
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	if _, err := Setup(context.Background()); err == nil || strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), endpoint) {
		t.Fatalf("Setup error = %v; want a redacted invalid-endpoint error", err)
	}
}
