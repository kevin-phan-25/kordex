package observability

import "testing"

func TestMaintenanceMetricLabelsAreBounded(t *testing.T) {
	if got := boundedPhase("Executing"); got != "Executing" {
		t.Fatalf("known phase label = %q", got)
	}
	if got := boundedPhase("node-12345"); got != "other" {
		t.Fatalf("unknown phase label leaked through: %q", got)
	}
	if got := boundedReason("NodeNotReady"); got != "NodeNotReady" {
		t.Fatalf("known reason label = %q", got)
	}
	for _, reason := range []string{"node-12345", "GKEUpgradeFailed:customer-specific text", ""} {
		if got := boundedReason(reason); got != "other" {
			t.Errorf("unbounded reason %q mapped to %q", reason, got)
		}
	}
}
