package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

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

func TestMaintenanceMetricActionAndOutcomeLabelsAreBounded(t *testing.T) {
	for _, action := range []string{"ValidateOnly", "DrainAndVerify", "UpgradePackages", "UpgradeNodePool"} {
		if got := ActionFromAuthorization(`{"action":"` + action + `"}`); got != action {
			t.Errorf("known action %q mapped to %q", action, got)
		}
	}
	for _, authorization := range []string{"not-json", `{"action":"UpgradePackages:secret"}`, `{"action":"FedoraUpgrade"}`} {
		if got := ActionFromAuthorization(authorization); got != "other" {
			t.Errorf("unbounded action from %q mapped to %q", authorization, got)
		}
	}
	for _, outcome := range []string{"Succeeded", "Failed", "Cancelled"} {
		if got := boundedOutcome(outcome); got != outcome {
			t.Errorf("known outcome %q mapped to %q", outcome, got)
		}
	}
	if got := boundedOutcome("failed-node-worker-123"); got != "other" {
		t.Fatalf("unbounded outcome label leaked through: %q", got)
	}
	if got := boundedOutcome("RecoveryRequired"); got != "other" {
		t.Fatalf("nonterminal phase treated as outcome: %q", got)
	}
}

func TestRecoveryRequiredMetricRecordsBoundedAction(t *testing.T) {
	before := testutil.ToFloat64(maintenanceRecoveryRequired.WithLabelValues("other"))
	RecordMaintenanceRecoveryRequired("customer-node-7")
	after := testutil.ToFloat64(maintenanceRecoveryRequired.WithLabelValues("other"))
	if after-before != 1 {
		t.Fatalf("bounded recovery-required counter delta = %v; want 1", after-before)
	}
}

func TestActiveRecoveryAgeSnapshotSignalsCompletenessAndStaleness(t *testing.T) {
	SetActiveRecoveryAgeSnapshot(3, 1, 125, 1700000000)
	if got := testutil.ToFloat64(activeRecoveryOperations); got != 3 {
		t.Fatalf("active recovery count = %v; want 3", got)
	}
	if got := testutil.ToFloat64(oldestActiveRecoveryAge); got != 125 {
		t.Fatalf("oldest active recovery age = %v; want 125", got)
	}
	if got := testutil.ToFloat64(recoveryAgeSnapshotComplete); got != 0 {
		t.Fatalf("incomplete snapshot completeness = %v; want 0", got)
	}
	if got := testutil.ToFloat64(recoveryAgeSnapshotInvalidOperations); got != 1 {
		t.Fatalf("invalid operation count = %v; want 1", got)
	}
	if got := testutil.ToFloat64(recoveryAgeSnapshotTimestamp); got != 1700000000 {
		t.Fatalf("snapshot timestamp = %v; want 1700000000", got)
	}

	SetRecoveryAgeSnapshotSuccess(false)
	if got := testutil.ToFloat64(recoveryAgeSnapshotSuccess); got != 0 {
		t.Fatalf("failed snapshot success = %v; want 0", got)
	}
	if got := testutil.ToFloat64(oldestActiveRecoveryAge); got != 125 {
		t.Fatalf("failed read replaced last known age with %v; want stale value 125", got)
	}
	if got := testutil.ToFloat64(recoveryAgeSnapshotTimestamp); got != 1700000000 {
		t.Fatalf("failed read replaced last success timestamp with %v", got)
	}

	SetActiveRecoveryAgeSnapshot(0, 0, 0, 1700000015)
	if got := testutil.ToFloat64(recoveryAgeSnapshotSuccess); got != 1 {
		t.Fatalf("successful empty snapshot success = %v; want 1", got)
	}
	if got := testutil.ToFloat64(recoveryAgeSnapshotComplete); got != 1 {
		t.Fatalf("successful empty snapshot completeness = %v; want 1", got)
	}
	if got := testutil.ToFloat64(activeRecoveryOperations); got != 0 {
		t.Fatalf("active recovery count after empty snapshot = %v; want 0", got)
	}
}

func TestMaintenanceOutcomeMetricRecordsOnlyBoundedLabels(t *testing.T) {
	before := testutil.ToFloat64(maintenanceOutcomes.WithLabelValues("other", "Failed"))
	RecordMaintenanceOutcome("customer-node-7", "Failed", -1)
	after := testutil.ToFloat64(maintenanceOutcomes.WithLabelValues("other", "Failed"))
	if after-before != 1 {
		t.Fatalf("bounded failure counter delta = %v; want 1", after-before)
	}
}
