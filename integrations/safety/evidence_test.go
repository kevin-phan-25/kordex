package safety

import (
	"testing"
	"time"
)

func TestCephEvidenceFailsClosed(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	base := CephEvidence{Health: "HEALTH_OK", OSDExpected: 3, OSDUp: 3, OSDIn: 3, ObservedAt: now, EvidenceValidFor: time.Minute}
	if got := EvaluateCephEvidence(base, now); got.Decision != DecisionPass {
		t.Fatalf("healthy evidence decision = %s (%s), want Pass", got.Decision, got.Reason)
	}
	stale := base
	stale.ObservedAt = now.Add(-2 * time.Minute)
	if got := EvaluateCephEvidence(stale, now); got.Decision != DecisionUnknown {
		t.Fatalf("stale evidence decision = %s, want Unknown", got.Decision)
	}
	degraded := base
	degraded.OSDUp = 2
	if got := EvaluateCephEvidence(degraded, now); got.Decision != DecisionBlock {
		t.Fatalf("missing OSD decision = %s, want Block", got.Decision)
	}
	foreignNoout := base
	foreignNoout.MaintenanceOwner = "operation-a"
	foreignNoout.NooutSet = true
	foreignNoout.NooutOwner = "operation-b"
	if got := EvaluateCephEvidence(foreignNoout, now); got.Decision != DecisionBlock {
		t.Fatalf("foreign noout decision = %s, want Block", got.Decision)
	}
}

func TestEtcdQuorumAfterTargetRemoval(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	evidence := EtcdEvidence{ObservedAt: now, EvidenceValidFor: time.Minute, Members: []EtcdMember{{ID: "a", Healthy: true}, {ID: "b", Healthy: true}, {ID: "c", Healthy: true}}}
	if got := EvaluateEtcdEvidence(evidence, "a", now); got.Decision != DecisionPass {
		t.Fatalf("3-member quorum decision = %s (%s), want Pass", got.Decision, got.Reason)
	}
	evidence.Members[1].Healthy = false
	if got := EvaluateEtcdEvidence(evidence, "a", now); got.Decision != DecisionBlock {
		t.Fatalf("lost quorum decision = %s, want Block", got.Decision)
	}
	evidence.Members[1].Healthy = true
	evidence.Members[2].ID = "b"
	if got := EvaluateEtcdEvidence(evidence, "a", now); got.Decision != DecisionUnknown {
		t.Fatalf("contradictory membership decision = %s, want Unknown", got.Decision)
	}
}
