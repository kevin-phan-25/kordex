package protocol

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpgradeOperationReportCarriesValidatedCheckpoint(t *testing.T) {
	now := time.Now().UTC()
	report := OperationReport{
		OperationID: "22222222-2222-4222-8222-222222222222",
		Sequence:    1,
		Phase:       "Executing",
		Reason:      "UpgradeJobRunning",
		Events:      []PhaseEvent{{Sequence: 1, Phase: "Executing", Reason: "UpgradeJobRunning", Time: metav1.NewTime(now)}},
		UpgradeCheckpoint: &UpgradeCheckpoint{
			PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid",
			MachineID: strings.Repeat("b", 32), BootID: "33333333-3333-4333-8333-333333333333",
			Phase: UpgradeExecuting, Sequence: 3, ExecutionReference: "kordex-ee-operation-apply",
			UpdatedAt: metav1.NewTime(now),
		},
	}
	if !report.Validate() {
		t.Fatal("valid upgrade checkpoint report rejected")
	}
	report.Phase = "Rebooting"
	report.Events = []PhaseEvent{{Sequence: 1, Phase: "Rebooting", Reason: "UpgradeJobRunning", Time: metav1.NewTime(now)}}
	if !report.Validate() {
		t.Fatal("reboot lifecycle phase rejected")
	}
	report.UpgradeCheckpoint.PlanDigest = "invalid"
	if report.Validate() {
		t.Fatal("invalid persisted upgrade checkpoint accepted")
	}
}

func TestUpgradeCheckpointReceiptEvidenceIsBoundedAndImmutable(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC())
	base := UpgradeCheckpoint{
		PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid",
		MachineID: strings.Repeat("b", 32), BootID: "33333333-3333-4333-8333-333333333333",
		Phase: UpgradeExecuting, Sequence: 4, UpdatedAt: now,
	}
	receipt := UpgradeReceiptEvidence{
		Phase: "apply", Reference: "kordex-ee-op-apply-receipt", Digest: strings.Repeat("c", 64),
		MachineID: strings.Repeat("b", 32), BootIDBefore: base.BootID, BootIDAfter: base.BootID,
		Packages: map[string]string{"curl": "8.1.0-1"}, CompletedAt: now,
	}
	next := base
	next.Phase = UpgradeVerifyingNode
	next.Sequence++
	next.UpdatedAt = metav1.NewTime(now.Add(time.Second))
	next.Receipts = []UpgradeReceiptEvidence{receipt}
	if err := ValidateUpgradeCheckpoint(next); err != nil {
		t.Fatalf("valid receipt evidence rejected: %v", err)
	}
	if err := ValidateUpgradeCheckpointAdvance(base, next); err != nil {
		t.Fatalf("receipt append rejected: %v", err)
	}
	changed := next.DeepCopy()
	changed.Receipts[0].Packages["curl"] = "8.2.0-1"
	changed.Sequence++
	changed.UpdatedAt = metav1.NewTime(next.UpdatedAt.Add(time.Second))
	if err := ValidateUpgradeCheckpointAdvance(next, *changed); err == nil {
		t.Fatal("mutation of persisted receipt evidence accepted")
	}
}
