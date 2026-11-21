package protocol

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpgradeOperationReportCarriesValidatedCheckpoint(t *testing.T) {
	now := time.Now().UTC()
	phases := []string{"Pending", "Validating", "SafetyChecking", "Preflighting", "Cordoning", "Draining", "Executing"}
	events := make([]PhaseEvent, 0, len(phases)+1)
	for i, phase := range phases {
		events = append(events, PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "UpgradeProgress", Time: metav1.NewTime(now.Add(time.Duration(i) * time.Second))})
	}
	events[len(events)-1].Reason = "UpgradeJobRunning"
	report := OperationReport{
		OperationID: "22222222-2222-4222-8222-222222222222",
		Sequence:    int64(len(events)),
		Phase:       "Executing",
		Reason:      "UpgradeJobRunning",
		Events:      events,
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
	report.Sequence++
	report.Phase = "Rebooting"
	report.Reason = "UpgradeJobRunning"
	report.Events = append(report.Events, PhaseEvent{Sequence: report.Sequence, Phase: report.Phase, Reason: report.Reason, Time: metav1.NewTime(now.Add(time.Duration(report.Sequence) * time.Second))})
	if !report.Validate() {
		t.Fatal("reboot lifecycle phase rejected")
	}
	report.UpgradeCheckpoint.PlanDigest = "invalid"
	if report.Validate() {
		t.Fatal("invalid persisted upgrade checkpoint accepted")
	}
}

func TestMaintenancePhaseTransitionGraphRejectsUnsafeSkips(t *testing.T) {
	for _, tc := range []struct {
		from, to, resume string
		want             bool
	}{
		{from: "", to: "Pending", want: true},
		{from: "Pending", to: "Validating", want: true},
		{from: "Validating", to: "SafetyChecking", want: true},
		{from: "SafetyChecking", to: "Succeeded", want: true},
		{from: "SafetyChecking", to: "Blocked", want: true},
		{from: "Blocked", to: "Cordoning", resume: "SafetyChecking", want: true},
		{from: "Blocked", to: "Succeeded", resume: "SafetyChecking", want: true},
		{from: "Blocked", to: "Draining", resume: "Draining", want: true},
		{from: "Blocked", to: "Cordoning", resume: "Cordoning", want: true},
		{from: "Cordoning", to: "Draining", want: true},
		{from: "Draining", to: "Executing", want: true},
		{from: "Executing", to: "Rebooting", want: true},
		{from: "Rebooting", to: "VerifyingNode", want: true},
		{from: "VerifyingNode", to: "VerifyingWorkloads", want: true},
		{from: "VerifyingWorkloads", to: "Uncordoning", want: true},
		{from: "VerifyingWorkloads", to: "Succeeded", want: true},
		{from: "VerifyingWorkloads", to: "Cancelled", want: true},
		{from: "Uncordoning", to: "Succeeded", want: true},
		{from: "Succeeded", to: "RecoveryRequired", want: true},
		{from: "RecoveryRequired", to: "Uncordoning", want: true},
		{from: "Pending", to: "Succeeded", want: false},
		{from: "Draining", to: "Uncordoning", want: false},
		{from: "Executing", to: "Cancelled", want: false},
		{from: "RecoveryRequired", to: "Failed", want: false},
		{from: "Succeeded", to: "Pending", want: false},
		{from: "Blocked", to: "Succeeded", resume: "Draining", want: false},
		{from: "Blocked", to: "Cordoning", resume: "Draining", want: false},
		{from: "Blocked", to: "Draining", resume: "SafetyChecking", want: false},
	} {
		if got := CanAdvanceMaintenancePhase(tc.from, tc.to, tc.resume); got != tc.want {
			t.Errorf("CanAdvanceMaintenancePhase(%q, %q, %q)=%t, want %t", tc.from, tc.to, tc.resume, got, tc.want)
		}
	}
}

func TestOperationReportAllowsResumingTheInterruptedPhase(t *testing.T) {
	now := time.Now().UTC()
	phases := []string{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining", "Blocked", "Draining"}
	report := OperationReport{OperationID: "22222222-2222-4222-8222-222222222222", Sequence: int64(len(phases))}
	for i, phase := range phases {
		report.Events = append(report.Events, PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "test", Time: metav1.NewTime(now.Add(time.Duration(i) * time.Second))})
	}
	last := report.Events[len(report.Events)-1]
	report.Phase, report.Reason = last.Phase, last.Reason
	if !report.Validate() {
		t.Fatal("valid transition from Blocked to the saved resume phase was rejected")
	}
	report.Events[len(report.Events)-1].Phase = "Succeeded"
	report.Phase = "Succeeded"
	if report.Validate() {
		t.Fatal("blocked operation skipped its saved resume phase")
	}
}

func TestOperationReportRejectsImpossiblePhaseHistory(t *testing.T) {
	makeReport := func(phases ...string) OperationReport {
		now := time.Now().UTC()
		report := OperationReport{OperationID: "22222222-2222-4222-8222-222222222222", Sequence: int64(len(phases))}
		for i, phase := range phases {
			report.Events = append(report.Events, PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "test", Time: metav1.NewTime(now.Add(time.Duration(i) * time.Second))})
		}
		last := report.Events[len(report.Events)-1]
		report.Phase, report.Reason = last.Phase, last.Reason
		return report
	}

	validBlockedResume := makeReport("Pending", "Validating", "SafetyChecking", "Blocked", "Blocked", "Cordoning")
	if !validBlockedResume.Validate() {
		t.Fatal("valid blocked-operation resume was rejected")
	}
	terminalRecovery := makeReport("Pending", "Validating", "SafetyChecking", "Succeeded", "RecoveryRequired")
	terminalRecovery.Events[len(terminalRecovery.Events)-1].Reason = "TerminalRecoveryIncomplete"
	terminalRecovery.Reason = "TerminalRecoveryIncomplete"
	if !terminalRecovery.Validate() {
		t.Fatal("owned-cordon recovery re-entry was rejected")
	}
	terminalRecovery.Events[len(terminalRecovery.Events)-1].Reason = "ReservationLost"
	terminalRecovery.Reason = "ReservationLost"
	if terminalRecovery.Validate() {
		t.Fatal("unexplained terminal-to-recovery transition was accepted")
	}
	for _, phases := range [][]string{
		{"Pending", "Succeeded"},
		{"Pending", "Validating", "SafetyChecking", "Blocked", "Blocked", "Draining"},
		{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining", "Executing", "Cancelled"},
		{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining", "Executing", "RecoveryRequired", "Failed"},
		{"Pending", "Validating", "SafetyChecking", "Succeeded", "Validating"},
	} {
		if makeReport(phases...).Validate() {
			t.Errorf("impossible phase history accepted: %v", phases)
		}
	}
}

func TestOperationReportRejectsBackwardEventTime(t *testing.T) {
	now := time.Now().UTC()
	report := OperationReport{OperationID: "22222222-2222-4222-8222-222222222222", Sequence: 3}
	for i, phase := range []string{"Pending", "Validating", "SafetyChecking"} {
		report.Events = append(report.Events, PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "test", Time: metav1.NewTime(now.Add(time.Duration(i) * time.Second))})
	}
	last := report.Events[len(report.Events)-1]
	report.Phase, report.Reason = last.Phase, last.Reason
	if !report.Validate() {
		t.Fatal("chronological phase report was rejected")
	}

	// Equal timestamps can occur on clocks with coarse resolution and remain
	// valid as long as the sequence order is intact.
	report.Events[2].Time = report.Events[1].Time
	if !report.Validate() {
		t.Fatal("equal consecutive event times were rejected")
	}
	report.Events[2].Time = metav1.NewTime(report.Events[0].Time.Add(-time.Nanosecond))
	if report.Validate() {
		t.Fatal("backwards event timestamp was accepted")
	}
}

func TestOperationReportValidateAtBoundsAllEvidenceTimestamps(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	const skew = 2 * time.Minute
	makeReport := func() OperationReport {
		return OperationReport{
			OperationID: "22222222-2222-4222-8222-222222222222",
			Sequence:    1,
			Phase:       "Pending",
			Reason:      "RequestAccepted",
			Events:      []PhaseEvent{{Sequence: 1, Phase: "Pending", Reason: "RequestAccepted", Time: metav1.NewTime(now)}},
		}
	}
	if report := makeReport(); !report.ValidateAt(now, skew) {
		t.Fatal("valid report within the receiver clock bound was rejected")
	}

	t.Run("phase event", func(t *testing.T) {
		report := makeReport()
		report.Events[0].Time = metav1.NewTime(now.Add(skew + time.Nanosecond))
		if report.ValidateAt(now, skew) {
			t.Fatal("future phase event was accepted")
		}
	})
	t.Run("host checkpoint", func(t *testing.T) {
		report := makeReport()
		report.UpgradeCheckpoint = &UpgradeCheckpoint{
			PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid", Phase: UpgradePending,
			Sequence: 1, UpdatedAt: metav1.NewTime(now.Add(skew + time.Nanosecond)),
		}
		if report.ValidateAt(now, skew) {
			t.Fatal("future host checkpoint was accepted")
		}
	})
	t.Run("host receipt", func(t *testing.T) {
		report := makeReport()
		report.UpgradeCheckpoint = &UpgradeCheckpoint{
			PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid", Phase: UpgradePending,
			Sequence: 1, UpdatedAt: metav1.NewTime(now),
			Receipts: []UpgradeReceiptEvidence{{
				Phase: "preflight", Reference: "ee-preflight", Digest: strings.Repeat("c", 64),
				MachineID:    strings.Repeat("b", 32),
				BootIDBefore: "33333333-3333-4333-8333-333333333333",
				BootIDAfter:  "33333333-3333-4333-8333-333333333333",
				CompletedAt:  metav1.NewTime(now.Add(skew + time.Nanosecond)),
			}},
		}
		if report.ValidateAt(now, skew) {
			t.Fatal("future host receipt timestamp was accepted")
		}
	})
	t.Run("provider checkpoint intent", func(t *testing.T) {
		report := makeReport()
		report.ProviderUpgradeCheckpoint = &ProviderUpgradeCheckpoint{
			PlanDigest: strings.Repeat("a", 64), Resource: "projects/p/locations/us-east1/clusters/c/nodePools/pool",
			TargetVersion: "1.37.1-gke.1", Phase: "Submitting", Sequence: 1,
			IntentAt: metav1.NewTime(now.Add(skew + time.Nanosecond)), UpdatedAt: metav1.NewTime(now),
			OperationName:              "projects/p/locations/us-east1/operations/op",
			InitialNodeIdentityDigests: []string{strings.Repeat("b", 64)},
		}
		if report.ValidateAt(now, skew) {
			t.Fatal("future provider intent timestamp was accepted")
		}
	})
	t.Run("provider checkpoint update", func(t *testing.T) {
		report := makeReport()
		report.ProviderUpgradeCheckpoint = &ProviderUpgradeCheckpoint{
			PlanDigest: strings.Repeat("a", 64), Resource: "projects/p/locations/us-east1/clusters/c/nodePools/pool",
			TargetVersion: "1.37.1-gke.1", Phase: "Pending", Sequence: 1,
			UpdatedAt: metav1.NewTime(now.Add(skew + time.Nanosecond)),
		}
		if report.ValidateAt(now, skew) {
			t.Fatal("future provider checkpoint timestamp was accepted")
		}
	})
	if makeReport().ValidateAt(now, -time.Second) {
		t.Fatal("negative receiver clock allowance was accepted")
	}
}

func TestOperationReportPhasesMatchAuthorizedAction(t *testing.T) {
	now := time.Now().UTC()
	makeReport := func(phases ...string) OperationReport {
		report := OperationReport{OperationID: "22222222-2222-4222-8222-222222222222", Sequence: int64(len(phases))}
		for i, phase := range phases {
			report.Events = append(report.Events, PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "test", Time: metav1.NewTime(now.Add(time.Duration(i) * time.Second))})
		}
		last := report.Events[len(report.Events)-1]
		report.Phase, report.Reason = last.Phase, last.Reason
		return report
	}
	for _, tc := range []struct {
		name   string
		action string
		phases []string
		want   bool
	}{
		{name: "validate-only success", action: ValidateOnly, phases: []string{"Pending", "Validating", "SafetyChecking", "Succeeded"}, want: true},
		{name: "validate-only cannot drain", action: ValidateOnly, phases: []string{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining"}},
		{name: "drain cannot report success without a drain", action: DrainAndVerify, phases: []string{"Pending", "Validating", "SafetyChecking", "Succeeded"}},
		{name: "drain success", action: DrainAndVerify, phases: []string{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "Succeeded"}, want: true},
		{name: "drain cannot execute host packages", action: DrainAndVerify, phases: []string{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining", "Executing"}},
		{name: "host upgrade cannot report success without execution", action: UpgradePackages, phases: []string{"Pending", "Validating", "SafetyChecking", "Succeeded"}},
		{name: "host upgrade success", action: UpgradePackages, phases: []string{"Pending", "Validating", "SafetyChecking", "Preflighting", "Cordoning", "Draining", "Executing", "Rebooting", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "Succeeded"}, want: true},
		{name: "host upgrade success without reboot", action: UpgradePackages, phases: []string{"Pending", "Validating", "SafetyChecking", "Preflighting", "Cordoning", "Draining", "Executing", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "Succeeded"}, want: true},
		{name: "host upgrade cannot use provider-only path", action: UpgradePackages, phases: []string{"Pending", "Validating", "SafetyChecking", "Executing", "VerifyingNode", "Succeeded"}},
		{name: "provider cannot report success without verification", action: UpgradeNodePool, phases: []string{"Pending", "Validating", "SafetyChecking", "Succeeded"}},
		{name: "provider upgrade success", action: UpgradeNodePool, phases: []string{"Pending", "Validating", "SafetyChecking", "Executing", "VerifyingNode", "VerifyingWorkloads", "Succeeded"}, want: true},
		{name: "provider no-op verifies already-current pool", action: UpgradeNodePool, phases: []string{"Pending", "Validating", "SafetyChecking", "VerifyingNode", "VerifyingWorkloads", "Succeeded"}, want: true},
		{name: "provider upgrade cannot cordon locally", action: UpgradeNodePool, phases: []string{"Pending", "Validating", "SafetyChecking", "Cordoning", "Draining"}},
		{name: "unknown action", action: "DeleteCluster", phases: []string{"Pending"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := makeReport(tc.phases...)
			if tc.action == UpgradePackages && tc.want {
				rebootRequested := false
				for _, phase := range tc.phases {
					if phase == "Rebooting" {
						rebootRequested = true
					}
				}
				checkpoint := validSuccessfulUpgradeCheckpoint(now, report.OperationID, rebootRequested)
				report.UpgradeCheckpoint = &checkpoint
			}
			if tc.action == UpgradeNodePool && tc.want {
				initialVersion := "1.36.4-gke.1"
				if tc.name == "provider no-op verifies already-current pool" {
					initialVersion = "1.37.1-gke.1"
				}
				report.ProviderUpgradeCheckpoint = &ProviderUpgradeCheckpoint{
					PlanDigest: strings.Repeat("a", 64), Resource: "projects/p/locations/us-east1/clusters/c/nodePools/pool",
					TargetVersion: "1.37.1-gke.1", InitialVersion: initialVersion, Phase: "Succeeded", Sequence: 1,
					UpdatedAt: metav1.NewTime(now), InitialNodeIdentityDigests: []string{strings.Repeat("b", 64)},
				}
			}
			if got := report.ValidateForAction(tc.action); got != tc.want {
				t.Fatalf("ValidateForAction(%q, %v)=%t, want %t", tc.action, tc.phases, got, tc.want)
			}
		})
	}
}

func validSuccessfulUpgradeCheckpoint(now time.Time, operationID string, reboot bool) UpgradeCheckpoint {
	const nodeUID = "node-uid"
	const machineID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const oldBootID = "33333333-3333-4333-8333-333333333333"
	const newBootID = "44444444-4444-4444-8444-444444444444"
	planDigest := strings.Repeat("a", 64)
	checkpointBootID := oldBootID
	sequence := int64(9)
	outcome := "PackagesVerified"
	if reboot {
		checkpointBootID = newBootID
		sequence = 10
		outcome = "PackagesAndRebootVerified"
	}
	marker := func(bootID, phase string, markerSequence int64) *ActionMarkerEvidence {
		return &ActionMarkerEvidence{Version: 1, OperationID: operationID, ActionDigest: planDigest, NodeUID: nodeUID, MachineID: machineID, BootID: bootID, Phase: phase, Sequence: markerSequence, SHA256: strings.Repeat("e", 64)}
	}
	completed := metav1.NewTime(now.Add(time.Second))
	preflight := UpgradeReceiptEvidence{Phase: "preflight", Reference: "kordex-op-preflight-receipt", Digest: strings.Repeat("c", 64), MachineID: machineID, BootIDBefore: oldBootID, BootIDAfter: oldBootID, KernelVersion: "6.8.0-1", CompletedAt: completed}
	apply := UpgradeReceiptEvidence{Phase: "apply", Reference: "kordex-op-apply-receipt", Digest: strings.Repeat("d", 64), MachineID: machineID, BootIDBefore: oldBootID, BootIDAfter: oldBootID, KernelVersion: "6.8.0-1", RebootRequired: reboot, Packages: map[string]string{"curl": "8.5.0-1"}, ActionMarker: marker(oldBootID, "packages-verified", 2), CompletedAt: metav1.NewTime(now.Add(2 * time.Second))}
	checkpoint := UpgradeCheckpoint{
		PlanDigest: planDigest, NodeUID: nodeUID, MachineID: machineID, BootID: checkpointBootID,
		Phase: UpgradeSucceeded, Sequence: sequence, Outcome: outcome,
		UpdatedAt: metav1.NewTime(now.Add(10 * time.Second)), Receipts: []UpgradeReceiptEvidence{preflight, apply},
	}
	if reboot {
		checkpoint.RebootRequested = true
		checkpoint.Receipts = append(checkpoint.Receipts, UpgradeReceiptEvidence{
			Phase: "reboot", Reference: "kordex-op-reboot-receipt", Digest: strings.Repeat("f", 64),
			MachineID: machineID, BootIDBefore: oldBootID, BootIDAfter: newBootID, KernelVersion: "6.8.0-1",
			Rebooted: true, RebootRequired: true, Packages: map[string]string{"curl": "8.5.0-1"},
			ActionMarker: marker(newBootID, "reboot-verified", 4), CompletedAt: metav1.NewTime(now.Add(3 * time.Second)),
		})
	}
	return checkpoint
}

func TestSuccessfulHostUpgradeRequiresConsistentReceipts(t *testing.T) {
	now := time.Now().UTC()
	operationID := "22222222-2222-4222-8222-222222222222"
	for _, test := range []struct {
		name   string
		mutate func(*UpgradeCheckpoint)
	}{
		{name: "missing apply receipt", mutate: func(checkpoint *UpgradeCheckpoint) { checkpoint.Receipts = checkpoint.Receipts[:1] }},
		{name: "apply receipt precedes preflight", mutate: func(checkpoint *UpgradeCheckpoint) {
			checkpoint.Receipts[0], checkpoint.Receipts[1] = checkpoint.Receipts[1], checkpoint.Receipts[0]
		}},
		{name: "missing action marker", mutate: func(checkpoint *UpgradeCheckpoint) { checkpoint.Receipts[1].ActionMarker = nil }},
		{name: "wrong marker operation", mutate: func(checkpoint *UpgradeCheckpoint) {
			checkpoint.Receipts[1].ActionMarker.OperationID = "55555555-5555-4555-8555-555555555555"
		}},
		{name: "apply unexpectedly requires reboot", mutate: func(checkpoint *UpgradeCheckpoint) { checkpoint.Receipts[1].RebootRequired = true }},
		{name: "reboot intent without reboot evidence", mutate: func(checkpoint *UpgradeCheckpoint) { checkpoint.RebootRequested = true }},
		{name: "no-reboot expected kernel mismatch", mutate: func(checkpoint *UpgradeCheckpoint) { checkpoint.Receipts[1].ExpectedKernelVersion = "6.9.0-1" }},
		{name: "checkpoint boot identity mismatch", mutate: func(checkpoint *UpgradeCheckpoint) { checkpoint.BootID = "55555555-5555-4555-8555-555555555555" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkpoint := validSuccessfulUpgradeCheckpoint(now, operationID, false)
			test.mutate(&checkpoint)
			report := OperationReport{
				OperationID: operationID, Phase: "Succeeded", Reason: "test", Sequence: 11,
				Events: []PhaseEvent{
					{Sequence: 1, Phase: "Pending", Reason: "test", Time: metav1.NewTime(now)},
					{Sequence: 2, Phase: "Validating", Reason: "test", Time: metav1.NewTime(now.Add(time.Second))},
					{Sequence: 3, Phase: "SafetyChecking", Reason: "test", Time: metav1.NewTime(now.Add(2 * time.Second))},
					{Sequence: 4, Phase: "Preflighting", Reason: "test", Time: metav1.NewTime(now.Add(3 * time.Second))},
					{Sequence: 5, Phase: "Cordoning", Reason: "test", Time: metav1.NewTime(now.Add(4 * time.Second))},
					{Sequence: 6, Phase: "Draining", Reason: "test", Time: metav1.NewTime(now.Add(5 * time.Second))},
					{Sequence: 7, Phase: "Executing", Reason: "test", Time: metav1.NewTime(now.Add(6 * time.Second))},
					{Sequence: 8, Phase: "VerifyingNode", Reason: "test", Time: metav1.NewTime(now.Add(7 * time.Second))},
					{Sequence: 9, Phase: "VerifyingWorkloads", Reason: "test", Time: metav1.NewTime(now.Add(8 * time.Second))},
					{Sequence: 10, Phase: "Uncordoning", Reason: "test", Time: metav1.NewTime(now.Add(9 * time.Second))},
					{Sequence: 11, Phase: "Succeeded", Reason: "test", Time: metav1.NewTime(now.Add(10 * time.Second))},
				},
				UpgradeCheckpoint: &checkpoint,
			}
			if report.ValidateForAction(UpgradePackages) {
				t.Fatal("inconsistent host-upgrade success evidence was accepted")
			}
		})
	}
}

func TestSuccessfulHostUpgradeRejectsPackageDriftAcrossReboot(t *testing.T) {
	now := time.Now().UTC()
	operationID := "22222222-2222-4222-8222-222222222222"
	checkpoint := validSuccessfulUpgradeCheckpoint(now, operationID, true)
	checkpoint.Receipts[2].Packages["curl"] = "8.5.0-2"
	phases := []string{"Pending", "Validating", "SafetyChecking", "Preflighting", "Cordoning", "Draining", "Executing", "Rebooting", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "Succeeded"}
	events := make([]PhaseEvent, 0, len(phases))
	for i, phase := range phases {
		events = append(events, PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: "test", Time: metav1.NewTime(now.Add(time.Duration(i) * time.Second))})
	}
	report := OperationReport{
		OperationID: operationID, Sequence: int64(len(events)), Phase: "Succeeded", Reason: "test",
		Events: events, UpgradeCheckpoint: &checkpoint,
	}
	if report.ValidateForAction(UpgradePackages) {
		t.Fatal("successful host upgrade accepted package-version drift across reboot")
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
