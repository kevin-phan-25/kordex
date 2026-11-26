package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kordex.local/api/protocol"
)

func TestValidateOperationReportBindsLocalUpgradeCheckpoint(t *testing.T) {
	request := protocol.MaintenanceRequest{Action: protocol.UpgradePackages, PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid"}
	checkpoint := protocol.UpgradeCheckpoint{
		PlanDigest: request.PlanDigest, NodeUID: request.NodeUID,
		BootID: "33333333-3333-4333-8333-333333333333", Phase: protocol.UpgradePending,
		Sequence: 1, UpdatedAt: metav1.NewTime(time.Now().UTC()),
	}
	report := validOperationReport(string(checkpoint.Phase), &checkpoint, nil)
	if err := validateOperationReport(nil, request, report); err != nil {
		t.Fatalf("valid local upgrade report rejected: %v", err)
	}
	wrongAction := request
	wrongAction.Action = protocol.DrainAndVerify
	if err := validateOperationReport(nil, wrongAction, report); err == nil {
		t.Fatal("local upgrade checkpoint accepted for a drain operation")
	}
	wrongPlan := checkpoint
	wrongPlan.PlanDigest = strings.Repeat("b", 64)
	if err := validateOperationReport(nil, request, validOperationReport(string(wrongPlan.Phase), &wrongPlan, nil)); err == nil {
		t.Fatal("checkpoint with a different signed plan digest was accepted")
	}

	nextCheckpoint := checkpoint
	nextCheckpoint.Phase, nextCheckpoint.Sequence = protocol.UpgradePreflighting, 2
	nextCheckpoint.UpdatedAt = metav1.NewTime(checkpoint.UpdatedAt.Add(time.Second))
	previous := validOperationReport("Pending", &checkpoint, nil)
	previous.Events = append(previous.Events,
		protocol.PhaseEvent{Sequence: 2, Phase: "Validating", Reason: "test", Time: metav1.NewTime(time.Now().UTC())},
		protocol.PhaseEvent{Sequence: 3, Phase: "SafetyChecking", Reason: "test", Time: metav1.NewTime(time.Now().UTC())},
	)
	previous.Sequence = 3
	previous.Phase = "SafetyChecking"
	previous.Reason = "test"
	next := validOperationReport("Preflighting", &nextCheckpoint, &previous)
	if err := validateOperationReport(&previous, request, next); err != nil {
		t.Fatalf("monotonic local checkpoint update rejected: %v", err)
	}
	regressed := nextCheckpoint
	regressed.Phase, regressed.Sequence = protocol.UpgradePending, 3
	regressed.UpdatedAt = metav1.NewTime(nextCheckpoint.UpdatedAt.Add(time.Second))
	if err := validateOperationReport(&next, request, validOperationReport(string(protocol.UpgradePreflighting), &regressed, &next)); err == nil {
		t.Fatal("checkpoint regression was accepted")
	}
}

func TestTerminalRecoveryTransitionRequiresPriorSuccessfulIdentity(t *testing.T) {
	request := protocol.MaintenanceRequest{Action: protocol.ValidateOnly}
	status := protocol.OperationReport{OperationID: "123e4567-e89b-12d3-a456-426614174000", Sequence: 4, Phase: "Succeeded", Reason: "verified"}
	for i, phase := range []string{"Pending", "Validating", "SafetyChecking", "Succeeded"} {
		reason := "test-" + phase
		if phase == "Succeeded" {
			reason = status.Reason
		}
		status.Events = append(status.Events, protocol.PhaseEvent{Sequence: int64(i + 1), Phase: phase, Reason: reason, Time: metav1.NewTime(time.Now().UTC().Add(time.Duration(i) * time.Second))})
	}
	recovery := protocol.OperationReport{OperationID: status.OperationID, Sequence: 5, Phase: "RecoveryRequired", Reason: "TerminalRecoveryIncomplete", Events: append([]protocol.PhaseEvent(nil), status.Events...)}
	recovery.Events = append(recovery.Events, protocol.PhaseEvent{Sequence: 5, Phase: recovery.Phase, Reason: recovery.Reason, Time: metav1.NewTime(time.Now().UTC().Add(5 * time.Second))})
	op := NodeOperation{ID: status.OperationID, Request: request, Phase: "Succeeded", Sequence: 4, Status: &status}
	if !terminalRecoveryTransition(op, recovery) {
		t.Fatal("protocol-defined Succeeded to RecoveryRequired transition was rejected")
	}

	cases := map[string]func(*NodeOperation, *protocol.OperationReport){
		"failed operation":    func(op *NodeOperation, _ *protocol.OperationReport) { op.Phase = "Failed" },
		"cancelled operation": func(op *NodeOperation, _ *protocol.OperationReport) { op.Phase = "Cancelled" },
		"wrong reason":        func(_ *NodeOperation, report *protocol.OperationReport) { report.Reason = "other" },
		"wrong operation identity": func(_ *NodeOperation, report *protocol.OperationReport) {
			report.OperationID = "223e4567-e89b-12d3-a456-426614174000"
		},
		"malformed prior identity": func(op *NodeOperation, _ *protocol.OperationReport) {
			op.Status.OperationID = "223e4567-e89b-12d3-a456-426614174000"
		},
		"missing prior status":  func(op *NodeOperation, _ *protocol.OperationReport) { op.Status = nil },
		"wrong terminal status": func(op *NodeOperation, _ *protocol.OperationReport) { op.Status.Phase = "Cancelled" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidateOp := op
			candidateStatus := status
			candidateOp.Status = &candidateStatus
			candidateReport := recovery
			candidateReport.Events = append([]protocol.PhaseEvent(nil), recovery.Events...)
			mutate(&candidateOp, &candidateReport)
			if terminalRecoveryTransition(candidateOp, candidateReport) {
				t.Fatal("accepted invalid terminal recovery identity or reason")
			}
		})
	}
}

func TestMaintenanceZoneUsesConsistentTopologyAndFailsClosedOnConflict(t *testing.T) {
	for _, test := range []struct {
		name string
		node protocol.Node
		want string
	}{
		{name: "reported zone", node: protocol.Node{Zone: "us-east-1a"}, want: "us-east-1a"},
		{name: "standard topology label", node: protocol.Node{Labels: map[string]string{"topology.kubernetes.io/zone": "us-east-1b"}}, want: "us-east-1b"},
		{name: "legacy topology label", node: protocol.Node{Labels: map[string]string{"failure-domain.beta.kubernetes.io/zone": "us-east-1c"}}, want: "us-east-1c"},
		{name: "matching evidence", node: protocol.Node{Zone: "us-east-1d", Labels: map[string]string{"topology.kubernetes.io/zone": "us-east-1d"}}, want: "us-east-1d"},
		{name: "conflicting evidence is unknown", node: protocol.Node{Zone: "us-east-1e", Labels: map[string]string{"topology.kubernetes.io/zone": "us-east-1f"}}},
		{name: "invalid label value is unknown", node: protocol.Node{Zone: "bad zone"}},
		{name: "missing evidence is unknown", node: protocol.Node{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := maintenanceZone(test.node); got != test.want {
				t.Fatalf("maintenanceZone()=%q, want %q", got, test.want)
			}
		})
	}
}

func TestValidateOperationReportBindsProviderUpgradeCheckpoint(t *testing.T) {
	request := protocol.MaintenanceRequest{Action: protocol.UpgradeNodePool, PlanDigest: strings.Repeat("a", 64)}
	checkpoint := protocol.ProviderUpgradeCheckpoint{
		PlanDigest: request.PlanDigest, Resource: "projects/p/locations/us-central1/clusters/c/nodePools/pool",
		TargetVersion: "1.37.1-gke.1", Phase: "Pending", Sequence: 1,
		UpdatedAt: metav1.NewTime(time.Now().UTC()),
	}
	report := validOperationReport("Pending", nil, nil)
	report.ProviderUpgradeCheckpoint = &checkpoint
	if err := validateOperationReport(nil, request, report); err != nil {
		t.Fatalf("valid provider upgrade report rejected: %v", err)
	}
	wrongAction := request
	wrongAction.Action = protocol.UpgradePackages
	if err := validateOperationReport(nil, wrongAction, report); err == nil {
		t.Fatal("provider checkpoint accepted for a package upgrade operation")
	}
	wrongDigest := checkpoint
	wrongDigest.PlanDigest = strings.Repeat("c", 64)
	report.ProviderUpgradeCheckpoint = &wrongDigest
	if err := validateOperationReport(nil, request, report); err == nil {
		t.Fatal("provider checkpoint with a different plan digest was accepted")
	}
}

func TestOperationCheckpointAuditCapturesOnlyCheckpointChanges(t *testing.T) {
	checkpoint := &protocol.UpgradeCheckpoint{
		PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid", Phase: protocol.UpgradePending,
		Sequence: 1, UpdatedAt: metav1.NewTime(time.Now().UTC()),
	}
	report := validOperationReport("Pending", checkpoint, nil)
	action, metadata, changed, err := operationCheckpointAudit(report, nil)
	if err != nil || !changed || action != "maintenance.upgrade_checkpoint" {
		t.Fatalf("initial checkpoint audit missing: action=%q changed=%t err=%v", action, changed, err)
	}
	var decoded map[string]json.RawMessage
	if err = json.Unmarshal(metadata, &decoded); err != nil || len(decoded["upgradeCheckpoint"]) == 0 {
		t.Fatalf("upgrade checkpoint evidence missing from audit metadata: %s err=%v", metadata, err)
	}
	if _, _, changed, err = operationCheckpointAudit(report, &report); err != nil || changed {
		t.Fatalf("unchanged checkpoint generated a duplicate audit record: changed=%t err=%v", changed, err)
	}
	provider := protocol.ProviderUpgradeCheckpoint{
		PlanDigest: strings.Repeat("b", 64), Resource: "projects/p/locations/us-central1/clusters/c/nodePools/pool",
		TargetVersion: "1.37.1-gke.1", Phase: "Pending", Sequence: 1, UpdatedAt: metav1.NewTime(time.Now().UTC()),
	}
	providerReport := validOperationReport("Pending", nil, nil)
	providerReport.ProviderUpgradeCheckpoint = &provider
	action, metadata, changed, err = operationCheckpointAudit(providerReport, nil)
	if err != nil || !changed || action != "maintenance.provider_upgrade_checkpoint" {
		t.Fatalf("provider checkpoint audit missing: action=%q changed=%t err=%v", action, changed, err)
	}
}

func validOperationReport(phase string, checkpoint *protocol.UpgradeCheckpoint, previous *protocol.OperationReport) protocol.OperationReport {
	report := protocol.OperationReport{OperationID: "123e4567-e89b-12d3-a456-426614174000", Sequence: 1, Phase: phase, Reason: "test"}
	if previous != nil {
		report.Events = append(report.Events, previous.Events...)
		report.Sequence = previous.Sequence + 1
	}
	report.Events = append(report.Events, protocol.PhaseEvent{Sequence: report.Sequence, Phase: phase, Reason: report.Reason, Time: metav1.NewTime(time.Now().UTC())})
	report.UpgradeCheckpoint = checkpoint
	return report
}
