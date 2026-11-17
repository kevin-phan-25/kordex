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
	previous := validOperationReport(string(protocol.UpgradePending), &checkpoint, nil)
	next := validOperationReport(string(protocol.UpgradePreflighting), &nextCheckpoint, &previous)
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
