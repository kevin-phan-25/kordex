package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
)

func TestUpgradeFailureClassificationPreservesOnlyKnownSSHReasons(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"SSHHostKeyVerificationFailed", "UpgradeSSHHostKeyVerificationFailed"},
		{"SSHAuthenticationFailed", "UpgradeSSHAuthenticationFailed"},
		{"SSHTransportUnavailable", "UpgradeSSHTransportUnavailable"},
		{"operator controlled text", ""},
	}
	for _, tc := range cases {
		if got := classifiedUpgradeFailure(errors.New(tc.input)); got != tc.want {
			t.Errorf("classifiedUpgradeFailure(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
	if got := recoveryInspectionFailureReason("SSHHostKeyVerificationFailed"); got != "UpgradeRecoverySSHHostKeyVerificationFailed" {
		t.Fatalf("recovery identity failure reason = %q", got)
	}
}

type completedUpgradeExecutor struct {
	observation execution.AnsibleJobObservation
	observed    int
	cancelled   int
}

func (*completedUpgradeExecutor) RecoveryTrustDigest(context.Context) (string, error) {
	return strings.Repeat("a", 64), nil
}

type inspectionUpgradeExecutor struct {
	observation  execution.AnsibleJobObservation
	observations []execution.AnsibleJobObservation
	request      execution.AnsibleJobRequest
	trustDigest  string
	ensured      int
	started      int
}

func (e *inspectionUpgradeExecutor) RecoveryTrustDigest(context.Context) (string, error) {
	if e.trustDigest == "" {
		e.trustDigest = strings.Repeat("a", 64)
	}
	return e.trustDigest, nil
}

func (e *inspectionUpgradeExecutor) Ensure(_ context.Context, request execution.AnsibleJobRequest) (string, error) {
	e.request = request
	e.ensured++
	if request.RecoveryTrustDigest != "" {
		return execution.AnsibleInspectionAttemptReference(request.OperationID, request.RecoveryTrustDigest, request.RecoveryAttempt), nil
	}
	return execution.AnsibleJobReference(request.OperationID, request.Phase), nil
}
func (e *inspectionUpgradeExecutor) Start(context.Context, execution.AnsibleJobRequest, string) error {
	e.started++
	return nil
}

func (e *inspectionUpgradeExecutor) Observe(context.Context, execution.AnsibleJobRequest, string) (execution.AnsibleJobObservation, error) {
	if len(e.observations) != 0 {
		observation := e.observations[0]
		e.observations = e.observations[1:]
		return observation, nil
	}
	return e.observation, nil
}
func (*inspectionUpgradeExecutor) Cancel(context.Context, execution.AnsibleJobRequest, string) error {
	return nil
}

func (*completedUpgradeExecutor) Ensure(context.Context, execution.AnsibleJobRequest) (string, error) {
	return "", errors.New("unexpected ensure")
}
func (*completedUpgradeExecutor) Start(context.Context, execution.AnsibleJobRequest, string) error {
	return errors.New("unexpected start")
}
func (e *completedUpgradeExecutor) Observe(context.Context, execution.AnsibleJobRequest, string) (execution.AnsibleJobObservation, error) {
	e.observed++
	return e.observation, nil
}
func (e *completedUpgradeExecutor) Cancel(context.Context, execution.AnsibleJobRequest, string) error {
	e.cancelled++
	return nil
}

func TestRebootJobRequiresVerifiedPackageCheckpoint(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1,
		ID:            "debian-test",
		OSFamily:      "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04",
		ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID:     "kordex.os-upgrade.debian.v2",
		ExecutionEnvironment:  "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:        strings.Repeat("b", 64),
		CollectionsDigest:     strings.Repeat("c", 64),
		Packages:              []protocol.PackagePin{{Name: "linux-image-generic", Version: "6.1.0-1"}},
		ExpectedKernelVersion: "6.1.0-1-generic",
		Channel:               "stable",
		Reboot:                protocol.RebootIfNeeded,
		ExecutionTimeout:      time.Minute,
		RebootTimeout:         time.Minute,
		VerificationTimeout:   time.Minute,
		MaxAttempts:           1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	permit := protocol.MaintenancePermit{MaintenanceRequest: protocol.MaintenanceRequest{
		OperationID: testOperation,
		NodeName:    "worker1",
		NodeUID:     "worker1-uid",
		PlanDigest:  digest,
	}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker1", UID: types.UID("worker1-uid")}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.10"}}}}
	m := &operations.NodeMaintenance{ObjectMeta: metav1.ObjectMeta{Name: "op-" + testOperation, UID: "maintenance-uid"}}
	m.Status.UpgradeCheckpoint = &protocol.UpgradeCheckpoint{
		PlanDigest: digest, NodeUID: permit.NodeUID, Phase: protocol.UpgradeRebooting, Outcome: "PackagesVerified", RebootRequested: true,
		MachineID: strings.Repeat("d", 32), BootID: "33333333-3333-4333-8333-333333333333", Sequence: 1, UpdatedAt: metav1.Now(),
		Receipts: []protocol.UpgradeReceiptEvidence{{
			Phase: execution.EEPhaseApply, Reference: "kordex-ee-receipt", Digest: strings.Repeat("e", 64),
			MachineID: strings.Repeat("d", 32), BootIDBefore: "33333333-3333-4333-8333-333333333333", BootIDAfter: "33333333-3333-4333-8333-333333333333",
			ExpectedKernelVersion: policy.ExpectedKernelVersion, RebootRequired: true,
			Packages: map[string]string{"linux-image-generic": "6.1.0-1"}, CompletedAt: metav1.Now(),
			ActionMarker: &protocol.ActionMarkerEvidence{Version: 1, OperationID: testOperation, ActionDigest: digest, NodeUID: permit.NodeUID,
				MachineID: strings.Repeat("d", 32), BootID: "33333333-3333-4333-8333-333333333333", Phase: "packages-verified", Sequence: 2, SHA256: strings.Repeat("f", 64)},
		}},
	}

	request, err := upgradeJobRequest(m, permit, node, policy, execution.EEPhaseReboot)
	if err != nil {
		t.Fatal(err)
	}
	if !request.RebootAuthorized {
		t.Fatal("verified package receipt did not authorize reboot Job")
	}
	m.Status.UpgradeCheckpoint.Receipts[0].Packages["linux-image-generic"] = "6.1.0-2"
	if _, err = upgradeJobRequest(m, permit, node, policy, execution.EEPhaseReboot); err == nil {
		t.Fatal("package receipt for a different version authorized reboot")
	}

	m.Status.UpgradeCheckpoint.Outcome = "Ambiguous"
	if _, err = upgradeJobRequest(m, permit, node, policy, execution.EEPhaseReboot); err == nil {
		t.Fatal("ambiguous package outcome authorized reboot Job")
	}
}

func TestRecoveryInspectionReceiptMustMatchExactPackagePins(t *testing.T) {
	policy := protocol.UpgradePolicy{OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", Reboot: protocol.RebootIfNeeded, Packages: []protocol.PackagePin{{Name: "curl", Version: "8.1.0-1"}}}
	permit := protocol.MaintenancePermit{MaintenanceRequest: protocol.MaintenanceRequest{OperationID: testOperation, NodeUID: "node-uid", PlanDigest: strings.Repeat("a", 64)}}
	checkpoint := &protocol.UpgradeCheckpoint{MachineID: strings.Repeat("b", 32)}
	receipt := &execution.AnsibleReceipt{
		OperationID: testOperation, PlanDigest: permit.PlanDigest, NodeUID: permit.NodeUID,
		MachineID: checkpoint.MachineID, BootIDBefore: "33333333-3333-4333-8333-333333333333", BootIDAfter: "33333333-3333-4333-8333-333333333333",
		OSFamily: "debian", KernelVersion: "6.1.0-1-generic", Packages: map[string]string{"curl": "8.1.0-1"}, CompletedAt: time.Now().UTC(),
	}
	if !validRecoveryInspectionReceipt(receipt, permit, policy, checkpoint) {
		t.Fatal("valid read-only package evidence rejected")
	}
	receipt.Packages["curl"] = "8.2.0-1"
	if validRecoveryInspectionReceipt(receipt, permit, policy, checkpoint) {
		t.Fatal("inspection receipt with a non-pinned package version accepted")
	}
}

func TestAmbiguousInspectionKeepsRebootPendingOrUnexpectedStateFenced(t *testing.T) {
	checkpoint := &protocol.UpgradeCheckpoint{BootID: "33333333-3333-4333-8333-333333333333"}
	receipt := &execution.AnsibleReceipt{BootIDAfter: "44444444-4444-4444-8444-444444444444", KernelVersion: "6.1.0-1-generic"}
	cases := []struct {
		name        string
		interrupted string
		bootID      string
		reboot      bool
		kernel      string
		wantOutcome string
		wantReason  string
	}{
		{name: "apply unexpectedly rebooted", interrupted: execution.EEPhaseApply, bootID: "44444444-4444-4444-8444-444444444444", wantOutcome: "UpgradeOutcomeAmbiguous", wantReason: "UpgradeRecoveryUnexpectedReboot"},
		{name: "apply still needs reboot", interrupted: execution.EEPhaseApply, bootID: checkpoint.BootID, reboot: true, wantOutcome: "RecoveredWithRebootPending", wantReason: "UpgradeRecoveryRebootStillRequired"},
		{name: "reboot not observed", interrupted: execution.EEPhaseReboot, bootID: checkpoint.BootID, wantOutcome: "RebootNotObserved", wantReason: "UpgradeRebootNotObserved"},
		{name: "reboot still pending after changed boot", interrupted: execution.EEPhaseReboot, bootID: "44444444-4444-4444-8444-444444444444", reboot: true, wantOutcome: "RecoveredWithRebootPending", wantReason: "UpgradeRecoveryRebootStillRequired"},
		{name: "wrong kernel after reboot", interrupted: execution.EEPhaseReboot, bootID: "44444444-4444-4444-8444-444444444444", kernel: "6.0.0-old", wantOutcome: "KernelVersionMismatch", wantReason: "UpgradeRecoveryKernelMismatch"},
		{name: "verified reboot", interrupted: execution.EEPhaseReboot, bootID: "44444444-4444-4444-8444-444444444444"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := *receipt
			candidate.BootIDAfter = tc.bootID
			candidate.RebootRequired = tc.reboot
			candidate.KernelVersion = receipt.KernelVersion
			if tc.kernel != "" {
				candidate.KernelVersion = tc.kernel
			}
			outcome, reason := ambiguousInspectionIntervention(tc.interrupted, &candidate, checkpoint, "6.1.0-1-generic")
			if outcome != tc.wantOutcome || reason != tc.wantReason {
				t.Fatalf("intervention=(%q, %q), want (%q, %q)", outcome, reason, tc.wantOutcome, tc.wantReason)
			}
		})
	}
}

func TestMarkedRecoveryInspectionRequiresPhaseAndBootBoundHostEvidence(t *testing.T) {
	policy := protocol.UpgradePolicy{OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", Reboot: protocol.RebootIfNeeded, ActionMarkerVersion: 1, Packages: []protocol.PackagePin{{Name: "curl", Version: "8.1.0-1"}}}
	permit := protocol.MaintenancePermit{MaintenanceRequest: protocol.MaintenanceRequest{OperationID: testOperation, NodeUID: "node-uid", PlanDigest: strings.Repeat("a", 64)}}
	checkpoint := &protocol.UpgradeCheckpoint{MachineID: strings.Repeat("b", 32), BootID: "33333333-3333-4333-8333-333333333333", InterruptedPhase: execution.EEPhaseApply}
	receipt := &execution.AnsibleReceipt{
		OperationID: testOperation, PlanDigest: permit.PlanDigest, NodeUID: permit.NodeUID,
		MachineID: checkpoint.MachineID, BootIDBefore: checkpoint.BootID, BootIDAfter: checkpoint.BootID,
		OSFamily: "debian", KernelVersion: "6.1.0-1-generic", Packages: map[string]string{"curl": "8.1.0-1"}, CompletedAt: time.Now().UTC(),
		ActionMarker: &protocol.ActionMarkerEvidence{
			Version: 1, OperationID: testOperation, ActionDigest: permit.PlanDigest, NodeUID: permit.NodeUID,
			MachineID: checkpoint.MachineID, BootID: checkpoint.BootID, Phase: "packages-verified", Sequence: 2, SHA256: strings.Repeat("c", 64),
		},
	}
	if !validRecoveryInspectionReceipt(receipt, permit, policy, checkpoint) {
		t.Fatal("matching apply recovery marker was rejected")
	}
	receipt.ActionMarker.BootID = "44444444-4444-4444-8444-444444444444"
	if validRecoveryInspectionReceipt(receipt, permit, policy, checkpoint) {
		t.Fatal("apply recovery marker from another boot was accepted")
	}
	receipt.ActionMarker.BootID = checkpoint.BootID
	receipt.ActionMarker.Phase = "reboot-verified"
	receipt.ActionMarker.Sequence = 4
	if validRecoveryInspectionReceipt(receipt, permit, policy, checkpoint) {
		t.Fatal("reboot marker was accepted for interrupted package apply")
	}
}

func TestCancellationConsumesCompletedPackageReceiptAndDefersReboot(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	node := f.node()
	node.Status.NodeInfo.BootID = "33333333-3333-4333-8333-333333333333"
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.10"}}
	node.Spec.Unschedulable = true
	node.Annotations = map[string]string{execution.OwnerAnnotation: "maintenance-uid"}
	if err := f.client.Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	node = f.node()
	node.Status.NodeInfo.BootID = "33333333-3333-4333-8333-333333333333"
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.10"}}
	if err := f.client.Status().Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "linux-image-generic", Version: "6.1.0-1"}}, ExpectedKernelVersion: "6.1.0-1-generic", Channel: "stable", Reboot: protocol.RebootIfNeeded,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	permit := protocol.MaintenancePermit{MaintenanceRequest: protocol.MaintenanceRequest{
		OperationID: testOperation, NodeName: node.Name, NodeUID: string(node.UID), PlanDigest: digest,
	}}
	m := f.get()
	m.Status.Phase = "Executing"
	m.Status.Sequence = 4
	m.Status.OperationID = testOperation
	m.Status.TargetNodeName = node.Name
	m.Status.TargetNodeUID = string(node.UID)
	m.Status.OriginalBootID = node.Status.NodeInfo.BootID
	originallyUnschedulable := false
	m.Status.OriginalUnschedulable = &originallyUnschedulable
	m.Status.UpgradeCheckpoint = &protocol.UpgradeCheckpoint{
		PlanDigest: digest, NodeUID: string(node.UID), MachineID: strings.Repeat("d", 32), BootID: node.Status.NodeInfo.BootID,
		Phase: protocol.UpgradeExecuting, Sequence: 4, ExecutionReference: execution.AnsibleJobReference(testOperation, execution.EEPhaseApply), UpdatedAt: metav1.NewTime(f.now),
	}
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	executor := &completedUpgradeExecutor{observation: execution.AnsibleJobObservation{
		Phase: "Succeeded", ReceiptReference: "kordex-ee-receipt", ReceiptDigest: strings.Repeat("e", 64),
		Receipt: &execution.AnsibleReceipt{OperationID: testOperation, PlanDigest: digest, NodeUID: string(node.UID),
			MachineID: strings.Repeat("d", 32), BootIDBefore: node.Status.NodeInfo.BootID, BootIDAfter: node.Status.NodeInfo.BootID,
			OSFamily: "debian", KernelVersion: "6.0.0-old-generic", ExpectedKernelVersion: "6.1.0-1-generic", RebootRequired: true, Packages: map[string]string{"linux-image-generic": "6.1.0-1"}, CompletedAt: f.now},
	}}
	f.r.Upgrader = executor
	m = f.get()
	if _, err := upgradeJobRequest(&m, permit, node, policy, execution.EEPhaseApply); err != nil {
		t.Fatalf("construct interrupted apply request: %v (addresses=%+v)", err, node.Status.Addresses)
	}
	if err := f.r.interruptUpgrade(f.ctx, &m, permit, node, policy, "CancelledByHub"); err != nil {
		t.Fatal(err)
	}
	updated := f.get()
	if executor.observed != 1 || executor.cancelled != 0 {
		t.Fatalf("completed job handling observed=%d cancelled=%d", executor.observed, executor.cancelled)
	}
	if updated.Status.Phase != "RecoveryRequired" || updated.Status.Outcome != "Cancelled" || updated.Status.UpgradeCheckpoint.Phase != protocol.UpgradeRecoveryRequired {
		t.Fatalf("cancelled package receipt requiring reboot did not retain recovery fence: phase=%s outcome=%s checkpoint=%s", updated.Status.Phase, updated.Status.Outcome, updated.Status.UpgradeCheckpoint.Phase)
	}
	if updated.Status.UpgradeCheckpoint.Outcome != "CancelledWithRebootDeferred" || len(updated.Status.UpgradeCheckpoint.Receipts) != 1 {
		t.Fatalf("partial package state was not made explicit: %+v", updated.Status.UpgradeCheckpoint)
	}
	if err := f.r.recover(f.ctx, &updated); err != nil {
		t.Fatal(err)
	}
	updated = f.get()
	if updated.Status.Phase != "RecoveryRequired" || updated.Status.Reason != "UpgradeRebootRequiresOperatorIntervention" {
		t.Fatalf("recovery released a package-upgraded node with reboot deferred: phase=%s reason=%s", updated.Status.Phase, updated.Status.Reason)
	}
	node = f.node()
	if !node.Spec.Unschedulable || node.Annotations[execution.OwnerAnnotation] != "maintenance-uid" {
		t.Fatalf("recovery relinquished the operation-owned cordon: schedulable=%t owner=%s", !node.Spec.Unschedulable, node.Annotations[execution.OwnerAnnotation])
	}
}

func TestManagementDisconnectCancelsExecutingHostJobAndRetainsRecoveryFence(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	node := f.node()
	node.Status.NodeInfo.OSImage = "Ubuntu 24.04 LTS"
	node.Status.NodeInfo.BootID = "33333333-3333-4333-8333-333333333333"
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.10"}}
	node.Spec.Unschedulable = true
	node.Annotations = map[string]string{execution.OwnerAnnotation: "maintenance-uid"}
	if err := f.client.Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	node = f.node()
	node.Status.NodeInfo.OSImage = "Ubuntu 24.04 LTS"
	node.Status.NodeInfo.BootID = "33333333-3333-4333-8333-333333333333"
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.10"}}
	if err := f.client.Status().Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.5.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var localPolicy operations.MaintenancePolicy
	if err = f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &localPolicy); err != nil {
		t.Fatal(err)
	}
	localPolicy.Spec.Upgrade = &policy
	if err = f.client.Update(f.ctx, &localPolicy); err != nil {
		t.Fatal(err)
	}
	permit := protocol.MaintenancePermit{
		OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: "cluster-uid",
		MaintenanceRequest: protocol.MaintenanceRequest{
			OperationID: testOperation, NodeName: node.Name, NodeUID: string(node.UID),
			Policy: protocol.PolicyReference{Name: localPolicy.Name, UID: string(localPolicy.UID), Generation: localPolicy.Generation},
			Action: protocol.UpgradePackages, PlanDigest: digest,
		},
		IssuedAt: f.now, NotBefore: f.now, ExpiresAt: f.now.Add(15 * time.Minute),
	}
	command, err := protocol.SignMaintenance(permit, f.key)
	if err != nil {
		t.Fatal(err)
	}
	m := f.get()
	m.Spec.Authorization, m.Spec.Signature = command.Authorization, command.Signature
	m.Finalizers = []string{Finalizer}
	originallyUnschedulable := false
	status := operations.NodeMaintenanceStatus{
		Phase: "Executing", Sequence: 4, OperationID: testOperation,
		TargetNodeName: node.Name, TargetNodeUID: string(node.UID), OriginalBootID: node.Status.NodeInfo.BootID,
		OriginalUnschedulable: &originallyUnschedulable,
		UpgradeCheckpoint: &protocol.UpgradeCheckpoint{
			PlanDigest: digest, NodeUID: string(node.UID), MachineID: strings.Repeat("d", 32), BootID: node.Status.NodeInfo.BootID,
			Phase: protocol.UpgradeExecuting, Sequence: 4, UpdatedAt: metav1.NewTime(f.now),
			ExecutionReference: execution.AnsibleJobReference(testOperation, execution.EEPhaseApply),
		},
	}
	if err = f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	m.Status = status
	if err = f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}

	executor := &completedUpgradeExecutor{observation: execution.AnsibleJobObservation{Phase: "Running"}}
	f.r.Upgrader = executor
	f.connected = false
	f.now = f.now.Add(protocol.ConnectionTTL + time.Second)
	updated := f.step()

	if executor.observed != 1 || executor.cancelled != 1 {
		t.Fatalf("disconnected execution observed=%d cancelled=%d; phase=%s reason=%s; want one observation and cancellation", executor.observed, executor.cancelled, updated.Status.Phase, updated.Status.Reason)
	}
	if updated.Status.Phase != "RecoveryRequired" || updated.Status.Reason != "ManagementDisconnected" || updated.Status.UpgradeCheckpoint == nil || updated.Status.UpgradeCheckpoint.Phase != protocol.UpgradeRecoveryRequired || updated.Status.UpgradeCheckpoint.Outcome != "Ambiguous" || updated.Status.UpgradeCheckpoint.InterruptedPhase != execution.EEPhaseApply {
		t.Fatalf("disconnect did not persist ambiguous recovery state: phase=%s reason=%s checkpoint=%+v", updated.Status.Phase, updated.Status.Reason, updated.Status.UpgradeCheckpoint)
	}
	currentNode := f.node()
	if !currentNode.Spec.Unschedulable || currentNode.Annotations[execution.OwnerAnnotation] != string(m.UID) {
		t.Fatal("management disconnect released the operation-owned cordon before recovery")
	}
}

func TestAmbiguousUpgradeUsesReadOnlyInspectionBeforeRecovery(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	node := f.node()
	bootID := "33333333-3333-4333-8333-333333333333"
	node.Status.NodeInfo.BootID = bootID
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.10"}}
	node.Spec.Unschedulable = true
	node.Annotations = map[string]string{execution.OwnerAnnotation: "maintenance-uid"}
	if err := f.client.Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	node = f.node()
	node.Status.NodeInfo.BootID = bootID
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.10"}}
	if err := f.client.Status().Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "openssh-server", Version: "1.2.3-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var localPolicy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &localPolicy); err != nil {
		t.Fatal(err)
	}
	localPolicy.Spec.Upgrade = &policy
	if err := f.client.Update(f.ctx, &localPolicy); err != nil {
		t.Fatal(err)
	}
	permit := protocol.MaintenancePermit{
		OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: "cluster-uid",
		MaintenanceRequest: protocol.MaintenanceRequest{
			OperationID: testOperation, NodeName: node.Name, NodeUID: string(node.UID), Action: protocol.UpgradePackages,
			PlanDigest: digest, Policy: protocol.PolicyReference{Name: localPolicy.Name, UID: string(localPolicy.UID), Generation: localPolicy.Generation},
		},
		IssuedAt: f.now.Add(-time.Minute), NotBefore: f.now.Add(-time.Minute), ExpiresAt: f.now,
	}
	command, err := protocol.SignMaintenance(permit, f.key)
	if err != nil {
		t.Fatal(err)
	}
	m := f.get()
	m.Spec.Authorization = command.Authorization
	m.Spec.Signature = command.Signature
	if err := f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	m.Status = operations.NodeMaintenanceStatus{
		Phase: "RecoveryRequired", Reason: "UpgradeInterruptedAmbiguous", Sequence: 1,
		OperationID: testOperation, TargetNodeName: node.Name, TargetNodeUID: string(node.UID),
		OriginalBootID: bootID, RecoverySeconds: 10, Outcome: "Failed",
		UpgradeCheckpoint: &protocol.UpgradeCheckpoint{
			PlanDigest: digest, NodeUID: string(node.UID), MachineID: strings.Repeat("d", 32), BootID: bootID,
			Phase: protocol.UpgradeRecoveryRequired, Sequence: 3, InterruptedPhase: execution.EEPhaseApply,
			ExecutionReference: execution.AnsibleJobReference(testOperation, execution.EEPhaseApply),
			Outcome:            "Ambiguous", UpdatedAt: metav1.NewTime(f.now),
		},
	}
	m.Status.Events = []protocol.PhaseEvent{{Sequence: 1, Phase: "RecoveryRequired", Reason: m.Status.Reason, Time: metav1.NewTime(f.now)}}
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	trustDigest := strings.Repeat("a", 64)
	retryTrustDigest := strings.Repeat("b", 64)
	inspectionName := execution.AnsibleInspectionAttemptReference(testOperation, trustDigest, 1)
	transportRetryName := execution.AnsibleInspectionAttemptReference(testOperation, trustDigest, 2)
	retryInspectionName := execution.AnsibleInspectionAttemptReference(testOperation, retryTrustDigest, 3)
	completedObservation := execution.AnsibleJobObservation{
		Name: retryInspectionName, Phase: "Succeeded", ReceiptReference: retryInspectionName + "-receipt", ReceiptDigest: strings.Repeat("e", 64),
		Receipt: &execution.AnsibleReceipt{OperationID: testOperation, PlanDigest: digest, NodeUID: string(node.UID),
			MachineID: strings.Repeat("d", 32), BootIDBefore: bootID, BootIDAfter: bootID,
			OSFamily: "debian", KernelVersion: "6.1.0-1-generic", Packages: map[string]string{"openssh-server": "1.2.3-1"}, CompletedAt: f.now,
			ActionMarker: &protocol.ActionMarkerEvidence{Version: 1, OperationID: testOperation, ActionDigest: digest, NodeUID: string(node.UID),
				MachineID: strings.Repeat("d", 32), BootID: bootID, Phase: "packages-verified", Sequence: 2, SHA256: strings.Repeat("f", 64)}},
	}
	executor := &inspectionUpgradeExecutor{
		observation:  completedObservation,
		observations: []execution.AnsibleJobObservation{{Phase: "Prepared"}, {Phase: "RecoveryRequired", Reason: "SSHTransportUnavailable"}, {Phase: "RecoveryRequired", Reason: "SSHTransportUnavailable"}, {Phase: "Prepared"}, {Phase: "RecoveryRequired", Reason: "SSHHostKeyVerificationFailed"}, {Phase: "Prepared"}, completedObservation},
		trustDigest:  trustDigest,
	}
	f.r.Upgrader = executor
	held, err := f.r.slot(f.ctx, m.UID, true)
	if err != nil || !held {
		t.Fatalf("ambiguous upgrade failed to hold cluster reservation: held=%v err=%v", held, err)
	}
	m = f.get()
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.UpgradeCheckpoint.RecoveryReference != inspectionName || m.Status.Phase != "RecoveryRequired" {
		t.Fatalf("read-only inspection intent was not checkpointed before execution: %+v", m.Status.UpgradeCheckpoint)
	}
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.Phase != "RecoveryRequired" || executor.started != 1 {
		t.Fatalf("recovery inspection did not remain fenced while running: phase=%s starts=%d", m.Status.Phase, executor.started)
	}
	// Reconstruct the controller with no in-memory progress. The durable
	// checkpoint and operation-owned reservation must remain authoritative.
	restarted := *f.r
	restarted.Client = f.client
	f.r = &restarted
	var reservation coordinationv1.Lease
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &reservation); err != nil {
		t.Fatal(err)
	}
	if reservation.Spec.HolderIdentity == nil || *reservation.Spec.HolderIdentity != string(m.UID) {
		t.Fatal("controller restart lost the ambiguous upgrade reservation")
	}
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.Reason != "UpgradeRecoverySSHTransportUnavailable" || m.Status.UpgradeCheckpoint.RecoveryReference != inspectionName {
		t.Fatalf("failed trusted inspection was not retained: reason=%q checkpoint=%+v", m.Status.Reason, m.Status.UpgradeCheckpoint)
	}
	// Reconciliation alone must not loop another SSH attempt while transport is
	// still unavailable. A fresh administrator token explicitly authorizes one.
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.UpgradeCheckpoint.RecoveryAttempt != 1 || executor.request.RecoveryAttempt != 1 {
		t.Fatalf("transport failure retried without explicit authorization: checkpoint=%+v request=%+v", m.Status.UpgradeCheckpoint, executor.request)
	}
	if m.Annotations == nil {
		m.Annotations = make(map[string]string)
	}
	m.Annotations[recoveryRetryAnnotation] = "11111111-2222-4333-8444-555555555555"
	if err := f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.UpgradeCheckpoint.RecoveryAttempt != 2 || m.Status.UpgradeCheckpoint.RecoveryReference != transportRetryName || m.Status.UpgradeCheckpoint.RecoveryRetryToken != m.Annotations[recoveryRetryAnnotation] {
		t.Fatalf("authorized transport retry was not persisted with a new inspection identity: checkpoint=%+v", m.Status.UpgradeCheckpoint)
	}
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.Reason != "UpgradeRecoverySSHHostKeyVerificationFailed" || executor.request.RecoveryAttempt != 2 {
		t.Fatalf("retry did not remain read-only or preserve the next recovery failure: reason=%q request=%+v", m.Status.Reason, executor.request)
	}
	executor.trustDigest = retryTrustDigest
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.UpgradeCheckpoint.RecoveryAttempt != 3 || m.Status.UpgradeCheckpoint.RecoveryReference != retryInspectionName || m.Status.Phase != "RecoveryRequired" {
		t.Fatalf("changed trust did not persist a distinct fenced retry: %+v", m.Status.UpgradeCheckpoint)
	}
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	m = f.get()
	if m.Status.Phase != "RecoveryRequired" || executor.started != 3 {
		t.Fatalf("retry inspection did not stay fenced while running: phase=%s starts=%d", m.Status.Phase, executor.started)
	}
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	updated := f.get()
	if executor.ensured != 7 || executor.started != 3 || executor.request.Phase != execution.EEPhaseInspect || executor.request.RebootAuthorized || executor.request.RecoveryAttempt != 3 || executor.request.RecoveryTrustDigest != retryTrustDigest {
		t.Fatalf("recovery did not use a read-only inspection request: %+v", executor)
	}
	if updated.Status.Phase != "VerifyingNode" || updated.Status.UpgradeCheckpoint.Phase != protocol.UpgradeVerifyingNode || len(updated.Status.UpgradeCheckpoint.Receipts) != 1 || updated.Status.UpgradeCheckpoint.Receipts[0].Phase != execution.EEPhaseInspect {
		t.Fatalf("verified read-only inspection did not enter node recovery: phase=%s checkpoint=%+v", updated.Status.Phase, updated.Status.UpgradeCheckpoint)
	}
}
