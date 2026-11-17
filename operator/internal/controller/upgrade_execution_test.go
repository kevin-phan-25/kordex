package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
)

type completedUpgradeExecutor struct {
	observation execution.AnsibleJobObservation
	observed    int
	cancelled   int
}

type inspectionUpgradeExecutor struct {
	observation  execution.AnsibleJobObservation
	observations []execution.AnsibleJobObservation
	request      execution.AnsibleJobRequest
	ensured      int
	started      int
}

func (e *inspectionUpgradeExecutor) Ensure(_ context.Context, request execution.AnsibleJobRequest) (string, error) {
	e.request = request
	e.ensured++
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
		SchemaVersion:         1,
		ID:                    "debian-test",
		OSFamily:              "debian",
		ExecutionBackend:      "ansible-ee",
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
	m.Status.UpgradeCheckpoint = &protocol.UpgradeCheckpoint{Phase: protocol.UpgradeRebooting, Outcome: "PackagesVerified", RebootRequested: true, MachineID: strings.Repeat("d", 32), BootID: "33333333-3333-4333-8333-333333333333"}

	request, err := upgradeJobRequest(m, permit, node, policy, execution.EEPhaseReboot)
	if err != nil {
		t.Fatal(err)
	}
	if !request.RebootAuthorized {
		t.Fatal("verified package receipt did not authorize reboot Job")
	}

	m.Status.UpgradeCheckpoint.Outcome = "Ambiguous"
	request, err = upgradeJobRequest(m, permit, node, policy, execution.EEPhaseReboot)
	if err != nil {
		t.Fatal(err)
	}
	if request.RebootAuthorized {
		t.Fatal("ambiguous package outcome authorized reboot Job")
	}
}

func TestRecoveryInspectionReceiptMustMatchExactPackagePins(t *testing.T) {
	policy := protocol.UpgradePolicy{OSFamily: "debian", Reboot: protocol.RebootIfNeeded, Packages: []protocol.PackagePin{{Name: "curl", Version: "8.1.0-1"}}}
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
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee",
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
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee",
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
	inspectionName := execution.AnsibleJobReference(testOperation, execution.EEPhaseInspect)
	completedObservation := execution.AnsibleJobObservation{
		Name: inspectionName, Phase: "Succeeded", ReceiptReference: inspectionName + "-receipt", ReceiptDigest: strings.Repeat("e", 64),
		Receipt: &execution.AnsibleReceipt{OperationID: testOperation, PlanDigest: digest, NodeUID: string(node.UID),
			MachineID: strings.Repeat("d", 32), BootIDBefore: bootID, BootIDAfter: bootID,
			OSFamily: "debian", KernelVersion: "6.1.0-1-generic", Packages: map[string]string{"openssh-server": "1.2.3-1"}, CompletedAt: f.now},
	}
	executor := &inspectionUpgradeExecutor{
		observation:  completedObservation,
		observations: []execution.AnsibleJobObservation{{Phase: "Prepared"}, completedObservation},
	}
	f.r.Upgrader = executor
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
	if err := f.r.reconcileAmbiguousUpgrade(f.ctx, &m, node); err != nil {
		t.Fatal(err)
	}
	updated := f.get()
	if executor.ensured != 2 || executor.started != 1 || executor.request.Phase != execution.EEPhaseInspect || executor.request.RebootAuthorized {
		t.Fatalf("recovery did not use a read-only inspection request: %+v", executor)
	}
	if updated.Status.Phase != "VerifyingNode" || updated.Status.UpgradeCheckpoint.Phase != protocol.UpgradeVerifyingNode || len(updated.Status.UpgradeCheckpoint.Receipts) != 1 || updated.Status.UpgradeCheckpoint.Receipts[0].Phase != execution.EEPhaseInspect {
		t.Fatalf("verified read-only inspection did not enter node recovery: phase=%s checkpoint=%+v", updated.Status.Phase, updated.Status.UpgradeCheckpoint)
	}
}
