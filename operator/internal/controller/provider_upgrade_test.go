package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/provider/gke"
	ctrl "sigs.k8s.io/controller-runtime"
)

type testGKEProvider struct {
	pool        gke.NodePool
	operations  []gke.Operation
	operation   gke.Operation
	listErr     error
	updateCount *int
	getCount    *int
}

func (p testGKEProvider) GetNodePool(context.Context, protocol.GKENodePoolReference) (gke.NodePool, error) {
	return p.pool, nil
}
func (p testGKEProvider) UpdateNodePool(context.Context, protocol.GKENodePoolReference, string, string, string) (gke.Operation, error) {
	if p.updateCount != nil {
		(*p.updateCount)++
	}
	return gke.Operation{}, nil
}
func (p testGKEProvider) GetOperation(context.Context, protocol.GKENodePoolReference, string) (gke.Operation, error) {
	if p.getCount != nil {
		(*p.getCount)++
	}
	return p.operation, nil
}
func (p testGKEProvider) ListOperations(context.Context, protocol.GKENodePoolReference) ([]gke.Operation, error) {
	return p.operations, p.listErr
}

func gkePlanForFixture() (*protocol.ProviderNodeUpgradePlan, string) {
	plan := &protocol.ProviderNodeUpgradePlan{
		SchemaVersion: 2,
		Provider:      "gke",
		Resource:      "projects/test-project/locations/us-central1-a/clusters/test-cluster/nodePools/default-pool",
		TargetVersion: "1.36.5-gke.100",
		MaxSurge:      1,
		Timeout:       time.Hour,
	}
	digest, err := plan.Digest()
	if err != nil {
		panic(err)
	}
	return plan, digest
}

func TestGKEUpgradeRequiresExactSurgePolicy(t *testing.T) {
	plan, _ := gkePlanForFixture()
	pool := gke.NodePool{}
	pool.UpgradeSettings.MaxSurge = 1
	pool.UpgradeSettings.MaxUnavailable = 0
	if !gkeUpgradeSettingsMatch(pool, plan) {
		t.Fatal("exact GKE default SURGE settings should be accepted")
	}
	pool.UpgradeSettings.Strategy = "NODE_POOL_UPDATE_STRATEGY_UNSPECIFIED"
	if !gkeUpgradeSettingsMatch(pool, plan) {
		t.Fatal("GKE's documented unspecified strategy should use its SURGE default")
	}
	pool.UpgradeSettings.Strategy = ""
	pool.UpgradeSettings.MaxUnavailable = 1
	if gkeUpgradeSettingsMatch(pool, plan) {
		t.Fatal("GKE pool allowing unavailable nodes was accepted")
	}
	pool.UpgradeSettings.MaxUnavailable = 0
	pool.UpgradeSettings.MaxSurge = 2
	if gkeUpgradeSettingsMatch(pool, plan) {
		t.Fatal("GKE pool with unapproved surge parallelism was accepted")
	}
	pool.UpgradeSettings.MaxSurge = 1
	pool.UpgradeSettings.Strategy = "BLUE_GREEN"
	if gkeUpgradeSettingsMatch(pool, plan) {
		t.Fatal("GKE blue-green strategy was accepted by the surge adapter")
	}
}

func TestGKEUnsafePoolSettingsBlockBeforeProviderMutation(t *testing.T) {
	f := newFixture(t, protocol.UpgradeNodePool)
	configureGKENode(t, f, "worker1", "worker1-new", "new-1")
	configureGKENode(t, f, "worker2", "worker2-new", "new-2")
	plan, digest := gkePlanForFixture()

	var policy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.ProviderUpgrade = plan
	if err := f.client.Update(f.ctx, &policy); err != nil {
		t.Fatal(err)
	}

	current := f.get()
	permit := protocol.MaintenancePermit{
		OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: "cluster-uid",
		MaintenanceRequest: protocol.MaintenanceRequest{
			OperationID: testOperation, NodeName: "worker1", NodeUID: "worker1-new",
			Action: protocol.UpgradeNodePool, Policy: protocol.PolicyReference{Name: "safe-workers", UID: "policy-uid", Generation: 1},
			PlanDigest: digest,
		},
		IssuedAt: f.now, NotBefore: f.now, ExpiresAt: f.now.Add(15 * time.Minute),
	}
	command, err := protocol.SignMaintenance(permit, f.key)
	if err != nil {
		t.Fatal(err)
	}
	current.Spec.Authorization = command.Authorization
	current.Spec.Signature = command.Signature
	if err = f.client.Update(f.ctx, &current); err != nil {
		t.Fatal(err)
	}

	updates := 0
	pool := gke.NodePool{Version: "1.36.4-gke.100", Status: "RUNNING", Etag: "etag-1"}
	pool.Config.ImageType = "COS_CONTAINERD"
	pool.UpgradeSettings.MaxSurge = 1
	pool.UpgradeSettings.MaxUnavailable = 1
	f.r.GKE = testGKEProvider{pool: pool, updateCount: &updates}

	blocked := f.until("Blocked")
	if blocked.Status.Reason != "GKENodePoolUpgradeSettingsMismatch" {
		t.Fatalf("unsafe pool blocked for unexpected reason %q", blocked.Status.Reason)
	}
	if updates != 0 {
		t.Fatalf("provider update called %d times for unsafe settings", updates)
	}
	if f.node().Spec.Unschedulable {
		t.Fatal("node was cordoned before the pool settings check passed")
	}
}

func configureGKENode(t *testing.T, f *fixture, name, uid, suffix string) {
	t.Helper()
	var node corev1.Node
	if err := f.client.Get(f.ctx, types.NamespacedName{Name: name}, &node); err != nil {
		t.Fatal(err)
	}
	node.UID = types.UID(uid)
	node.Labels["cloud.google.com/gke-nodepool"] = "default-pool"
	node.Labels["topology.kubernetes.io/zone"] = "us-central1-a"
	node.Spec.ProviderID = "gce://test-project/us-central1-a/instance-" + suffix
	if err := f.client.Update(f.ctx, &node); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(f.ctx, types.NamespacedName{Name: name}, &node); err != nil {
		t.Fatal(err)
	}
	node.Status.NodeInfo.MachineID = "machine-" + suffix
	node.Status.NodeInfo.BootID = "boot-" + suffix
	node.Status.NodeInfo.KubeletVersion = "v1.36.5-gke.100"
	if err := f.client.Status().Update(f.ctx, &node); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyGKENodePoolDoesNotReapplyPreDisruptionPDBGate(t *testing.T) {
	f := newFixture(t, protocol.ValidateOnly)
	configureGKENode(t, f, "worker1", "worker1-new", "new-1")
	configureGKENode(t, f, "worker2", "worker2-new", "new-2")
	plan, digest := gkePlanForFixture()
	f.r.GKE = testGKEProvider{pool: gke.NodePool{Version: plan.TargetVersion, Status: "RUNNING"}}
	old := gkeOldIdentityDigests()
	m := f.get()
	m.Status.TargetNodeName = "worker1"
	m.Status.OperationID = testOperation
	m.Status.Phase = "VerifyingNode"
	m.Status.Reason = "GKEOperationCompleted"
	m.Status.Sequence = 1
	m.Status.Events = []protocol.PhaseEvent{{Sequence: 1, Phase: m.Status.Phase, Reason: m.Status.Reason, Time: metav1.NewTime(f.now)}}
	m.Status.ProviderUpgradeCheckpoint = &protocol.ProviderUpgradeCheckpoint{
		PlanDigest: digest, Resource: "projects/test-project/locations/us-central1-a/clusters/test-cluster/nodePools/default-pool",
		TargetVersion: "1.36.5-gke.100", InitialVersion: "1.36.4-gke.200",
		InitialNodeIdentityDigests: old, Phase: "Verifying", Sequence: 1,
		IntentAt: metav1.NewTime(f.now.Add(-5 * time.Minute)), UpdatedAt: metav1.NewTime(f.now),
	}
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	// GKE may have consumed the only currently available disruption. That is
	// relevant before an update, but does not invalidate verified recovery.
	var pdb policyv1.PodDisruptionBudget
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: "apps", Name: "web"}, &pdb); err != nil {
		t.Fatal(err)
	}
	pdb.Status.DisruptionsAllowed = 0
	if err := f.client.Status().Update(f.ctx, &pdb); err != nil {
		t.Fatal(err)
	}
	result := f.get()
	if result.Status.ProviderUpgradeCheckpoint.Validate() != nil {
		t.Fatal("test checkpoint is invalid")
	}
	if err := f.r.verifyProviderNodes(f.ctx, &result, mustGKEReference(t), plan); err != nil {
		t.Fatal(err)
	}
	result = f.get()
	if result.Status.Phase != "VerifyingWorkloads" {
		t.Fatalf("expected node verification to advance despite PDB preflight no longer being applicable, got phase=%q reason=%q", result.Status.Phase, result.Status.Reason)
	}
}

func TestVerifyGKENodePoolWaitsUntilFullPoolSizeReturns(t *testing.T) {
	f := newFixture(t, protocol.ValidateOnly)
	configureGKENode(t, f, "worker1", "worker1-new", "new-1")
	configureGKENode(t, f, "worker2", "worker2-new", "new-2")
	plan, digest := gkePlanForFixture()
	f.r.GKE = testGKEProvider{pool: gke.NodePool{Version: plan.TargetVersion, Status: "RUNNING"}}
	m := f.get()
	m.Status.TargetNodeName = "worker1"
	m.Status.Phase = "VerifyingNode"
	m.Status.Reason = "GKEOperationCompleted"
	m.Status.ProviderUpgradeCheckpoint = &protocol.ProviderUpgradeCheckpoint{
		PlanDigest: digest, Resource: plan.Resource, TargetVersion: plan.TargetVersion, InitialVersion: "1.36.4-gke.200",
		InitialNodeIdentityDigests: gkeOldIdentityDigests(), Phase: "Verifying", Sequence: 1,
		IntentAt: metav1.NewTime(f.now.Add(-5 * time.Minute)), UpdatedAt: metav1.NewTime(f.now),
	}
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	var missing corev1.Node
	if err := f.client.Get(f.ctx, types.NamespacedName{Name: "worker2"}, &missing); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(f.ctx, &missing); err != nil {
		t.Fatal(err)
	}
	result := f.get()
	if err := f.r.verifyProviderNodes(f.ctx, &result, mustGKEReference(t), plan); err != nil {
		t.Fatal(err)
	}
	result = f.get()
	if result.Status.Phase != "VerifyingNode" || result.Status.Reason != "GKEOperationCompleted" {
		t.Fatalf("pool upgrade completed with an incomplete node set: phase=%q reason=%q", result.Status.Phase, result.Status.Reason)
	}
}

func TestVerifyGKENodePoolCancellationCompletesOnlyAfterWorkloadRecovery(t *testing.T) {
	f := newFixture(t, protocol.ValidateOnly)
	configureGKENode(t, f, "worker1", "worker1-new", "new-1")
	configureGKENode(t, f, "worker2", "worker2-new", "new-2")
	plan, digest := gkePlanForFixture()
	m := f.get()
	m.Status.TargetNodeName = "worker1"
	m.Status.Phase = "VerifyingWorkloads"
	m.Status.ProviderUpgradeCheckpoint = &protocol.ProviderUpgradeCheckpoint{
		PlanDigest: digest, Resource: plan.Resource, TargetVersion: plan.TargetVersion, InitialVersion: "1.36.4-gke.200",
		InitialNodeIdentityDigests: gkeOldIdentityDigests(), Phase: "Verifying", Sequence: 2,
		IntentAt: metav1.NewTime(f.now.Add(-5 * time.Minute)), UpdatedAt: metav1.NewTime(f.now), CancelRequested: true,
	}
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	var pdb policyv1.PodDisruptionBudget
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: "apps", Name: "web"}, &pdb); err != nil {
		t.Fatal(err)
	}
	pdb.Status.DisruptionsAllowed = 0
	if err := f.client.Status().Update(f.ctx, &pdb); err != nil {
		t.Fatal(err)
	}
	result := f.get()
	if err := f.r.verifyProviderWorkloads(f.ctx, &result, mustGKEReference(t), plan); err != nil {
		t.Fatal(err)
	}
	result = f.get()
	if result.Status.Phase != "Cancelled" || result.Status.Outcome != "Cancelled" {
		t.Fatalf("cancel should be acknowledged only after verified recovery, got phase=%q outcome=%q reason=%q", result.Status.Phase, result.Status.Outcome, result.Status.Reason)
	}
}

func TestSignedCancellationContinuesObservingSubmittedGKEOperation(t *testing.T) {
	f := newFixture(t, protocol.UpgradeNodePool)
	configureGKENode(t, f, "worker1", "worker1-new", "new-1")
	configureGKENode(t, f, "worker2", "worker2-new", "new-2")
	plan, digest := gkePlanForFixture()
	var policy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.ProviderUpgrade = plan
	if err := f.client.Update(f.ctx, &policy); err != nil {
		t.Fatal(err)
	}
	current := f.get()
	permit := protocol.MaintenancePermit{
		OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: "cluster-uid",
		MaintenanceRequest: protocol.MaintenanceRequest{
			OperationID: testOperation, NodeName: "worker1", NodeUID: "worker1-new",
			Action: protocol.UpgradeNodePool, Policy: protocol.PolicyReference{Name: "safe-workers", UID: "policy-uid", Generation: 1},
			PlanDigest: digest,
		},
		IssuedAt: f.now, NotBefore: f.now, ExpiresAt: f.now.Add(15 * time.Minute),
	}
	command, err := protocol.SignMaintenance(permit, f.key)
	if err != nil {
		t.Fatal(err)
	}
	current.Spec.Authorization = command.Authorization
	current.Spec.Signature = command.Signature
	current.Finalizers = []string{Finalizer}
	control, err := protocol.SignCancellation(testOperation, testCluster, current.Spec.Command().Digest(), f.now, f.key)
	if err != nil {
		t.Fatal(err)
	}
	controlData, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	current.Annotations = map[string]string{protocol.CancellationAnnotation: string(controlData)}
	if err = f.client.Update(f.ctx, &current); err != nil {
		t.Fatal(err)
	}
	if err = f.client.Get(f.ctx, f.name, &current); err != nil {
		t.Fatal(err)
	}
	current.Status.OperationID = testOperation
	current.Status.TargetNodeName = permit.NodeName
	current.Status.TargetNodeUID = permit.NodeUID
	current.Status.Phase = "Executing"
	current.Status.ProviderUpgradeCheckpoint = &protocol.ProviderUpgradeCheckpoint{
		PlanDigest: digest, Resource: plan.Resource, TargetVersion: plan.TargetVersion,
		InitialVersion: "1.36.4-gke.100", InitialNodeIdentityDigests: gkeOldIdentityDigests(),
		OperationName: "projects/test-project/locations/us-central1-a/operations/operation-1", Phase: "Updating", Sequence: 4,
		IntentAt: metav1.NewTime(f.now.Add(-time.Minute)), UpdatedAt: metav1.NewTime(f.now), CancelRequested: true,
	}
	if err = f.client.Status().Update(f.ctx, &current); err != nil {
		t.Fatal(err)
	}
	queued := f.get()
	if queued.Status.ProviderUpgradeCheckpoint == nil {
		t.Fatalf("test did not persist provider checkpoint: %+v", queued.Status)
	}

	reads := 0
	target := "https://container.googleapis.com/v1/" + plan.Resource
	f.r.GKE = testGKEProvider{
		operation: gke.Operation{Name: "projects/test-project/locations/us-central1-a/operations/operation-1", OperationType: "UPGRADE_NODES", Status: "RUNNING", TargetLink: target},
		getCount:  &reads,
	}
	_, err = f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name})
	if err != nil {
		t.Fatal(err)
	}
	result := f.get()
	if reads != 1 {
		t.Fatalf("provider operation was not observed after durable cancellation: GetOperation calls=%d phase=%q reason=%q checkpoint=%+v", reads, result.Status.Phase, result.Status.Reason, result.Status.ProviderUpgradeCheckpoint)
	}
	if result.Status.Phase != "Executing" || !result.Status.ProviderUpgradeCheckpoint.CancelRequested {
		t.Fatalf("uncertain provider operation must remain reserved and observable, got phase=%q checkpoint=%+v", result.Status.Phase, result.Status.ProviderUpgradeCheckpoint)
	}
}

func gkeOldIdentityDigests() []string {
	first := sha256.Sum256([]byte("old-node-identity-1"))
	second := sha256.Sum256([]byte("old-node-identity-2"))
	return []string{hex.EncodeToString(first[:]), hex.EncodeToString(second[:])}
}

func TestFindSubmittedGKEOperationUsesExactTargetAndBoundedIntentWindow(t *testing.T) {
	plan, _ := gkePlanForFixture()
	ref, ok := plan.GKENodePool()
	if !ok {
		t.Fatal("fixture provider plan is invalid")
	}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	intent := now.Add(-10 * time.Minute)
	target := "https://container.googleapis.com/v1/" + plan.Resource
	base := gke.Operation{Name: "operation-1", OperationType: "UPGRADE_NODES", Status: "RUNNING", TargetLink: target, StartTime: intent.Add(10 * time.Second).Format(time.RFC3339Nano)}
	checkpoint := &protocol.ProviderUpgradeCheckpoint{IntentAt: metav1.NewTime(intent)}
	reconciler := &Reconciler{GKE: testGKEProvider{operations: []gke.Operation{base}}, Now: func() time.Time { return now }}
	operation, found, err := reconciler.findSubmittedGKEOperation(context.Background(), ref, checkpoint)
	if err != nil || !found || operation.Name != base.Name {
		t.Fatalf("unique in-window operation was not adopted: operation=%+v found=%t err=%v", operation, found, err)
	}

	cases := []struct {
		name      string
		operation gke.Operation
	}{
		{name: "before intent window", operation: func() gke.Operation {
			value := base
			value.StartTime = intent.Add(-30 * time.Second).Format(time.RFC3339Nano)
			return value
		}()},
		{name: "after intent window", operation: func() gke.Operation {
			value := base
			value.StartTime = intent.Add(gkeSubmissionWindow + time.Second).Format(time.RFC3339Nano)
			return value
		}()},
		{name: "similar pool name", operation: func() gke.Operation { value := base; value.TargetLink += "-other"; return value }()},
		{name: "wrong operation type", operation: func() gke.Operation { value := base; value.OperationType = "UPGRADE_MASTER"; return value }()},
		{name: "malformed timestamp", operation: func() gke.Operation { value := base; value.StartTime = "not-a-time"; return value }()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reconciler.GKE = testGKEProvider{operations: []gke.Operation{test.operation}}
			_, found, err := reconciler.findSubmittedGKEOperation(context.Background(), ref, checkpoint)
			if err != nil || found {
				t.Fatalf("unsafe GKE operation candidate was accepted: found=%t err=%v", found, err)
			}
		})
	}

	second := base
	second.Name = "operation-2"
	second.StartTime = intent.Add(20 * time.Second).Format(time.RFC3339Nano)
	reconciler.GKE = testGKEProvider{operations: []gke.Operation{base, second}}
	if _, found, err = reconciler.findSubmittedGKEOperation(context.Background(), ref, checkpoint); found || !errors.Is(err, errMultipleProviderOperations) {
		t.Fatalf("multiple in-window candidates were not rejected as ambiguous: found=%t err=%v", found, err)
	}
}

func mustGKEReference(t *testing.T) protocol.GKENodePoolReference {
	t.Helper()
	ref, ok := mustGKEPlan(t).GKENodePool()
	if !ok {
		t.Fatal("test plan is not a valid GKE node-pool plan")
	}
	return ref
}

func mustGKEPlan(t *testing.T) *protocol.ProviderNodeUpgradePlan {
	t.Helper()
	plan, _ := gkePlanForFixture()
	return plan
}
