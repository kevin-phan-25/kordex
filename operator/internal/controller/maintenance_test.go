package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
	"kordex.local/operator/internal/reboot"
	"kordex.local/operator/internal/safety"
)

func TestReconcileErrorClassIsStableAndBounded(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "conflict", err: apierrors.NewConflict(schema.GroupResource{Resource: "nodemaintenances"}, "private-name", errors.New("details")), want: "conflict"},
		{name: "not found", err: apierrors.NewNotFound(schema.GroupResource{Resource: "nodemaintenances"}, "private-name"), want: "not_found"},
		{name: "deadline", err: context.DeadlineExceeded, want: "timeout"},
		{name: "cancelled", err: context.Canceled, want: "canceled"},
		{name: "other detail", err: errors.New("sql text and private node name"), want: "other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := reconcileErrorClass(test.err); got != test.want {
				t.Fatalf("reconcileErrorClass(%v) = %q; want %q", test.err, got, test.want)
			}
		})
	}
}

const testCluster = "11111111-1111-4111-8111-111111111111"
const testOperation = "22222222-2222-4222-8222-222222222222"
const testOrg = "33333333-3333-4333-8333-333333333333"
const testNamespace = "kordex-system"

type testHealth struct{ err error }

func (h *testHealth) Ready(context.Context) error { return h.err }

type listFailReader struct {
	client.Reader
	err error
}

func (r listFailReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return r.err
}

type fixture struct {
	t                    *testing.T
	ctx                  context.Context
	now                  time.Time
	client               client.Client
	r                    *Reconciler
	key                  ed25519.PrivateKey
	name                 types.NamespacedName
	evictions            int
	evictionError        error
	loseEvictionResponse bool
	connected            bool
	health               *testHealth
}
type testEvictor struct{ f *fixture }

func (e testEvictor) Evict(ctx context.Context, pod *corev1.Pod, _ int64) error {
	e.f.evictions++
	if e.f.evictionError != nil {
		return e.f.evictionError
	}
	if err := e.f.client.Delete(ctx, pod); err != nil {
		return err
	}
	replacement := pod.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = types.UID(fmt.Sprintf("replacement-%d", e.f.evictions))
	replacement.Name = string(replacement.UID)
	replacement.Spec.NodeName = "worker2"
	if err := e.f.client.Create(ctx, replacement); err != nil {
		return err
	}
	if e.f.loseEvictionResponse {
		e.f.loseEvictionResponse = false
		return fmt.Errorf("injected lost eviction response")
	}
	return nil
}
func worker(name string, now time.Time) *corev1.Node {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid"), Labels: map[string]string{safety.StatelessLabel: "stateless"}}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: "boot-" + name}}}
	for _, kind := range []corev1.NodeConditionType{corev1.NodeReady, corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure} {
		status := corev1.ConditionFalse
		if kind == corev1.NodeReady {
			status = corev1.ConditionTrue
		}
		node.Status.Conditions = append(node.Status.Conditions, corev1.NodeCondition{Type: kind, Status: status, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))})
	}
	return node
}
func newFixture(t *testing.T, action string) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background(), now: time.Now().UTC().Truncate(time.Second), connected: true, health: &testHealth{}}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := operations.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	yes := true
	replicas := int32(2)
	minAvailable := intstr.FromInt32(1)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web", UID: "deployment-uid", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 2, ReadyReplicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-rs", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: deployment.UID, Controller: &yes}}}}
	actions := []string{protocol.ValidateOnly, protocol.DrainAndVerify}
	if action == protocol.UpgradePackages || action == protocol.UpgradeNodePool {
		actions = append(actions, action)
	}
	var objects []client.Object
	objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, worker("worker1", f.now), worker("worker2", f.now), deployment, rs, &operations.MaintenancePolicy{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "safe-workers", UID: "policy-uid", Generation: 1}, Spec: operations.MaintenancePolicySpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{safety.StatelessLabel: "stateless"}}, AllowedActions: actions, RecoverySeconds: 10, GracePeriodSeconds: 30}}, &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web", Generation: 1}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailable, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}, Status: policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 1, DisruptionsAllowed: 1}})
	for i, name := range []string{"worker1", "worker2"} {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: fmt.Sprintf("web-%d", i), UID: types.UID(fmt.Sprintf("pod-%d", i)), Labels: map[string]string{"app": "web"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: corev1.PodSpec{NodeName: name, Containers: []corev1.Container{{Name: "web", Image: "example.invalid/web"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
		objects = append(objects, pod, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-node-lease", Name: name}, Spec: coordinationv1.LeaseSpec{RenewTime: &metav1.MicroTime{Time: f.now}}})
	}
	holder := ""
	cluster := testCluster
	objects = append(objects, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder}}, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: protocol.ConnectionLease}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &cluster, RenewTime: &metav1.MicroTime{Time: f.now}}})
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	permit := protocol.MaintenancePermit{OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: "cluster-uid", MaintenanceRequest: protocol.MaintenanceRequest{OperationID: testOperation, NodeName: "worker1", NodeUID: "worker1-uid", Action: action, Policy: protocol.PolicyReference{Name: "safe-workers", UID: "policy-uid", Generation: 1}}, IssuedAt: f.now, NotBefore: f.now, ExpiresAt: f.now.Add(15 * time.Minute)}
	command, err := protocol.SignMaintenance(permit, key)
	if err != nil {
		t.Fatal(err)
	}
	m := &operations.NodeMaintenance{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "op-" + testOperation, UID: "maintenance-uid", Generation: 1}, Spec: operations.NodeMaintenanceSpec{Authorization: command.Authorization, Signature: command.Signature}}
	objects = append(objects, m)
	f.client = fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&operations.NodeMaintenance{}, &operations.MaintenancePolicy{}, &corev1.Node{}, &corev1.Pod{}, &appsv1.Deployment{}, &policyv1.PodDisruptionBudget{}).WithObjects(objects...).Build()
	f.name = client.ObjectKeyFromObject(m)
	checker := &safety.Checker{Reader: f.client, Storage: safety.StatelessStorage{Reader: f.client}, Quorum: safety.WorkerOnlyQuorum{}, API: f.health, Now: func() time.Time { return f.now }}
	f.r = &Reconciler{Client: f.client, Reader: f.client, Checker: checker, Evictor: testEvictor{f}, Keys: map[string]ed25519.PublicKey{protocol.KeyID(public): public}, ClusterID: testCluster, Now: func() time.Time { return f.now }}
	return f
}

func TestRecoveryRequiredPhaseJournalStopsAtAuditCapacity(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	m := f.get()
	unschedulable := false
	m.Status.OperationID = testOperation
	m.Status.Phase = "RecoveryRequired"
	m.Status.Reason = "PreviousRecoveryBlock"
	m.Status.OriginalUnschedulable = &unschedulable
	m.Status.Sequence = 240
	m.Status.Events = make([]protocol.PhaseEvent, m.Status.Sequence)
	for i := range m.Status.Events {
		m.Status.Events[i] = protocol.PhaseEvent{
			Sequence: int64(i + 1), Phase: "RecoveryRequired", Reason: fmt.Sprintf("RecoveryBlock%d", i),
			Time: metav1.NewTime(f.now.Add(time.Duration(i) * time.Second)),
		}
	}
	m.Status.Reason = m.Status.Events[len(m.Status.Events)-1].Reason
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 40; i++ {
		if err := f.r.transition(f.ctx, &m, "RecoveryRequired", fmt.Sprintf("ChangingRecoveryBlock%d", i)); err != nil {
			t.Fatalf("recovery transition %d failed: %v", i, err)
		}
	}
	if got := len(m.Status.Events); got > 256 {
		t.Fatalf("phase event journal exceeded report limit: %d", got)
	}
	if m.Status.Phase != "RecoveryRequired" || m.Status.Reason != "AuditCapacityReached" {
		t.Fatalf("capacity blocker was not retained: phase=%s reason=%s", m.Status.Phase, m.Status.Reason)
	}
	report := protocol.OperationReport{OperationID: m.Status.OperationID, Sequence: m.Status.Sequence, Phase: m.Status.Phase, Reason: m.Status.Reason, Events: m.Status.Events}
	if !report.Validate() {
		t.Fatal("bounded recovery report does not satisfy the operation report contract")
	}

	// A forced checkpoint write at capacity must persist structured status
	// without growing the immutable phase history.
	checkpoint := &protocol.UpgradeCheckpoint{PlanDigest: strings.Repeat("a", 64), NodeUID: "worker1-uid", Phase: protocol.UpgradeRecoveryRequired, Sequence: 1, UpdatedAt: metav1.NewTime(f.now)}
	m.Status.UpgradeCheckpoint = checkpoint
	if err := f.r.checkpoint(f.ctx, &m, "ChangingRecoveryCheckpoint", ""); err != nil {
		t.Fatalf("forced checkpoint write failed at audit capacity: %v", err)
	}
	var persisted operations.NodeMaintenance
	if err := f.client.Get(f.ctx, f.name, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Status.UpgradeCheckpoint == nil || persisted.Status.UpgradeCheckpoint.Sequence != 1 {
		t.Fatal("forced checkpoint write was not persisted")
	}
	if got := len(persisted.Status.Events); got > 256 {
		t.Fatalf("forced checkpoint write grew phase journal: %d", got)
	}
	persistedReport := protocol.OperationReport{OperationID: persisted.Status.OperationID, Sequence: persisted.Status.Sequence, Phase: persisted.Status.Phase, Reason: persisted.Status.Reason, Events: persisted.Status.Events, UpgradeCheckpoint: persisted.Status.UpgradeCheckpoint}
	if !persistedReport.Validate() {
		t.Fatal("checkpoint persistence left the recovery report invalid")
	}
}

func TestRecoveryWithoutOriginalCordonCheckpointStaysNonterminal(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	m := f.get()
	m.Status.OperationID = testOperation
	m.Status.Phase = "RecoveryRequired"
	m.Status.Reason = "PriorRecoveryBlock"
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	if held, err := f.r.slot(f.ctx, m.UID, true); err != nil || !held {
		t.Fatalf("fixture could not hold operation reservation: held=%t err=%v", held, err)
	}

	if err := f.r.recover(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	updated := f.get()
	if updated.Status.Phase != "RecoveryRequired" || updated.Status.Reason != "NoRecoverableCheckpoint" {
		t.Fatalf("missing recovery checkpoint became terminal: phase=%s reason=%s", updated.Status.Phase, updated.Status.Reason)
	}
	var lease coordinationv1.Lease
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(m.UID) {
		t.Fatal("missing recovery checkpoint released the operation reservation")
	}
}

func TestOperatorPhasePersistenceRejectsSkippedSafetyPhases(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Pending")
	m := f.get()
	if err := f.r.transition(f.ctx, &m, "Succeeded", "InjectedPhaseSkip"); err == nil {
		t.Fatal("operator persisted terminal success without validation and recovery phases")
	}
	updated := f.get()
	if updated.Status.Phase != "Pending" || updated.Status.Sequence != 1 || len(updated.Status.Events) != 1 {
		t.Fatalf("rejected phase skip changed durable status: phase=%s sequence=%d events=%d", updated.Status.Phase, updated.Status.Sequence, len(updated.Status.Events))
	}
}

func TestOperatorPhaseJournalClampsBackwardClockStep(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Pending")
	m := f.get()
	if err := f.r.transition(f.ctx, &m, "Validating", "AuthorizationValidated"); err != nil {
		t.Fatal(err)
	}
	firstEventTime := m.Status.Events[len(m.Status.Events)-1].Time

	f.now = firstEventTime.Add(-time.Minute)
	if err := f.r.transition(f.ctx, &m, "SafetyChecking", "SafetyChecksStarted"); err != nil {
		t.Fatal(err)
	}
	secondEventTime := m.Status.Events[len(m.Status.Events)-1].Time
	if secondEventTime.Before(&firstEventTime) {
		t.Fatalf("phase event time moved backwards: first=%s second=%s", firstEventTime, secondEventTime)
	}
	report := protocol.OperationReport{OperationID: m.Status.OperationID, Sequence: m.Status.Sequence, Phase: m.Status.Phase, Reason: m.Status.Reason, Events: m.Status.Events}
	if !report.Validate() {
		t.Fatal("operator emitted a report rejected by the shared chronology contract")
	}
}

func (f *fixture) refresh() {
	f.now = f.now.Add(2 * time.Second)
	for _, key := range []types.NamespacedName{{Namespace: "kube-node-lease", Name: "worker1"}, {Namespace: "kube-node-lease", Name: "worker2"}, {Namespace: testNamespace, Name: protocol.ConnectionLease}} {
		if !f.connected && key.Name == protocol.ConnectionLease {
			continue
		}
		var lease coordinationv1.Lease
		if err := f.client.Get(f.ctx, key, &lease); err != nil {
			f.t.Fatal(err)
		}
		lease.Spec.RenewTime = &metav1.MicroTime{Time: f.now}
		if err := f.client.Update(f.ctx, &lease); err != nil {
			f.t.Fatal(err)
		}
	}
}
func (f *fixture) step() operations.NodeMaintenance {
	f.t.Helper()
	f.refresh()
	current := f.get()
	if protocol.TerminalPhase(current.Status.Phase) {
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[protocol.AckAnnotation] = fmt.Sprint(current.Status.Sequence)
		if err := f.client.Update(f.ctx, &current); err != nil {
			f.t.Fatal(err)
		}
	}
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err != nil {
		f.t.Fatal(err)
	}
	var m operations.NodeMaintenance
	if err := f.client.Get(f.ctx, f.name, &m); err != nil {
		f.t.Fatal(err)
	}
	return m
}
func (f *fixture) until(phase string) operations.NodeMaintenance {
	f.t.Helper()
	for i := 0; i < 80; i++ {
		m := f.step()
		if m.Status.Phase == phase {
			return m
		}
	}
	m := f.get()
	f.t.Fatalf("never reached %s: phase=%s reason=%s", phase, m.Status.Phase, m.Status.Reason)
	return m
}
func (f *fixture) get() operations.NodeMaintenance {
	var m operations.NodeMaintenance
	if err := f.client.Get(f.ctx, f.name, &m); err != nil {
		f.t.Fatal(err)
	}
	return m
}
func (f *fixture) node() *corev1.Node {
	var n corev1.Node
	if err := f.client.Get(f.ctx, types.NamespacedName{Name: "worker1"}, &n); err != nil {
		f.t.Fatal(err)
	}
	return &n
}
func TestValidationAndReplayReceipt(t *testing.T) {
	f := newFixture(t, protocol.ValidateOnly)
	m := f.until("Succeeded")
	f.step()
	if f.evictions != 0 || f.node().Spec.Unschedulable {
		t.Fatal("validation performed a disruption")
	}
	if err := f.client.Delete(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	m.ResourceVersion = ""
	m.UID = "new-maintenance-uid"
	m.Status = operations.NodeMaintenanceStatus{}
	m.Finalizers = nil
	if err := f.client.Create(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	blocked := f.until("Failed")
	if blocked.Status.Reason != "DuplicateOperation" {
		t.Fatalf("replay not rejected: %+v", blocked.Status)
	}
}

func TestPolicyActionAllowlistBlocksBeforeCordon(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	var policy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.AllowedActions = []string{protocol.ValidateOnly}
	if err := f.client.Update(f.ctx, &policy); err != nil {
		t.Fatal(err)
	}
	failed := f.until("Failed")
	if failed.Status.Reason != "PolicyActionNotAllowed" {
		t.Fatalf("unexpected block reason: %s", failed.Status.Reason)
	}
	if f.evictions != 0 || f.node().Spec.Unschedulable {
		t.Fatalf("disallowed action mutated node: evictions=%d cordoned=%t", f.evictions, f.node().Spec.Unschedulable)
	}
}

func TestPolicySelectorDecisionBlocksBeforeCordon(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	var policy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.NodeSelector = metav1.LabelSelector{MatchLabels: map[string]string{safety.StatelessLabel: "not-stateless"}}
	if err := f.client.Update(f.ctx, &policy); err != nil {
		t.Fatal(err)
	}
	blocked := f.until("Blocked")
	if blocked.Status.Reason != "PolicySelectorMismatch" {
		t.Fatalf("unexpected selector block reason: %s", blocked.Status.Reason)
	}
	if f.evictions != 0 || f.node().Spec.Unschedulable {
		t.Fatalf("selector mismatch mutated node: evictions=%d cordoned=%t", f.evictions, f.node().Spec.Unschedulable)
	}
}

func TestProtectedNodePolicyBlocksBeforeCordon(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	var policy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.ProtectedNodeSelector = &metav1.LabelSelector{MatchLabels: map[string]string{safety.StatelessLabel: "stateless"}}
	if err := f.client.Update(f.ctx, &policy); err != nil {
		t.Fatal(err)
	}
	blocked := f.until("Blocked")
	if blocked.Status.Reason != "ProtectedNode" {
		t.Fatalf("unexpected protected-node block reason: %s", blocked.Status.Reason)
	}
	if f.evictions != 0 || f.node().Spec.Unschedulable {
		t.Fatalf("protected node was mutated: evictions=%d cordoned=%t", f.evictions, f.node().Spec.Unschedulable)
	}
}

func TestHostUpgradeBlocksWhenLocalNodeOSDoesNotMatchPinnedPlan(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "ubuntu-workers", OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
	localPolicy.Spec.AllowedActions = []string{protocol.ValidateOnly, protocol.DrainAndVerify, protocol.UpgradePackages}
	if err = f.client.Update(f.ctx, &localPolicy); err != nil {
		t.Fatal(err)
	}
	permit := protocol.MaintenancePermit{
		OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: "cluster-uid",
		MaintenanceRequest: protocol.MaintenanceRequest{
			OperationID: testOperation, NodeName: "worker1", NodeUID: "worker1-uid", Policy: protocol.PolicyReference{Name: localPolicy.Name, UID: string(localPolicy.UID), Generation: localPolicy.Generation},
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
	if err = f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	node := f.node()
	node.Status.NodeInfo.OSImage = "Container-Optimized OS from Google"
	if err = f.client.Status().Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}

	failed := f.until("Failed")
	if failed.Status.Reason != "UpgradePlanOSIdentityMismatch" || f.evictions != 0 || f.node().Spec.Unschedulable {
		t.Fatalf("local OS mismatch did not fail before disruption: reason=%s evictions=%d cordoned=%t", failed.Status.Reason, f.evictions, f.node().Spec.Unschedulable)
	}
}

func TestDrainRecoversAfterCordonAcknowledgementLoss(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Cordoning")
	failed := false
	f.r.Client = interceptor.NewClient(f.client.(client.WithWatch), interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, name string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
		if m, ok := obj.(*operations.NodeMaintenance); ok && m.Status.Phase == "Draining" && !failed {
			failed = true
			return fmt.Errorf("injected lost cordon acknowledgement")
		}
		return c.SubResource(name).Update(ctx, obj, opts...)
	}})
	f.refresh()
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err == nil {
		t.Fatal("expected injected acknowledgement failure")
	}
	if !f.node().Spec.Unschedulable {
		t.Fatal("cordon side effect was not applied")
	}
	// A fresh reconciler has no in-memory progress and observes the durable ownership marker.
	restarted := *f.r
	restarted.Client = f.client
	f.r = &restarted
	completed := f.until("Succeeded")
	f.step()
	if f.evictions != 1 || f.node().Spec.Unschedulable || f.node().Annotations[execution.OwnerAnnotation] != "" {
		t.Fatal("node did not recover safely")
	}
	if completed.Status.Sequence != int64(len(completed.Status.Events)) || len(completed.Status.Evictions) != 1 {
		t.Fatal("durable phase history incomplete")
	}
	var slot coordinationv1.Lease
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &slot); err != nil {
		t.Fatal(err)
	}
	if *slot.Spec.HolderIdentity != "" {
		t.Fatal("slot not released after verified recovery")
	}
}
func TestBlockedSafetyNeverCordons(t *testing.T) {
	for _, scenario := range []string{"pdb", "storage", "control-plane", "unhealthy", "api", "unmanaged"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, protocol.DrainAndVerify)
			switch scenario {
			case "pdb":
				var p policyv1.PodDisruptionBudget
				_ = f.client.Get(f.ctx, types.NamespacedName{Namespace: "apps", Name: "web"}, &p)
				p.Status.DisruptionsAllowed = 0
				if err := f.client.Status().Update(f.ctx, &p); err != nil {
					t.Fatal(err)
				}
			case "storage":
				var p corev1.Pod
				_ = f.client.Get(f.ctx, types.NamespacedName{Namespace: "apps", Name: "web-0"}, &p)
				p.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
				if err := f.client.Update(f.ctx, &p); err != nil {
					t.Fatal(err)
				}
			case "control-plane":
				n := f.node()
				n.Labels["node-role.kubernetes.io/control-plane"] = ""
				if err := f.client.Update(f.ctx, n); err != nil {
					t.Fatal(err)
				}
			case "unhealthy":
				n := f.node()
				n.Status.Conditions[0].Status = corev1.ConditionFalse
				if err := f.client.Status().Update(f.ctx, n); err != nil {
					t.Fatal(err)
				}
			case "api":
				f.health.err = fmt.Errorf("API health unknown")
			case "unmanaged":
				var p corev1.Pod
				_ = f.client.Get(f.ctx, types.NamespacedName{Namespace: "apps", Name: "web-0"}, &p)
				p.OwnerReferences = nil
				if err := f.client.Update(f.ctx, &p); err != nil {
					t.Fatal(err)
				}
			}
			m := f.until("Blocked")
			for i := 0; i < 3; i++ {
				f.step()
			}
			if f.node().Spec.Unschedulable || f.evictions != 0 {
				t.Fatalf("unsafe work while blocked: %s", m.Status.Reason)
			}
		})
	}
}
func TestDisconnectExpiryRecoversWithoutFurtherEviction(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Draining")
	f.connected = false
	f.now = f.now.Add(time.Minute)
	m := f.until("Blocked")
	if m.Status.Reason != "ManagementDisconnected" {
		t.Fatal(m.Status.Reason)
	}
	if f.evictions != 0 {
		t.Fatal("evicted after disconnect")
	}
	f.now = f.now.Add(16 * time.Minute)
	f.until("RecoveryRequired")
	m = f.until("Failed")
	f.step()
	if f.evictions != 0 || f.node().Spec.Unschedulable || m.Status.Reason != "AuthorizationExpired" {
		t.Fatal("offline recovery unsafe or lost failure reason")
	}
}
func TestNodeReplacementRetainsReservation(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Draining")
	old := f.node()
	if err := f.client.Delete(f.ctx, old); err != nil {
		t.Fatal(err)
	}
	replacement := worker("worker1", f.now)
	replacement.UID = "replacement-node-uid"
	if err := f.client.Create(f.ctx, replacement); err != nil {
		t.Fatal(err)
	}
	f.until("RecoveryRequired")
	restarted := *f.r
	restarted.Client = f.client
	f.r = &restarted
	for i := 0; i < 10; i++ {
		f.step()
	}
	if f.node().Spec.Unschedulable || f.evictions != 0 {
		t.Fatal("replacement node was modified")
	}
	var slot coordinationv1.Lease
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &slot); err != nil {
		t.Fatal(err)
	}
	if *slot.Spec.HolderIdentity != "maintenance-uid" {
		t.Fatal("reservation released for missing original node")
	}
}
func TestEvictionPDBRaceStopsWithoutDeleteFallback(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.evictionError = apierrors.NewTooManyRequests("PDB changed", 1)
	f.until("Draining")
	for i := 0; i < 10; i++ {
		m := f.step()
		if m.Status.Reason == "EvictionPDBBlocked" {
			if !f.node().Spec.Unschedulable {
				t.Fatal("lost cordon")
			}
			var pod corev1.Pod
			if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: "apps", Name: "web-0"}, &pod); err != nil {
				t.Fatal("PDB bypass deleted the pod")
			}
			return
		}
	}
	t.Fatal("eviction race not blocked")
}

func TestPreexistingCordonNeverAdopted(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	node := f.node()
	node.Spec.Unschedulable = true
	if err := f.client.Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	m := f.until("Blocked")
	if m.Status.Reason != "NodeAlreadyCordoned" || m.Status.OriginalUnschedulable != nil {
		t.Fatal("adopted an external cordon")
	}
	if err := f.client.Delete(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	f.refresh()
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err != nil {
		t.Fatal(err)
	}
	f.refresh()
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err != nil {
		t.Fatal(err)
	}
	if !f.node().Spec.Unschedulable || f.evictions != 0 {
		t.Fatal("changed an original cordon during cancellation")
	}
}
func TestPolicyChangeAfterCordonRequiresRecovery(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Draining")
	var p operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &p); err != nil {
		t.Fatal(err)
	}
	p.Generation++
	p.Spec.Suspended = true
	if err := f.client.Update(f.ctx, &p); err != nil {
		t.Fatal(err)
	}
	f.until("RecoveryRequired")
	m := f.until("Failed")
	if m.Status.Reason != "PolicyGenerationChanged" || f.evictions != 0 || f.node().Spec.Unschedulable {
		t.Fatal("continued disruption after policy changed")
	}
}
func TestRecoveryRetainsCordonWhenClusterReservationIsLost(t *testing.T) {
	for _, scenario := range []string{"missing", "owned-by-another-operation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, protocol.DrainAndVerify)
			f.until("Draining")
			var policy operations.MaintenancePolicy
			if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
				t.Fatal(err)
			}
			policy.Generation++
			policy.Spec.Suspended = true
			if err := f.client.Update(f.ctx, &policy); err != nil {
				t.Fatal(err)
			}
			f.until("RecoveryRequired")
			// Model reservation loss after recovery has reached its uncordon phase.
			operation := f.get()
			operation.Status.Sequence++
			operation.Status.Phase = "Uncordoning"
			operation.Status.Reason = "TestRecoveryReachedUncordoning"
			operation.Status.Events = append(operation.Status.Events, protocol.PhaseEvent{
				Sequence: operation.Status.Sequence, Phase: operation.Status.Phase, Reason: operation.Status.Reason, Time: metav1.NewTime(f.now),
			})
			if err := f.client.Status().Update(f.ctx, &operation); err != nil {
				t.Fatal(err)
			}

			key := types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}
			var lease coordinationv1.Lease
			if err := f.client.Get(f.ctx, key, &lease); err != nil {
				t.Fatal(err)
			}
			if scenario == "missing" {
				if err := f.client.Delete(f.ctx, &lease); err != nil {
					t.Fatal(err)
				}
			} else {
				other := "other-operation"
				lease.Spec.HolderIdentity = &other
				if err := f.client.Update(f.ctx, &lease); err != nil {
					t.Fatal(err)
				}
			}

			m := f.step()
			if m.Status.Phase != "RecoveryRequired" || m.Status.Reason != "ReservationLost" {
				t.Fatalf("lost reservation did not block recovery: phase=%s reason=%s", m.Status.Phase, m.Status.Reason)
			}
			node := f.node()
			if !node.Spec.Unschedulable || node.Annotations[execution.OwnerAnnotation] != string(m.UID) || f.evictions != 0 {
				t.Fatal("recovery changed the owned cordon or resumed disruption without its reservation")
			}
			if scenario == "owned-by-another-operation" {
				var current coordinationv1.Lease
				if err := f.client.Get(f.ctx, key, &current); err != nil {
					t.Fatal(err)
				}
				if current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != "other-operation" {
					t.Fatal("recovery changed the other operation's reservation")
				}
			}
		})
	}
}
func TestClusterReservationCompareAndSwap(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	results := make(chan bool, 8)
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			acquired, err := f.r.slot(f.ctx, types.UID(fmt.Sprintf("operation-%d", i)), true)
			results <- acquired
			errors <- err
		}(i)
	}
	count := 0
	for i := 0; i < 8; i++ {
		if <-results {
			count++
		}
		if err := <-errors; err != nil && !apierrors.IsConflict(err) {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatalf("cluster slot acquired %d times", count)
	}
}

func TestClusterReservationBlockReasonDistinguishesOrphanedOwner(t *testing.T) {
	for _, tc := range []struct {
		name        string
		createOwner bool
		wantReason  string
	}{
		{name: "live operation", createOwner: true, wantReason: "ClusterConcurrencyLimit"},
		{name: "missing operation", wantReason: "OrphanedClusterReservation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, protocol.DrainAndVerify)
			f.until("Pending")
			ownerUID := types.UID("reservation-owner-uid")
			if tc.createOwner {
				owner := &operations.NodeMaintenance{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "op-reservation-owner", UID: ownerUID}}
				if err := f.client.Create(f.ctx, owner); err != nil {
					t.Fatal(err)
				}
			}
			key := types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}
			var lease coordinationv1.Lease
			if err := f.client.Get(f.ctx, key, &lease); err != nil {
				t.Fatal(err)
			}
			holder := string(ownerUID)
			lease.Spec.HolderIdentity = &holder
			if err := f.client.Update(f.ctx, &lease); err != nil {
				t.Fatal(err)
			}

			blocked := f.until("Blocked")
			if blocked.Status.Reason != tc.wantReason {
				t.Fatalf("reservation blocker=%s, want %s", blocked.Status.Reason, tc.wantReason)
			}
			var current coordinationv1.Lease
			if err := f.client.Get(f.ctx, key, &current); err != nil {
				t.Fatal(err)
			}
			if current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != string(ownerUID) {
				t.Fatal("diagnostic handling modified the active or stale reservation")
			}
		})
	}
}

func TestClusterReservationBlockReasonFailsClosedWhenOwnerLookupFails(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	ownerUID := types.UID("reservation-owner-uid")
	if held, err := f.r.slot(f.ctx, ownerUID, true); err != nil || !held {
		t.Fatalf("fixture could not reserve cluster slot: held=%t err=%v", held, err)
	}
	f.r.Reader = listFailReader{Reader: f.r.Reader, err: fmt.Errorf("injected operation list failure")}
	if reason, err := f.r.slotBlockReason(f.ctx); err == nil || reason != "" {
		t.Fatalf("owner lookup failure did not fail closed: reason=%s err=%v", reason, err)
	}
	var lease coordinationv1.Lease
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(ownerUID) {
		t.Fatal("failed owner lookup changed the reservation")
	}
}

func TestLostEvictionResponseIsObservedBeforeRetry(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Draining")
	f.loseEvictionResponse = true
	observed := false
	for i := 0; i < 10; i++ {
		f.refresh()
		_, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name})
		if err != nil {
			if err.Error() != "injected lost eviction response" {
				t.Fatal(err)
			}
			observed = true
			break
		}
	}
	if !observed || f.evictions != 1 {
		t.Fatal("failed to inject ambiguous eviction outcome")
	}
	restarted := *f.r
	f.r = &restarted
	f.until("Succeeded")
	if f.evictions != 1 || f.node().Spec.Unschedulable {
		t.Fatal("replayed an already-completed eviction")
	}
}
func TestDeletionAfterCordonWaitsForVerifiedRecovery(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Draining")
	m := f.get()
	if err := f.client.Delete(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	f.until("RecoveryRequired")
	cancelled := f.until("Cancelled")
	if cancelled.Annotations == nil {
		cancelled.Annotations = map[string]string{}
	}
	cancelled.Annotations[protocol.AckAnnotation] = fmt.Sprint(cancelled.Status.Sequence)
	if err := f.client.Update(f.ctx, &cancelled); err != nil {
		t.Fatal(err)
	}
	f.refresh()
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(f.ctx, f.name, &m); !apierrors.IsNotFound(err) {
		t.Fatal("deletion finalizer was not cleared after recovery")
	}
	if f.node().Spec.Unschedulable || f.evictions != 0 {
		t.Fatal("cancellation disrupted additional workloads or retained the cordon")
	}
}

func TestTerminalFinalizerWaitsForDurableHubAcknowledgement(t *testing.T) {
	f := newFixture(t, protocol.ValidateOnly)
	m := f.until("Succeeded")
	// Bypass the fixture's simulated agent acknowledgement.
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err != nil {
		t.Fatal(err)
	}
	retained := f.get()
	if !hasFinalizer(&retained) {
		t.Fatal("completion could disappear before hub persistence")
	}
	if err := f.client.Delete(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err != nil {
		t.Fatal(err)
	}
	retained = f.get()
	if retained.DeletionTimestamp.IsZero() || !hasFinalizer(&retained) {
		t.Fatal("deleted unacknowledged completion")
	}
	retained.Annotations = map[string]string{protocol.AckAnnotation: fmt.Sprint(retained.Status.Sequence)}
	if err := f.client.Update(f.ctx, &retained); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: f.name}); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(f.ctx, f.name, &retained); !apierrors.IsNotFound(err) {
		t.Fatal("acknowledged completion was not released")
	}
}

type slowStorage struct {
	f    *fixture
	base safety.Storage
}

func (s slowStorage) Check(ctx context.Context, node *corev1.Node, pods []corev1.Pod) (safety.Result, error) {
	result, err := s.base.Check(ctx, node, pods)
	s.f.now = s.f.now.Add(16 * time.Minute)
	s.f.refresh() // The hub and kubelets remain live, but this operation permit has expired.
	return result, err
}
func TestSlowPreflightCannotUseAnExpiredGrant(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Cordoning")
	f.r.Checker.Storage = slowStorage{f: f, base: f.r.Checker.Storage}
	f.step()
	if f.node().Spec.Unschedulable || f.evictions != 0 {
		t.Fatal("disrupted a node after a slow preflight exhausted authorization")
	}
}

func TestSignedHubCancellationRecoversOwnedCordon(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Draining")
	m := f.get()
	control, err := protocol.SignCancellation(testOperation, testCluster, m.Spec.Command().Digest(), f.now, f.key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	m.Annotations[protocol.CancellationAnnotation] = string(data)
	if err = f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	f.until("Cancelled")
	if f.node().Spec.Unschedulable || f.evictions != 0 {
		t.Fatal("cancellation did not safely recover without further eviction")
	}
}

func TestHostUpgradeDrainingCancellationRecoversCheckpoint(t *testing.T) {
	for _, available := range []bool{true, false} {
		for _, interlock := range []bool{false, true} {
			t.Run(fmt.Sprintf("executor_available=%t/kured=%t", available, interlock), func(t *testing.T) {
				testHostUpgradeDrainingCancellation(t, available, interlock)
			})
		}
	}
}

func TestCancelledDrainRejectsExecutionEvidence(t *testing.T) {
	for _, mutation := range []string{"job", "reboot", "interrupted", "receipt"} {
		t.Run(mutation, func(t *testing.T) {
			checkpoint := &protocol.UpgradeCheckpoint{Phase: protocol.UpgradeDraining}
			switch mutation {
			case "job":
				checkpoint.ExecutionReference = "apply-job"
			case "reboot":
				checkpoint.RebootRequested = true
			case "interrupted":
				checkpoint.InterruptedPhase = "apply"
			case "receipt":
				checkpoint.Receipts = []protocol.UpgradeReceiptEvidence{{Phase: "apply"}}
			}
			m := &operations.NodeMaintenance{Status: operations.NodeMaintenanceStatus{UpgradeCheckpoint: checkpoint}}
			if err := (&Reconciler{}).checkpointCancelledDrain(m); err == nil || m.Status.UpgradeCheckpoint.Phase != protocol.UpgradeDraining {
				t.Fatal("execution evidence was classified as a cancellation before apply")
			}
		})
	}
}

func testHostUpgradeDrainingCancellation(t *testing.T, available, interlock bool) {
	f := newFixture(t, protocol.UpgradePackages)
	if interlock {
		attachKured(f)
	}
	node := f.node()
	node.Status.NodeInfo.BootID = "44444444-4444-4444-8444-444444444444"
	node.Status.NodeInfo.OSImage = "Ubuntu 24.04 LTS"
	node.Status.NodeInfo.KernelVersion = "6.8.0"
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}}
	if err := f.client.Status().Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	var policy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.Upgrade = &protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "ubuntu-test", OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.5.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	policy.Spec.AllowedActions = []string{protocol.ValidateOnly, protocol.DrainAndVerify, protocol.UpgradePackages}
	if err := f.client.Update(f.ctx, &policy); err != nil {
		t.Fatal(err)
	}
	digest, err := policy.Spec.Upgrade.Digest()
	if err != nil {
		t.Fatal(err)
	}
	m := f.get()
	var permit protocol.MaintenancePermit
	if err := json.Unmarshal([]byte(m.Spec.Authorization), &permit); err != nil {
		t.Fatal(err)
	}
	permit.PlanDigest = digest
	command, err := protocol.SignMaintenance(permit, f.key)
	if err != nil {
		t.Fatal(err)
	}
	m.Spec.Authorization, m.Spec.Signature = command.Authorization, command.Signature
	if err := f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	executor := &inspectionUpgradeExecutor{observation: execution.AnsibleJobObservation{
		Phase: "Succeeded", ReceiptReference: "host-preflight", ReceiptDigest: strings.Repeat("d", 64),
		Receipt: &execution.AnsibleReceipt{MachineID: strings.Repeat("b", 32), BootIDBefore: node.Status.NodeInfo.BootID,
			BootIDAfter: node.Status.NodeInfo.BootID, KernelVersion: "6.8.0", CompletedAt: f.now},
	}}
	f.r.Upgrader = executor
	m = f.until("Draining")
	if !available {
		f.r.Upgrader = nil // Model a restart with host execution disabled.
		if f.r.Kured != nil {
			f.r.Kured.Enabled = false
		}
	}
	control, err := protocol.SignCancellation(testOperation, testCluster, m.Spec.Command().Digest(), f.now, f.key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	m.Annotations[protocol.CancellationAnnotation] = string(data)
	if err := f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	// Live safety still fences recovery; no additional eviction or host Job.
	f.health.err = fmt.Errorf("injected API health failure")
	for i := 0; i < 3; i++ {
		f.step()
	}
	var lease coordinationv1.Lease
	key := types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}
	if err := f.client.Get(f.ctx, key, &lease); err != nil {
		t.Fatal(err)
	}
	if !f.node().Spec.Unschedulable || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(m.UID) {
		t.Fatal("cancelled drain released its cordon or reservation before recovery")
	}
	if interlock {
		ds, err := f.r.Kured.Client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
		if err != nil || ds.Annotations[reboot.LockAnnotation] == "" {
			t.Fatal("cancelled host drain lost its kured interlock")
		}
	}
	f.health.err = nil
	final := f.until("Cancelled")
	if final.Status.UpgradeCheckpoint.Phase != protocol.UpgradeCancelled {
		t.Fatalf("outer phase=%s but upgrade checkpoint=%s", final.Status.Phase, final.Status.UpgradeCheckpoint.Phase)
	}
	f.step() // Terminal reconciliation releases the reservation.
	if err := f.client.Get(f.ctx, key, &lease); err != nil {
		t.Fatal(err)
	}
	if f.node().Spec.Unschedulable || f.node().Annotations[execution.OwnerAnnotation] != "" ||
		lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == string(m.UID) {
		t.Fatal("verified cancellation did not release its owned cordon and reservation")
	}
	if f.evictions != 0 || executor.ensured != 1 || executor.started != 0 {
		t.Fatal("pre-apply cancellation performed further host or eviction work")
	}
	if interlock {
		ds, err := f.r.Kured.Client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
		if err != nil || ds.Annotations[reboot.LockAnnotation] != "" {
			t.Fatal("verified cancellation retained its kured interlock")
		}
	}
}

func TestInvalidHubCancellationStopsAndRecovers(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	f.until("Draining")
	m := f.get()
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	m.Annotations[protocol.CancellationAnnotation] = `{"kind":"Cancel","signature":"forged"}`
	if err := f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	final := f.until("Failed")
	if f.node().Spec.Unschedulable || f.evictions != 0 || final.Status.Reason != "InvalidCancellation" {
		t.Fatal("invalid cancellation bypassed recovery")
	}
}

func TestRecoveryKeepsUnresolvedUpgradeCordonWhenExecutorUnavailable(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	node := f.node()
	node.Spec.Unschedulable = true
	node.Annotations = map[string]string{execution.OwnerAnnotation: "maintenance-uid"}
	if err := f.client.Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	m := f.get()
	original := false
	m.Status = operations.NodeMaintenanceStatus{
		Phase:                 "RecoveryRequired",
		Reason:                "UpgradeInterruptedAmbiguous",
		Sequence:              1,
		OperationID:           testOperation,
		TargetNodeName:        node.Name,
		TargetNodeUID:         string(node.UID),
		OriginalBootID:        node.Status.NodeInfo.BootID,
		OriginalUnschedulable: &original,
		Outcome:               "Failed",
		UpgradeCheckpoint: &protocol.UpgradeCheckpoint{
			PlanDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			NodeUID:    string(node.UID),
			BootID:     node.Status.NodeInfo.BootID,
			Phase:      protocol.UpgradeExecuting,
			Sequence:   2,
			UpdatedAt:  metav1.NewTime(f.now),
		},
	}
	m.Status.Events = []protocol.PhaseEvent{{Sequence: 1, Phase: "RecoveryRequired", Reason: m.Status.Reason, Time: metav1.NewTime(f.now)}}
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	if held, err := f.r.slot(f.ctx, m.UID, true); err != nil || !held {
		t.Fatalf("fixture could not restore operation reservation: held=%t err=%v", held, err)
	}
	if err := f.r.recover(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	if !f.node().Spec.Unschedulable || f.node().Annotations[execution.OwnerAnnotation] != string(m.UID) {
		t.Fatal("ambiguous package execution was uncordoned without explicit recovery evidence")
	}
	if m.Status.Phase != "RecoveryRequired" || m.Status.Reason != "UpgradeOutcomeAmbiguous" {
		t.Fatalf("expected visible ambiguous recovery blocker, got phase=%s reason=%s", m.Status.Phase, m.Status.Reason)
	}
}

func TestVerifiedCancelledUpgradeFinishesAsCancelledAfterRecovery(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	node := f.node()
	node.Spec.Unschedulable = true
	node.Annotations = map[string]string{execution.OwnerAnnotation: "maintenance-uid"}
	if err := f.client.Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	m := f.get()
	original := false
	m.Status = operations.NodeMaintenanceStatus{
		Phase: "Uncordoning", Reason: "WorkloadRecoveryVerified", Sequence: 3, OperationID: testOperation,
		TargetNodeName: node.Name, TargetNodeUID: string(node.UID), OriginalBootID: node.Status.NodeInfo.BootID,
		OriginalUnschedulable: &original, RecoverySeconds: 10, RecoveryStartedAt: &metav1.Time{Time: f.now.Add(-time.Minute)}, Outcome: "Cancelled",
		UpgradeCheckpoint: &protocol.UpgradeCheckpoint{
			PlanDigest: strings.Repeat("a", 64), NodeUID: string(node.UID), BootID: node.Status.NodeInfo.BootID,
			Phase: protocol.UpgradeUncordoning, Sequence: 7, UpdatedAt: metav1.NewTime(f.now),
		},
	}
	m.Status.Events = []protocol.PhaseEvent{
		{Sequence: 1, Phase: "RecoveryRequired", Reason: "CancelledByHub", Time: metav1.NewTime(f.now.Add(-time.Minute))},
		{Sequence: 2, Phase: "VerifyingWorkloads", Reason: "CancelledDrainRecoveryVerified", Time: metav1.NewTime(f.now.Add(-30 * time.Second))},
		{Sequence: 3, Phase: "Uncordoning", Reason: "WorkloadRecoveryVerified", Time: metav1.NewTime(f.now)},
	}
	if err := f.client.Status().Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	if held, err := f.r.slot(f.ctx, m.UID, true); err != nil || !held {
		t.Fatalf("fixture could not restore operation reservation: held=%t err=%v", held, err)
	}
	if err := f.r.recover(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	if f.node().Spec.Unschedulable {
		t.Fatal("verified cancelled operation kept its owned cordon")
	}
	m = f.get()
	if err := f.r.recover(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	final := f.get()
	if final.Status.Phase != "Cancelled" || final.Status.UpgradeCheckpoint.Phase != protocol.UpgradeCancelled {
		t.Fatalf("cancelled recovery outcome was rewritten: operation=%s checkpoint=%s", final.Status.Phase, final.Status.UpgradeCheckpoint.Phase)
	}
}

func TestExpiredPermitOnlyContinuesVerifiedUpgradeReboot(t *testing.T) {
	now := time.Now().UTC()
	permit := protocol.MaintenancePermit{
		MaintenanceRequest: protocol.MaintenanceRequest{Action: protocol.UpgradePackages, PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid"},
		IssuedAt:           now.Add(-20 * time.Minute),
		NotBefore:          now.Add(-20 * time.Minute),
		ExpiresAt:          now.Add(-5 * time.Minute),
	}
	m := &operations.NodeMaintenance{}
	if permitFreshForBoundary(m, permit, "Rebooting", now) {
		t.Fatal("expired permit authorized reboot without a durable checkpoint")
	}
	m.Status.UpgradeCheckpoint = &protocol.UpgradeCheckpoint{
		PlanDigest: permit.PlanDigest, NodeUID: permit.NodeUID,
		Phase: protocol.UpgradeRebooting, Outcome: "PackagesVerified", RebootRequested: true,
		MachineID: strings.Repeat("b", 32), BootID: "33333333-3333-4333-8333-333333333333", Sequence: 1, UpdatedAt: metav1.NewTime(now),
		Receipts: []protocol.UpgradeReceiptEvidence{{
			Phase: "apply", Reference: "kordex-ee-receipt", Digest: strings.Repeat("c", 64),
			MachineID: strings.Repeat("b", 32), BootIDBefore: "33333333-3333-4333-8333-333333333333", BootIDAfter: "33333333-3333-4333-8333-333333333333",
			RebootRequired: true, Packages: map[string]string{"curl": "8.1.0-1"}, CompletedAt: metav1.NewTime(now.Add(-time.Minute)),
		}},
	}
	if !permitFreshForBoundary(m, permit, "Rebooting", now) {
		t.Fatal("verified reboot continuation was rejected after the original permit expired")
	}
	if permitFreshForBoundary(m, permit, "Executing", now) {
		t.Fatal("expired permit authorized a new package execution")
	}
	m.Status.UpgradeCheckpoint.Outcome = "Ambiguous"
	if permitFreshForBoundary(m, permit, "Rebooting", now) {
		t.Fatal("ambiguous package outcome authorized reboot")
	}
	m.Status.UpgradeCheckpoint.Outcome = "PackagesVerified"
	m.Status.UpgradeCheckpoint.PlanDigest = strings.Repeat("d", 64)
	if permitFreshForBoundary(m, permit, "Rebooting", now) {
		t.Fatal("checkpoint for a different plan authorized reboot continuation")
	}
	m.Status.UpgradeCheckpoint.PlanDigest = permit.PlanDigest
	m.Status.UpgradeCheckpoint.NodeUID = "different-node"
	if permitFreshForBoundary(m, permit, "Rebooting", now) {
		t.Fatal("checkpoint for a different node authorized reboot continuation")
	}
}
