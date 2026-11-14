package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	"kordex.local/operator/internal/safety"
)

const testCluster = "11111111-1111-4111-8111-111111111111"
const testOperation = "22222222-2222-4222-8222-222222222222"
const testOrg = "33333333-3333-4333-8333-333333333333"
const testNamespace = "kordex-system"

type testHealth struct{ err error }

func (h *testHealth) Ready(context.Context) error { return h.err }

type fixture struct {
	t             *testing.T
	ctx           context.Context
	now           time.Time
	client        client.Client
	r             *Reconciler
	key           ed25519.PrivateKey
	name          types.NamespacedName
	evictions     int
	evictionError error
	connected     bool
	health        *testHealth
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
	return e.f.client.Create(ctx, replacement)
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
	var objects []client.Object
	objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, worker("worker1", f.now), worker("worker2", f.now), deployment, rs, &operations.MaintenancePolicy{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "safe-workers", UID: "policy-uid", Generation: 1}, Spec: operations.MaintenancePolicySpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{safety.StatelessLabel: "stateless"}}, RecoverySeconds: 10, GracePeriodSeconds: 30}}, &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web", Generation: 1}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailable, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}, Status: policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 1, DisruptionsAllowed: 1}})
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
