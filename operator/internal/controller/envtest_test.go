package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
	"kordex.local/operator/internal/safety"
)

func TestEnvtestCRDAdmissionAndStatus(t *testing.T) {
	c := startEnvtestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := c.Create(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	policy := &operations.MaintenancePolicy{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "safe"}, Spec: operations.MaintenancePolicySpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"test": "true"}}}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if policy.Spec.RecoverySeconds != 10 || policy.Spec.GracePeriodSeconds != 30 {
		t.Fatal("CRD defaults not applied")
	}
	invalid := policy.DeepCopy()
	invalid.ResourceVersion = ""
	invalid.UID = ""
	invalid.Name = "invalid"
	invalid.Spec.RecoverySeconds = 1
	if err := c.Create(ctx, invalid); !apierrors.IsInvalid(err) {
		t.Fatalf("unsafe policy admitted: %v", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	command, err := protocol.SignMaintenance(protocol.MaintenancePermit{OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: "cluster-uid", MaintenanceRequest: protocol.MaintenanceRequest{OperationID: testOperation, NodeName: "worker1", NodeUID: "worker1-uid", Action: protocol.ValidateOnly, Policy: protocol.PolicyReference{Name: policy.Name, UID: string(policy.UID), Generation: policy.Generation}}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute)}, key)
	if err != nil {
		t.Fatal(err)
	}
	m := &operations.NodeMaintenance{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "op-" + testOperation}, Spec: operations.NodeMaintenanceSpec{Authorization: command.Authorization, Signature: command.Signature}}
	if err = c.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	oldGeneration := m.Generation
	copy := m.DeepCopy()
	copy.Spec.Authorization += " "
	if err = c.Update(ctx, copy); !apierrors.IsInvalid(err) {
		t.Fatalf("immutable operation changed: %v", err)
	}
	if err = c.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: m.Name}, m); err != nil {
		t.Fatal(err)
	}
	m.Status.Phase = "Pending"
	m.Status.Sequence = 1
	m.Status.Events = []protocol.PhaseEvent{{Sequence: 1, Phase: "Pending", Reason: "RequestAccepted", Time: metav1.NewTime(now)}}
	if err = c.Status().Update(ctx, m); err != nil {
		t.Fatal(err)
	}
	if m.Generation != oldGeneration {
		t.Fatal("status update changed desired generation")
	}
	stale := m.DeepCopy()
	m.Annotations = map[string]string{"test": "new"}
	if err = c.Update(ctx, m); err != nil {
		t.Fatal(err)
	}
	stale.Status.Phase = "Failed"
	if err = c.Status().Update(ctx, stale); !apierrors.IsConflict(err) {
		t.Fatalf("stale controller overwrote status: %v", err)
	}
	m.Finalizers = []string{Finalizer}
	if err = c.Update(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err = c.Delete(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err = c.Get(ctx, client.ObjectKeyFromObject(m), m); err != nil || m.DeletionTimestamp.IsZero() {
		t.Fatal("recovery finalizer did not retain deleting operation")
	}
}

// startEnvtestClient uses the same API-server/etcd assets and CRD bundle as CI.
// Returned clients speak directly to envtest's API server (no fake client/cache).
func startEnvtestClient(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("KORDEX_REQUIRE_ENVTEST") == "true" {
			t.Fatal("envtest assets required")
		}
		t.Skip("set KUBEBUILDER_ASSETS for a real Kubernetes API-server test")
	}
	environment := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd")}, ErrorIfCRDPathMissing: true}
	cfg, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	if err = clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err = operations.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type envtestUnexpectedEvictor struct{ calls int }

func (e *envtestUnexpectedEvictor) Evict(context.Context, *corev1.Pod, int64) error {
	e.calls++
	return fmt.Errorf("unexpected eviction during cancellation recovery")
}

func TestEnvtestRestartPreservesCancelAndRecoveryFence(t *testing.T) {
	c := startEnvtestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	now := time.Now().UTC().Truncate(time.Second)
	createNamespace := func(name string) {
		t.Helper()
		var namespace corev1.Namespace
		err := c.Get(ctx, types.NamespacedName{Name: name}, &namespace)
		if err == nil {
			return
		}
		if !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	createNamespace("kube-system")
	createNamespace("kube-node-lease")
	createNamespace("apps")
	createNamespace(protocol.SlotNamespace)
	createNamespace(testNamespace)

	var clusterNamespace corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: "kube-system"}, &clusterNamespace); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"worker1", "worker2"} {
		node := worker(name, now.Add(-time.Minute))
		node.UID = ""
		if err := c.Create(ctx, node); err != nil {
			t.Fatal(err)
		}
		leaseTime := metav1.NewMicroTime(now)
		if err := c.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-node-lease", Name: name}, Spec: coordinationv1.LeaseSpec{RenewTime: &leaseTime}}); err != nil {
			t.Fatal(err)
		}
	}
	var target corev1.Node
	if err := c.Get(ctx, types.NamespacedName{Name: "worker1"}, &target); err != nil {
		t.Fatal(err)
	}

	policy := &operations.MaintenancePolicy{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "safe-restart"}, Spec: operations.MaintenancePolicySpec{
		NodeSelector:   metav1.LabelSelector{MatchLabels: map[string]string{safety.StatelessLabel: "stateless"}},
		AllowedActions: []string{protocol.DrainAndVerify}, RecoverySeconds: 10, GracePeriodSeconds: 30,
	}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	replicas := int32(1)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"}, Spec: appsv1.DeploymentSpec{
		Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "example.invalid/web"}}}},
	}}
	if err := c.Create(ctx, deployment); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
		t.Fatal(err)
	}
	deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: deployment.Generation, Replicas: 1, ReadyReplicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}
	if err := c.Status().Update(ctx, deployment); err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := now
	command, err := protocol.SignMaintenance(protocol.MaintenancePermit{
		OrganizationID: testOrg, ClusterID: testCluster, ClusterUID: string(clusterNamespace.UID),
		MaintenanceRequest: protocol.MaintenanceRequest{OperationID: testOperation, NodeName: target.Name, NodeUID: string(target.UID), Action: protocol.DrainAndVerify,
			Policy: protocol.PolicyReference{Name: policy.Name, UID: string(policy.UID), Generation: policy.Generation}},
		IssuedAt: issued, NotBefore: issued, ExpiresAt: issued.Add(time.Hour),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	m := &operations.NodeMaintenance{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "op-" + testOperation, Finalizers: []string{Finalizer}}, Spec: operations.NodeMaintenanceSpec{Authorization: command.Authorization, Signature: command.Signature}}
	if err := c.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(m), m); err != nil {
		t.Fatal(err)
	}

	unschedulable := false
	m.Status = operations.NodeMaintenanceStatus{
		OperationID: testOperation, TargetNodeName: target.Name, TargetNodeUID: string(target.UID), Phase: "Draining", Reason: "NodeCordoned", Sequence: 5,
		OriginalUnschedulable: &unschedulable, OriginalBootID: target.Status.NodeInfo.BootID, RecoverySeconds: 10,
		Events: []protocol.PhaseEvent{
			{Sequence: 1, Phase: "Pending", Reason: "RequestAccepted", Time: metav1.NewTime(issued)},
			{Sequence: 2, Phase: "Validating", Reason: "AuthorizationValidated", Time: metav1.NewTime(issued.Add(time.Second))},
			{Sequence: 3, Phase: "SafetyChecking", Reason: "SlotReserved", Time: metav1.NewTime(issued.Add(2 * time.Second))},
			{Sequence: 4, Phase: "Cordoning", Reason: "CordonIntentPersisted", Time: metav1.NewTime(issued.Add(3 * time.Second))},
			{Sequence: 5, Phase: "Draining", Reason: "NodeCordoned", Time: metav1.NewTime(issued.Add(4 * time.Second))},
		},
		Evictions: []operations.EvictionRecord{{Namespace: "apps", Name: "web-pod-0", UID: "evicted-pod-uid", Workload: operations.WorkloadReference{Namespace: "apps", Name: "web", UID: string(deployment.UID), Replicas: 1}}},
	}
	if err := c.Status().Update(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: target.Name}, &target); err != nil {
		t.Fatal(err)
	}
	if err := execution.Cordon(ctx, c, &target, string(m.UID), true); err != nil {
		t.Fatal(err)
	}
	holder := string(m.UID)
	leaseTime := metav1.NewMicroTime(now)
	if err := c.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, RenewTime: &leaseTime}}); err != nil {
		t.Fatal(err)
	}
	connectionHolder := testCluster
	if err := c.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: protocol.ConnectionLease}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &connectionHolder, RenewTime: &leaseTime}}); err != nil {
		t.Fatal(err)
	}
	control, err := protocol.SignCancellation(testOperation, testCluster, m.Spec.Command().Digest(), now, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cancelJSON, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(m), m); err != nil {
		t.Fatal(err)
	}
	m.Annotations = map[string]string{protocol.CancellationAnnotation: string(cancelJSON)}
	if err := c.Update(ctx, m); err != nil {
		t.Fatal(err)
	}

	var evictor envtestUnexpectedEvictor
	newReconciler := func() *Reconciler {
		checker := &safety.Checker{Reader: c, Storage: safety.StatelessStorage{Reader: c}, Quorum: safety.WorkerOnlyQuorum{}, API: &testHealth{}, Now: func() time.Time { return now }}
		return &Reconciler{Client: c, Reader: c, Checker: checker, Evictor: &evictor, Keys: map[string]ed25519.PublicKey{protocol.KeyID(publicKey): publicKey}, ClusterID: testCluster, Now: func() time.Time { return now }}
	}
	reconcileAfterRestart := func() operations.NodeMaintenance {
		t.Helper()
		if _, err := newReconciler().Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: m.Name}}); err != nil {
			t.Fatal(err)
		}
		var current operations.NodeMaintenance
		if err := c.Get(ctx, client.ObjectKeyFromObject(m), &current); err != nil {
			t.Fatal(err)
		}
		return current
	}
	assertFence := func() {
		t.Helper()
		var node corev1.Node
		if err := c.Get(ctx, types.NamespacedName{Name: "worker1"}, &node); err != nil {
			t.Fatal(err)
		}
		if !node.Spec.Unschedulable || node.Annotations[execution.OwnerAnnotation] != holder {
			t.Fatalf("recovery fence lost before verification: unschedulable=%t owner=%q", node.Spec.Unschedulable, node.Annotations[execution.OwnerAnnotation])
		}
		var lease coordinationv1.Lease
		if err := c.Get(ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &lease); err != nil {
			t.Fatal(err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != holder {
			t.Fatalf("recovery reservation lost before verification: holder=%v", lease.Spec.HolderIdentity)
		}
	}

	// This new reconciler represents a controller process restarted with only
	// API-server-persisted operation, cordon ownership, cancellation and Lease state.
	current := reconcileAfterRestart()
	if current.Status.Phase != "RecoveryRequired" || current.Status.Outcome != "Cancelled" {
		t.Fatalf("signed cancellation was not durably fenced for recovery: phase=%s outcome=%s", current.Status.Phase, current.Status.Outcome)
	}
	if current.Status.Sequence != 6 || len(current.Status.Events) != 6 || len(current.Status.Evictions) != 1 {
		t.Fatalf("restart lost or duplicated the durable checkpoint: sequence=%d events=%d evictions=%d", current.Status.Sequence, len(current.Status.Events), len(current.Status.Evictions))
	}
	assertFence()
	if evictor.calls != 0 {
		t.Fatalf("restart repeated destructive eviction work: calls=%d", evictor.calls)
	}

	terminal := false
	for i := 0; i < 16; i++ {
		now = now.Add(2 * time.Second)
		for _, name := range []string{"worker1", "worker2"} {
			var nodeLease coordinationv1.Lease
			key := types.NamespacedName{Namespace: "kube-node-lease", Name: name}
			if err := c.Get(ctx, key, &nodeLease); err != nil {
				t.Fatal(err)
			}
			renew := metav1.NewMicroTime(now)
			nodeLease.Spec.RenewTime = &renew
			if err := c.Update(ctx, &nodeLease); err != nil {
				t.Fatal(err)
			}
		}
		current = reconcileAfterRestart()
		if current.Status.Phase == "RecoveryRequired" {
			assertFence()
		}
		if current.Status.Phase == "Cancelled" {
			terminal = true
			break
		}
	}
	if !terminal {
		t.Fatalf("verified cancellation recovery did not finish: phase=%s reason=%s", current.Status.Phase, current.Status.Reason)
	}
	if evictor.calls != 0 {
		t.Fatalf("recovery repeated destructive eviction work: calls=%d", evictor.calls)
	}

	// Terminal cleanup releases only the matching operation reservation after
	// the operation-owned cordon was removed by the verified recovery path.
	if _, err := newReconciler().Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: m.Name}}); err != nil {
		t.Fatal(err)
	}
	var finalNode corev1.Node
	if err := c.Get(ctx, types.NamespacedName{Name: "worker1"}, &finalNode); err != nil {
		t.Fatal(err)
	}
	if finalNode.Spec.Unschedulable || finalNode.Annotations[execution.OwnerAnnotation] != "" {
		t.Fatal("verified recovery did not release its own cordon")
	}
	var finalLease coordinationv1.Lease
	if err := c.Get(ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &finalLease); err != nil {
		t.Fatal(err)
	}
	if finalLease.Spec.HolderIdentity == nil || *finalLease.Spec.HolderIdentity != "" {
		t.Fatalf("terminal cleanup did not release its own reservation: holder=%v", finalLease.Spec.HolderIdentity)
	}
	var finalOperation operations.NodeMaintenance
	if err := c.Get(ctx, client.ObjectKeyFromObject(m), &finalOperation); err != nil {
		t.Fatal(err)
	}
	if len(finalOperation.Status.Evictions) != 1 {
		t.Fatalf("recovery duplicated or lost the existing eviction checkpoint: count=%d", len(finalOperation.Status.Evictions))
	}
	recoveryRequiredEvents := 0
	for _, event := range finalOperation.Status.Events {
		if event.Phase == "RecoveryRequired" {
			recoveryRequiredEvents++
		}
	}
	if recoveryRequiredEvents != 1 {
		t.Fatalf("restart duplicated the recovery fence event: count=%d", recoveryRequiredEvents)
	}
}
