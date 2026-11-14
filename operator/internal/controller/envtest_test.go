package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
)

func TestEnvtestCRDAdmissionAndStatus(t *testing.T) {
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
	defer func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	}()
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err = c.Create(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	policy := &operations.MaintenancePolicy{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "safe"}, Spec: operations.MaintenancePolicySpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"test": "true"}}}}
	if err = c.Create(ctx, policy); err != nil {
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
	if err = c.Create(ctx, invalid); !apierrors.IsInvalid(err) {
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
