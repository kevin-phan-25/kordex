package controller

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/reboot"
)

func attachKured(f *fixture) *fake.Clientset {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kured", UID: "kured-uid", ResourceVersion: "1", Generation: 1},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "kured", Image: "ghcr.io/kubereboot/kured@sha256:" + strings.Repeat("a", 64),
		}}}}}, Status: appsv1.DaemonSetStatus{ObservedGeneration: 1, DesiredNumberScheduled: 1, UpdatedNumberScheduled: 1, NumberReady: 1, NumberAvailable: 1},
	})
	f.r.Kured = &reboot.Kured{Client: client, Enabled: true, Namespace: "kube-system", Name: "kured"}
	return client
}

func TestKuredLockIntentAndAcquisitionAreDurableBeforeHostActions(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	client := attachKured(f)
	m := f.get()
	ready, err := f.r.ensureKuredLock(f.ctx, &m, "Validating")
	if err != nil || ready {
		t.Fatalf("intent was not persisted separately: %v %v", ready, err)
	}
	ds, _ := client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
	if ds.Annotations[reboot.LockAnnotation] != "" {
		t.Fatal("external lock changed before durable intent")
	}
	m = f.get()
	ref, err := kuredReference(&m)
	if err != nil || ref.Acquired {
		t.Fatalf("invalid acquisition intent: %+v %v", ref, err)
	}
	ready, err = f.r.ensureKuredLock(f.ctx, &m, "Validating")
	if err != nil || ready {
		t.Fatalf("ownership was not persisted before continuation: %v %v", ready, err)
	}
	m = f.get()
	ref, err = kuredReference(&m)
	if err != nil || !ref.Acquired {
		t.Fatalf("ownership missing: %+v %v", ref, err)
	}
	f.r.Kured.Enabled = false // A restart can disable new acquisition, not recovery.
	ready, err = f.r.ensureKuredLock(f.ctx, &m, "SafetyChecking")
	if err != nil || !ready {
		t.Fatalf("persisted ownership was not recovered: %v %v", ready, err)
	}
	ds, _ = client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
	delete(ds.Annotations, reboot.LockAnnotation)
	_, _ = client.AppsV1().DaemonSets("kube-system").Update(f.ctx, ds, metav1.UpdateOptions{})
	ready, err = f.r.ensureKuredLock(f.ctx, &m, "Executing")
	if err == nil || ready {
		t.Fatal("lost ownership was reacquired during execution")
	}
	ds, _ = client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
	if ds.Annotations[reboot.LockAnnotation] != "" {
		t.Fatal("ownership loss triggered another lock request")
	}
}

func TestKuredLockStaysHeldThroughCancellationAndVerifiedRecovery(t *testing.T) {
	f := newFixture(t, protocol.DrainAndVerify)
	client := attachKured(f)
	m := f.get()
	for i := 0; i < 2; i++ {
		if _, err := f.r.ensureKuredLock(f.ctx, &m, "Validating"); err != nil {
			t.Fatal(err)
		}
		m = f.get()
	}
	m = f.until("Draining")
	if err := f.r.abort(f.ctx, &m, "CancelledByHub", true); err != nil {
		t.Fatal(err)
	}
	f.r.Kured.Enabled = false
	// Losing the external lock blocks even read-only recovery from uncordoning.
	ds, _ := client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
	owned := ds.Annotations[reboot.LockAnnotation]
	delete(ds.Annotations, reboot.LockAnnotation)
	_, _ = client.AppsV1().DaemonSets("kube-system").Update(f.ctx, ds, metav1.UpdateOptions{})
	blocked := f.step()
	if blocked.Status.Reason != "KuredLockUnavailable" || !f.node().Spec.Unschedulable {
		t.Fatal("lost kured lock allowed recovery release")
	}
	var slot coordinationv1.Lease
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &slot); err != nil {
		t.Fatal(err)
	}
	if slot.Spec.HolderIdentity == nil || *slot.Spec.HolderIdentity != string(m.UID) {
		t.Fatal("lost external lock released the local reservation")
	}
	// Model an explicit administrator restoring the same known lock after review.
	ds.Annotations[reboot.LockAnnotation] = owned
	_, _ = client.AppsV1().DaemonSets("kube-system").Update(f.ctx, ds, metav1.UpdateOptions{})
	f.until("Cancelled")
	ds, _ = client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
	if ds.Annotations[reboot.LockAnnotation] != owned {
		t.Fatal("external lock released before terminal recovery")
	}
	f.step()
	ds, _ = client.AppsV1().DaemonSets("kube-system").Get(f.ctx, "kured", metav1.GetOptions{})
	if _, exists := ds.Annotations[reboot.LockAnnotation]; exists {
		t.Fatal("verified cancellation leaked its owned external lock")
	}
}

func TestKuredCannotBeIntroducedAfterHostExecutionStarts(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	client := attachKured(f)
	m := f.get()
	if ready, err := f.r.ensureKuredLock(f.ctx, &m, "Executing"); err == nil || ready {
		t.Fatal("late acquisition was allowed")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("late admission contacted the external lock")
	}
}

func TestExpiredHostPermitCannotReserveTheKuredLock(t *testing.T) {
	f := newFixture(t, protocol.UpgradePackages)
	client := attachKured(f)
	f.r.Upgrader = &inspectionUpgradeExecutor{}
	node := f.node()
	node.Status.NodeInfo.OSImage = "Ubuntu 24.04 LTS"
	if err := f.client.Status().Update(f.ctx, node); err != nil {
		t.Fatal(err)
	}
	var policy operations.MaintenancePolicy
	if err := f.client.Get(f.ctx, types.NamespacedName{Namespace: testNamespace, Name: "safe-workers"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.Upgrade = &protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "ubuntu-test", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.5.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
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
	permit.IssuedAt = f.now.Add(-20 * time.Minute)
	permit.NotBefore = permit.IssuedAt
	permit.ExpiresAt = f.now.Add(-5 * time.Minute)
	command, err := protocol.SignMaintenance(permit, f.key)
	if err != nil {
		t.Fatal(err)
	}
	m.Spec.Authorization, m.Spec.Signature = command.Authorization, command.Signature
	if err := f.client.Update(f.ctx, &m); err != nil {
		t.Fatal(err)
	}
	final := f.until("Failed")
	if final.Status.Reason != "AuthorizationExpired" || len(client.Actions()) != 0 || f.node().Spec.Unschedulable {
		t.Fatalf("expired permit reached kured: reason=%s actions=%v", final.Status.Reason, client.Actions())
	}
}
