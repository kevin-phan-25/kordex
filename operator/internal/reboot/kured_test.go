package reboot

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func daemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kured", UID: "kured-uid", ResourceVersion: "1", Generation: 1,
		Annotations: map[string]string{"unrelated": "preserve"}},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "kured", Image: "ghcr.io/kubereboot/kured@sha256:" + strings.Repeat("a", 64), Command: []string{"/usr/bin/kured"},
		}}}}}, Status: appsv1.DaemonSetStatus{ObservedGeneration: 1, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberReady: 2, NumberAvailable: 2}}
}

func fixture(t *testing.T) (*Kured, *fake.Clientset, Reference) {
	t.Helper()
	client := fake.NewSimpleClientset(daemonSet())
	k := &Kured{Client: client, Enabled: true, Namespace: "kube-system", Name: "kured"}
	ref, err := k.Prepare(context.Background(), types.UID("operation-uid"))
	if err != nil {
		t.Fatal(err)
	}
	return k, client, ref
}

func TestKuredManualLockSurvivesRestartAndReleasesOnlyOwnedAnnotation(t *testing.T) {
	k, client, ref := fixture(t)
	ctx := context.Background()
	if err := k.Acquire(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := k.Acquire(ctx, ref); err != nil {
		t.Fatal(err)
	}
	ds, _ := client.AppsV1().DaemonSets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	var value struct {
		NodeID string `json:"nodeID"`
		TTL    int64  `json:"TTL"`
	}
	if err := json.Unmarshal([]byte(ds.Annotations[LockAnnotation]), &value); err != nil {
		t.Fatal(err)
	}
	if value.NodeID != "manual:kordex:operation-uid" || value.TTL != 0 {
		t.Fatalf("unsafe manual lock: %+v", value)
	}
	// A host reboot can temporarily make a kured Pod unready. Ownership still
	// applies, including a restarted operator with new acquisition disabled.
	ds.Status.NumberReady = 1
	if _, err := client.AppsV1().DaemonSets(ref.Namespace).UpdateStatus(ctx, ds, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	k.Enabled = false
	if err := k.Check(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := k.Release(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := k.Release(ctx, ref); err != nil {
		t.Fatal(err)
	}
	ds, _ = client.AppsV1().DaemonSets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if _, exists := ds.Annotations[LockAnnotation]; exists || ds.Annotations["unrelated"] != "preserve" {
		t.Fatal("release changed another annotation or retained its own lock")
	}
}

func TestKuredNeverStealsOrExpiresAnExistingLock(t *testing.T) {
	for _, value := range []string{`{"nodeID":"worker-1"}`, `{"nodeID":"manual"}`, `broken`, ``,
		`{"nodeID":"worker-1","created":"2000-01-01T00:00:00Z","TTL":1}`, `{"maxOwners":2,"locks":[]}`} {
		t.Run(value, func(t *testing.T) {
			k, client, ref := fixture(t)
			ds, _ := client.AppsV1().DaemonSets(ref.Namespace).Get(context.Background(), ref.Name, metav1.GetOptions{})
			ds.Annotations[LockAnnotation] = value
			_, _ = client.AppsV1().DaemonSets(ref.Namespace).Update(context.Background(), ds, metav1.UpdateOptions{})
			if err := k.Acquire(context.Background(), ref); !errors.Is(err, ErrBusy) {
				t.Fatalf("foreign lock accepted: %v", err)
			}
			if err := k.Release(context.Background(), ref); err != nil {
				t.Fatal(err)
			}
			ds, _ = client.AppsV1().DaemonSets(ref.Namespace).Get(context.Background(), ref.Name, metav1.GetOptions{})
			if ds.Annotations[LockAnnotation] != value {
				t.Fatal("foreign lock changed")
			}
		})
	}
}

func TestKuredLockLossAndDaemonSetReplacementFailClosed(t *testing.T) {
	for _, mutation := range []string{"missing", "foreign", "spec", "replacement"} {
		t.Run(mutation, func(t *testing.T) {
			k, client, ref := fixture(t)
			ctx := context.Background()
			if err := k.Acquire(ctx, ref); err != nil {
				t.Fatal(err)
			}
			ds, _ := client.AppsV1().DaemonSets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
			switch mutation {
			case "missing":
				delete(ds.Annotations, LockAnnotation)
			case "foreign":
				ds.Annotations[LockAnnotation] = `{"nodeID":"other"}`
			case "spec":
				ds.Spec.Template.Spec.Containers[0].Args = []string{"--concurrency=2"}
			case "replacement":
				ds.UID = "replacement-uid"
			}
			_, _ = client.AppsV1().DaemonSets(ref.Namespace).Update(ctx, ds, metav1.UpdateOptions{})
			if err := k.Check(ctx, ref); err == nil {
				t.Fatal("missing or changed custody was accepted")
			}
			if mutation == "replacement" && k.Release(ctx, ref) == nil {
				t.Fatal("released a replacement DaemonSet")
			}
			actual, _ := client.AppsV1().DaemonSets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
			if actual.Annotations[LockAnnotation] != ds.Annotations[LockAnnotation] {
				t.Fatal("check reacquired or changed the lock")
			}
		})
	}
}

func TestKuredRejectsUnsafeOrUnknownConfiguration(t *testing.T) {
	for _, mutation := range []string{"concurrency", "environment", "ttl", "annotation", "namespace", "image", "shell", "envfrom", "secret", "sidecar", "unready", "stale", "terminated-flags"} {
		t.Run(mutation, func(t *testing.T) {
			ds := daemonSet()
			c := &ds.Spec.Template.Spec.Containers[0]
			switch mutation {
			case "concurrency":
				c.Args = []string{"--concurrency", "2"}
			case "environment":
				c.Env = []corev1.EnvVar{{Name: "KURED_CONCURRENCY", Value: "2"}}
			case "ttl":
				c.Args = []string{"--lock-ttl=1h"}
			case "annotation":
				c.Args = []string{"--lock-annotation=other"}
			case "namespace":
				c.Args = []string{"--ds-namespace=other"}
			case "image":
				c.Image = "kured:latest"
			case "shell":
				c.Command = []string{"sh", "-c", "kured"}
			case "envfrom":
				c.EnvFrom = []corev1.EnvFromSource{{Prefix: "KURED_"}}
			case "secret":
				c.Env = []corev1.EnvVar{{Name: "KURED_CONCURRENCY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "count"}}}}
			case "sidecar":
				ds.Spec.Template.Spec.Containers = append(ds.Spec.Template.Spec.Containers, corev1.Container{Name: "other"})
			case "unready":
				ds.Status.NumberReady = 1
			case "stale":
				ds.Status.ObservedGeneration = 0
			case "terminated-flags":
				c.Args = []string{"--concurrency=2", "--", "--concurrency=1"}
			}
			k := &Kured{Client: fake.NewSimpleClientset(ds), Enabled: true, Namespace: ds.Namespace, Name: ds.Name}
			if _, err := k.Prepare(context.Background(), "operation-uid"); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestKuredRejectsAmbiguousArgumentsAndLockingEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  []corev1.EnvVar
	}{
		{name: "value masquerading as flag", args: []string{"--concurrency=2", "--message-template-reboot", "concurrency=1"}},
		{name: "unprefixed flag", args: []string{"concurrency=1"}},
		{name: "split locking flag", args: []string{"--concurrency", "1"}},
		{name: "bare flag", args: []string{"--annotate-nodes"}},
		{name: "positional argument", args: []string{"--concurrency=1", "extra"}},
		{name: "short flag", args: []string{"-concurrency=1"}},
		{name: "whole argument expansion", args: []string{"$(LOCK_FLAG)"}, env: []corev1.EnvVar{{Name: "LOCK_FLAG", Value: "--lock-annotation=other"}}},
		{name: "flag name expansion", args: []string{"--$(LOCK_FLAG)=1"}},
		{name: "locking value expansion", args: []string{"--lock-annotation=$(LOCK_NAME)"}},
		{name: "other value expansion", args: []string{"--message-template-reboot=$(MESSAGE)"}},
		{name: "locking environment expansion", env: []corev1.EnvVar{{Name: "KURED_DS_NAME", Value: "$(LOCK_NAME)"}}},
		{name: "noncanonical environment override", env: []corev1.EnvVar{{Name: "KURED_CONCURRENCY", Value: "2"}, {Name: "KURED_concurrency", Value: "1"}}},
		{name: "duplicate locking environment", env: []corev1.EnvVar{{Name: "KURED_CONCURRENCY", Value: "2"}, {Name: "KURED_CONCURRENCY", Value: "1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds := daemonSet()
			ds.Spec.Template.Spec.Containers[0].Args = tc.args
			ds.Spec.Template.Spec.Containers[0].Env = tc.env
			k := &Kured{Client: fake.NewSimpleClientset(ds), Namespace: ds.Namespace, Name: ds.Name}
			if _, err := k.Prepare(context.Background(), "operation-uid"); err == nil {
				t.Fatal("ambiguous configuration accepted")
			}
		})
	}
}

func TestKuredAcceptsLiteralArgumentsAndExplicitLockingEnvironment(t *testing.T) {
	ds := daemonSet()
	ds.Namespace, ds.Name = "maintenance", "reboot-daemon"
	ds.Spec.Template.Spec.Containers[0].Args = []string{
		"--concurrency=1", "--lock-ttl=0", "--lock-annotation=" + LockAnnotation,
		"--message-template-reboot=Rebooting node %s", "--annotate-nodes=false",
	}
	ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
		{Name: "KURED_DS_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
		{Name: "KURED_DS_NAME", Value: ds.Name},
		{Name: "KURED_CONCURRENCY", Value: "1"},
	}
	k := &Kured{Client: fake.NewSimpleClientset(ds), Namespace: ds.Namespace, Name: ds.Name}
	ref, err := k.Prepare(context.Background(), "operation-uid")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Acquire(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
}

func TestKuredLostAcquireResponseIsResolvedWithoutASecondPatch(t *testing.T) {
	k, client, ref := fixture(t)
	patches := 0
	client.PrependReactor("patch", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
		patches++
		ds, _ := client.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("daemonsets"), ref.Namespace, ref.Name)
		copy := ds.(*appsv1.DaemonSet).DeepCopy()
		copy.Annotations[LockAnnotation] = lockValue(ref)
		_ = client.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("daemonsets"), copy, ref.Namespace)
		return true, nil, apierrors.NewTimeoutError("lost response", 0)
	})
	if err := k.Acquire(context.Background(), ref); err == nil {
		t.Fatal("injected timeout not observed")
	}
	if err := k.Acquire(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if patches != 1 {
		t.Fatal("resolved acquisition repeated a mutating request")
	}
}

func TestKuredCASConflictDoesNotClaimOwnership(t *testing.T) {
	k, client, ref := fixture(t)
	client.PrependReactor("patch", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "apps", Resource: "daemonsets"}, ref.Name, errors.New("concurrent acquisition"))
	})
	if err := k.Acquire(context.Background(), ref); !apierrors.IsConflict(err) {
		t.Fatalf("conflict not preserved: %v", err)
	}
	if err := k.Check(context.Background(), ref); !errors.Is(err, ErrLost) {
		t.Fatalf("conflict claimed lock: %v", err)
	}
}

func TestKuredCASPatchCannotOverwriteAConcurrentAcquisition(t *testing.T) {
	k, client, ref := fixture(t)
	client.PrependReactor("patch", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
		object, _ := client.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("daemonsets"), ref.Namespace, ref.Name)
		ds := object.(*appsv1.DaemonSet).DeepCopy()
		ds.ResourceVersion = "2"
		ds.Annotations[LockAnnotation] = `{"nodeID":"worker-2"}`
		_ = client.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("daemonsets"), ds, ref.Namespace)
		return false, nil, nil // Apply the real JSON Patch against the changed object.
	})
	if err := k.Acquire(context.Background(), ref); err == nil {
		t.Fatal("stale CAS patch replaced a competing owner")
	}
	ds, _ := client.AppsV1().DaemonSets(ref.Namespace).Get(context.Background(), ref.Name, metav1.GetOptions{})
	if ds.Annotations[LockAnnotation] != `{"nodeID":"worker-2"}` {
		t.Fatal("concurrent holder was changed")
	}
}

func TestKuredLostReleaseResponseDoesNotDeleteASubsequentHolder(t *testing.T) {
	k, client, ref := fixture(t)
	if err := k.Acquire(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	patches := 0
	client.PrependReactor("patch", "daemonsets", func(action ktesting.Action) (bool, runtime.Object, error) {
		patches++
		object, _ := client.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("daemonsets"), ref.Namespace, ref.Name)
		ds := object.(*appsv1.DaemonSet).DeepCopy()
		ds.Annotations[LockAnnotation] = `{"nodeID":"worker-2"}` // Release succeeded, another node acquired it.
		_ = client.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("daemonsets"), ds, ref.Namespace)
		return true, nil, apierrors.NewTimeoutError("lost release response", 0)
	})
	if err := k.Release(context.Background(), ref); err == nil {
		t.Fatal("injected timeout not observed")
	}
	if err := k.Release(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if patches != 1 {
		t.Fatal("release replayed against a subsequent holder")
	}
}
