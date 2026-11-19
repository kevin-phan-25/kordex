package safety

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLonghornStorageRequiresFreshHealthyEvidenceAndNoTargetReplica(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	newStorage := func(objects ...runtime.Object) LonghornStorage {
		return LonghornStorage{
			Reader:  fake.NewClientBuilder().WithScheme(longhornReaderScheme(t)).Build(),
			Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), longhornListKinds(), objects...),
			Now:     func() time.Time { return now },
		}
	}
	target := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-target"}}
	objects := []runtime.Object{
		longhornNode("worker-target", now), longhornNode("worker-a", now), longhornNode("worker-b", now),
		longhornVolume("vol-a", "attached", "healthy", "worker-a", 2, nil),
		longhornReplica("replica-a", "vol-a", "worker-a", "running"),
		longhornReplica("replica-b", "vol-a", "worker-b", "running"),
	}
	storage := newStorage(objects...)
	if result, err := storage.Check(context.Background(), target, nil); err != nil || !result.Allowed {
		t.Fatalf("healthy replicated volume on other nodes blocked unrelated target: result=%+v err=%v", result, err)
	}

	storage = newStorage(
		longhornNode("worker-target", now), longhornNode("worker-a", now),
		longhornVolume("vol-a", "attached", "healthy", "worker-a", 2, nil),
		longhornReplica("replica-a", "vol-a", "worker-a", "running"),
		longhornReplica("replica-b", "vol-a", "worker-target", "running"),
	)
	if result, err := storage.Check(context.Background(), target, nil); err != nil || result.Allowed || result.Reason != "LonghornReplicaOnTarget" {
		t.Fatalf("replica on target must block: result=%+v err=%v", result, err)
	}

	storage = newStorage(
		longhornNode("worker-target", now), longhornNode("worker-a", now), longhornNode("worker-b", now),
		longhornVolume("vol-a", "attached", "healthy", "worker-target", 2, nil),
		longhornReplica("replica-a", "vol-a", "worker-a", "running"),
		longhornReplica("replica-b", "vol-a", "worker-b", "running"),
	)
	if result, err := storage.Check(context.Background(), target, nil); err != nil || result.Allowed || result.Reason != "LonghornVolumeAttachedToTarget" {
		t.Fatalf("volume attached to target must block: result=%+v err=%v", result, err)
	}
}

func TestLonghornStorageBlocksDegradedRebuildingAndStaleEvidence(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		objects []runtime.Object
		reason  string
	}{
		{
			name: "degraded volume",
			objects: []runtime.Object{
				longhornNode("worker-target", now), longhornNode("worker-a", now), longhornNode("worker-b", now),
				longhornVolume("vol-a", "attached", "degraded", "worker-a", 2, nil),
				longhornReplica("replica-a", "vol-a", "worker-a", "running"), longhornReplica("replica-b", "vol-a", "worker-b", "running"),
			},
			reason: "LonghornVolumeNotHealthy",
		},
		{
			name: "rebuild active",
			objects: []runtime.Object{
				longhornNode("worker-target", now), longhornNode("worker-a", now), longhornNode("worker-b", now),
				longhornVolume("vol-a", "attached", "healthy", "worker-a", 2, map[string]interface{}{"replica-a": map[string]interface{}{"isRebuilding": true}}),
				longhornReplica("replica-a", "vol-a", "worker-a", "running"), longhornReplica("replica-b", "vol-a", "worker-b", "running"),
			},
			reason: "LonghornRebuildInProgress",
		},
		{
			name: "stale node probe",
			objects: []runtime.Object{
				longhornNode("worker-target", now.Add(-3*time.Minute)), longhornNode("worker-a", now), longhornNode("worker-b", now),
				longhornVolume("vol-a", "attached", "healthy", "worker-a", 2, nil),
				longhornReplica("replica-a", "vol-a", "worker-a", "running"), longhornReplica("replica-b", "vol-a", "worker-b", "running"),
			},
			reason: "LonghornNodeEvidenceStale",
		},
		{
			name: "missing replica",
			objects: []runtime.Object{
				longhornNode("worker-target", now), longhornNode("worker-a", now),
				longhornVolume("vol-a", "attached", "healthy", "worker-a", 2, nil),
				longhornReplica("replica-a", "vol-a", "worker-a", "running"),
			},
			reason: "LonghornReplicaCountMismatch",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := LonghornStorage{
				Reader:  fake.NewClientBuilder().WithScheme(longhornReaderScheme(t)).Build(),
				Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), longhornListKinds(), test.objects...),
				Now:     func() time.Time { return now },
			}
			result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-target"}}, nil)
			if err != nil || result.Allowed || result.Reason != test.reason {
				t.Fatalf("result=%+v err=%v, want fail-closed reason %q", result, err, test.reason)
			}
		})
	}

	for _, signal := range []struct {
		name   string
		path   []string
		value  interface{}
		reason string
	}{
		{name: "migration", path: []string{"status", "currentMigrationNodeID"}, value: "worker-a", reason: "LonghornMigrationInProgress"},
		{name: "restore", path: []string{"status", "restoreStatus", "isRestoring"}, value: true, reason: "LonghornRestoreInProgress"},
	} {
		t.Run(signal.name, func(t *testing.T) {
			volume := longhornVolume("vol-a", "attached", "healthy", "worker-a", 2, nil)
			path := append([]string(nil), signal.path...)
			if err := unstructured.SetNestedField(volume.Object, signal.value, path...); err != nil {
				t.Fatal(err)
			}
			storage := LonghornStorage{
				Reader: fake.NewClientBuilder().WithScheme(longhornReaderScheme(t)).Build(),
				Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), longhornListKinds(),
					longhornNode("worker-target", now), longhornNode("worker-a", now), longhornNode("worker-b", now), volume,
					longhornReplica("replica-a", "vol-a", "worker-a", "running"), longhornReplica("replica-b", "vol-a", "worker-b", "running")),
				Now: func() time.Time { return now },
			}
			result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-target"}}, nil)
			if err != nil || result.Allowed || result.Reason != signal.reason {
				t.Fatalf("result=%+v err=%v, want fail-closed reason %q", result, err, signal.reason)
			}
		})
	}
}

func TestLonghornStorageBlocksServiceNodeAndUnknownFootprint(t *testing.T) {
	ctx := context.Background()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-target"}}
	reader := fake.NewClientBuilder().WithScheme(longhornReaderScheme(t)).Build()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), longhornListKinds())
	storage := LonghornStorage{Reader: reader, Dynamic: dyn}
	manager := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Labels: map[string]string{"app": "longhorn-manager"}}, Spec: corev1.PodSpec{NodeName: node.Name}}
	if result, err := storage.Check(ctx, node, []corev1.Pod{manager}); err != nil || result.Allowed || result.Reason != "LonghornMaintenanceWorkflowRequired" {
		t.Fatalf("Longhorn service node must remain blocked: result=%+v err=%v", result, err)
	}

	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "lh-pv"}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io"}}}}
	reader = fake.NewClientBuilder().WithScheme(longhornReaderScheme(t)).WithObjects(pv).Build()
	storage.Reader = reader
	if result, err := storage.Check(ctx, node, nil); err != nil || result.Allowed || result.Reason != "LonghornNodeInventoryUnknown" {
		t.Fatalf("Longhorn PV with missing CR inventory must block: result=%+v err=%v", result, err)
	}
}

func TestLonghornStorageFallsBackWhenNoLonghornFootprintExists(t *testing.T) {
	storage := LonghornStorage{
		Reader:  fake.NewClientBuilder().WithScheme(longhornReaderScheme(t)).Build(),
		Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), longhornListKinds()),
	}
	result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-target"}}, nil)
	if err != nil || !result.Allowed {
		t.Fatalf("cluster without Longhorn footprint should defer to generic storage checks: result=%+v err=%v", result, err)
	}
}

func TestRookStorageComposesLonghornEvidenceBeforeGenericChecks(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	objects := []runtime.Object{
		longhornNode("worker-target", now), longhornNode("worker-a", now), longhornNode("worker-b", now),
		longhornVolume("vol-a", "attached", "healthy", "worker-a", 2, nil),
		longhornReplica("replica-a", "vol-a", "worker-a", "running"),
		longhornReplica("replica-b", "vol-a", "worker-b", "running"),
	}
	listKinds := longhornListKinds()
	listKinds[schema.GroupVersionResource{Group: "ceph.rook.io", Version: "v1", Resource: "cephclusters"}] = "CephClusterList"
	reader := fake.NewClientBuilder().WithScheme(longhornReaderScheme(t)).Build()
	storage := RookCephStorage{
		Reader:  reader,
		Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...),
		Now:     func() time.Time { return now },
	}
	remoteManager := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Labels: map[string]string{"app": "longhorn-manager"}}, Spec: corev1.PodSpec{NodeName: "worker-a"}}
	if result, err := storage.Check(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-target"}}, []corev1.Pod{remoteManager}); err != nil || !result.Allowed {
		t.Fatalf("healthy remote Longhorn service pod should be filtered after adapter validation: result=%+v err=%v", result, err)
	}
}

func longhornReaderScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func longhornListKinds() map[schema.GroupVersionResource]string {
	return map[schema.GroupVersionResource]string{
		longhornNodes: "NodeList", longhornVolumes: "VolumeList", longhornReplicas: "ReplicaList",
	}
}

func longhornNode(name string, probe time.Time) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "longhorn.io/v1beta2", "kind": "Node",
		"metadata": map[string]interface{}{"name": name, "namespace": "longhorn-system"},
		"status": map[string]interface{}{"conditions": []interface{}{map[string]interface{}{
			"type": "Ready", "status": "True", "lastProbeTime": probe.UTC().Format(time.RFC3339),
		}}},
	}}
}

func longhornVolume(name, state, robustness, currentNode string, replicas int64, rebuild map[string]interface{}) *unstructured.Unstructured {
	status := map[string]interface{}{"state": state, "robustness": robustness, "currentNodeID": currentNode}
	if rebuild != nil {
		status["rebuildStatus"] = rebuild
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "longhorn.io/v1beta2", "kind": "Volume",
		"metadata": map[string]interface{}{"name": name, "namespace": "longhorn-system"},
		"spec":     map[string]interface{}{"numberOfReplicas": replicas, "dataLayout": "v1"},
		"status":   status,
	}}
}

func longhornReplica(name, volume, node, state string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "longhorn.io/v1beta2", "kind": "Replica",
		"metadata": map[string]interface{}{"name": name, "namespace": "longhorn-system"},
		"spec":     map[string]interface{}{"volumeName": volume, "nodeID": node, "healthyAt": "2026-11-19T11:00:00Z", "failedAt": ""},
		"status":   map[string]interface{}{"currentState": state},
	}}
}
