package safety

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestStatelessStorageScopesPersistentVolumeChecksToTarget(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", Labels: map[string]string{"kubernetes.io/hostname": "worker-1"}}}
	remotePV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "remote-pv"},
		Spec:       corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "pd.csi.storage.gke.io", VolumeHandle: "volume-1"}}},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(remotePV).Build()
	checker := StatelessStorage{Reader: reader}
	if result, err := checker.Check(ctx, node, nil); err != nil || !result.Allowed {
		t.Fatalf("unrelated remote PV blocked target node: result=%+v err=%v", result, err)
	}

	otherNodePV := localTestPV("other-node-pv", "worker-2")
	reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(otherNodePV).Build()
	checker.Reader = reader
	if result, err := checker.Check(ctx, node, nil); err != nil || !result.Allowed {
		t.Fatalf("local PV on another node blocked target: result=%+v err=%v", result, err)
	}

	localPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "local-pv"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: "/mnt/data"}},
			NodeAffinity:           &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker-1"}}}}}}},
		},
	}
	reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(localPV).Build()
	checker.Reader = reader
	if result, err := checker.Check(ctx, node, nil); err != nil || result.Allowed || result.Reason != "NodeLocalPersistentVolumePresent" {
		t.Fatalf("target-local PV result=%+v err=%v, want block for target-local PV", result, err)
	}
}

func TestStatelessStorageChecksOpenEBSLocalPVNodeAffinity(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", Labels: map[string]string{"kubernetes.io/hostname": "worker-1", "openebs.io/nodename": "worker-1"}}}
	targetAffinity := &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "openebs.io/nodename", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker-1"}}}}}}}
	otherAffinity := &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker-2"}}}}}}}
	tests := []struct {
		name   string
		volume *corev1.PersistentVolume
		allow  bool
		reason string
	}{
		{
			name: "LVM local PV on target",
			volume: &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "lvm-target"}, Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "local.csi.openebs.io"}}, NodeAffinity: targetAffinity,
			}},
			reason: "NodeLocalPersistentVolumePresent",
		},
		{
			name: "ZFS local PV on another node",
			volume: &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "zfs-other"}, Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "zfs.csi.openebs.io"}}, NodeAffinity: otherAffinity,
			}},
			allow: true,
		},
		{
			name: "local CSI placement missing",
			volume: &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "lvm-unknown"}, Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "local.csi.openebs.io"}},
			}},
			reason: "LocalPVPlacementUnknown",
		},
		{
			name: "legacy hostpath provisioner on target",
			volume: &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "hostpath-target", Annotations: map[string]string{"pv.kubernetes.io/provisioned-by": "openebs.io/local"}}, Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/openebs/local"}}, NodeAffinity: targetAffinity,
			}},
			reason: "NodeLocalPersistentVolumePresent",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(test.volume).Build()
			result, err := (StatelessStorage{Reader: reader}).Check(ctx, node, nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.allow {
				if !result.Allowed {
					t.Fatalf("OpenEBS PV on another node blocked maintenance: %+v", result)
				}
				return
			}
			if result.Allowed || result.Reason != test.reason {
				t.Fatalf("OpenEBS local PV result=%+v, want blocked reason %q", result, test.reason)
			}
		})
	}
}

func TestStatelessStorageBlocksLonghornNodesWithoutHealthAdapter(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).Build()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "storage-1"}}
	for _, test := range []struct {
		pod    corev1.Pod
		reason string
	}{
		{pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Labels: map[string]string{"app": "longhorn-manager"}}, Spec: corev1.PodSpec{NodeName: node.Name}}, reason: "LonghornSafetyAdapterRequired"},
		{pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Labels: map[string]string{"longhorn.io/component": "instance-manager"}}, Spec: corev1.PodSpec{NodeName: node.Name}}, reason: "LonghornSafetyAdapterRequired"},
		{pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Labels: map[string]string{"app": "longhorn-manager"}}, Spec: corev1.PodSpec{NodeName: "storage-2"}}, reason: "StorageHealthUnknown"},
	} {
		result, err := (StatelessStorage{Reader: reader}).Check(ctx, node, []corev1.Pod{test.pod})
		if err != nil || result.Allowed || result.Reason != test.reason {
			t.Fatalf("Longhorn storage evidence result=%+v err=%v, want block reason %q", result, err, test.reason)
		}
	}
}

func localTestPV(name, hostname string) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: "/mnt/data"}},
			NodeAffinity:           &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{hostname}}}}}}},
		},
	}
}

func TestStatelessStorageBlocksPVCUsedOnTargetNode(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).Build()
	checker := StatelessStorage{Reader: reader}
	pod := corev1.Pod{Spec: corev1.PodSpec{NodeName: "worker-1", Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}}}}
	result, err := checker.Check(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}}, []corev1.Pod{pod})
	if err != nil || result.Allowed || result.Reason != "PersistentVolumeUsedOnTargetNode" {
		t.Fatalf("target PVC result=%+v err=%v, want fail-closed storage block", result, err)
	}
}
