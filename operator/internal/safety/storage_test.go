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
