package inventory

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInventoryIncludesRecoverySignals(t *testing.T) {
	kube := fake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", UID: "node-uid", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "", "topology.kubernetes.io/zone": "zone1"}}, Spec: corev1.NodeSpec{Unschedulable: true}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OSImage: "Linux", KernelVersion: "6.1", KubeletVersion: "v1.35.0"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}})
	report, err := (Collector{Client: kube}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.ClusterUID != "cluster-uid" || len(report.Nodes) != 1 || !report.Nodes[0].Ready || !report.Nodes[0].ControlPlane || !report.Nodes[0].Unschedulable {
		t.Fatalf("incorrect inventory: %+v", report)
	}
}
