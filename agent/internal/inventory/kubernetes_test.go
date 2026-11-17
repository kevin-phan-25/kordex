package inventory

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
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

func TestInventoryRelaysFreshOperatorCapabilities(t *testing.T) {
	now := metav1.NewMicroTime(time.Now().UTC())
	duration := int32(45)
	holder := "kordex-operator"
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "kordex-operator-capabilities", Namespace: "kordex-system", Annotations: map[string]string{
		"operations.kordex.local/host-upgrades": "true", "operations.kordex.local/gke-node-pool-upgrade": "false",
	}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &now}}
	kube := fake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, lease)
	policies := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{MaintenancePoliciesGVR: "MaintenancePolicyList"})
	report, err := (Collector{Client: kube, OperatorLease: kube.CoordinationV1().Leases("kordex-system"), PolicyReader: policies.Resource(MaintenancePoliciesGVR).Namespace("kordex-system")}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.PolicyCatalog == nil || report.PolicyCatalog.Capabilities == nil || !report.PolicyCatalog.Capabilities.HostUpgrades || report.PolicyCatalog.Capabilities.GKENodePoolUpgrade {
		t.Fatalf("fresh operator capabilities were not relayed: %+v", report.PolicyCatalog)
	}
}

func TestInventoryDoesNotTrustMalformedOperatorCapabilityLease(t *testing.T) {
	for _, test := range []struct {
		name   string
		holder string
		life   int32
	}{{name: "unowned lease", holder: "unexpected-writer", life: 45}, {name: "extended lifetime", holder: "kordex-operator", life: 600}} {
		t.Run(test.name, func(t *testing.T) {
			now := metav1.NewMicroTime(time.Now().UTC())
			lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "kordex-operator-capabilities", Namespace: "kordex-system", Annotations: map[string]string{"operations.kordex.local/host-upgrades": "true"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &test.holder, LeaseDurationSeconds: &test.life, RenewTime: &now}}
			kube := fake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, lease)
			policies := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{MaintenancePoliciesGVR: "MaintenancePolicyList"})
			report, err := (Collector{Client: kube, OperatorLease: kube.CoordinationV1().Leases("kordex-system"), PolicyReader: policies.Resource(MaintenancePoliciesGVR).Namespace("kordex-system")}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if report.PolicyCatalog == nil || report.PolicyCatalog.Capabilities != nil {
				t.Fatalf("malformed lease was relayed as capability evidence: %+v", report.PolicyCatalog)
			}
		})
	}
}
