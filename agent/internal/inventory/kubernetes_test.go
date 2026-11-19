package inventory

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	ktesting "k8s.io/client-go/testing"
	"kordex.local/api/protocol"
)

func TestInventoryIncludesRecoverySignals(t *testing.T) {
	created := metav1.NewTime(time.Now().Add(-time.Hour))
	kube := fake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", UID: "node-uid", CreationTimestamp: created, Labels: map[string]string{"node-role.kubernetes.io/control-plane": "", "topology.kubernetes.io/zone": "zone1", "cloud.google.com/gke-nodepool": "ubuntu-pool"}}, Spec: corev1.NodeSpec{ProviderID: "gce://project/zone/node1", Unschedulable: true, Taints: []corev1.Taint{{Key: "dedicated", Value: "control-plane", Effect: corev1.TaintEffectNoSchedule}}}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", OSImage: "Ubuntu 24.04.5 LTS", KernelVersion: "6.1", KubeletVersion: "v1.35.0", Architecture: "amd64", ContainerRuntimeVersion: "containerd://2"}, Capacity: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourcePods: resource.MustParse("110")}, Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3900m"), corev1.ResourcePods: resource.MustParse("110")}, Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}, {Type: corev1.NodeExternalIP, Address: "34.1.2.3"}}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "KubeletReady", LastTransitionTime: created}}}})
	report, err := (Collector{Client: kube}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.ClusterUID != "cluster-uid" || len(report.Nodes) != 1 || !report.Nodes[0].Ready || !report.Nodes[0].ControlPlane || !report.Nodes[0].Unschedulable {
		t.Fatalf("incorrect inventory: %+v", report)
	}
	if report.Nodes[0].Lifecycle == nil || report.Nodes[0].Lifecycle.Validate() != nil || report.Nodes[0].Lifecycle.Kubernetes.Distribution != "gke" {
		t.Fatal("inventory missed the GKE node-pool distribution hint")
	}
	node := report.Nodes[0]
	if node.OSID != "ubuntu" || node.OSVersion != "24.04.5" || node.OperatingSystem != "linux" || node.ProviderID != "gce://project/zone/node1" || node.InternalIP != "10.0.0.1" || node.ExternalIP != "34.1.2.3" || node.CreatedAt.IsZero() || node.Capacity["pods"] != "110" || node.Allocatable["cpu"] != "3900m" || len(node.Taints) != 1 || len(node.Conditions) != 1 || node.Lifecycle.Kubernetes.NodePool != "ubuntu-pool" {
		t.Fatalf("detailed node inventory incomplete: %+v", node)
	}
}

func TestClassifyOSImage(t *testing.T) {
	for _, tc := range []struct{ image, id, version string }{
		{"Container-Optimized OS from Google", "cos", ""},
		{"Ubuntu 24.04.5 LTS", "ubuntu", "24.04.5"},
		{"Rocky Linux 9.5 (Blue Onyx)", "rocky", "9.5"},
		{"unfamiliar image", "unknown", ""},
	} {
		id, version := ClassifyOSImage(tc.image)
		if id != tc.id || version != tc.version {
			t.Errorf("ClassifyOSImage(%q)=(%q,%q), want (%q,%q)", tc.image, id, version, tc.id, tc.version)
		}
	}
}

func TestCollectorKeepsUnknownOSAndNotReadyNodeExplicit(t *testing.T) {
	kube := fake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-unknown", UID: "worker-uid"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OSImage: "Unrecognized node image"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse, Reason: "KubeletNotReady"}}}},
	)
	report, err := (Collector{Client: kube}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Nodes) != 1 {
		t.Fatalf("unexpected node count: %d", len(report.Nodes))
	}
	node := report.Nodes[0]
	if node.Ready || node.OSID != "unknown" || node.OSVersion != "" || node.UID != "worker-uid" || node.Name != "worker-unknown" || node.ProviderID != "" || node.InternalIP != "" || node.Labels == nil || len(node.Labels) != 0 {
		t.Fatalf("missing metadata was not represented safely: %+v", node)
	}
}

func TestMaintenancePolicyCatalogCarriesExplicitAllowedActions(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "operations.kordex.local/v1alpha1",
		"kind":       "MaintenancePolicy",
		"metadata":   map[string]any{"name": "safe", "uid": "policy-uid", "generation": int64(2)},
		"spec": map[string]any{
			"nodeSelector":          map[string]any{"matchLabels": map[string]any{"pool": "worker"}},
			"protectedNodeSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "maintenance", "operator": "In", "values": []any{"forbidden"}}}},
			"allowedActions":        []any{protocol.ValidateOnly, protocol.DrainAndVerify},
		},
	}}
	entry, err := maintenancePolicyEntry(object)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.MaintenancePolicyAllows(entry.AllowedActions, protocol.ValidateOnly) || !protocol.MaintenancePolicyAllows(entry.AllowedActions, protocol.DrainAndVerify) || protocol.MaintenancePolicyAllows(entry.AllowedActions, protocol.UpgradePackages) {
		t.Fatalf("policy catalog did not retain the explicit action ceiling: %+v", entry)
	}
	decision := protocol.EvaluateProtectedNode(entry.ProtectedNodeSelector, map[string]string{"maintenance": "forbidden"})
	if decision.Allowed || decision.ReasonCode != "ProtectedNode" {
		t.Fatalf("agent catalog dropped the protected-node veto: %+v", entry)
	}
}

func TestClusterCapabilityInventoryReportsBoundedAdvisoryEvidence(t *testing.T) {
	kube := fake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kordex-system", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "kube-system"}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "kube-proxy", Namespace: "kube-system"}},
		&storagev1.CSINode{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}, Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{{Name: "pd.csi.storage.example"}}}},
		&storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "standard"}, Provisioner: "pd.csi.storage.example"},
	)
	kube.Discovery().(*fakediscovery.FakeDiscovery).Resources = []*metav1.APIResourceList{{GroupVersion: "admissionregistration.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "mutatingwebhookconfigurations"}, {Name: "validatingwebhookconfigurations"}, {Name: "validatingadmissionpolicies"}, {Name: "validatingadmissionpolicybindings"}}}}
	metadata := admissionMetadataClient(map[string]int{"mutatingwebhookconfigurations": 1, "validatingwebhookconfigurations": 1, "validatingadmissionpolicies": 1, "validatingadmissionpolicybindings": 1})
	capabilities := (Collector{Client: kube, Metadata: metadata, Namespace: "kordex-system"}).collectClusterCapabilities(context.Background())
	if err := capabilities.Validate(time.Now().UTC()); err != nil {
		t.Fatalf("collected capability inventory is invalid: %v; %+v", err, capabilities)
	}
	if capabilities.CNIHints.State != "Observed" || len(capabilities.CNIHints.Values) != 1 || capabilities.CNIHints.Values[0] != "calico" {
		t.Fatalf("CNI name hints were not reported as advisory evidence: %+v", capabilities.CNIHints)
	}
	if capabilities.CSIDrivers.Values[0] != "pd.csi.storage.example" || capabilities.StorageProvisioners.Values[0] != "pd.csi.storage.example" {
		t.Fatalf("CSI inventory mismatch: CSI=%+v classes=%+v", capabilities.CSIDrivers, capabilities.StorageProvisioners)
	}
	wantAdmissionCounts := []string{"mutatingwebhookconfigurations=1", "validatingadmissionpolicies=1", "validatingadmissionpolicybindings=1", "validatingwebhookconfigurations=1"}
	if !slices.Equal(capabilities.AdmissionAPIs.Values, wantAdmissionCounts) || capabilities.PodSecurityNamespaceLabels.Values[0] != "pod-security.kubernetes.io/enforce=restricted" {
		t.Fatalf("admission or Pod Security signals missing: admission=%+v labels=%+v", capabilities.AdmissionAPIs, capabilities.PodSecurityNamespaceLabels)
	}
	if actions := metadata.Actions(); len(actions) != 4 {
		t.Fatalf("expected one metadata-only list per served admission resource, got %v", actions)
	}
	for _, action := range kube.Actions() {
		if action.GetResource().Group == "admissionregistration.k8s.io" {
			t.Fatalf("full admission object client was used: %+v", action)
		}
	}
}

func TestAdmissionConfigurationPermissionFailureRemainsUnknown(t *testing.T) {
	kube := fake.NewClientset()
	kube.Discovery().(*fakediscovery.FakeDiscovery).Resources = []*metav1.APIResourceList{{GroupVersion: "admissionregistration.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "mutatingwebhookconfigurations"}}}}
	kube.Fake.PrependReactor("list", "mutatingwebhookconfigurations", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingwebhookconfigurations"}, "", fmt.Errorf("denied"))
	})
	metadata := admissionMetadataClient(nil)
	metadata.PrependReactor("list", "mutatingwebhookconfigurations", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingwebhookconfigurations"}, "", fmt.Errorf("denied"))
	})
	observation := (Collector{Client: kube, Metadata: metadata}).collectAdmissionConfiguration(context.Background())
	if observation.State != "Unknown" || observation.ReasonCode != "PermissionDenied" || len(observation.Values) != 0 {
		t.Fatalf("admission permission failure must fail closed without partial counts: %+v", observation)
	}
}

func TestClusterCapabilityInventoryKeepsDeniedEvidenceUnknown(t *testing.T) {
	kube := fake.NewClientset()
	denied := func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "inventory"}, "", fmt.Errorf("denied"))
	}
	for _, resource := range []string{"daemonsets", "csinodes", "storageclasses", "namespaces"} {
		kube.Fake.PrependReactor("list", resource, denied)
		kube.Fake.PrependReactor("get", resource, denied)
	}
	kube.Discovery().(*fakediscovery.FakeDiscovery).Resources = []*metav1.APIResourceList{{GroupVersion: "admissionregistration.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "mutatingwebhookconfigurations"}}}}
	metadata := admissionMetadataClient(nil)
	metadata.PrependReactor("list", "*", denied)
	capabilities := (Collector{Client: kube, Metadata: metadata, Namespace: "kordex-system"}).collectClusterCapabilities(context.Background())
	for name, observation := range map[string]protocol.CapabilityObservation{
		"CNI": capabilities.CNIHints, "CSI": capabilities.CSIDrivers,
		"storage": capabilities.StorageProvisioners, "admission": capabilities.AdmissionAPIs,
		"Pod Security": capabilities.PodSecurityNamespaceLabels,
	} {
		if observation.State != "Unknown" || len(observation.Values) != 0 {
			t.Errorf("%s permission failure was not kept unknown: %+v", name, observation)
		}
		if observation.ReasonCode != "PermissionDenied" {
			t.Errorf("%s permission failure has unstable or misleading reason code: %+v", name, observation)
		}
	}
}

func TestCNIInventoryDoesNotClaimAnUnrecognizedDaemonSet(t *testing.T) {
	kube := fake.NewClientset(&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "vendor-network-agent", Namespace: "kube-system"}})
	observation := (Collector{Client: kube}).collectCNIHints(context.Background())
	if observation.State != "Unknown" || observation.ReasonCode != "NoRecognizedHint" || len(observation.Values) != 0 {
		t.Fatalf("unrecognized DaemonSet name was treated as CNI identity: %+v", observation)
	}
}

func admissionMetadataClient(counts map[string]int) *metadatafake.FakeMetadataClient {
	scheme := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		panic(err)
	}
	client := metadatafake.NewSimpleMetadataClient(scheme)
	kinds := map[string]string{
		"mutatingwebhookconfigurations":     "MutatingWebhookConfiguration",
		"validatingwebhookconfigurations":   "ValidatingWebhookConfiguration",
		"validatingadmissionpolicies":       "ValidatingAdmissionPolicy",
		"validatingadmissionpolicybindings": "ValidatingAdmissionPolicyBinding",
	}
	client.PrependReactor("list", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		count := counts[action.GetResource().Resource]
		items := make([]runtime.RawExtension, 0, count)
		for i := 0; i < count; i++ {
			object := &metav1.PartialObjectMetadata{
				TypeMeta:   metav1.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: kinds[action.GetResource().Resource]},
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("private-admission-object-%d", i)},
			}
			items = append(items, runtime.RawExtension{Object: object})
		}
		return true, &metav1.List{Items: items}, nil
	})
	return client
}

func TestInventoryRelaysFreshOperatorCapabilities(t *testing.T) {
	now := metav1.NewMicroTime(time.Now().UTC())
	duration := int32(45)
	holder := "kordex-operator"
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "kordex-operator-capabilities", Namespace: "kordex-system", Annotations: map[string]string{
		"operations.kordex.local/node-maintenance": "true", "operations.kordex.local/host-upgrades": "true", "operations.kordex.local/gke-node-pool-upgrade": "false",
	}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &now}}
	kube := fake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, lease)
	policies := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{MaintenancePoliciesGVR: "MaintenancePolicyList"})
	report, err := (Collector{Client: kube, OperatorLease: kube.CoordinationV1().Leases("kordex-system"), PolicyReader: policies.Resource(MaintenancePoliciesGVR).Namespace("kordex-system")}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.PolicyCatalog == nil || report.PolicyCatalog.Capabilities == nil || !report.PolicyCatalog.Capabilities.NodeMaintenance || !report.PolicyCatalog.Capabilities.HostUpgrades || report.PolicyCatalog.Capabilities.GKENodePoolUpgrade {
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
