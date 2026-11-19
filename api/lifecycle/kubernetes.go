package lifecycle

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// KubernetesPermissionRule records a narrow Kubernetes RBAC grant from the
// checked-in operator manifests. Empty APIGroup denotes the core API group.
type KubernetesPermissionRule struct {
	Scope           string   `json:"scope"`
	APIGroup        string   `json:"apiGroup"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type KubernetesPermissionProfile struct {
	ID              string                     `json:"id"`
	Description     string                     `json:"description"`
	Rules           []KubernetesPermissionRule `json:"rules"`
	ProviderActions []string                   `json:"providerActions"`
}

// KubernetesCompatibility describes known integration targets. Empty
// qualified-version/OS/architecture lists mean that no such combination has
// passed Kordex's distribution qualification; they are never inferred from a
// successful generic API call or a related distribution.
type KubernetesCompatibility struct {
	ID                            string             `json:"id"`
	DisplayName                   string             `json:"displayName"`
	Qualification                 Support            `json:"qualification"`
	Identification                string             `json:"identification"`
	QualifiedKubernetesVersions   []string           `json:"qualifiedKubernetesVersions"`
	QualifiedNodeOperatingSystems []string           `json:"qualifiedNodeOperatingSystems"`
	QualifiedArchitectures        []string           `json:"qualifiedArchitectures"`
	RequiredPermissionProfiles    []string           `json:"requiredPermissionProfiles"`
	OptionalPermissionProfiles    []string           `json:"optionalPermissionProfiles"`
	RequiredCRDs                  []string           `json:"requiredCRDs"`
	NetworkRequirements           []string           `json:"networkRequirements"`
	OptionalNetworkRequirements   []string           `json:"optionalNetworkRequirements"`
	Operations                    map[string]Support `json:"operations"`
	AutomatedTestCoverage         []string           `json:"automatedTestCoverage"`
	KnownLimitations              []string           `json:"knownLimitations"`
}

type KubernetesCompatibilityCatalog struct {
	Items              []KubernetesCompatibility     `json:"items"`
	PermissionProfiles []KubernetesPermissionProfile `json:"permissionProfiles"`
}

// ClusterCompatibility summarizes advisory node inventory against the
// qualification registry. It cannot grant maintenance or infer host identity
// from Kubernetes Node OS display strings.
type ClusterCompatibility struct {
	Status                string   `json:"status"`
	DistributionHints     []string `json:"distributionHints"`
	NodeCount             int      `json:"nodeCount"`
	DistinctOSImages      int      `json:"distinctOSImages"`
	DistinctArchitectures int      `json:"distinctArchitectures"`
	ReasonCodes           []string `json:"reasonCodes"`
}

func AssessClusterCompatibility(nodeCount, distinctOSImages, distinctArchitectures int, distributionHints []string, registry *KubernetesCompatibilityRegistry) ClusterCompatibility {
	distributions := map[string]struct{}{}
	hasUnknown := false
	for _, distribution := range distributionHints {
		if strings.TrimSpace(distribution) == "" {
			distribution = "unknown"
		}
		if distribution == "unknown" {
			hasUnknown = true
		}
		distributions[distribution] = struct{}{}
	}
	sortedDistributions := make([]string, 0, len(distributions))
	for distribution := range distributions {
		sortedDistributions = append(sortedDistributions, distribution)
	}
	slices.Sort(sortedDistributions)
	result := ClusterCompatibility{
		Status: "Unknown", DistributionHints: sortedDistributions,
		NodeCount: max(nodeCount, 0), DistinctOSImages: max(distinctOSImages, 0),
		DistinctArchitectures: max(distinctArchitectures, 0), ReasonCodes: []string{},
	}
	if nodeCount <= 0 {
		result.ReasonCodes = []string{"NoNodeInventory"}
		return result
	}
	knownDistributions := len(sortedDistributions)
	if hasUnknown {
		knownDistributions--
	}
	if knownDistributions > 1 {
		result.Status = "MixedSignals"
		result.ReasonCodes = []string{"MixedDistributionHints"}
		return result
	}
	if hasUnknown || knownDistributions != 1 {
		result.ReasonCodes = []string{"DistributionUnknown"}
		return result
	}
	// Unknown node hints make the cluster identity incomplete even when the
	// remaining nodes share one known hint. Keep those signals visible without
	// mislabeling them as conflicting distributions.
	if len(sortedDistributions) != 1 {
		result.ReasonCodes = []string{"DistributionUnknown"}
		return result
	}
	if registry == nil {
		result.Status = "Unqualified"
		result.ReasonCodes = []string{"CompatibilityRegistryUnavailable"}
		return result
	}
	entry, exists := registry.Lookup(sortedDistributions[0])
	if !exists {
		result.Status = "Unqualified"
		result.ReasonCodes = []string{"DistributionNotInRegistry"}
		return result
	}
	if entry.Qualification != Qualified || len(entry.QualifiedKubernetesVersions) == 0 || len(entry.QualifiedNodeOperatingSystems) == 0 || len(entry.QualifiedArchitectures) == 0 {
		result.Status = "Unqualified"
		result.ReasonCodes = []string{"QualificationEvidenceMissing"}
		return result
	}
	// Node.status.nodeInfo.osImage is a display string, not the host's
	// normalized os-release ID/major. It cannot satisfy the registry's OS
	// qualification contract, even if Kubernetes and architecture are known.
	result.ReasonCodes = []string{"NodeOSReleaseIdentityUnavailable"}
	return result
}

// KubernetesCompatibilityRegistry is immutable after construction. It is
// descriptive metadata only and has no method that grants execution.
type KubernetesCompatibilityRegistry struct {
	items    []KubernetesCompatibility
	profiles []KubernetesPermissionProfile
}

func NewKubernetesCompatibilityRegistry(items []KubernetesCompatibility, profiles []KubernetesPermissionProfile) (*KubernetesCompatibilityRegistry, error) {
	profileIDs := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if strings.TrimSpace(profile.ID) == "" || strings.TrimSpace(profile.Description) == "" || len(profile.Rules)+len(profile.ProviderActions) == 0 || profileIDs[profile.ID] {
			return nil, errors.New("invalid or duplicate Kubernetes permission profile")
		}
		profileIDs[profile.ID] = true
		for _, rule := range profile.Rules {
			if rule.Scope == "" || len(rule.Resources)+len(rule.NonResourceURLs) == 0 || len(rule.Verbs) == 0 {
				return nil, fmt.Errorf("invalid Kubernetes permission rule in profile %s", profile.ID)
			}
		}
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.DisplayName) == "" || strings.TrimSpace(item.Identification) == "" || seen[item.ID] {
			return nil, errors.New("invalid or duplicate Kubernetes compatibility entry")
		}
		// A registry entry cannot assert support or qualification. Those states
		// require a separate reviewed evidence-backed activation process.
		if item.Qualification != Unverified && item.Qualification != Unsupported {
			return nil, fmt.Errorf("Kubernetes registry cannot confer qualification for %s", item.ID)
		}
		if len(item.QualifiedKubernetesVersions)+len(item.QualifiedNodeOperatingSystems)+len(item.QualifiedArchitectures) != 0 {
			return nil, fmt.Errorf("unqualified Kubernetes entry %s cannot list qualified versions, OSs, or architectures", item.ID)
		}
		if len(item.RequiredCRDs) == 0 || len(item.NetworkRequirements) == 0 || len(item.KnownLimitations) == 0 {
			return nil, fmt.Errorf("incomplete Kubernetes compatibility requirements for %s", item.ID)
		}
		for _, id := range item.RequiredPermissionProfiles {
			if !profileIDs[id] {
				return nil, fmt.Errorf("unknown Kubernetes permission profile %q for %s", id, item.ID)
			}
		}
		for _, id := range item.OptionalPermissionProfiles {
			if !profileIDs[id] {
				return nil, fmt.Errorf("unknown optional Kubernetes permission profile %q for %s", id, item.ID)
			}
		}
		for operation, state := range item.Operations {
			if strings.TrimSpace(operation) == "" || state != Unsupported && state != Unverified {
				return nil, fmt.Errorf("Kubernetes registry cannot assert operation qualification for %s", item.ID)
			}
		}
		if item.Qualification == Unsupported && len(item.Operations) == 0 {
			return nil, fmt.Errorf("unsupported Kubernetes entry %s must state its operation boundary", item.ID)
		}
		seen[item.ID] = true
	}
	r := &KubernetesCompatibilityRegistry{}
	for _, item := range items {
		r.items = append(r.items, cloneKubernetesCompatibility(item))
	}
	for _, profile := range profiles {
		r.profiles = append(r.profiles, cloneKubernetesPermissionProfile(profile))
	}
	return r, nil
}

func (r *KubernetesCompatibilityRegistry) Catalog() KubernetesCompatibilityCatalog {
	result := KubernetesCompatibilityCatalog{}
	for _, item := range r.items {
		result.Items = append(result.Items, cloneKubernetesCompatibility(item))
	}
	for _, profile := range r.profiles {
		result.PermissionProfiles = append(result.PermissionProfiles, cloneKubernetesPermissionProfile(profile))
	}
	return result
}

func (r *KubernetesCompatibilityRegistry) Lookup(id string) (KubernetesCompatibility, bool) {
	for _, item := range r.items {
		if item.ID == id {
			return cloneKubernetesCompatibility(item), true
		}
	}
	return KubernetesCompatibility{}, false
}

func cloneKubernetesCompatibility(item KubernetesCompatibility) KubernetesCompatibility {
	item.QualifiedKubernetesVersions = cloneKubernetesStrings(item.QualifiedKubernetesVersions)
	item.QualifiedNodeOperatingSystems = cloneKubernetesStrings(item.QualifiedNodeOperatingSystems)
	item.QualifiedArchitectures = cloneKubernetesStrings(item.QualifiedArchitectures)
	item.RequiredPermissionProfiles = cloneKubernetesStrings(item.RequiredPermissionProfiles)
	item.OptionalPermissionProfiles = cloneKubernetesStrings(item.OptionalPermissionProfiles)
	item.RequiredCRDs = cloneKubernetesStrings(item.RequiredCRDs)
	item.NetworkRequirements = cloneKubernetesStrings(item.NetworkRequirements)
	item.OptionalNetworkRequirements = cloneKubernetesStrings(item.OptionalNetworkRequirements)
	item.AutomatedTestCoverage = cloneKubernetesStrings(item.AutomatedTestCoverage)
	item.KnownLimitations = cloneKubernetesStrings(item.KnownLimitations)
	operations := item.Operations
	item.Operations = make(map[string]Support, len(operations))
	for name, status := range operations {
		item.Operations[name] = status
	}
	return item
}

func cloneKubernetesPermissionProfile(profile KubernetesPermissionProfile) KubernetesPermissionProfile {
	if profile.Rules == nil {
		profile.Rules = []KubernetesPermissionRule{}
	} else {
		profile.Rules = slices.Clone(profile.Rules)
	}
	for i := range profile.Rules {
		profile.Rules[i].Resources = cloneKubernetesStrings(profile.Rules[i].Resources)
		profile.Rules[i].Verbs = cloneKubernetesStrings(profile.Rules[i].Verbs)
		profile.Rules[i].ResourceNames = cloneKubernetesStrings(profile.Rules[i].ResourceNames)
		profile.Rules[i].NonResourceURLs = cloneKubernetesStrings(profile.Rules[i].NonResourceURLs)
	}
	profile.ProviderActions = cloneKubernetesStrings(profile.ProviderActions)
	return profile
}

func cloneKubernetesStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return slices.Clone(values)
}

// BuiltinKubernetesCompatibilityRegistry records the current tested surface.
// No distribution/version/OS/architecture combination is qualified today.
func BuiltinKubernetesCompatibilityRegistry() *KubernetesCompatibilityRegistry {
	profiles := []KubernetesPermissionProfile{
		{
			ID:          "agent-inventory",
			Description: "Read-only Kordex agent inventory permissions for node facts, admission configuration counts, storage drivers/classes, Pod Security labels in the Kordex namespace, and advisory CNI DaemonSet name hints in kube-system.",
			Rules: []KubernetesPermissionRule{
				{Scope: "cluster", APIGroup: "", Resources: []string{"nodes"}, Verbs: []string{"list"}},
				{Scope: "cluster", APIGroup: "", Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system", "Kordex agent namespace"}, Verbs: []string{"get"}},
				{Scope: "cluster", APIGroup: "storage.k8s.io", Resources: []string{"csinodes", "storageclasses"}, Verbs: []string{"list"}},
				{Scope: "cluster", APIGroup: "admissionregistration.k8s.io", Resources: []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings"}, Verbs: []string{"list"}},
				{Scope: "cluster", NonResourceURLs: []string{"/version", "/api", "/api/*", "/apis", "/apis/*"}, Verbs: []string{"get"}},
				{Scope: "kube-system namespace", APIGroup: "apps", Resources: []string{"daemonsets"}, Verbs: []string{"list"}},
			},
		},
		{
			ID:          "operator-default",
			Description: "Kordex operator ClusterRole, namespace Role, heartbeat Role, and operation-ledger Role as rendered by Helm/Kustomize.",
			Rules: []KubernetesPermissionRule{
				{Scope: "cluster", APIGroup: "", Resources: []string{"nodes"}, Verbs: []string{"get", "list", "patch"}},
				{Scope: "cluster", APIGroup: "", Resources: []string{"pods", "persistentvolumes", "services"}, Verbs: []string{"get", "list"}},
				{Scope: "cluster", APIGroup: "", Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system"}, Verbs: []string{"get"}},
				{Scope: "cluster", APIGroup: "", Resources: []string{"pods/eviction"}, Verbs: []string{"create"}},
				{Scope: "cluster", APIGroup: "apps", Resources: []string{"deployments", "replicasets", "daemonsets"}, Verbs: []string{"get", "list"}},
				{Scope: "cluster", APIGroup: "policy", Resources: []string{"poddisruptionbudgets"}, Verbs: []string{"get", "list"}},
				{Scope: "cluster", APIGroup: "authorization.k8s.io", Resources: []string{"selfsubjectaccessreviews"}, Verbs: []string{"create"}},
				{Scope: "cluster", APIGroup: "ceph.rook.io", Resources: []string{"cephclusters"}, Verbs: []string{"get", "list"}},
				{Scope: "cluster", APIGroup: "longhorn.io", Resources: []string{"nodes", "replicas", "volumes"}, Verbs: []string{"get", "list"}},
				{Scope: "cluster", NonResourceURLs: []string{"/readyz"}, Verbs: []string{"get"}},
				{Scope: "kordex-system namespace", APIGroup: "", Resources: []string{"events"}, Verbs: []string{"create", "patch"}},
				{Scope: "kordex-system namespace", APIGroup: "", Resources: []string{"configmaps"}, Verbs: []string{"get", "create"}},
				{Scope: "kordex-system namespace", APIGroup: "", Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
				{Scope: "kordex-system namespace", APIGroup: "", Resources: []string{"pods/log"}, Verbs: []string{"get"}},
				{Scope: "kordex-system namespace", APIGroup: "batch", Resources: []string{"jobs"}, Verbs: []string{"get", "list", "watch", "create", "update", "delete"}},
				{Scope: "kordex-system namespace", APIGroup: "operations.kordex.local", Resources: []string{"nodemaintenances"}, Verbs: []string{"get", "list", "watch", "update", "patch"}},
				{Scope: "kordex-system namespace", APIGroup: "operations.kordex.local", Resources: []string{"maintenancepolicies", "maintenancecampaigns"}, Verbs: []string{"get", "list", "watch"}},
				{Scope: "kordex-system namespace", APIGroup: "operations.kordex.local", Resources: []string{"nodemaintenances/status", "maintenancepolicies/status", "maintenancecampaigns/status"}, Verbs: []string{"get", "update", "patch"}},
				{Scope: "kordex-system namespace", APIGroup: "coordination.k8s.io", Resources: []string{"leases"}, ResourceNames: []string{"kordex-operator", "kordex-operator-capabilities"}, Verbs: []string{"get", "update"}},
				{Scope: "kordex-system namespace", APIGroup: "coordination.k8s.io", Resources: []string{"leases"}, ResourceNames: []string{"kordex-hub-connection"}, Verbs: []string{"get"}},
				{Scope: "kube-node-lease namespace", APIGroup: "coordination.k8s.io", Resources: []string{"leases"}, Verbs: []string{"get"}},
				{Scope: "kordex-operations-ledger namespace", APIGroup: "", Resources: []string{"configmaps"}, Verbs: []string{"get", "create"}},
				{Scope: "kordex-operations-ledger namespace", APIGroup: "coordination.k8s.io", Resources: []string{"leases"}, ResourceNames: []string{"kordex-maintenance-cluster-slot"}, Verbs: []string{"get", "update"}},
			},
		},
		{
			ID:          "self-managed-host-execution",
			Description: "Additional namespaced permissions when the lab-only fixed-catalog Ansible EE gate is enabled.",
			Rules: []KubernetesPermissionRule{
				{Scope: "kordex-system namespace", APIGroup: "networking.k8s.io", Resources: []string{"networkpolicies"}, Verbs: []string{"get", "list", "create", "delete"}},
				{Scope: "kordex-system namespace", APIGroup: "", Resources: []string{"secrets"}, ResourceNames: []string{"configured SSH credential Secret"}, Verbs: []string{"get"}},
			},
		},
		{ID: "gke-node-pool-upgrade", Description: "Optional GKE adapter identity and Google Kubernetes Engine API permissions; not part of default operator RBAC.", ProviderActions: []string{"container.clusters.get", "container.nodePools.get", "container.nodePools.update"}},
	}

	coreNetwork := []string{
		"Operator requires access to the in-cluster Kubernetes API server.",
		"Agent initiates outbound HTTPS to the configured Kordex management endpoint; the hub does not connect inbound to the cluster.",
		"Kubelet probes the in-pod agent health endpoint on TCP/8081; the deployment does not create a Service for it.",
	}
	optionalNetwork := []string{"When host execution is separately enabled, the isolated execution Job requires access only to the selected node SSH endpoint on TCP/22."}
	crds := []string{
		"nodemaintenances.operations.kordex.local/v1alpha1",
		"maintenancepolicies.operations.kordex.local/v1alpha1",
		"maintenancecampaigns.operations.kordex.local/v1alpha1",
	}
	baseOps := func(providerUpgrade Support) map[string]Support {
		return map[string]Support{
			"ValidateOnly": Unverified, "DrainAndVerify": Unverified,
			"HostPackageReboot": Unverified, "ProviderNodePoolUpgrade": providerUpgrade,
			"ControlPlaneUpgrade": Unsupported, "StorageMutation": Unsupported,
		}
	}
	known := []KubernetesCompatibility{
		{ID: "upstream", DisplayName: "Upstream Kubernetes", Qualification: Unverified, Identification: "Not reliably distinguishable from Node metadata alone; requires an independently verified distribution identity.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, OptionalPermissionProfiles: []string{"self-managed-host-execution"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: optionalNetwork, Operations: baseOps(Unsupported), AutomatedTestCoverage: []string{"Kind v1.37.0 appears in CI registration and PDB-aware drain test configuration; this is test-substrate coverage, not distribution qualification."}, KnownLimitations: []string{"No upstream release range, node OS, or architecture is qualified.", "Kind tests do not establish compatibility with arbitrary upstream installations.", "Storage, control-plane, and provider-managed maintenance are unavailable."}},
		{ID: "k3s", DisplayName: "K3s", Qualification: Unverified, Identification: "Kubelet version suffix may provide an advisory hint; it does not attest the server/control-plane distribution.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, OptionalPermissionProfiles: []string{"self-managed-host-execution"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: optionalNetwork, Operations: baseOps(Unsupported), KnownLimitations: []string{"No real K3s Kubernetes-version/OS/architecture qualification record exists.", "The checked-in GCP K3s lab provisions an optional test environment but does not itself qualify it."}},
		{ID: "rke2", DisplayName: "RKE2", Qualification: Unverified, Identification: "Kubelet version suffix may provide an advisory hint; it does not attest the server/control-plane distribution.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, OptionalPermissionProfiles: []string{"self-managed-host-execution"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: optionalNetwork, Operations: baseOps(Unsupported), KnownLimitations: []string{"No RKE2 version/OS/architecture qualification record exists.", "Distribution-specific admission, CNI, and CSI behavior has not been qualified."}},
		{ID: "gke", DisplayName: "Google Kubernetes Engine", Qualification: Unverified, Identification: "GKE node-pool label and GCE provider ID are advisory signals; the local GKE adapter performs separate live identity checks.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, OptionalPermissionProfiles: []string{"gke-node-pool-upgrade"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: []string{"GKE node-pool updates require outbound access to the Google Kubernetes Engine API through configured Workload Identity."}, Operations: baseOps(Unverified), KnownLimitations: []string{"GKE maintenance and node-pool execution remain unqualified.", "Container-Optimized OS is not a self-managed APT/DNF target.", "Storage and workload topology can block drain even when Kubernetes API access works."}},
		{ID: "eks", DisplayName: "Amazon Elastic Kubernetes Service", Qualification: Unverified, Identification: "EKS node-group label plus AWS provider ID is only an advisory signal; no EKS lifecycle adapter is implemented.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: []string{}, Operations: baseOps(Unsupported), KnownLimitations: []string{"EKS discovery is advisory only; no EKS node-group executor or AWS credential path is implemented.", "No EKS version/OS/architecture qualification record exists."}},
		{ID: "aks", DisplayName: "Azure Kubernetes Service", Qualification: Unverified, Identification: "AKS agent-pool label plus Azure provider ID is only an advisory signal; no AKS lifecycle adapter is implemented.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: []string{}, Operations: baseOps(Unsupported), KnownLimitations: []string{"AKS discovery is advisory only; no AKS node-pool executor or Azure credential path is implemented.", "No AKS version/OS/architecture qualification record exists."}},
		{ID: "openshift", DisplayName: "OpenShift", Qualification: Unverified, Identification: "Machine-configuration labels are advisory; cluster-wide OpenShift identity is not verified by current inventory.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: []string{}, Operations: baseOps(Unsupported), KnownLimitations: []string{"No OpenShift qualification or SCC/admission compatibility test exists.", "No version/OS/architecture combination is qualified."}},
		{ID: "kubeadm", DisplayName: "kubeadm-based Kubernetes", Qualification: Unverified, Identification: "Not distinguishable from upstream Kubernetes by current Node metadata.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, OptionalPermissionProfiles: []string{"self-managed-host-execution"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: optionalNetwork, Operations: baseOps(Unsupported), KnownLimitations: []string{"No kubeadm control-plane topology, version, OS, or architecture qualification exists.", "Control-plane maintenance is explicitly unsupported."}},
		{ID: "talos", DisplayName: "Talos Linux Kubernetes", Qualification: Unverified, Identification: "No reliable Talos distribution classifier is implemented in the agent inventory.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: []string{}, Operations: baseOps(Unsupported), KnownLimitations: []string{"Talos is image-based and has no supported generic host package/SSH execution path.", "No Talos Kubernetes or image-upgrade qualification exists."}},
		{ID: "microk8s", DisplayName: "MicroK8s", Qualification: Unverified, Identification: "No MicroK8s distribution classifier is implemented in the agent inventory.", RequiredPermissionProfiles: []string{"agent-inventory", "operator-default"}, OptionalPermissionProfiles: []string{"self-managed-host-execution"}, RequiredCRDs: crds, NetworkRequirements: coreNetwork, OptionalNetworkRequirements: optionalNetwork, Operations: baseOps(Unsupported), KnownLimitations: []string{"No MicroK8s version, OS, architecture, CNI, or CSI qualification exists."}},
	}
	r, err := NewKubernetesCompatibilityRegistry(known, profiles)
	if err != nil {
		panic(err)
	}
	return r
}
