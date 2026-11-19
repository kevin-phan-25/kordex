package lifecycle

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestBuiltinKubernetesRegistryIsExplicitAndNeverQualified(t *testing.T) {
	catalog := BuiltinKubernetesCompatibilityRegistry().Catalog()
	want := map[string]bool{"upstream": true, "k3s": true, "rke2": true, "gke": true, "eks": true, "aks": true, "openshift": true, "kubeadm": true, "talos": true, "microk8s": true}
	profiles := map[string]KubernetesPermissionProfile{}
	for _, profile := range catalog.PermissionProfiles {
		profiles[profile.ID] = profile
	}
	if len(catalog.Items) != len(want) || len(profiles) < 3 {
		t.Fatalf("unexpected registry size: %d entries, %d permission profiles", len(catalog.Items), len(profiles))
	}
	for _, item := range catalog.Items {
		if !want[item.ID] {
			t.Fatalf("unexpected distribution entry %q", item.ID)
		}
		delete(want, item.ID)
		if item.Qualification != Unverified && item.Qualification != Unsupported {
			t.Fatalf("registry claimed qualification for %s: %s", item.ID, item.Qualification)
		}
		if len(item.QualifiedKubernetesVersions) != 0 || len(item.QualifiedNodeOperatingSystems) != 0 || len(item.QualifiedArchitectures) != 0 {
			t.Fatalf("unqualified entry %s advertises qualified versions/OS/architectures", item.ID)
		}
		if len(item.RequiredCRDs) != 3 || len(item.NetworkRequirements) == 0 || len(item.KnownLimitations) == 0 {
			t.Fatalf("incomplete requirements for %s: %+v", item.ID, item)
		}
		for _, profileID := range append(item.RequiredPermissionProfiles, item.OptionalPermissionProfiles...) {
			if _, ok := profiles[profileID]; !ok {
				t.Fatalf("unknown permission profile %q on %s", profileID, item.ID)
			}
		}
		if !slices.Contains(item.RequiredPermissionProfiles, "agent-inventory") {
			t.Fatalf("%s does not require the agent inventory permission profile", item.ID)
		}
		for name, state := range item.Operations {
			if state != Unsupported && state != Unverified {
				t.Fatalf("registry claimed %s on %s: %s", name, item.ID, state)
			}
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing compatibility entries: %v", want)
	}
	gke, ok := BuiltinKubernetesCompatibilityRegistry().Lookup("gke")
	if !ok || gke.Operations["ProviderNodePoolUpgrade"] != Unverified {
		t.Fatal("GKE's opt-in provider adapter was not accurately marked unverified")
	}
	if _, ok := BuiltinKubernetesCompatibilityRegistry().Lookup("unknown-vendor"); ok {
		t.Fatal("unknown distribution was silently admitted")
	}
	encoded, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	items := decoded["items"].([]any)
	first := items[0].(map[string]any)
	if versions, ok := first["qualifiedKubernetesVersions"].([]any); !ok || len(versions) != 0 {
		t.Fatalf("empty qualifications must be explicit arrays, got %#v", first["qualifiedKubernetesVersions"])
	}
}

func TestAgentInventoryPermissionProfileIsReadOnlyAndScoped(t *testing.T) {
	catalog := BuiltinKubernetesCompatibilityRegistry().Catalog()
	var profile *KubernetesPermissionProfile
	for i := range catalog.PermissionProfiles {
		if catalog.PermissionProfiles[i].ID == "agent-inventory" {
			profile = &catalog.PermissionProfiles[i]
			break
		}
	}
	if profile == nil {
		t.Fatal("agent inventory permission profile is missing")
	}
	for _, rule := range profile.Rules {
		for _, verb := range rule.Verbs {
			if verb != "get" && verb != "list" {
				t.Fatalf("agent inventory profile has mutating verb %q in %+v", verb, rule)
			}
		}
	}
	containsRule := func(group, resource, scope string) bool {
		for _, rule := range profile.Rules {
			if rule.APIGroup == group && rule.Scope == scope && slices.Contains(rule.Resources, resource) {
				return true
			}
		}
		return false
	}
	if !containsRule("", "namespaces", "cluster") || !containsRule("apps", "daemonsets", "kube-system namespace") {
		t.Fatalf("namespace/CNI hint reads are not represented: %+v", profile.Rules)
	}
	for _, resource := range []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings"} {
		if !containsRule("admissionregistration.k8s.io", resource, "cluster") {
			t.Errorf("agent inventory is missing read-only admission permission for %s", resource)
		}
	}
}

func TestAssessClusterCompatibilityNeverPromotesAdvisoryHints(t *testing.T) {
	registry := BuiltinKubernetesCompatibilityRegistry()
	for _, test := range []struct {
		name                 string
		nodes                int
		osImages             int
		architectures        int
		hints                []string
		registryUnavailable  bool
		wantStatus, wantCode string
	}{
		{name: "no inventory", wantStatus: "Unknown", wantCode: "NoNodeInventory"},
		{name: "unknown distribution", nodes: 2, hints: []string{"unknown"}, wantStatus: "Unknown", wantCode: "DistributionUnknown"},
		{name: "unknown node alongside known hint", nodes: 2, hints: []string{"gke", "unknown"}, wantStatus: "Unknown", wantCode: "DistributionUnknown"},
		{name: "conflicting known hints", nodes: 2, hints: []string{"gke", "k3s"}, wantStatus: "MixedSignals", wantCode: "MixedDistributionHints"},
		{name: "known but unqualified", nodes: 3, osImages: 2, architectures: 2, hints: []string{"k3s", "k3s"}, wantStatus: "Unqualified", wantCode: "QualificationEvidenceMissing"},
		{name: "unregistered distribution", nodes: 1, hints: []string{"vendor-k8s"}, wantStatus: "Unqualified", wantCode: "DistributionNotInRegistry"},
		{name: "registry unavailable", nodes: 1, hints: []string{"k3s"}, wantStatus: "Unqualified", wantCode: "CompatibilityRegistryUnavailable", registryUnavailable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			useRegistry := registry
			if test.registryUnavailable {
				useRegistry = nil
			}
			got := AssessClusterCompatibility(test.nodes, test.osImages, test.architectures, test.hints, useRegistry)
			if got.Status != test.wantStatus || len(got.ReasonCodes) != 1 || got.ReasonCodes[0] != test.wantCode {
				t.Fatalf("unexpected assessment: %+v", got)
			}
			if test.name == "known but unqualified" && (got.NodeCount != 3 || got.DistinctOSImages != 2 || got.DistinctArchitectures != 2 || len(got.DistributionHints) != 1) {
				t.Fatalf("assessment omitted bounded inventory summary: %+v", got)
			}
		})
	}
}
