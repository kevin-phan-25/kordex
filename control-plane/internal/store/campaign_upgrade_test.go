package store

import (
	"strings"
	"testing"
	"time"

	"kordex.local/api/protocol"
)

func TestResolveFleetUpgradeSelectsNodeCompatiblePlan(t *testing.T) {
	hostPlan := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "workers", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.5.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	hostDigest, err := hostPlan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	providerPlan := protocol.ProviderNodeUpgradePlan{
		SchemaVersion: 2, Provider: "gke", Resource: "projects/test-project/locations/us-central1-a/clusters/cluster-1/nodePools/default-pool",
		TargetVersion: "1.37.1-gke.100", MaxSurge: 1, Timeout: 5 * time.Minute,
	}
	providerDigest, err := providerPlan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	entry := protocol.MaintenancePolicyCatalogEntry{
		Upgrade: &hostPlan, UpgradePlanDigest: hostDigest,
		ProviderUpgrade: &providerPlan, ProviderPlanDigest: providerDigest,
	}
	capabilities := protocol.OperatorCapabilities{HostUpgrades: true, GKENodePoolUpgrade: true}

	tests := []struct {
		name         string
		provider     string
		node         protocol.Node
		capabilities protocol.OperatorCapabilities
		boundDigest  string
		wantAction   string
		wantDigest   string
		wantReason   string
	}{
		{
			name: "self-managed node selects host executor", provider: "self-managed",
			node: protocol.Node{OSImage: "Ubuntu 24.04 LTS"}, capabilities: capabilities,
			wantAction: protocol.UpgradePackages, wantDigest: hostDigest,
		},
		{
			name: "GKE COS falls back to provider executor", provider: "gke",
			node:         protocol.Node{Name: "worker", UID: "node-1", OSImage: "Container-Optimized OS from Google", Zone: "us-central1-a", ProviderID: "gce://test-project/us-central1-a/instance-1", Labels: map[string]string{"cloud.google.com/gke-nodepool": "default-pool"}},
			capabilities: capabilities, wantAction: protocol.UpgradeNodePool, wantDigest: providerDigest,
		},
		{
			name: "host plan remains preferred when compatible", provider: "gke",
			node:         protocol.Node{OSImage: "Ubuntu 24.04 LTS", Name: "worker", UID: "node-1", Zone: "us-central1-a", ProviderID: "gce://test-project/us-central1-a/instance-1", Labels: map[string]string{"cloud.google.com/gke-nodepool": "default-pool"}},
			capabilities: capabilities, wantAction: protocol.UpgradePackages, wantDigest: hostDigest,
		},
		{
			name: "explicit host digest cannot fall through", provider: "gke",
			node:         protocol.Node{Name: "worker", UID: "node-1", OSImage: "Container-Optimized OS from Google", Zone: "us-central1-a", ProviderID: "gce://test-project/us-central1-a/instance-1", Labels: map[string]string{"cloud.google.com/gke-nodepool": "default-pool"}},
			capabilities: capabilities, boundDigest: hostDigest, wantReason: "UpgradePlanOSFamilyMismatch",
		},
		{
			name: "provider fallback requires its local gate", provider: "gke",
			node:         protocol.Node{Name: "worker", UID: "node-1", OSImage: "Container-Optimized OS from Google", Zone: "us-central1-a", ProviderID: "gce://test-project/us-central1-a/instance-1", Labels: map[string]string{"cloud.google.com/gke-nodepool": "default-pool"}},
			capabilities: protocol.OperatorCapabilities{HostUpgrades: true}, wantReason: "LocalGKENodePoolAdapterUnavailable",
		},
		{
			name: "host action requires its local gate", provider: "self-managed",
			node: protocol.Node{OSImage: "Ubuntu 24.04 LTS"}, capabilities: protocol.OperatorCapabilities{GKENodePoolUpgrade: true},
			wantReason: "LocalUpgradeExecutorUnavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action, digest, reason := resolveFleetUpgrade(entry, test.provider, "cluster-1", test.node, test.capabilities, test.boundDigest)
			if action != test.wantAction || digest != test.wantDigest || reason != test.wantReason {
				t.Fatalf("resolveFleetUpgrade() = (%q, %q, %q), want (%q, %q, %q)", action, digest, reason, test.wantAction, test.wantDigest, test.wantReason)
			}
		})
	}
}
