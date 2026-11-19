package store

import "kordex.local/api/protocol"

// resolveFleetUpgrade selects a concrete, digest-bound executor for one node
// from an agent-reported policy catalog. The empty boundDigest mode is used by
// UpgradeFleet campaigns: the central resolver binds the chosen digest into
// each immutable target snapshot before any operation can be issued.
func resolveFleetUpgrade(
	entry protocol.MaintenancePolicyCatalogEntry,
	clusterProvider, clusterName string,
	node protocol.Node,
	capabilities protocol.OperatorCapabilities,
	boundDigest string,
) (action, digest, reason string) {
	hostPlanDigestMatches := false
	hostPlanMatches := false
	hostDigest := ""
	if entry.Upgrade != nil && !entry.UpgradePlanInvalid {
		candidate, err := entry.Upgrade.Digest()
		hostPlanDigestMatches = err == nil && candidate == entry.UpgradePlanDigest && (boundDigest == "" || candidate == boundDigest)
		hostPlanMatches = hostPlanDigestMatches && entry.Upgrade.MatchesNodeOS(node)
		if hostPlanDigestMatches {
			hostDigest = candidate
		}
	}

	providerPlanMatches := false
	providerPlanDigestMatches := false
	providerDigest := ""
	if entry.ProviderUpgrade != nil && !entry.ProviderPlanInvalid && entry.ProviderUpgrade.Provider == clusterProvider && clusterProvider == "gke" {
		candidate, err := entry.ProviderUpgrade.Digest()
		providerPlanDigestMatches = err == nil && candidate == entry.ProviderPlanDigest && (boundDigest == "" || candidate == boundDigest)
		providerPlanMatches = providerPlanDigestMatches && entry.ProviderUpgrade.MatchesInventory(clusterProvider, clusterName, node)
		if providerPlanMatches {
			providerDigest = candidate
		}
	}

	// Prefer the provider-neutral host action whenever its plan matches this
	// node, the local host executor is enabled, and ordinary node maintenance
	// permissions are ready. The managed-cluster adapter is an optional fallback
	// for nodes such as GKE COS that cannot take APT/DNF.
	switch {
	case hostPlanMatches && capabilities.HostUpgrades && capabilities.NodeMaintenance:
		return protocol.UpgradePackages, hostDigest, ""
	case providerPlanMatches && capabilities.GKENodePoolUpgrade:
		return protocol.UpgradeNodePool, providerDigest, ""
	case hostPlanMatches && capabilities.HostUpgrades && !capabilities.NodeMaintenance:
		return "", "", "LocalOperatorRBACIncomplete"
	case hostPlanMatches:
		return "", "", "LocalUpgradeExecutorUnavailable"
	case providerPlanMatches:
		return "", "", "LocalGKENodePoolAdapterUnavailable"
	case hostPlanDigestMatches:
		return "", "", "UpgradePlanOSIdentityMismatch"
	case providerPlanDigestMatches:
		return "", "", "ProviderTargetIdentityMismatch"
	default:
		return "", "", "UpgradePlanInvalid"
	}
}
