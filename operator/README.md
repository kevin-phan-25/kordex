# Kubernetes maintenance operator (0.4.0)

This controller-runtime operator independently validates hub-authorized maintenance and persists every phase in NodeMaintenance status. It supports:

- ValidateOnly: live preflight checks with no cordon or eviction.
- DrainAndVerify: an opted-in stateless worker evacuation drill, verified workload recovery and restoration of an operator-owned cordon.
- UpgradePackages: a digest-pinned Debian Ansible EE package/reboot path behind `KORDEX_ENABLE_HOST_UPGRADES` (off by default and not production-qualified). When enabled, configure `KORDEX_UPGRADE_EE_ALLOWLIST` with exact, reviewed image digests; policy-provided images outside that allowlist are rejected. `KORDEX_UPGRADE_IMAGE_PULL_SECRETS` optionally names namespace-local registry pull Secrets for the execution Jobs.
- UpgradeNodePool: an opt-in GKE-native node-pool Kubernetes version update behind `KORDEX_ENABLE_GKE_UPGRADES` (off by default and not production-qualified). It requires Google Workload Identity on the operator ServiceAccount and a canonical GKE resource in `MaintenancePolicy.spec.providerUpgrade`. See [GKE node-pool upgrades](../docs/gke-node-pool-upgrades.md) for permissions, recovery behavior, and qualification requirements.

Unknown safety evidence blocks work. Rook/Ceph evidence is read-only and OSD-host operations stay blocked. An optional mTLS etcd adapter checks live self-managed membership and endpoint status, but does not enable control-plane maintenance; static-pod draining and topology-specific recovery remain unsupported. Target PVC-backed workloads and target-local PVs remain blocked; unrelated remote PVs do not block by themselves. Keep host upgrades disabled until disposable VM failure and recovery drills pass.

Read [the workflow and safety model](../docs/maintenance-operator.md) before deployment. The normal entry point is the management API, not a handwritten unsigned CR. Install the [operator chart](../deployments/helm/kordex-operator) and opt the agent into maintenance delivery in the same namespace.

For the explicit, PDB-preserving GKE system add-on exception and its disposable-cluster qualification steps, see [GKE maintenance validation](../docs/gke-maintenance-validation.md).

Build and tests from repository root:

```sh
go build -o bin/kordex-operator ./operator/cmd/kordex-operator
go test ./operator/...
# Real API-server admission and status tests:
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.3-0.20261103101737-9603adbb18be
export KUBEBUILDER_ASSETS="$(setup-envtest use 1.37.0 -p path)"
KORDEX_REQUIRE_ENVTEST=true go test ./operator/internal/controller
```

KUBECONFIG is supported for a lab process. In Kubernetes, service-account credentials are used. Required configuration: KORDEX_CLUSTER_ID, KORDEX_NAMESPACE, KORDEX_HUB_PUBLIC_KEYS_FILE (public trust JSON). The manager uses leader election and serves health/readiness on 8081. Metrics bind to 127.0.0.1:8082 by default; set KORDEX_METRICS_ADDR to change the address. Keeping metrics on loopback avoids exposing them from the pod and leaves 8080 available for a local control plane during validation. The optional Helm metrics Service and NetworkPolicy are enabled with `metrics.enabled=true`; only the configured monitoring namespace can scrape metrics, while health checks remain available.

For optional self-managed etcd evidence, configure `KORDEX_ETCD_ENDPOINTS` with one HTTPS origin per member and set `KORDEX_ETCD_CA_FILE`, `KORDEX_ETCD_CERT_FILE`, and `KORDEX_ETCD_KEY_FILE` to the mounted mTLS files. Every configured maintenance operation verifies live etcd member health; a control-plane target must also carry its verified hexadecimal member ID in `operations.kordex.local/etcd-member-id` so projected quorum can exclude it. Missing or contradictory evidence blocks. Omit the endpoints to keep the default control-plane block.

CRDs and deep-copy methods are generated from api/operations/v1alpha1 using controller-gen v0.23.0. `make generate` also updates chart CRD copies. The private API group operations.kordex.local is a deliberate pilot identifier, not a claim to a publicly owned DNS domain; settle ownership/conversion before external API publication.

Phase 4 adds independently verified signed withdrawal and safe recovery after cancellation. Campaign plans and approvals reside at the hub; the local MaintenanceCampaign resource reports HubOrchestrationRequired. See [campaigns](../docs/campaigns.md).


Optional kured coordination is configured with `KORDEX_KURED_ENABLED`,
`KORDEX_KURED_NAMESPACE`, and `KORDEX_KURED_DAEMONSET`, or the operator chart's
`kured` values. It reserves the existing kured manual lock around the entire
host maintenance/recovery operation. Reboot execution remains in the signed EE
path. See the authoritative [interlock requirements, configuration, and
qualification limits](../docs/production-upgrade-requirements.md#kured-interlock--optional-unqualified).
