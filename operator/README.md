# Kubernetes maintenance operator (0.4.0)

This controller-runtime operator independently validates hub-authorized maintenance and persists every phase in NodeMaintenance status. It supports:

- ValidateOnly: live preflight checks with no cordon or eviction.
- DrainAndVerify: an opted-in stateless worker evacuation drill, verified workload recovery and restoration of an operator-owned cordon.

It cannot update packages, change a kernel, reboot, maintain control-plane nodes or operate storage nodes. Unsupported or unknown safety evidence blocks work. Target PVC-backed workloads and target-local PVs remain blocked; unrelated remote PVs do not block by themselves. MaintenanceCampaign is an initial schema only; its controller reports OrchestrationNotImplemented and creates no operations.

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

CRDs and deep-copy methods are generated from api/operations/v1alpha1 using controller-gen v0.23.0. `make generate` also updates chart CRD copies. The private API group operations.kordex.local is a deliberate pilot identifier, not a claim to a publicly owned DNS domain; settle ownership/conversion before external API publication.

Phase 4 adds independently verified signed withdrawal and safe recovery after cancellation. Campaign plans and approvals reside at the hub; the local MaintenanceCampaign resource reports HubOrchestrationRequired. See [campaigns](../docs/campaigns.md).
