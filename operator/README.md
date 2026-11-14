# Kubernetes maintenance operator (0.3.0)

This controller-runtime operator independently validates hub-authorized maintenance and persists every phase in NodeMaintenance status. It supports:

- ValidateOnly: live preflight checks with no cordon or eviction.
- DrainAndVerify: an opted-in stateless worker evacuation drill, verified workload recovery and restoration of an operator-owned cordon.

It cannot update packages, change a kernel, reboot, maintain control-plane nodes or maintain storage-bearing clusters. Unsupported or unknown safety evidence blocks work. MaintenanceCampaign is an initial schema only; its controller reports OrchestrationNotImplemented and creates no operations.

Read [the workflow and safety model](../docs/maintenance-operator.md) before deployment. The normal entry point is the management API, not a handwritten unsigned CR. Install the [operator chart](../deployments/helm/kordex-operator) and opt the agent into maintenance delivery in the same namespace.

Build and tests from repository root:

```sh
go build -o bin/kordex-operator ./operator/cmd/kordex-operator
go test ./operator/...
# Real API-server admission and status tests:
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.3-0.20261103101737-9603adbb18be
export KUBEBUILDER_ASSETS="$(setup-envtest use 1.37.0 -p path)"
KORDEX_REQUIRE_ENVTEST=true go test ./operator/internal/controller
```

KUBECONFIG is supported for a lab process. In Kubernetes, service-account credentials are used. Required configuration: KORDEX_CLUSTER_ID, KORDEX_NAMESPACE, KORDEX_HUB_PUBLIC_KEYS_FILE (public trust JSON). The manager uses leader election and serves health/readiness on 8081; metrics bind loopback on 8080.

CRDs and deep-copy methods are generated from api/operations/v1alpha1 using controller-gen v0.23.0. `make generate` also updates chart CRD copies. The private API group operations.kordex.local is a deliberate pilot identifier, not a claim to a publicly owned DNS domain; settle ownership/conversion before external API publication.
