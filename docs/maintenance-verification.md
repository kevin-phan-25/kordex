# Phase 3 maintenance verification — release 0.3.0

This phase is implemented and tested as a constrained stateless-worker maintenance foundation. It is not a package/reboot, storage, control-plane or fleet-campaign implementation. No cloud resources were provisioned and no host maintenance command was executed.

## What changed

- Added the controller-runtime operator module, generated MaintenancePolicy/MaintenanceCampaign/NodeMaintenance CRDs and deep-copy methods, policy conditions and explicit deferred campaign status.
- Added hub-signed operation permits, manual tenant-scoped APIs, database migration 3, idempotent operation identity and a one-active-operation cluster constraint.
- Added the agent's opt-in durable CRD inbox, short-lived connection Lease and restart-safe status acknowledgements.
- Implemented live preflight safety, stable node/kubelet health, controller/UID validation, PDB checks, conservative storage/quorum vetoes and global local reservations.
- Implemented intent-before-side-effect cordon, UID-preconditioned eviction, bounded reconciliation, immediate authorization/ownership revalidation and independently verified recovery/uncordon.
- Added immutable replay receipts, cancellation recovery, terminal finalizers retained until hub audit acknowledgement and upgrade-safe handling of runtime Helm state.
- Added key-generation tooling, operator/agent chart permissions, OCI packaging, 21-operation OpenAPI, CI/envtest/kind jobs, tests and operational documentation.

## Actual verification

| Check | Result |
| --- | --- |
| Build | Control plane, agent, operator and key generator compiled |
| Go tests | Unit/API/database suites passed with an explicit disposable PostgreSQL DSN |
| Race detector | Passed across api, control-plane, agent and operator |
| Envtest | Real API-server/etcd admission, defaults, immutable spec, status conflicts and deletion finalizer tests passed |
| Failure/recovery tests | PDB denial and eviction race, degraded/unknown health, storage/control-plane veto, unmanaged pods, ownership, policy change, replacement node, disconnect/expiry, slow preflight, lost cordon/eviction acknowledgement, cancellation and terminal acknowledgement |
| Delivery/database | Durable retry, conflicting UUID reuse, expiry without freeing unknown capacity, nonce replay, changed event-history rejection, append-only audit and acknowledged completion |
| Real kind | Three-node Kubernetes v1.37.0; real chart RBAC, zero-disruption PDB blocking before cordon, signed delivery, eviction, operator restart, workload recovery, uncordon and retained receipt replay rejection passed |
| OpenAPI | Full specification validation, 21-operation sanity check and initial/completed operation response schemas passed |
| Helm | Both charts lint/render; real-cluster smoke exercises service-account RBAC and retained coordination resources |
| Dependency scan | All four Go modules reported no vulnerabilities |
| Generated artifacts | controller-gen v0.23.0; chart CRD copies match generated schemas |

The real kind smoke uses host-run compiled processes with service-account impersonation to exercise Kubernetes RBAC. It does not prove an installed OCI pod lifecycle, public HTTPS ingress, cloud identity integration or production scaling. The application-signature/TLS transport and OIDC validation have separate tests. The initial real smoke, acknowledgement/Helm-state-preservation rerun and final immediate-boundary-guard rerun all passed.

## Commands and tooling

Go 1.26.11, controller-gen v0.23.0, envtest Kubernetes v1.37.0, kind v0.33.0 and Helm v3.19.0 were used from /tmp. Default host tooling lacks a C compiler and Make; equivalent Go/Python commands ran directly. Race tests ran in a Go toolchain container. PostgreSQL was disposable and bound to loopback.

```sh
go build ./api/... ./control-plane/... ./agent/... ./operator/...
go vet ./api/... ./control-plane/... ./agent/... ./operator/...
KORDEX_TEST_DATABASE_URL='<disposable DSN>' go test -count=1 ./api/... ./control-plane/... ./agent/... ./operator/...
go test -race -count=1 ./api/... ./control-plane/... ./agent/... ./operator/...
KUBEBUILDER_ASSETS='<envtest path>' KORDEX_REQUIRE_ENVTEST=true go test -count=1 ./operator/internal/controller
controller-gen object crd paths=./api/operations/... output:crd:artifacts:config=operator/config/crd
python3 scripts/check-openapi.py
```

The smoke command supplies KUBECONFIG, KUBECTL, HELM, the four compiled binary paths and a fresh KORDEX_TEST_DATABASE_URL to `python3 tests/integration/maintenance_smoke.py`. Separate databases avoid conflicting immutable cluster-UID registrations. The key generator created temporary signing material; the private key and administrative kubeconfig were never committed or printed.

Rootless kind needed a transient delegated user scope. The host's DNS helper could not connect to its user-session bus, so the disposable workers received explicit API-server hostname mappings on a DNS-disabled test network. This was a host-specific lab workaround, not a product requirement. Hosted CI uses normal Docker networking. Failed setup attempts were cleaned up by kind. Socket/network-restricted test attempts were retried with authorized local access. The disposable three-node cluster was deleted and PostgreSQL was stopped after verification.

OCI builds use nonroot distroless runtime stages and GOWORK=off to verify independent module packaging. All three OCI images are verified by standalone builds; final tags are localhost/kordex:phase3, localhost/kordex-agent:phase3 and localhost/kordex-operator:phase3.

## Known limits and next milestone

- Only ValidateOnly and stateless-worker DrainAndVerify execute. No package/kernel/reboot, etcd/Ceph/Rook or managed-cloud lifecycle support is claimed.
- Multi-scope concurrency, approval gates, campaigns, scheduling, retries/rollout stages and notifications are Phase 4. MaintenanceCampaign explicitly reports unavailable orchestration.
- The 45-second hub evidence age and five-second clock synchronization bound are operational assumptions. Multi-object Kubernetes health cannot be one atomic snapshot; eviction's PDB enforcement is authoritative.
- Receipt/coordination retention, ledger backup/restore, least-privilege database roles, external immutable audit, production TLS, rate limits, key rotation drills and public API-group ownership remain hardening work.
- Hosted GitHub Actions, Trivy runtime scanning, full Docker Compose startup, installed-container rolling upgrades, real-VM host recovery and production-scale tests were not run here.
- A forced deletion of finalizers/receipts/slot state is privileged incident handling outside automated safety guarantees. Do not reset coordination state to make work run.

The next feature milestone is Phase 4: campaign orchestration, target snapshots, approval/window gates, canaries, batches and multi-scope reservations with multi-replica scheduler tests. Existing local safety must remain authoritative.

## Phase 3 file manifest

- `.github/workflows/ci.yaml`
- `Makefile`
- `README.md`
- `agent/README.md`
- `agent/cmd/kordex-agent/main.go`
- `agent/go.mod`
- `agent/internal/operations/bridge.go`
- `agent/internal/operations/bridge_test.go`
- `agent/internal/runner/runner.go`
- `api/README.md`
- `api/cmd/kordex-keygen/main.go`
- `api/go.mod`
- `api/go.sum`
- `api/openapi/v1.json`
- `api/operations/v1alpha1/types.go`
- `api/operations/v1alpha1/zz_generated.deepcopy.go`
- `api/protocol/maintenance.go`
- `api/protocol/maintenance_test.go`
- `control-plane/cmd/kordex/main.go`
- `control-plane/go.mod`
- `control-plane/go.sum`
- `control-plane/internal/httpapi/fleet.go`
- `control-plane/internal/httpapi/operations.go`
- `control-plane/internal/httpapi/server.go`
- `control-plane/internal/store/operations.go`
- `control-plane/internal/store/operations_test.go`
- `control-plane/migrations/003_node_operations.sql`
- `deployments/helm/README.md`
- `deployments/helm/kordex-agent/Chart.yaml`
- `deployments/helm/kordex-agent/templates/deployment.yaml`
- `deployments/helm/kordex-agent/templates/identity.yaml`
- `deployments/helm/kordex-agent/templates/rbac.yaml`
- `deployments/helm/kordex-agent/values.yaml`
- `deployments/helm/kordex-operator/Chart.yaml`
- `deployments/helm/kordex-operator/crds/operations.kordex.local_maintenancecampaigns.yaml`
- `deployments/helm/kordex-operator/crds/operations.kordex.local_maintenancepolicies.yaml`
- `deployments/helm/kordex-operator/crds/operations.kordex.local_nodemaintenances.yaml`
- `deployments/helm/kordex-operator/templates/_helpers.tpl`
- `deployments/helm/kordex-operator/templates/deployment.yaml`
- `deployments/helm/kordex-operator/templates/ledger.yaml`
- `deployments/helm/kordex-operator/templates/rbac.yaml`
- `deployments/helm/kordex-operator/values.yaml`
- `docs/adr/0005-durable-local-maintenance.md`
- `docs/agent-protocol.md`
- `docs/architecture.md`
- `docs/failure-recovery.md`
- `docs/maintenance-operator.md`
- `docs/maintenance-verification.md`
- `docs/mvp-plan.md`
- `docs/registration-verification.md`
- `docs/security.md`
- `go.work`
- `go.work.sum`
- `operator/Dockerfile`
- `operator/README.md`
- `operator/cmd/kordex-operator/main.go`
- `operator/config/crd/operations.kordex.local_maintenancecampaigns.yaml`
- `operator/config/crd/operations.kordex.local_maintenancepolicies.yaml`
- `operator/config/crd/operations.kordex.local_nodemaintenances.yaml`
- `operator/config/samples/maintenancepolicy.yaml`
- `operator/go.mod`
- `operator/go.sum`
- `operator/internal/controller/authorization.go`
- `operator/internal/controller/durable.go`
- `operator/internal/controller/envtest_test.go`
- `operator/internal/controller/maintenance.go`
- `operator/internal/controller/maintenance_test.go`
- `operator/internal/controller/policy.go`
- `operator/internal/controller/recovery.go`
- `operator/internal/execution/kubernetes.go`
- `operator/internal/safety/checks.go`
- `scripts/check-openapi.py`
- `tests/integration/README.md`
- `tests/integration/maintenance_smoke.py`
- `tests/kind/maintenance.yaml`
