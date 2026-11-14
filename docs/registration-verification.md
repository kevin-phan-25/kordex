> Historical Phase 2 report. See [maintenance verification](maintenance-verification.md) for release 0.3.0.

# Registration and inventory verification — 0.2.0

The code was written directly into the repository, extending the tested foundation. This is a working registration/inventory release, not a complete maintenance platform. No GCP resources were provisioned and no maintenance action was executed.

## Implemented

- Shared Go API module for protocol version 1, canonical Ed25519 signing, enrollment, rotation and node snapshots.
- Control-plane fleets/clusters with composite organization foreign keys; OIDC membership authorization; viewer/administrator roles; organization listing filtered by subject.
- Single-use expiring enrollment tokens, immutable Kubernetes cluster UID binding, key expiry/rotation, durable replay rejection, transactional revocation and identity audit.
- Authenticated heartbeats, stale-connectivity indicators, bounded full node snapshots, observation/version checks and atomic inventory replacement.
- Kubernetes client-go agent, paged inventory, OS/kernel/Kubernetes fields, durable current/pending identity keys and report version, retries/jitter, Lease leadership and Secret compare-and-swap.
- Ordered immutable migrations 1–2, strict UUID regression fix, HEAD read-method safety, safe SQLSTATE diagnostics, full OpenAPI validation and representative response-schema tests.
- Nonroot agent/control-plane OCI packaging, agent Helm chart, multi-module Make targets and CI jobs for race/database tests, scanners, images, Helm and kind registration.

## Verification performed

| Check | Result |
| --- | --- |
| Go build | Both binaries built |
| Go vet | All modules passed |
| Unit/API/PostgreSQL tests | Passed with an explicit disposable database DSN |
| OIDC verification | Actual TLS discovery/JWKS server; valid signature accepted, wrong issuer/audience and expiry denied |
| Authorization | Cross-tenant reads/writes and viewer escalation denied; organization listing scoped; HEAD stays read-only |
| Enrollment | Replay/expiry denied; eight competing requests consume a token exactly once |
| Agent requests | Method/path/body/cluster/key/time binding, nonce replay, stale reports, duplicates and revocation tested |
| Persistence/recovery | API restart, fresh database pool, identity file permissions, Secret stale-writer rejection, lost enrollment/rotation response recovery |
| OpenAPI | 18 operations; full document validation and representative foundation/registration response checks passed |
| Helm | Chart lint and rendering passed; rendered YAML parsed |
| OCI packaging | Control-plane and agent images built independently of go.work |
| Dependency scan | Control-plane and agent govulncheck reported no vulnerabilities |
| Real kind smoke | Passed against Kubernetes v1.37.0: enrollment, actual node inventory, heartbeat connectivity, restart without token, revocation |

Final race-enabled tests passed across all three modules with the disposable PostgreSQL database. The real-cluster smoke runs the actual agent as a host process using a temporary kubeconfig and development file state. It does not prove an installed Helm pod, production OIDC ingress or multi-replica deployment.

## Commands

From the repository root, with Go caches configured in /tmp:

```sh
go build -trimpath -o /tmp/kordex-phase2 ./control-plane/cmd/kordex
go build -trimpath -o /tmp/kordex-phase2-agent ./agent/cmd/kordex-agent
go vet ./api/... ./control-plane/... ./agent/...
KORDEX_TEST_DATABASE_URL='<disposable DSN>' go test -count=1 ./control-plane/... ./api/... ./agent/...
go test -race -count=1 ./api/... ./control-plane/... ./agent/...
python3 scripts/check-openapi.py
helm lint deployments/helm/kordex-agent --set controlPlaneURL=https://hub.example --set clusterID=80bd80f9-f097-4474-86f4-b80986fd5423 --set enrollmentSecretName=enrollment
podman build -f control-plane/Dockerfile -t localhost/kordex:phase2 .
podman build -f agent/Dockerfile -t localhost/kordex-agent:phase2 .
```

`govulncheck ./...` ran from each module directory with the temporary Go compiler on PATH. Module dependencies were checksummed with tidy and workspace sync; standalone agent tidy fixed a checksum gap exposed by its independent OCI build. No dependency vulnerability was waived.

Actual process smoke commands supplied KORDEX_BINARY and KORDEX_TEST_DATABASE_URL to tests/integration/smoke.py. Real Kubernetes smoke additionally supplied KORDEX_AGENT_BINARY and a temporary KUBECONFIG to tests/integration/registration_smoke.py.

The host lacks Go, Make, Docker and a C compiler in its default toolchain. Go 1.26.11, Helm 3.19.0 and kind 0.33.0 were downloaded to /tmp; the kind binary checksum was verified. Race tests used a Go toolchain container with a C compiler and actual PostgreSQL. Restricted local socket/network attempts were rerun with authorized access; failed sandbox-only runs are not application failures.

Rootless kind initially failed due to missing cgroup delegation, then Podman DNS-helper session-bus startup. A transient delegated user scope and DNS-disabled disposable kind network allowed successful creation. No host-wide service configuration was changed. Kubernetes image was kindest/node:v1.37.0 at the digest recorded in CI. Test credentials stayed in temporary files/runtime memory. The disposable kind cluster was deleted after verification and PostgreSQL was stopped after the final test run.

## Remaining limits

- Operator/CRDs, node maintenance, durable command inbox, campaigns, approvals, notifications, dashboard, Ceph/quorum/OS execution, simulator and Terraform remain unimplemented.
- Provider names are inventory metadata, not GKE/EKS/AKS lifecycle integrations.
- Public production deployment requires TLS ingress, separate database roles, secret encryption/rotation procedures, rate limiting, immutable audit export, backups and restoration drills.
- One configured OIDC issuer is supported; changing it requires membership migration. Interactive login, browser sessions, principal provisioning UI and approval roles are future work.
- An agent offline beyond 24-hour key expiry requires administrator revocation/re-enrollment. Identity Secrets and Helm release storage are sensitive.
- Inventory is a current snapshot, not historical telemetry. Connectivity and Node Ready do not constitute maintenance safety authorization.
- Hosted GitHub Actions, local Trivy container scanning, full Docker Compose startup, Helm pod upgrades, network interruption drills, agent leader-loss injection and production TLS/IAM integration were not executed here.
- No production capacity claim follows from one kind node or the 5,000-node request bound.

The next feature milestone is Phase 3: local MaintenancePolicy/NodeMaintenance reconciliation, durable operation delivery and independently enforced preflight safety, before enabling cordon/drain or host execution.

## Changed and created files

- `.github/workflows/ci.yaml`
- `Makefile`
- `README.md`
- `agent/README.md`
- `api/README.md`
- `api/openapi/v1.json`
- `control-plane/Dockerfile`
- `control-plane/cmd/kordex/main.go`
- `control-plane/go.mod`
- `control-plane/go.sum`
- `control-plane/internal/config/config.go`
- `control-plane/internal/config/config_test.go`
- `control-plane/internal/httpapi/server.go`
- `control-plane/internal/httpapi/server_test.go`
- `control-plane/internal/store/integration_test.go`
- `control-plane/internal/store/migrate.go`
- `control-plane/internal/store/store.go`
- `control-plane/internal/telemetry/telemetry.go`
- `deployments/helm/README.md`
- `docs/architecture.md`
- `docs/failure-recovery.md`
- `docs/mvp-plan.md`
- `docs/security.md`
- `docs/verification.md`
- `go.work`
- `scripts/check-openapi.py`
- `tests/integration/README.md`
- `agent/Dockerfile`
- `agent/cmd/kordex-agent/main.go`
- `agent/go.mod`
- `agent/go.sum`
- `agent/internal/client/client.go`
- `agent/internal/client/client_test.go`
- `agent/internal/inventory/kubernetes.go`
- `agent/internal/inventory/kubernetes_test.go`
- `agent/internal/runner/runner.go`
- `agent/internal/runner/runner_test.go`
- `agent/internal/state/state.go`
- `agent/internal/state/state_test.go`
- `api/go.mod`
- `api/protocol/agent.go`
- `api/protocol/agent_test.go`
- `control-plane/internal/httpapi/contract_test.go`
- `control-plane/internal/httpapi/fleet.go`
- `control-plane/internal/identity/oidc.go`
- `control-plane/internal/identity/oidc_test.go`
- `control-plane/internal/store/fleet.go`
- `control-plane/internal/store/registration_test.go`
- `control-plane/migrations/002_cluster_registration.sql`
- `deployments/helm/kordex-agent/Chart.yaml`
- `deployments/helm/kordex-agent/templates/_helpers.tpl`
- `deployments/helm/kordex-agent/templates/deployment.yaml`
- `deployments/helm/kordex-agent/templates/identity.yaml`
- `deployments/helm/kordex-agent/templates/rbac.yaml`
- `deployments/helm/kordex-agent/values.yaml`
- `docs/adr/0004-agent-workload-identity.md`
- `docs/agent-protocol.md`
- `docs/registration-verification.md`
- `go.work.sum`
- `tests/integration/registration_smoke.py`
