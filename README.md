# Kordex

Enterprise infrastructure lifecycle and fleet orchestration, with centralized coordination and independent local safety.

**Current product state: multi-cluster inventory and campaigns, a constrained local maintenance operator, an opt-in Debian Ansible EE package/reboot path, and an opt-in GKE node-pool version-upgrade adapter.** Both upgrade executors remain off by default and unqualified outside disposable infrastructure. Rook safety checks fresh cluster status and manager metrics for OSD availability, recovery/backfill, and flags; OSD-host maintenance is still blocked, TLS-enabled metrics are unsupported, and the adapter is unqualified against real Rook/Ceph releases. The etcd mTLS adapter is read-only and does not enable control-plane maintenance. EKS/AKS provider upgrades, ownership-aware storage maintenance, and production qualification remain incomplete. See the [production upgrade requirements and acceptance plan](docs/production-upgrade-requirements.md) and [GKE upgrade setup](docs/gke-node-pool-upgrades.md).

See [campaign orchestration](docs/campaigns.md), [Phase 5 verification](docs/dashboard-verification.md), [Phase 4 verification record](docs/campaign-verification.md), the [maintenance workflow and deployment boundary](docs/maintenance-operator.md), and [operator](operator/README.md). Maintenance is disabled unless a hub signing key is configured and agent delivery is explicitly enabled.

See the [Phase 6 hardening guide](docs/phase6-hardening.md) and [verification record](docs/phase6-verification.md) for audit export, database roles, rate limits, metrics, backup/restore procedures and remaining operational gates.

See [Phase 7 integrations](docs/phase7-integrations.md), its [verification record](docs/phase7-verification.md), the [Phase 8 observability work](docs/phase8-operational-observability.md), and the [GCP Terraform foundation](infrastructure/terraform/gcp/README.md). Production qualification and additional integrations remain ongoing work.

See [production upgrade requirements](docs/production-upgrade-requirements.md) for the staged roadmap, acceptance evidence, and the boundary between implemented code paths and qualified upgrade execution.

For a first real-cloud pilot, follow the [Google Cloud test deployment guide](docs/gcp-test-deployment.md). It creates a disposable GKE cluster and connects it to the local control plane; it is not a cloud-hosted Kordex deployment.

For the limited, PDB-preserving GKE maintenance qualification flow, see [GKE maintenance validation](docs/gke-maintenance-validation.md). It covers `ValidateOnly` on a disposable cluster; it is not an OS-update or reboot workflow.

Branding is configurable through KORDEX_PRODUCT_NAME. Internal protocol identifiers remain stable across renaming. Fleet size targets are design goals, not proven production capacity.

## Dashboard

The responsive Next.js dashboard is in [dashboard/](dashboard/README.md). It uses OIDC authorization-code flow with PKCE, encrypted HTTP-only sessions, and a same-origin server API proxy. It receives no Kubernetes credentials. Configure an OIDC issuer, a client ID that matches the management API audience, and a 32-byte random session secret. The OIDC callback is `${KORDEX_DASHBOARD_URL}/api/auth/callback`; production origins must use HTTPS. See [dashboard deployment and limitations](dashboard/README.md).

The campaign planner uses fresh agent-reported MaintenancePolicy catalogs and binds each target to its exact policy UID, generation, and upgrade-plan digest. It offers validation, stateless worker drain/recovery, Debian Ansible package campaigns, and the separately gated GKE node-pool version action. Upgrade paths are not production qualified; see the [GKE upgrade guide](docs/gke-node-pool-upgrades.md) and [production acceptance plan](docs/production-upgrade-requirements.md).

## Local management plane

Requirements: Go 1.26+, GNU Make, Python 3, Docker/Compose or equivalent OCI tooling. CI pins Go 1.26.11. Agent tests use Kubernetes fake clients; a real-cluster test is separate.

```sh
cp deployments/local/.env.example deployments/local/.env
openssl rand -hex 32
openssl rand -hex 32
# Insert the two distinct generated values as POSTGRES_PASSWORD and KORDEX_ADMIN_TOKEN.
docker compose --env-file deployments/local/.env -f deployments/local/compose.yaml up --build -d
curl http://127.0.0.1:8080/readyz
```

.env is ignored. Compose runs migrations before the API and binds database/API host ports to loopback. Local development uses a global bootstrap token and relaxed database TLS; never publish this configuration.

For host Go execution, configure DATABASE_URL and KORDEX_ADMIN_TOKEN, set KORDEX_LOCAL_DEVELOPMENT=true only for an isolated lab, then:

```sh
go run ./control-plane/cmd/kordex -migrate
go run ./control-plane/cmd/kordex
```

Default binding: 127.0.0.1:8080. PORT is honored when KORDEX_LISTEN_ADDRESS is unset. Non-loopback production binding requires KORDEX_OIDC_ISSUER and KORDEX_OIDC_AUDIENCE, disables the bootstrap token, and requires database sslmode=verify-full. Configure trusted HTTPS ingress; the API itself serves HTTP behind the TLS terminator. Cloud Run deployment, secure Cloud SQL connectivity, Terraform and service IAM are not packaged yet.

## Register a cluster

Use an isolated bootstrap session to create an organization and initial administrator membership. OIDC users can then access only their memberships; roles are viewer, operator, approver and administrator.

1. POST /v1/organizations with name (bootstrap administration only).
2. PUT /v1/organizations/{org}/memberships with OIDC subject and role.
3. POST /v1/organizations/{org}/sites with name and region.
4. POST /v1/organizations/{org}/fleets with name.
5. POST /v1/organizations/{org}/clusters with name, siteId, fleetId and provider.
6. POST /v1/organizations/{org}/clusters/{cluster}/enrollment-tokens.
7. Deliver the token to an existing Kubernetes Secret and install the [agent chart](deployments/helm/README.md).

Use `Authorization: Bearer` with the isolated bootstrap token or a verified OIDC ID token. Administrative JSON requests require Content-Type application/json. Enrollment tokens are returned once and expire in ten minutes; do not store them in Helm values or Git. Agent request authentication uses Ed25519 signatures over HTTPS, not an embedded shared secret. See the [protocol](docs/agent-protocol.md) and [OpenAPI](api/openapi/v1.json).

## Build and verify

```sh
make build
make vet
make test
make contract
# Disposable PostgreSQL only:
KORDEX_TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55432/kordex?sslmode=disable' make integration
```

`make build` also produces kordex-scheduler, kordex-operator, kordex-keygen and kordex-audit-verify. `make generate` regenerates CRDs/deep copies; `make envtest` requires KUBEBUILDER_ASSETS.

The database suite skips without a DSN outside CI. For race tests:

```sh
go test -race -count=1 ./api/... ./control-plane/... ./agent/... ./operator/...
```

`tests/integration/smoke.py` verifies an actual API process restart. `tests/integration/registration_smoke.py` runs the real agent against an existing disposable Kubernetes cluster and database. It requires KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_TEST_DATABASE_URL and KUBECONFIG. No maintenance is performed. The real three-node PDB/drain/restart test is `tests/integration/maintenance_smoke.py` and requires a fresh disposable database. See [registration verification](docs/registration-verification.md) for the previous release; [foundation verification](docs/verification.md) is a historical Phase 1 record.

## Repository

| Path | Responsibility |
| --- | --- |
| control-plane/ | REST, OIDC authorization, PostgreSQL, audit, registration/inventory |
| agent/ | Outbound identity, heartbeats, node inventory, durable key/version state |
| api/ | Shared signed-request protocol and versioned OpenAPI |
| operator/ | Live safety checks, durable reconciliation, eviction and recovery |
| dashboard/ | Next.js operations dashboard and same-origin OIDC session proxy |
| integrations/ | Ansible EE lifecycle artifacts, provider interfaces, and storage/quorum adapters |
| deployments/ | Local Compose and least-privilege agent Helm chart |
| infrastructure/ | Future Terraform; no resources provisioned |
| docs/ | Architecture, security, recovery, roadmap, ADRs and verification |
| tests/ | Process and real-cluster smoke tests |
| scripts/ | Contract checks, audit export and PostgreSQL backup/restore helpers |

Read the [vision](docs/product-vision.md), [architecture](docs/architecture.md), [security](docs/security.md), [failure model](docs/failure-recovery.md), and [roadmap](docs/mvp-plan.md). Phase 6 adds implementation aids for database role separation, audit export, rate limits, metrics and backup/restore; operators still need to configure external immutable retention, global gateway controls, run a restore drill and complete deployment security review.

## Deployment packaging

Kustomize deployment bases and GKE overlays are documented in
[`deployments/kustomize/README.md`](deployments/kustomize/README.md). Helm
charts remain available as an alternative.
