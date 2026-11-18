# Kordex

Enterprise infrastructure lifecycle and fleet orchestration, with centralized coordination and independent local safety.

The [Kordex Fleet Platform roadmap](docs/KORDEX-FLEET-PLATFORM-ROADMAP.md)
organizes the next product increments. See its [architecture](docs/KORDEX-ENTERPRISE-ARCHITECTURE.md),
[security boundary](docs/KORDEX-SECURITY-MODEL.md), [qualification guide](docs/KORDEX-UPGRADE-QUALIFICATION.md),
[readiness evidence](docs/KORDEX-PRODUCTION-READINESS.md), and
[customer-value measurement plan](docs/KORDEX-CUSTOMER-VALUE-VALIDATION.md).

## What is supported today

Kordex implements inventory, signed approval-driven campaigns, and constrained
stateless-worker drain/recovery. Host package/reboot execution (Debian/Ubuntu and
RPM-family Ansible EE) and GKE node-pool upgrades are opt-in, disabled by default,
and **not production-qualified**.

No upgrade path has recorded disposable VM or cluster upgrade failure evidence.
Host tooling has contract/simulator and Kubernetes API-server (envtest) evidence;
GKE upgrade behavior has contract/simulator evidence. Earlier Kubernetes
maintenance drills do not qualify package updates, reboot, or provider upgrades.

The [production upgrade requirements](docs/production-upgrade-requirements.md)
are the authoritative capability and qualification status. The next milestone is
one disposable Ubuntu LTS package + reboot + recovery qualification, including
failure cases and the self-managed offline artifact workflow. GKE expansion is
deferred until that Ubuntu failure evidence is recorded.

See [campaign orchestration](docs/campaigns.md), [Phase 5 verification](docs/dashboard-verification.md), [Phase 4 verification record](docs/campaign-verification.md), the [maintenance workflow and deployment boundary](docs/maintenance-operator.md), and [operator](operator/README.md). Maintenance is disabled unless a hub signing key is configured and agent delivery is explicitly enabled.

See the [Phase 6 hardening guide](docs/phase6-hardening.md) and [verification record](docs/phase6-verification.md) for audit export, database roles, rate limits, metrics, backup/restore procedures and remaining operational gates.

See [Phase 7 integrations](docs/phase7-integrations.md), its [verification record](docs/phase7-verification.md), the [Phase 8 observability work](docs/phase8-operational-observability.md), and the [GCP Terraform foundation](infrastructure/terraform/gcp/README.md).


For the optional GKE lab, follow the [Google Cloud test deployment guide](docs/gcp-test-deployment.md). It creates a disposable GKE cluster and connects it to the local control plane; it is not a cloud-hosted Kordex deployment.

For the limited, PDB-preserving GKE maintenance qualification flow, see [GKE maintenance validation](docs/gke-maintenance-validation.md). It covers `ValidateOnly` on a disposable cluster; it is not an OS-update or reboot workflow.

Branding is configurable through KORDEX_PRODUCT_NAME. Internal protocol identifiers remain stable across renaming. Fleet size targets are design goals, not proven production capacity.

## Dashboard

The responsive Next.js dashboard is in [dashboard/](dashboard/README.md). It uses OIDC authorization-code flow with PKCE, encrypted HTTP-only sessions, and a same-origin server API proxy. It receives no Kubernetes credentials. Configure an OIDC issuer, a client ID that matches the management API audience, and a 32-byte random session secret. The OIDC callback is `${KORDEX_DASHBOARD_URL}/api/auth/callback`; production origins must use HTTPS. See [dashboard deployment and limitations](dashboard/README.md).

The campaign planner binds targets to fresh agent-reported policies and exact
action digests. See [campaign orchestration](docs/campaigns.md) for workflow
instructions and the authoritative qualification status linked above.

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
| deployments/ | Local Compose, Helm charts, Kustomize hub and spoke deployments, self-managed overlays, plus signed offline bundles |
| infrastructure/ | Optional Terraform definitions and disposable lab scaffolding |
| docs/ | Architecture, security, recovery, roadmap, ADRs and verification |
| tests/ | Process and real-cluster smoke tests |
| scripts/ | Contract checks, audit export and PostgreSQL backup/restore helpers |

Read the [vision](docs/product-vision.md), [architecture](docs/architecture.md), [security](docs/security.md), [failure model](docs/failure-recovery.md), and [roadmap](docs/mvp-plan.md). Phase 6 adds implementation aids for database role separation, audit export, rate limits, metrics and backup/restore; operators still need to configure external immutable retention, global gateway controls, run a restore drill and complete deployment security review.

## Deployment packaging

Kustomize deployment bases and GKE overlays are documented in
[`deployments/kustomize/README.md`](deployments/kustomize/README.md). Helm
charts remain available as an alternative. For self-managed, private-network,
and air-gapped installation, the guide includes both the cluster-side agent /
operator and self-hosted hub deployment paths; use the [offline deployment
guide](docs/air-gapped-deployment.md) and its signed OCI image bundle workflow.
Cloud provider APIs are optional adapters; they are not required by the core
control plane, agent, or operator.
See [ADR 0008](docs/adr/0008-provider-neutral-airgap.md) for the design choice.
