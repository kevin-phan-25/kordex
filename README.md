# Kordex

Enterprise infrastructure lifecycle and fleet orchestration, with centralized coordination and independent local safety.

**Current release: 0.4.0 — durable fleet maintenance campaigns.** The Go control plane and outbound agent provide tenant-scoped inventory, OIDC, secure enrollment and durable signed operation delivery. The controller-runtime operator implements preflight validation and PDB-protected stateless-worker drain/recovery drills with durable ownership, replay receipts and verified uncordon. Phase 4 adds immutable campaign targets, four rollout stages, independent approvals, time-zone-aware windows, shared concurrency budgets, retries, failure gates and verified cancellation. OS/kernel updates, reboots, storage/control-plane maintenance, dashboard and cloud provisioning remain unimplemented.

See [campaign orchestration](docs/campaigns.md), [Phase 4 verification](docs/campaign-verification.md), the [maintenance workflow and deployment boundary](docs/maintenance-operator.md), [operator](operator/README.md) and [current verification](docs/maintenance-verification.md). Maintenance is disabled unless a hub signing key is configured and agent delivery is explicitly enabled.

Branding is configurable through KORDEX_PRODUCT_NAME. Internal protocol identifiers remain stable across renaming. Fleet size targets are design goals, not proven production capacity.

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

`make build` also produces kordex-scheduler, kordex-operator and kordex-keygen. `make generate` regenerates CRDs/deep copies; `make envtest` requires KUBEBUILDER_ASSETS.

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
| dashboard/ | Future Next.js operations UI |
| integrations/ | Future provider, storage, quorum and OS adapters |
| deployments/ | Local Compose and least-privilege agent Helm chart |
| infrastructure/ | Future Terraform; no resources provisioned |
| docs/ | Architecture, security, recovery, roadmap, ADRs and verification |
| tests/ | Process and real-cluster smoke tests |
| scripts/ | Contract sanity verification |

Read the [vision](docs/product-vision.md), [architecture](docs/architecture.md), [security](docs/security.md), [failure model](docs/failure-recovery.md), and [roadmap](docs/mvp-plan.md). Production hardening still requires separate database roles, backup/restore drills, security review, rate limits, immutable audit export and deployment verification.
