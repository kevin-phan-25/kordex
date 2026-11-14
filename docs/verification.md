> Historical Phase 1 report. For release 0.2.0, see [registration verification](registration-verification.md).

# Foundation verification and handoff

Phase 1 only. No agent, operator, campaign, UI, Terraform deployment or maintenance action was implemented. No Git commit, cloud deployment or hosted CI run was performed.

## Environment

Inspected an empty Git repository with no commits and no AGENTS.md. Host: Rocky Linux 10.2, x86-64. Go, Make, Docker and a C compiler were absent. Downloaded Go 1.26.11 into /tmp and checked its SHA-256 against the release manifest. Go caches and scanner tooling are in /tmp. Podman ran disposable PostgreSQL 17 and the compiler/runtime containers. Host unit tests initially skipped database tests without a DSN; final runs explicitly supplied the disposable database and did not skip them.

## Passed checks

| Check | Result |
| --- | --- |
| Go build and vet | Passed on final source/dependencies |
| Unit and API tests | Passed: auth, validation, bounded inputs, scope forwarding, errors, health/readiness |
| PostgreSQL integration | Passed: concurrent migrations, duplicate conflicts, tenant-scoped site queries, transactional audit rollback, reconnect persistence, migration drift rejection |
| Race tests with PostgreSQL | Passed in golang:1.26.11-bookworm with C compiler |
| Real-process HTTP smoke | Passed: auth, create, conflict, graceful SIGTERM, restart, persistent site read |
| Go vulnerability scan | No vulnerabilities found after dependency upgrades |
| OCI build | Passed; final image localhost/kordex:foundation |
| Runtime container | Nonroot, read-only filesystem, capabilities dropped; healthz and database-backed readyz returned 200 |
| Formatting | gofmt clean |
| OpenAPI sanity | Passed: six operation IDs, resolved local references, protected API declarations |
| YAML parsing | Compose and CI parsed successfully with PyYAML |

Race-run statement coverage: config 94.7%, HTTP API 87.6%, store 69.2%. Main and telemetry have no direct unit coverage; the process smoke exercises main but does not contribute to these Go coverage percentages. These are coverage observations, not a production-readiness claim.

The initial scan found vulnerable dependency versions. Updated pgx, OpenTelemetry and transitive dependencies, pinned resolved versions/checksums, reran tests and scan. No known reachable vulnerability was waived.

## Commands executed

Repository/environment inspection: `pwd`, `rg --files`, `git status --short`, `git log -1`, `find .. -name AGENTS.md`, tool discovery and OS inspection. No existing source was overwritten.

Tooling: curl Go release metadata/archive, `sha256sum`, tar extraction; `go mod tidy`; `go get -u ./...` to remediate scan findings; install `golang.org/x/vuln/cmd/govulncheck@latest` (resolved v1.9.0). CI pins scanner v1.9.0. Cache locations were explicitly set to writable /tmp paths.

Final equivalent verification commands (Go commands from control-plane/):

```sh
go build -trimpath -o /tmp/kordex-foundation ./cmd/kordex
go vet ./...
KORDEX_TEST_DATABASE_URL='<disposable PostgreSQL DSN>' go test -count=1 -v ./...
# Executed inside the Go toolchain container, with host-loopback PostgreSQL:
KORDEX_TEST_DATABASE_URL='<disposable PostgreSQL DSN>' go test -race -count=1 -cover ./...
govulncheck ./...
```

From the repository root:

```sh
gofmt -l control-plane
python3 scripts/check-openapi.py
KORDEX_BINARY=/tmp/kordex-foundation KORDEX_TEST_DATABASE_URL='<disposable DSN>' python3 tests/integration/smoke.py
podman build -f control-plane/Dockerfile -t localhost/kordex:foundation .
```

Podman used explicit /tmp storage/run directories, a temporary loopback-only PostgreSQL instance, a read-only source mount for race tests, and a runtime container with `--read-only --cap-drop ALL --security-opt no-new-privileges`. Runtime credentials were generated into a mode-0600 /tmp environment file and never committed. Health endpoints were checked over actual loopback HTTP. The test containers are stopped after validation. Toolchain/image caches remain available for follow-up work.

`make` could not run on this host, so its Go/Python targets were executed directly. Host `go test -race` could not run without C tooling; the containerized race run passed. Restricted network attempts failed before authorized tooling/dependency downloads were retried. Docker Compose is not installed: its YAML was parsed but the complete Compose startup was not exercised. The equivalent image/database/runtime path was tested through Podman. OpenAPI sanity checking is intentionally not full OpenAPI schema validation. Hosted Actions, Trivy container scanning, OTLP collector export and production TLS were not run locally.

## Architectural decisions

Three ADRs record modular hub/spoke/local authority, PostgreSQL/REST versioning, and restricted bootstrap authentication. The implemented management plane is a single bounded HTTP service. Explicit transactional migrations and audit writes establish persistence before scheduling. Future schedulers require database leases/fencing, atomic reservations and an outbox. Agent delivery remains outbound-only; local operator safety will always veto central intent. No public API domain or provider-specific core dependency is fixed.

## Outstanding risks and missing tests

- Bootstrap bearer access is global administration, not OIDC/RBAC or tenant membership enforcement. No public/production deployment is safe yet.
- Runtime/migration PostgreSQL roles are not separated; audit records are not externally immutable. Backup/restore drills, rate limits, secret rotation and security penetration tests are pending.
- Actions and base-image tags still need broader supply-chain hardening/digest policies; the Trivy action is commit-pinned. Container vulnerabilities have not been measured locally.
- No envtest, kind, controller, PDB/drain, agent disconnection/restart, scheduler HA/concurrency, campaign failure-injection, real-VM package/reboot, scale simulator or UI tests exist yet.
- No production SLO, measured fleet capacity, RPO/RTO, audit retention policy, notification routing or API group domain has been chosen. Offset pagination is only for small admin lists.
- OS/storage/quorum execution and ambiguous-action recovery remain design gates, not features. Kind cannot prove host reboot or kernel-upgrade safety.

## Exact next milestone

Phase 2: authenticated outbound cluster registration. First finalize enrollment/revocation and tenant authorization semantics. Implement single-use enrollment, rotatable cluster identity, cluster/agent persistence, freshness-aware heartbeats, bounded inventory and least-privilege Helm deployment. Exit with kind registration plus replay/impersonation/expiry/reconnect tests. Maintenance execution remains disabled. Do not start Phase 2 until the foundation has been presented.

## Created file manifest

- `.dockerignore`
- `.github/workflows/ci.yaml`
- `.gitignore`
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
- `control-plane/migrations/001_foundation.sql`
- `control-plane/migrations/embed.go`
- `dashboard/README.md`
- `deployments/helm/README.md`
- `deployments/local/.env.example`
- `deployments/local/compose.yaml`
- `docs/adr/0001-modular-hub-spoke.md`
- `docs/adr/0002-persistence-and-api.md`
- `docs/adr/0003-bootstrap-security.md`
- `docs/architecture.md`
- `docs/failure-recovery.md`
- `docs/mvp-plan.md`
- `docs/product-vision.md`
- `docs/security.md`
- `docs/verification.md`
- `go.work`
- `infrastructure/terraform/README.md`
- `integrations/README.md`
- `operator/README.md`
- `scripts/check-openapi.py`
- `tests/integration/README.md`
- `tests/integration/smoke.py`
