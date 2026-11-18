# Enterprise hardening assessment

Assessment date: 2026-11-18. This is an incremental audit of the existing
architecture, not a production qualification or a claim that every code path
has received independent security review. The authoritative capability status
remains [production upgrade requirements](production-upgrade-requirements.md).

## Baseline and scope

Inspected the five Go modules, dashboard authentication/proxy and deployment
configuration, API routing and authorization, campaign approval/admission and
reservation transactions, operator authorization/recovery/kured boundaries,+Ansible catalogs, migration inventory, CI, offline tooling, backup/restore
scripts, existing simulator, and qualification matrix. Read AGENTS.md,
architecture, security, agent protocol, durable-maintenance ADR, and recovery
documentation before implementation.

Existing safeguards to retain: issuer/audience/signature/expiry checks, tenant
membership on API requests, independent campaign approval bound to immutable
plans, signed expiring host permits, local safety vetoes, deterministic Jobs,
durable action intent/receipts, owned cordons and reservations, read-only
inspection after ambiguity, kured ownership CAS, transaction-scoped scheduler
fencing, and append-only audit history. Host and provider execution defaults
remain off.

Baseline checks before code changes:

| Check | Actual result |
|---|---|
| All five modules, `go test -race -count=1` | PASS; initial run skips PostgreSQL/envtest cases without configured prerequisites |
| `make vet build contract` | PASS; 48 API operations validated |
| Dashboard typecheck, lint, production build | PASS |
| `gofmt -l api control-plane agent operator integrations` | PASS; empty output |
| Upgrade tooling Python suite | PASS, 96 tests |
| Ansible EE contract suite | PASS, 49 tests, one skipped because ansible-playbook is unavailable |
| Offline package artifact suite | PASS, 9 tests |
| API-server envtest with existing local binaries | PASS |
| PostgreSQL integration suite in a separate disposable local database | Running; existing management database is not used |

No baseline test failure has been observed so far. A local PostgreSQL container
and API-server test binaries are available; there is still no configured
disposable Ubuntu worker/kube context. Local API-server or database evidence
does not qualify host execution, disconnected deployment, or scale.

## Confirmed findings and remediation

| ID / priority | Demonstrated path | Remediation strategy | Verification/status |
|---|---|---|---|
| SEC-01 / P0 | Dashboard proxy checks only whole `.`/`..` segments and backslashes. A decoded `../../agent` segment is accepted and URL construction resolves outside the active organization prefix. `dashboard/src/app/api/kordex/[...path]/route.ts` | Validate canonical segments and an explicit method/route allowlist; build only organization-scoped upstream URLs and refuse redirects | Reproduced with Node URL construction; patch/tests pending. This does not demonstrate bypass of API tenant membership or agent signatures |
| SEC-02 / P0 | Proxy and organization switch use `request.text()` before checking character count, buffering unbounded input and counting characters rather than bytes | Bound streaming request reads before allocation, including missing/false Content-Length and multibyte payloads | Code path demonstrated; streaming regression pending |
| SEC-03 / P0 | `control-plane/internal/config/config.go` derives bootstrap enablement from the local-development flag even when OIDC is configured. A production listener accidentally given that flag accepts the globally administrative bootstrap token | Make OIDC and local bootstrap modes disjoint; reject contradictory OIDC/local-development startup configuration while preserving isolated non-OIDC local Compose workflows | Configuration regression pending; no claim that shipped production chart defaults currently enable bootstrap |
| AUTH-01 / P1 | Dashboard deliberately forwards an ID token; API verifier deliberately accepts ID tokens for its configured audience. A dedicated access-token contract is not implemented | Document the exact existing audience contract and provide an explicit opt-in access-token mode only with resource audience/type/scope verification; never silently substitute token types | Existing contract inspected; migration pending |

## Requirements and remaining evidence

These patches address UPG-04, UPG-12, UPG-14, UPG-18 and UPG-19 without
completing their acceptance criteria. The existing qualification runner,
fault recorder, pinned matrix, fixed-catalog recovery, kured regressions,
scheduler integration tests, simulator, audit verifier and offline tools are
reused. They are not replaced with parallel implementations.

All real Ubuntu package/reboot/failure and disconnected installation cases
remain NOT RUN. An explicitly identified existing disposable worker, reviewed
lab policy/artifacts, console/reset/fault controls and off-cluster retention are
external prerequisites. No cloud or Kubernetes infrastructure is provisioned
by this audit. Multi-replica process-kill/partition drills, externally signed
audit checkpoints, full offline verification and the requested measured scale
profiles must be reported separately from ordinary unit/integration success.
