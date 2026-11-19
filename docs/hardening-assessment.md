# Enterprise hardening assessment

Assessment date: 2026-11-18. This is an incremental audit of the existing
architecture, not a production qualification or a claim that every code path
has received independent security review. The authoritative capability status
remains [production upgrade requirements](production-upgrade-requirements.md).

## Baseline and scope

Inspected the five Go modules, dashboard authentication/proxy and deployment
configuration, API routing and authorization, campaign approval/admission and
reservation transactions, operator authorization/recovery/kured boundaries,
Ansible catalogs, migration inventory, CI, offline tooling, backup/restore
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
| SEC-01 / P0 | Dashboard catch-all proxy receives decoded path segments. Traversal or encoded delimiters could escape the active organization prefix if forwarded into URL construction. `dashboard/src/app/api/kordex/[...path]/route.ts` | Validate canonical segments and a fixed method/route allowlist; construct only organization-scoped upstream paths; refuse redirects | Implemented in `dashboard/src/lib/proxy.ts`. Decoded and multiply encoded traversal cases are rejected before upstream fetch; route/method allowlist, organization prefix, and redirect refusal tests pass. This does not demonstrate a bypass of API tenant membership or agent signatures |
| SEC-02 / P0 | Proxy request bodies must not be buffered without a byte bound; declared lengths may be absent or inaccurate | Bound streaming reads before allocation, enforce bytes rather than characters, and cancel on overflow | Implemented in `readLimitedBody`, used by the management proxy and organization-switch route. Tests pass for chunked input, missing and false Content-Length, multibyte payloads, invalid UTF-8, and no upstream request on rejection |
| SEC-03 / P0 | Bootstrap authentication must never be enabled alongside OIDC, including when a production listener is given the local-development flag | Make OIDC and local bootstrap modes disjoint; reject contradictory OIDC/local-development configuration while preserving isolated non-OIDC local workflows | Implemented in `control-plane/internal/config/config.go`; config tests pass for loopback and exposed OIDC listeners, bootstrap disabled, and contradictory mode rejection. This does not establish external identity-provider qualification |
| SEC-04 / P1 | Dashboard server routes attach bearer credentials to configured management API calls; default fetch redirect handling could change the requested endpoint | Set `redirect: manual` on every dashboard-to-management API fetch and reject redirects in the catch-all proxy | Implemented with `fetchManagementNoRedirect` and used by the proxy, API library, sign-in session setup, and organization routes. Proxy and helper tests confirm manual mode and refusal; all current direct management API fetch call sites were checked |
| AUTH-01 / P1 | Dashboard and API default to an explicit ID-token contract | An opt-in RFC 9068 access-token mode now checks resource audience, `typ`, expiry/issued-at, subject, client ID, token ID and required scopes; dashboard uses access token for API calls while retaining ID token for profile claims | Local Go JWT contract, dashboard build/typecheck, Helm/Kustomize render tests pass; real identity-provider interoperability and rotation remain unqualified |

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

## Verification after the baseline

- `cd dashboard && npm test` — PASS, 11 tests, including SEC-01 path escape,
  SEC-02 bounded-body, and redirect refusal cases.
- `cd dashboard && npm run typecheck && npm run lint` — PASS.
- `cd control-plane && go test ./internal/config ./internal/httpapi` — PASS;
  SEC-03 OIDC/bootstrap separation tests are included in `internal/config`.
- The dashboard runtime image also completed its local production Next.js build
  from the digest-pinned Node base. These checks verify the local code path only;
  they are not an external penetration test or production deployment result.

The manual-redirect change applies to every dashboard management API request
that carries the user's bearer token. Identity-provider protocol redirects are
outside this management API boundary and continue to follow the OIDC client
library's protocol handling.
