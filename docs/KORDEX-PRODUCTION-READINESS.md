# Kordex Fleet Platform readiness report

Date: 2026-11-18. Baseline: `ab843a3`; implementation is an uncommitted working
tree patch. This report does not create a release, signed artifact, pilot signoff
or qualification. Authoritative [upgrade status](production-upgrade-requirements.md)
and the [implementation roadmap](KORDEX-FLEET-PLATFORM-ROADMAP.md) distinguish
implementation from real infrastructure evidence.

## Patch groups

| Area / priority | Confirmed problem or improvement | Files | Remaining risk / status |
|---|---|---|---|
| HTTP boundaries / P0 | Encoded path segments escaped the active organization prefix; bodies were buffered before size checks | `dashboard/src/lib/proxy.ts`, proxy and organization routes, `dashboard/tests/proxy.test.mjs`, package test command and CI | Implemented; deployment ingress limits and real browser/provider checks still required |
| Authentication / P0 | OIDC and development bootstrap could share a listener; authorized party was not independently checked | `control-plane/internal/config/`, `internal/identity/`, `internal/httpapi/server.go` and regression tests | Implemented; intentional isolation of OIDC/bootstrap is a security configuration change |
| Authorization / P0 | Strengthen fail-closed role handling and negative tenant coverage | `control-plane/internal/httpapi/authorization_hardening_test.go`, `campaigns.go`; store participant-approval regression | Implemented; independent security assessment remains pending |
| Transaction correctness / P1 | Nested coverage query returned pgx `conn busy`; three baseline fixtures omitted required approval | `control-plane/internal/store/campaigns.go`, `campaigns_test.go` | Implemented; original tenant/admission/approval gates preserved |
| Lifecycle discovery / P1 | Add typed, bounded, non-mutating discovery and compatibility contracts | `api/lifecycle/`, `integrations/lifecycle/drivers.go`, `integrations/cmd/kordex-discover/` | Implemented and unit-tested foundation; new mutators and signed-binding persistence integration pending |
| Inventory / P1 | Persist and display advisory distribution/provider/role/pool hints | Agent inventory, protocol Node, API report validation and OpenAPI, dashboard fleet/compatibility page and navigation | Implemented; definitive native discovery and remote host probes pending; hub-first rollout required |

## Verification

Baseline commands executed before patches: all-module race tests; `make vet build
contract`; dashboard typecheck/lint/build; formatting; Python upgrade tooling
(96), EE contracts (49, one syntax-rendering test skipped without Ansible), and
offline package tests (9). Initial Go invocation lacked database/envtest settings
and skipped those cases; they were then run with real local prerequisites.

Local API-server envtest passed using Kubernetes 1.37.0 binaries. A fresh isolated
database/role was created inside the existing local PostgreSQL 17 container;
the existing management database was not used. The first store run exposed five
preexisting failures: two `conn busy` failures and three tests expecting work
before independent approval. After correcting query ordering and fixtures,
the database-backed race suite passed. New participant-approval coverage is
included in final verification.

Final verification commands and results are recorded below after execution.

## Qualification and commercial acceptance

No disposable Ubuntu worker/context is configured. Real package, reboot,
network/failure/recovery, disconnected deployment, customer comparison,
10-cluster/500-node pilot and production qualification remain NOT RUN.
SUSE/APK/Pacman/image and additional Kubernetes mutating adapters remain
Unsupported, not hidden behind fake success. The requested later product
workstreams remain planned; this patch is a Release 0.1 increment, not a complete
enterprise platform. No production readiness, reduced effort or cost savings
has been established. The customer-value answer is **not yet**.
