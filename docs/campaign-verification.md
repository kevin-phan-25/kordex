# Phase 4 verification — 0.4.0

Implemented and exercised on 2026-11-14. These results establish the constrained campaign workflow, not a production readiness or fleet-capacity certification.

## Implemented boundary

Persistent campaign API, target snapshots and history; four rollout stages; target selectors and explicit canaries; IANA/offset-validated windows; independent stage approvals; shared organization/fleet/site/cluster/node budgets; bounded batches; pause/resume; signed cancellation with local recovery; bounded retries and failure gates; separate replicated scheduler process; OCI/Compose/self-hosted Helm packaging; simulator and CI coverage. Existing ValidateOnly and stateless-worker DrainAndVerify are the only executors.

New implementation files are grouped under:

- `api/campaign/`: contract normalization, time-zone windows, deterministic target plans, threshold/retry logic and tests.
- `api/protocol/control.go`: exact-operation signed withdrawal and verification tests; maintenance protocol carries campaign provenance and contiguous status history.
- `control-plane/internal/store/campaign*.go` and `limits.go`: durable campaign lifecycle, approvals, events, shared reservations, transactional scheduler and PostgreSQL integration tests.
- `control-plane/internal/httpapi/campaigns.go`: campaign, concurrency and cancellation routes with role checks; `api/openapi/v1.json` documents 37 total operations.
- `control-plane/cmd/kordex-scheduler/` and `kordex-simulate/`: continuous worker and explicitly synthetic test runner.
- `control-plane/migrations/004_campaigns.sql`, `005_campaign_admission_cursor.sql`, `006_campaign_query_indexes.sql`: immutable schema, bounded rotating admission scan and query indexes.
- `deployments/helm/kordex-control-plane/` and `deployments/local/compose.campaigns.yaml`: API/worker deployment packaging without committed secrets.
- Agent inventory/bridge and operator authorization/reconciliation: complete selector evidence, durable withdrawal delivery, independent signature validation and verified recovery tests.
- `tests/integration/maintenance_smoke.py`, CI, Makefile, README and campaign architecture/security/recovery documentation.

## Automated results

Passed:

- Build all four Go modules and API, agent, operator, scheduler, keygen and simulator binaries.
- Go unit, HTTP contract, OIDC, agent, controller and PostgreSQL integration suites, plus final API process restart/persistence smoke.
- Full `go test -race -count=1 ./api/... ./control-plane/... ./agent/... ./operator/...` with PostgreSQL and real Kubernetes API-server envtest enabled. The host has no C compiler; race execution uses the existing Go 1.26.11 bookworm compiler container and a read-only source mount.
- go vet, gofmt, git diff --check, OpenAPI reference/auth/operation checks and full OpenAPI document/response validation.
- Generated CRD/deep-copy verification: unchanged generated definitions.
- All three Helm charts lint with required configuration. Control-plane OCI build includes API and scheduler in the nonroot distroless runtime.
- govulncheck for all four modules: no known vulnerabilities reported at verification time. Container vulnerability scanning remains a CI gate; it was not run locally for this release.

Representative database/security cases:

- Four distinct stage gates, plan participant self-approval denial, organization isolation and operator/approver/viewer HTTP authorization.
- Eight concurrent scheduler workers without exceeding the shared budget.
- Competing manual and campaign operations, including offered permit expiry and cancellation that cannot release uncertain capacity.
- Organization, fleet, site, cluster and node limits plus site availability budget; stale site inventory defers admission.
- Pause/resume, pending cancellation, signed offered-operation cancellation and durable completion history.
- Failure threshold pause, independent acknowledged resume, bounded retry with a fresh operation ID, and stale revision rejection.
- Future windows, DST skipped/repeated time validation, changed selector target veto and deterministic 4,000-node target ordering.
- Injected PostgreSQL failure after command/reservation insertion: the entire admission rolls back, with no command or reservation left behind.
- Valid and forged cancellation after cordon: no additional eviction, original ownership retained until verified recovery, no stranded cordon caused by cancellation handling.

Reproduce core checks with a dedicated disposable PostgreSQL database:

```sh
export KORDEX_TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55432/kordex?sslmode=disable'
export KUBEBUILDER_ASSETS=/path/to/envtest/1.37.0
export KORDEX_REQUIRE_ENVTEST=true
make build vet contract
go test -race -count=1 ./api/... ./control-plane/... ./agent/... ./operator/...
```

Campaign integration tests create and drop unique test schemas, so their scheduler cannot claim another test's campaigns. Other database tests also require a disposable database. CI supplies PostgreSQL, envtest and kind.

## Real Kubernetes drill

Passed on a disposable three-node kind cluster (one control plane, two workers), with PostgreSQL and host-run binaries using chart-derived service-account impersonation:

- Existing real PDB blockage before cordon, eviction after budget availability, operator restart during maintenance, workload recovery, uncordon and durable operation replay rejection.
- Real two-target ValidateOnly campaign, paused admission, resume and sequential stage completion through the durable outbound agent/operator path.
- Two scheduler processes, then stopping one after admission; the remaining process completes the persisted campaign.
- Stop the operator, offer a second campaign's command, cancel, observe the durable signed withdrawal annotation, restart the operator and verify terminal cancellation with both workers schedulable.

The lab provider's broken container DNS required temporary `/etc/hosts` mappings inside disposable kind workers. This is a test-host workaround, not product configuration. Test namespaces, credentials and processes are disposable. This drill does not validate real host kernels/reboots, production HTTPS ingress, a fully Helm-managed hub pod deployment or GCP infrastructure.

The runner requires KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_OPERATOR_BINARY, KORDEX_KEYGEN_BINARY, KORDEX_SCHEDULER_BINARY, KORDEX_TEST_DATABASE_URL, KUBECONFIG, KUBECTL and HELM. Run `python3 tests/integration/maintenance_smoke.py` only against disposable infrastructure.

## Synthetic fleet measurement

A complete run processed 4,000 synthetic nodes in 100 synthetic clusters across four sites, issuing 4,000 synthetic ValidateOnly operations and reaching Succeeded in 254 scheduler ticks. The initial run took 71.29 seconds while the real kind lab was active. The final repeat, with the indexing/validation changes and the first run's 4,000-operation history retained, also succeeded in 254 ticks and took 107.15 seconds while container builds and race tests ran concurrently. These shared-host timings are observations, not a controlled throughput benchmark.

The simulator creates inventory and agent identities and fabricates explicitly named SyntheticSuccess reports. It has no Kubernetes clients and cannot prove real drain latency, quorum safety, node recovery, WAN reliability or production scalability. Historical events remain in the dedicated simulation database for inspection. No production-capacity claim is made.

```sh
export KORDEX_SIMULATION_DATABASE_URL='postgres://postgres@127.0.0.1:55432/disposable_simulation?sslmode=disable'
make simulate
```

## Remaining verification and engineering risks

Not implemented or not yet validated: real VM package/kernel/reboot workflows, storage/control-plane maintenance adapters, OS rollback, WAN partition soak tests at fleet scale, abrupt scheduler SIGKILL during a live database transaction, PostgreSQL HA failover/backup restore, multi-region clock/latency behavior, production OIDC/HTTPS deployment and a fully deployed hub Helm rollout. Existing local tests cover connection loss and operator/agent restart behavior, and SQL fault injection covers transaction rollback; these do not substitute for those infrastructure drills.

Offered operations deliberately retain capacity indefinitely until verified terminal recovery. A lost node therefore requires incident response; no force-release endpoint is provided. Audit and operation receipts have no automatic archival/garbage-collection policy yet. Admission is serialized within each organization, and cluster/node concurrency stays at one; production tuning requires measurement. OIDC and basic RBAC exist, while enterprise security hardening, rate limits, immutable audit export and air-gap distribution remain later work.

No cloud resources were provisioned. Phase 5, the Next.js operations dashboard consuming these APIs, is the next implementation milestone. Phase 4 implementation stops here.
