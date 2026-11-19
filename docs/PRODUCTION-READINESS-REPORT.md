# Kordex production readiness report

Date: 2026-11-19. This is a current implementation snapshot, not a release
approval. Upgrade qualification remains governed by
[`production-upgrade-requirements.md`](production-upgrade-requirements.md).
No executor is production-qualified.

| Capability | Implementation status | Automated test status | Real infrastructure qualification | Remaining blocker |
|---|---|---|---|---|
| Management API, PostgreSQL state, OIDC, tenant roles, audit | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Authenticated membership/role denials have a separate append-only hash chain and bounded Ed25519-signed export; the CLI tenant archive and authenticated dashboard endpoint produce signed snapshots, and the browser downloads the server-signed bundle. Local API tests verify fixed checkpoint, tenant binding, signature, ordering, and record integrity. Two-tenant PostgreSQL tests cover tenant-scoped reads, authenticated persisted-membership authorization, cross-tenant resource concealment, and concurrent-safe protection against demoting the final organization administrator. The API now revokes an exact OIDC bearer token by digest through its verified expiry and fails closed if the revocation registry is unavailable; dashboard logout clears the local cookie and reports an unconfirmed API revocation. Refresh tokens/silent refresh remain unimplemented. Production database, KMS-backed custody/rotation, deployed browser/API behavior, immutable external retention, and concurrent production tenant isolation remain unverified. Anonymous credential, malformed-target, and rate-limit failures stay in logs. Local disposable PostgreSQL backup/restore and migration validation passed; backup naming/permissions/sidecar guards are automated. OIDC has compatible ID-token and opt-in RFC 9068 JWT access-token contracts with local tests; real-provider login/scope mapping and key rotation, HA/PITR, ingress controller/certificates/redirect policy, and independent DR evidence remain |
| Agent enrollment, durable identity, outbound heartbeats, inventory and health diagnostics | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Runner unit tests cover transient report retry, monotonic report versions, bounded exponential backoff/jitter, and cancellation during retry wait. Capability inventory is advisory; multi-distribution installed-agent, key-rotation, real network-partition, and customer identity qualification remain. Local file state rejects unsafe permissions, symlinks, and writable directories |
| Local operator validation, PDB-aware drain, reservation and recovery | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | The operator probes effective node/workload/eviction, PV/service, Rook/Longhorn read-only, and durable drain/recovery permissions with self-subject access reviews and publishes `nodeMaintenance`; preview and scheduler admission fail closed on missing/stale readiness, while Kubernetes and local operator checks remain authoritative. PostgreSQL tests cover readiness withdrawal before dispatch. The probe runs at startup and is not a live RBAC-change monitor. Distribution/version matrix, long-running fault/restart coverage, and independent review remain |
| Host-execution RBAC readiness check | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Effective host permission probes are unit-tested; real host execution remains unqualified |
| Kubernetes compatibility registry and fleet summary | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Ten targets are listed as unverified; fleet status is advisory; version, normalized node OS, architecture, and distribution-specific qualification remain empty. Agent admission inventory reports bounded counts only and does not establish effective enforcement |
| Debian/Ubuntu APT and RPM-family DNF package/reboot execution | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Disposable Ubuntu 24.04 VM matrix first; RPM/AL2023 only after Ubuntu evidence. Gates remain off |
| GKE node-pool update | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Dedicated disposable GKE evidence and provider failure/recovery qualification |
| EKS and AKS node-pool updates | Not implemented | Not implemented | Blocked by external dependency | Provider-specific adapter, identity, and failure/recovery implementation |
| Rook/Ceph and etcd safety evidence | Partially implemented | Implemented, not qualified | Blocked by external dependency | Real topology/version compatibility and recovery evidence; no storage mutation |
| Longhorn, OpenEBS, other storage, quorum mutation | Partially implemented | Implemented, not qualified | Blocked by external dependency | Generic preflight identifies OpenEBS LocalPV LVM/ZFS CSI and legacy Hostpath PVs and uses PV node affinity to block target-local data or unknown placement. A read-only Longhorn v1beta2 adapter validates fresh node readiness, volume health, expected replica count and placement, plus rebuild, restore, and migration status; it still blocks Longhorn service nodes and nodes with replicas or attached volumes because no rebuild coordination workflow exists. OpenEBS health/recovery, other storage adapters, mutations, and real topology qualification remain |
| Campaign planning, independent approvals, reservations and scheduling | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Versioned action-allowlist decisions, shared target-selector semantics, protected-node vetoes, and transactional organization/fleet/site/zone/cluster/node limits are enforced at admission; missing or contradictory zone data overlaps all zones. Campaign limits are editable in draft creation and visible in preview, detail, and start confirmation. Local PostgreSQL tests cover zone serialization and cross-zone concurrency. Full typed policy evaluation, multi-replica, database/network fault, measured scale, and production authorization qualification remain outstanding |
| Dashboard operations and administration | Partially implemented | Implemented, not qualified | Blocked by external dependency | Campaign creation validates and previews seven campaign concurrency ceilings, then displays persisted limits in campaign detail and start confirmation. An administrator-only organization concurrency limits editor includes zone limits and uses API-enforced role checks, revision comparison, an explicit review/confirm step, and the existing audit event. The read-only organization-scoped recovery queue lists Blocked, RecoveryRequired, and Failed operations with phase, receipt, inventory, and agent context; it cannot resume work or release reservations, and local operators remain authoritative. Broader typed policy editing, recovery actions, system administration, full evidence workflows, and deployed browser/API qualification remain |
| Self-hosted production management plane | Partially implemented | Implemented, not qualified | Blocked by external dependency | API/scheduler/dashboard PDBs and probes, opt-in HTTPS ingress, and configurable default-off component-scoped egress policies render in Helm/Kustomize. Helm and hub/spoke Kustomize production profiles have CI checks requiring digest-pinned application images; Kustomize profiles require customer registry names, reviewed release digests, and spoke trust keys before rendering a site deployment. Hub and spoke Helm charts validate explicit egress peers and ports; the optional spoke Kustomize restricted-egress overlay has render contract coverage. CI now compares the five Helm/Kustomize workloads' security, resources, probes, ports, services, disruption budgets, default-off execution gates, and runtime image tags. PostgreSQL HA, migration rollback, controller/certificate/redirect, site-specific peers, CNI enforcement, secrets, scheduler replica fault qualification, and production DR remain unqualified |
| Air-gapped and restricted-network delivery | Partially implemented | Implemented, not qualified | Blocked by external dependency | Disconnected end-to-end install and host package execution; site artifacts still require controlled manual transfer |
| Supply chain and runtime hardening | Partially implemented | Implemented, not qualified | Blocked by external dependency | All runtime Dockerfiles are pinned to base image index digests and statically checked. Production Helm profiles reject tag-only app images across all four charts. CI scans images and retains source/image-bound CycloneDX artifacts. A manually dispatched, explicitly gated release path is configured to wait for all CI jobs, scan exact multi-platform candidate digests, publish provenance and SBOM attestations, sign with Cosign, and add a version tag only after those steps; it has not been run. An opt-in Kyverno ClusterPolicy verifies signatures from the exact workflow identity and requires digest references; it has not been installed or tested with a live admission controller. Provenance/SBOM admission enforcement, independent threat review, and release evidence verification remain |
| Metrics, dashboards, alerts and tracing | Partially implemented | Implemented, not qualified | Blocked by external dependency | API, scheduler, operator, and aggregate fleet-health signals have dashboards. Bounded operator outcome, terminal duration, verified drain/reboot duration, oldest reservation age, and aggregate active RecoveryRequired count/oldest age are exported. Recovery snapshot success, timestamp, and completeness expose stale or incomplete data without identifier labels. API, scheduler, maintenance-operator, and agent spans use bounded attributes; agent W3C context is injected into API calls. OTLP endpoint wiring is optional and off by default. Collector deployment, live trace continuity, scrape/trace freshness, alert thresholds, and measured SLOs remain |
| Capacity targets and 99.9% SLOs | Partially implemented | Implemented, not qualified | Blocked by external dependency | Reproducible load tests and production-like fault/load measurements; simulator is not capacity qualification |
| Disposable Ubuntu/RPM qualification environment | Implemented, not qualified | Implemented, not qualified | Blocked by external dependency | Terraform hard-denies the product project and retains allowlist, project-bound confirmation, and live disposable-label guards. The local wrapper re-reads live project identity/state/label immediately after apply/destroy confirmation and before mutation; every GCP execution rechecks the same designation and requires a separate typed project confirmation before target confirmation. It still relies on owner review to establish the project contains no shared/non-disposable resources. Terraform validation and wrapper guard tests are local only; a separately approved disposable project, worker, credentials, recovery access, and independent reviewer are still required |

## Verification performed for this snapshot

2026-11-19 operator node-maintenance RBAC readiness increment (partial
UPG-04/UPG-14):

- The operator checks its effective node, eviction, workload/PDB,
  PV/service, Rook/Longhorn read-only, maintenance/policy/campaign resources,
  hub-connection and reservation Leases, and durable ledger permissions using
  self-subject access reviews. It publishes `nodeMaintenance` in the existing
  capability Lease, relayed by the agent. Missing, denied, indeterminate, or
  unavailable reviews publish false. The hub blocks drain/package campaign
  preview when the report is stale or false, and scheduler admission rechecks
  it before issuing work. The local operator still checks each action and
  Kubernetes remains the authorization authority. The probe uses the
  configured operator namespace and currently runs at process startup.
- Operator, protocol/lifecycle, and agent inventory tests passed. The complete
  PostgreSQL-backed `control-plane/internal/store` package passed
  (`KORDEX_TEST_DATABASE_URL=<temporary loopback DSN> go test
  ./internal/store -count=1`) against a loopback-only disposable PostgreSQL 17
  container. It covers preview denial, readiness recovery, and capability
  withdrawal before dispatch; the campaign allowlist admission fixture now
  advertises the required drain capability before campaign start.
  Dashboard tests, typecheck, and lint passed; OpenAPI sanity checks and
  `git diff --check` passed. The self-managed Kustomize overlay rendered with a
  temporary empty trust-key placeholder, and assertions confirmed default
  self-review permission is present while host SSH/NetworkPolicy RBAC remains
  absent; the placeholder was removed. Helm chart rendering could not be run
  because Helm is unavailable in this environment.
- No Kubernetes cluster or host operation was used. This verifies local
  authorization-report plumbing and database admission behavior only; it does
  not qualify a distribution, prove long-lived RBAC-change detection, or
  change execution gates or qualification rows.

2026-11-19 operator lifecycle metrics increment (UPG-17 partial):

- The operator now exports bounded terminal operation outcomes, a separate
  RecoveryRequired counter, and terminal durations,
  verified drain-phase duration, and reboot-to-host-verification duration.
  Actions are parsed from the immutable authorization and allowlisted; unknown
  action/outcome labels collapse to `other`. Metrics omit operation, node,
  cluster, organization, and user identifiers. Durable reservations now expose
  oldest active reservation age; samples are omitted until a successful DB
  snapshot exists. The operations dashboard and alert examples include these
  metrics. The four-hour reservation alert is explicitly advisory and requires
  threshold review against deployed operation timeouts.
- `go test ./internal/observability ./internal/controller` and
  `go test ./internal/store ./internal/telemetry` passed. A loopback-only
  PostgreSQL 17 container passed the full
  `KORDEX_TEST_DATABASE_URL=<temporary loopback DSN> go test ./internal/store
  -count=1` suite, including active reservation count and age query assertions.
  The store fixtures initialize the public migration chain before per-test
  schemas (migration 011 binds its security-definer function to `public`) and
  use unique bearer tokens so revocation evidence cannot leak across runs. The
  temporary container was removed.
- `make test` passed across all Go modules and repository scripts; the separate
  full PostgreSQL-backed store suite also passed. `make vet build contract`
  passed, including the 52-operation OpenAPI check. Grafana JSON, alert YAML,
  and `git diff --check` passed local validation.
- No Prometheus/Grafana stack was installed or scraped, no alert threshold or
  SLO was validated, no OTLP collector was deployed or exercised, and no live cluster or
  maintenance was used. UPG-17 remains incomplete and no qualification row
  changed.

2026-11-19 active recovery age metrics increment (partial UPG-17):

- The operator now publishes aggregate active `RecoveryRequired` count and
  oldest valid `recoveryStartedAt` age from a 15-second, leader-elected,
  Kubernetes API snapshot limited to its configured namespace. Read failures
  mark the snapshot unsuccessful while retaining the last value and timestamp;
  leader loss marks that replica inactive, and missing or future start times
  mark the snapshot incomplete. Dashboard/alert expressions select successful
  snapshots. Snapshot success,
  completeness, invalid-record count, and last-success timestamp are separate
  gauges. These metrics contain no resource identifiers. The operations
  dashboard and alert examples expose age, count, stale snapshots, and
  incomplete timestamps. Durable status and reservation behavior are unchanged.
- Controller and metrics tests passed, including valid/missing/future timestamp
  aggregation, empty snapshots, incomplete snapshot signaling, and preservation
  of last-known values after a failed read. `make test` and `make vet build
  contract` passed. Grafana JSON and Prometheus alert YAML parsed, and
  `git diff --check` passed. Deployment parity tests were attempted but skipped
  because Helm is not installed in this environment.
- No monitoring stack or Kubernetes cluster was used; no alert threshold,
  scrape freshness, or restart behavior was qualified. UPG-17 remains
  incomplete and no upgrade matrix row or execution gate changed.

2026-11-19 dashboard concurrency-policy increment (partial UPG-20):

- Added an organization-scoped page to inspect and edit scheduler concurrency
  limits. Only organization administrators see the edit control; the API
  independently enforces the role. Edits require a review/confirmation step,
  include the current revision, and surface conflicts instead of overwriting a
  concurrent administrator change. The proxy also binds mutations to the
  organization used to render the page, so a stale tab cannot update a newly
  selected organization. Cluster and per-node concurrency stay fixed at one in
  both the UI and API validation. The UI explains that limits affect
  new admissions and cannot release existing reservations or bypass local
  operator gates. The page edits concurrency only; it is not the full typed
  maintenance-policy engine or circuit breaker.
- `npm test` passed all 23 dashboard tests, including concurrency-limit range,
  fixed cluster/node caps, organization-bound proxying, and mutation
  authorization behavior. Dashboard typecheck, lint, and production build
  passed. `make test` and `make vet build contract` passed; the Go campaign
  limits and API role tests passed. A loopback-only PostgreSQL 17 container ran
  `TestCampaignScopeBudgetsAndAtomicRollback`, including committed update
  audit, stale-revision rejection, and persisted-policy checks; the
  task-specific container was removed afterward. No cluster or maintenance
  operation was used.

2026-11-19 per-zone concurrency increment (partial UPG-20/§12/§13):

- Organization and campaign budgets now include zone concurrency. Reservations
  persist a zone ID, campaign admission checks the approved zone against fresh
  inventory, and missing/conflicting topology conservatively overlaps all zones.
  Migration 013 backfills available reservation topology and sets the default
  zone budget to one. The administrator concurrency page edits the zone limit.
- The full Go suite passed with a task-specific loopback PostgreSQL 17 database,
  including migration 013 and database tests for distinct zones, same-zone
  serialization, and unknown-zone wildcard behavior. All 23 dashboard tests,
  dashboard typecheck, `make vet build contract`, and `git diff --check` passed.
  The task-specific database container was removed afterward.
- This is not multi-replica or fleet-scale qualification. Topology data can be
  incomplete, in which case admission becomes more restrictive. UPG-20 remains
  incomplete; no cluster, host, or upgrade matrix was used or changed.

2026-11-19 campaign concurrency form increment (partial UPG-20/§12/§13): the
dashboard now accepts and validates explicit campaign organization, fleet,
site, zone, cluster, node, and site-unavailability ceilings. Preview and draft
creation use the same values, and persisted campaign detail and start
confirmation display them. Dashboard tests, typecheck, lint, and production
build passed. Server admission remains authoritative; this is not full policy,
fleet-scale, or production qualification.

2026-11-19 API and scheduler tracing increment (UPG-17 partial):

- HTTP spans use route templates rather than raw URLs and include a bounded
  method, response status, and duration. Scheduler tick spans include bounded
  outcome/error class and admitted count. Trace attributes omit customer IDs,
  operation/node IDs, SQL text, and request payloads. The scheduler now
  initializes and shuts down the OTLP/HTTP pipeline. Helm and Kustomize allow
  an explicit collector endpoint; the default remains empty. Helm schema and
  runtime checks reject endpoint URLs containing credentials, query strings,
  or fragments, including Kustomize-supplied values.
- HTTP tests verify W3C trace-context continuation, route-template attributes,
  error status, method bounding, and absence of raw path/query values. Scheduler
  tests verify bounded error/outcome attributes. Helm/Kustomize parity tests
  verify both workloads default to no exporter and that Helm can configure a
  collector (5 parity tests passed); the control-plane Helm chart lint passed.
  Telemetry tests verify invalid endpoint rejection without echoing secret URL
  content. `make test` and `make vet build contract` passed after the runtime
  endpoint validation test was added.
- No collector was deployed; TLS, egress, exporter retry/load, retention, and
  cross-service trace continuity were not tested. UPG-17 remains incomplete;
  operator and agent instrumentation are covered in the following increments.

2026-11-19 maintenance-operator tracing increment (partial UPG-17):

- The maintenance reconciler now emits sampled spans with allowlisted
  maintenance phase/action, bounded reconcile outcome, and a normalized API
  error class. Operation names/UIDs, node identifiers, annotations, and raw
  error details are omitted. The operator initializes and shuts down an
  OTLP/HTTP exporter when configured; Helm and Kustomize endpoint values remain
  empty by default. Runtime validation covers both the generic and traces-only
  OTLP endpoint variables.
- Controller tests verify error-class bounding; observability tests verify
  phase/action/outcome bounding, secret-detail exclusion, and endpoint
  validation. The six Helm/Kustomize parity tests verify default-off wiring,
  configured Helm endpoint rendering, Kustomize setting resolution, and
  credential rejection. Operator
  `go test ./...`, `go vet ./...`, and chart lint passed.
- No collector, CNI egress policy, TLS path, export delivery/retry behavior,
  trace retention, or cross-service context propagation was exercised. UPG-17
  is incomplete.

2026-11-19 agent tracing increment (partial UPG-17):

- The agent emits spans for fixed management API routes and injects W3C trace
  context into those requests; the hub API already extracts that context. Span
  attributes use bounded methods/routes, response status, and fixed outcome
  classes. Unknown paths map to `unmatched`; request/response data, cluster
  identifiers, and raw errors are excluded. OTLP/HTTP export is opt-in in both
  Helm and Kustomize and validates generic and trace-specific endpoint values.
- Client tests verify trace continuation, downstream child context, bounded
  routes, and omission of request/response details. Agent endpoint tests verify
  secret-safe rejection. The seven Helm/Kustomize parity tests verify agent,
  operator, API, and scheduler default-off wiring and configured endpoint
  resolution. `make test`, `make vet build contract`, both spoke Helm chart
  lints, Helm schema parsing, and `git diff --check` passed. The parity suite
  rendered the self-managed Kustomize spoke using a temporary test trust bundle.
- Local Podman builds from the checked-in agent and operator Dockerfiles passed
  with `GOWORK=off`; resulting local-only images were
  `localhost/kordex/agent:observability-local`
  (`sha256:2ba3ff896051066094f29b996a969e1942798b9f63b970e3f88211864258573c`)
  and `localhost/kordex/operator:observability-local`
  (`sha256:32c6f7434f293c246dc952a9a392b73c19e919a50512026dac031a5fcd696c55`).
  They were not pushed or deployed.
- No live collector or CNI path was exercised. Cross-service export delivery,
  TLS, retries, retention, and operator correlation to a hub trace remain
  unqualified; UPG-17 remains incomplete.

2026-11-19 organization recovery-queue increment (partial UPG-14, UPG-16,
UPG-18):

- Added `GET /v1/organizations/{organizationID}/operations` with a required
  allowlisted phase (`Blocked`, `RecoveryRequired`, or `Failed`), bounded
  pagination, organization scoping, and point-in-time cluster/agent evidence.
  A PostgreSQL index supports this queue. The dashboard provides a read-only
  recovery view with operation checkpoints and campaign links; it exposes no
  retry, uncordon, or reservation-release action.
- `go test ./api/... ./control-plane/...` passed. A disposable loopback-only
  PostgreSQL 17 run of `go test ./internal/store
  -run '^TestDurableNodeOperationDelivery$' -count=1 -v` passed, including
  recovery-queue evidence retrieval, phase rejection, pagination, and an
  empty result for another organization. The database container was removed.
- `npm test` (20 tests), `npm run typecheck`, `npm run lint`, and `npm run
  build` passed. `python3 scripts/check-openapi.py` passed with 52 operations;
  `git diff --check` passed. Helm v3.19.0 chart lint passed for all four charts;
  production image pinning, workload parity (4 tests), egress policies (9
  tests), Kured interlock, agent inventory RBAC, HTTPS ingress, OIDC token
  contracts, offline values, and management-plane availability render checks
  passed. The binary was built from the repository-pinned CI version in a
  temporary tooling directory. No live cluster or maintenance was used. This
  does not complete recovery actions, UPG-14/16/18, or any qualification row.

2026-11-19 Kordex API bearer revocation increment (UPG-16, UPG-18):

- OIDC verification now returns the trusted token expiry to the API auth layer.
  Authenticated requests check a SHA-256 bearer digest against PostgreSQL and
  fail closed when revocation state cannot be read. `POST /v1/session/revoke`
  stores the digest through issuer-verified expiry; active records cannot be
  modified, and cleanup is restricted to expired records. Dashboard logout
  invokes the endpoint, clears its cookie even if the API is unavailable, and
  reports when revocation was not confirmed.
- Unit/HTTP tests cover successful, repeated, and denied replay revocation and
  registry outage behavior. The PostgreSQL integration passed against a fresh
  disposable PostgreSQL 17 database, covering persistence, API replay rejection,
  and active-row immutability. With `kordex_runtime` present before migration,
  SQL privilege checks confirmed SELECT/INSERT and cleanup execution are
  granted while UPDATE/DELETE/TRUNCATE are denied. A reused test database with
  stale migration checksums was rejected by the migration guard as expected.
- This is local API token revocation only. Provider revocation, refresh tokens,
  silent refresh, deployed logout behavior, and full tenant isolation remain
  unqualified; UPG-16/UPG-18 remain incomplete.

2026-11-19 OIDC subject identity validation increment (UPG-16):

- OIDC verification now rejects empty, over-255-byte, non-ASCII, and control-
  character `sub` values before they can be used as membership keys or audit
  actors. The subject remains opaque and case-sensitive; no normalization is
  performed.
- Signed-token tests cover a valid subject and each rejected boundary case.
  This tightens one identity input boundary but does not complete tenant
  isolation, provider-backed login qualification, or UPG-16.

2026-11-19 tenant-scoped read-path increment (UPG-16, UPG-18):

- `KORDEX_TEST_DATABASE_URL=<loopback-only disposable PostgreSQL 17 DSN> go test ./internal/store -run '^TestPostgresTenantScopedReadPaths$' -count=1 -v`
  — passed against a temporary `postgres:17-alpine` container bound to
  loopback. Two isolated organizations each received one site, fleet, cluster,
  node, and audit trail; all dashboard/resource reads returned only the calling
  tenant's data, including rejection-by-empty-result for the other tenant's
  cluster filter. The container was stopped and removed after the run. This
  does not establish concurrent production tenant isolation or external DB
  qualification.
- `KORDEX_TEST_DATABASE_URL=<loopback-only disposable PostgreSQL 17 DSN> go test ./internal/store -count=1`
  — the full store package, including PostgreSQL-backed tests, passed against a
  separate temporary `postgres:17-alpine` container; it was stopped and removed
  after the run.
- `go vet ./internal/store`, `go test ./internal/httpapi -count=1`, and
  `git diff --check` passed.

2026-11-19 persisted-membership API isolation increment (UPG-16, UPG-18):

- `TestPostgresTenantScopedAPIEnforcesPersistedMembership` runs the HTTP API
  with the PostgreSQL store and a test subject verifier. A user with persisted
  membership in one organization can list only that organization's sites;
  listing another organization's sites returns 403. Supplying a foreign
  cluster ID under the user's organization returns 404 without disclosing the
  cluster, and audit results do not contain the other organization's resources.
- The focused test passed, then `KORDEX_TEST_DATABASE_URL=<loopback-only
  disposable PostgreSQL 17 DSN> go test ./internal/store -count=1` passed with
  all database-backed store tests. The temporary PostgreSQL container was
  stopped and removed. This does not qualify deployed identity-provider
  behavior or production tenant isolation.

2026-11-19 organization administrator continuity increment (UPG-16, UPG-18):

- Membership role changes now serialize on the organization limits row. The
  store rejects demotion of the last administrator with `ErrLastAdministrator`;
  the API returns HTTP 409 `last_administrator_required`. A replacement admin
  can be added before the prior admin is demoted.
- `go test ./internal/httpapi -run '^TestMembershipUpdateReportsLastAdministratorConflict$' -count=1 -v`
  passed. `go vet ./internal/store` passed.
- `KORDEX_TEST_DATABASE_URL=<loopback-only disposable PostgreSQL 17 DSN> go test ./internal/store -count=1`
  passed, including a concurrent demotion test: exactly one of two simultaneous
  demotions succeeded, and the other was rejected while retaining one admin.
  The temporary PostgreSQL container was stopped and removed after the run.
- `make test` passed. `make vet build contract` passed, including builds for all
  eight Go binaries and the OpenAPI sanity check (50 operations).
- This is local automated evidence, not a claim of complete tenant isolation,
  production database qualification, or completion of UPG-16/UPG-18.

2026-11-19 OpenEBS LocalPV placement safety increment (UPG-07):

- `StatelessStorage` now recognizes OpenEBS LocalPV LVM (`local.csi.openebs.io`),
  ZFS (`zfs.csi.openebs.io`), and legacy Hostpath (`openebs.io/local`) PVs.
  It evaluates standard Kubernetes PV node affinity: target-local data blocks,
  PVs pinned to another node do not block this target, and missing/unsupported
  placement remains fail-closed. Replicated OpenEBS engines and health/recovery
  are not covered by this placement check.
- `go test ./internal/safety -run 'TestStatelessStorage(ChecksOpenEBSLocalPVNodeAffinity|ScopesPersistentVolumeChecksToTarget)' -count=1 -v`,
  `go test ./... -count=1`, and `go vet ./...` passed in the operator module.
- This is unit-test evidence only; no OpenEBS cluster was used or qualified.

2026-11-19 Longhorn fail-closed node guard (UPG-07):

- `StatelessStorage` returns `LonghornSafetyAdapterRequired` when the target
  hosts a Longhorn manager, CSI plugin, instance manager, share manager, or
  backing-image service pod. Existing generic footprint detection returns
  `StorageHealthUnknown` when a nonterminal Longhorn storage pod exists in the
  cluster. This prevents the generic stateless path from treating a storage
  node or a cluster with unknown Longhorn state as safe without health and
  rebuild evidence.
- `go test ./internal/safety -run 'TestStatelessStorageBlocksLonghornNodesWithoutHealthAdapter' -count=1 -v`,
  the full operator test suite, and `go vet ./...` passed.
- This guard is not a Longhorn health/recovery adapter; no storage node or
  cluster was used or qualified.

2026-11-19 Longhorn read-only evidence increment (UPG-07):

- `LonghornStorage` reads the v1beta2 nodes, volumes, and replicas resources.
  Missing identity/health, stale node probes, degraded or unknown volume state,
  replica count/placement mismatch, target-attached volumes, target replicas,
  and active rebuild/restore/migration state fail closed. Longhorn service pods
  on the target remain blocked because no ownership-aware rebuild workflow is
  implemented. Validated remote Longhorn service pods are excluded from the
  generic unknown-storage check only after the adapter passes.
- Helm and Kustomize operator ClusterRoles grant only `get` and `list` on the
  three Longhorn resources. Tests cover healthy remote placement, target
  replica rejection, degraded/rebuilding/stale/missing evidence, service-node
  blocking, no-footprint fallback, and composition with the Rook storage path.
- Focused test command: `go test ./internal/safety -run 'Test(LonghornStorage|RookStorageComposesLonghorn)' -count=1`.
  This is synthetic unit evidence only; no Longhorn cluster was used or
  qualified, and UPG-07 remains partial.

2026-11-19 recovery reservation-custody increment (UPG-05, UPG-10):

- Recovery now requires the operation to retain the durable cluster-slot Lease
  before it verifies recovery or removes its node cordon. Missing or transferred
  ownership enters `RecoveryRequired` with reason `ReservationLost`; it never
  reacquires the slot or changes another operation's holder.
- Controller tests cover missing and transferred reservations at the
  uncordoning phase, plus existing recovery cases with a retained reservation.
  `make test` passed the repository Go packages, PostgreSQL backup/restore
  guards, audit-export checks, infrastructure wrapper tests, and supply-chain
  script tests. `make vet build contract` passed all Go vet/build checks and
  the 50-operation OpenAPI sanity check; `git diff --check` passed. Database-
  backed integration tests were not enabled because no disposable database URL
  was configured.
- This is fake-client controller evidence only. No live cluster or host
  maintenance was used; UPG-05/UPG-10 remain incomplete and qualification rows
  stay NOT RUN.

2026-11-19 recovery phase-journal capacity increment (UPG-05, UPG-10, UPG-14,
UPG-18):

- At 240 phase events, new recovery-block reasons now remain represented by the
  stable `AuditCapacityReached` condition instead of extending the journal
  beyond the 256-event report limit. Forced structured checkpoint writes still
  persist at the same phase and sequence; transitions are refused if the hard
  report bound is already full.
- `go test ./operator/internal/controller -run '^TestRecoveryRequiredPhaseJournalStopsAtAuditCapacity$' -count=1 -v` passed. The test verifies repeated blocker changes cannot invalidate the report and that a forced checkpoint is present after re-reading it from the API client.
- `make test` and `make vet build contract` passed. No cluster, cloud resource,
  or host maintenance was used; UPG-05/UPG-10/UPG-14/UPG-18 remain incomplete,
  and qualification rows are unchanged.

2026-11-19 durable operation phase-transition increment (UPG-04, UPG-05,
UPG-14, UPG-18):

- A shared phase graph now guards operator status writes and hub report
  ingestion. It rejects skipped recovery/verification steps and direct
  mutation-time cancellation to terminal status, while permitting verified
  provider cancellation. Terminal-to-recovery reports require
  `TerminalRecoveryIncomplete`; the operator emits that transition only after
  checking the original node UID and cordon-owner annotation. Hub report
  validation also rejects invalid initial phases and impossible event
  histories. Recovery without its original-cordon checkpoint stays
  `RecoveryRequired` and does not release the slot.
- `go test ./api/protocol ./operator/internal/controller ./control-plane/internal/store ./agent/internal/operations -count=1` passed. The full store package also passed with `KORDEX_TEST_DATABASE_URL` pointing to a temporary loopback-only PostgreSQL 17 container; it was stopped and removed after the run.
- `make test` and `make vet build contract` passed; OpenAPI remains at 50 operations. No cluster, cloud resource, or host maintenance was used. Real restart/recovery and production qualification remain outstanding.

2026-11-19 phase-event chronology increment (UPG-05, UPG-14, UPG-18):

- Shared operation-report validation rejects backwards event timestamps and
  accepts equal times for coarse clocks. Operator status persistence clamps an
  event to the preceding event time after a backwards wall-clock step.
- `make test` and `make vet build contract` passed. The full control-plane store
  suite passed against temporary PostgreSQL 17 bound to loopback; the container
  was removed after the run. This checks timestamp ordering and report
  ingestion only; it does not verify clock synchronization, real restart
  recovery, or production behavior. UPG-05/UPG-14/UPG-18 remain incomplete and
  qualification rows are unchanged.

2026-11-19 report receiver-clock bound increment (UPG-05, UPG-14, UPG-18):

- The hub rejects phase, host-checkpoint, host-receipt, and provider-checkpoint
  timestamps more than two minutes ahead of the PostgreSQL clock. The sync
  response now uses `clock_timestamp()` so it returns current database time,
  even when report processing takes a while.
- Protocol tests cover each future-dated evidence field, and the PostgreSQL
  store test rejects a future-dated operation report before accepting a valid
  report. This does not measure or enforce host clock synchronization. These
  requirements and qualification rows remain incomplete/NOT RUN.

2026-11-19 action-bound phase-history increment (UPG-04, UPG-05, UPG-14,
UPG-18):

- Hub ingestion now validates action-specific edges and success paths in
  addition to phase membership. Drain and host upgrade success must include
  recovery and uncordon; host/provider upgrades require terminal checkpoints,
  and provider success carries initial node identity digests. Local operator
  checks remain the authority; this prevents contradictory central audit
  records.
- Protocol tests cover ValidateOnly, drain, host-upgrade, and provider-upgrade
  histories. A PostgreSQL-backed store test verifies that a ValidateOnly
  operation cannot submit drain phases. This does not qualify live execution,
  and all production qualification rows remain unchanged.

2026-11-19 orphaned reservation diagnosis increment (UPG-10):

- Admission now distinguishes a held slot with a live `NodeMaintenance` owner
  (`ClusterConcurrencyLimit`) from a holder UID with no surviving operation
  (`OrphanedClusterReservation`). A failed owner lookup returns an error and
  retains the block; the controller never clears an orphaned Lease automatically.
- Focused live-owner, missing-owner, and list-failure tests passed. No live
  Kubernetes Lease or stale reservation was manipulated; UPG-10 remains
  incomplete and no qualification row changed.

2026-11-19 Helm/Kustomize workload parity increment:

- `HELM=/tmp/kordex-helm/linux-amd64/helm KUBECTL=kubectl python3 -m unittest scripts.test_deployment_parity -v`
  — 4 tests passed. Helm and Kustomize renders matched replicas, pod and
  container security contexts, workload resources, application image tags,
  shared ports, health probes, service selectors/ports, disruption budgets,
  and default-off agent/operator execution settings. Paired render inspection
  found stale Helm defaults for the control-plane and dashboard (`0.6.0`/`0.5.0`)
  while Kustomize and offline bundles use `0.8.0`; Helm image defaults and chart
  appVersions now match `0.8.0`, and chart package versions were bumped. The
  test normalizes Kubernetes defaults and CPU/memory quantities; it does not
  compare packaging-specific environment references or optional metrics.
- `helm package` succeeded for all four charts in a temporary directory; the
  control-plane and dashboard archives are now `kordex-control-plane-0.7.0.tgz`
  and `kordex-dashboard-0.6.0.tgz`, with appVersion/image tags `0.8.0`.
- CI's Helm job now runs this render-contract suite with its pinned Helm,
  kubectl, and PyYAML tools. No cluster was changed; the render comparison is
  not deployment qualification.

2026-11-19 Kustomize production image pin increment:

- `bash scripts/test-kustomize-production-image-pin.sh` — passed. Both
  production overlays rendered all hub and spoke application images as
  `repository@sha256:<64 hex>` references; the test uses a temporary copy and
  test digests so it does not alter working or ignored deployment inputs.
- `HELM=/tmp/kordex-helm/linux-amd64/helm bash scripts/test-helm-production-image-pin.sh`
  — passed for all four charts.
- `HELM=/tmp/kordex-helm/linux-amd64/helm bash scripts/test-control-plane-availability.sh`
  and `HELM=/tmp/kordex-helm/linux-amd64/helm bash scripts/test-self-hosted-ingress.sh`
  — passed across Helm and Kustomize renders.
- The CI Kustomize job now runs the production image pin check. No cluster was
  changed; rendered manifests are not a deployment qualification.

2026-11-19 explicit maintenance action allowlist increment:

- `make test` — passed across Go modules, backup/restore and audit-export
  scripts, qualification-wrapper tests, and supply-chain checks.
- `make vet build contract` — passed; OpenAPI contract remains 50 operations.
- Focused protocol, agent inventory, operator controller, and control-plane
  store tests passed; `python3 scripts/check-openapi.py` and `git diff --check`
  passed. The new reconciler status and pre-cordon denial tests passed.
- Kustomize base rendered the generated `allowedActions` CRD validation, and
  Helm/Kustomize CRD copies matched the source CRD. All control-plane store
  integration tests passed against a loopback-only disposable PostgreSQL 17
  container, including central denial of an unlisted action and campaign
  snapshot drift fencing. The campaign drift run exposed and fixed an ordering
  issue in which policy selector denial obscured the more actionable
  `TargetSnapshotChanged` reason. The ordinary `make test` invocation still
  skips database-backed tests when `KORDEX_TEST_DATABASE_URL` is absent.
- No cluster or cloud resource was changed. Host-upgrade defaults and all
  qualification rows remain unchanged; no executor qualification was gained.

2026-11-19 shared policy target-selector increment (UPG-06, UPG-14):

- A pure protocol evaluator now applies Kubernetes `LabelSelector` semantics
  consistently in campaign assessment, central operation admission, operator
  policy validation, local preflight, and final local authorization. Its
  decision includes a stable reason code, explanation, and corrective actions.
- Protocol tests cover match labels, match expressions, empty selector,
  mismatch, and invalid syntax. An operator test verifies mismatch blocks
  before cordon or eviction. A PostgreSQL-backed campaign test passed against a
  temporary loopback-only PostgreSQL 17 container; changed policy-selector
  evidence paused the approved campaign before issuing an operation. The other
  database-backed store tests were not run in this increment.
- Operator and API focused tests passed, followed by `make test` and
  `make vet build contract`. This centralizes target selection only; full policy
  evaluation and production qualification remain incomplete.

2026-11-19 versioned maintenance-action decision increment (UPG-04, UPG-06,
UPG-11, UPG-14):

- The protocol now returns an action-authorization decision bound to the
  evaluated policy generation, including allow/deny, stable reason code,
  explanation, requested action, evaluated allowlist, and corrective actions.
  Campaign assessment, central admission, operator reconciliation, local
  authorization, and policy validation use the shared evaluator. Central
  admission retains its API-specific reason code.
- Protocol, operator, and control-plane store focused tests passed. A
  PostgreSQL-backed regression test against a temporary loopback-only
  PostgreSQL 17 container verified that a changed allowlist pauses an already
  approved campaign before dispatch. `make test` and `make vet build contract`
  passed; OpenAPI remains at 50 operations. The ordinary store suite skips
  database-backed cases without `KORDEX_TEST_DATABASE_URL`; this increment ran
  only the focused PostgreSQL-backed campaign test.
- The evaluator covers action allowlists only. It does not implement the full
  shared policy engine for windows, concurrency, approvals, PDB, quorum,
  storage, and recovery. No cluster, cloud resource, or host maintenance was
  used. Host-upgrade defaults and all qualification rows remain unchanged.

2026-11-19 signed dashboard audit-download follow-up:

- `make test` — passed, including Go tests, audit CLI contract/tamper tests,
  PostgreSQL backup/restore guards, infrastructure qualification wrapper tests,
  and supply-chain policy tests.
- `make vet build contract` — passed; API contract remains 50 operations.
- `cd dashboard && npm test` — passed (19 tests); `npm run typecheck`,
  `npm run lint`, and `npm run build` — passed.
- `kubectl kustomize deployments/kustomize/hub/overlays/self-hosted` — passed;
  the API audit-key mount and pod fsGroup rendered. The chart now has an
  enabled/disabled Helm render assertion in `scripts/test-control-plane-availability.sh`,
  but Helm is not installed in this local environment, so that Helm render was
  not run here. Helm values schema JSON and shell syntax checks passed.
- No live API/browser session, deployed identity flow, key custody exercise,
  immutable export retention, cloud resource, cluster, or host-upgrade action
  was used. Audit evidence remains unqualified for production.

- `docs/threat-model.md` records the current trust boundaries, 14 attack
  scenarios, implemented controls, and residual risks. It is a repository
  engineering artifact; independent security review remains outstanding.
- `make test` — passed across all Go modules on Go 1.26.10.
- `make vet build contract` — passed; OpenAPI contract reports 50 operations.
- Dashboard `npm test`, `npm run typecheck`, `npm run lint`, `npm run build` — passed.
- `bash scripts/test-configure-offline-kustomize.sh` — passed.
- Default and optional Kustomize host-execution RBAC render checks — passed.
- Helm v3.19.0 archive checksum was verified; `scripts/test-kured-helm.sh`,
  operator chart lint, and `scripts/test-configure-offline-helm.sh` — passed.
- `python3 -m unittest scripts.test_validate_image_sbom -v` — 4 validator tests
  passed for valid CycloneDX inventories, wrong format, empty packages, invalid
  components, duplicate JSON members, and symlink rejection. A minimal CycloneDX
  fixture also passed the CLI. Trivy 0.69.3 generated a real CycloneDX SBOM from
  the existing local Podman image `localhost/kordex-dashboard:ci` (image config
  `sha256:7480863251c957ea3a99039c8e25b26ab9ca28a6fee405b7672ed1c19135c8a1`);
  the validator accepted all 41 components. Evidence file:
  `/tmp/kordex-sbom-validation/dashboard.cdx.json`, SHA-256
  `075d244d94aa754196885822a5d4078fa2621d3f51b00f647b638c4290038512`.
  The image predates this source snapshot; CI action execution against freshly
  built current-source images and retained workflow artifacts has not run.
- `python3 -m unittest scripts.test_validate_image_sbom scripts.test_create_image_sbom_manifest -v`
  — 9 tests passed. The manifest contract rejects unlisted image names,
  malformed source/image digests, symlink inputs, and overwrites; it binds the
  SBOM SHA-256, source revision, and built image configuration digest.
- `python3 -m unittest scripts.test_container_base_lock scripts.test_release_image_workflow -v`
  — verifies all four runtime Dockerfiles reference digest-pinned base images
  and checks the release workflow's manual gates, required CI dependencies,
  digest-bound scan/sign/attestation sequence, and full-SHA action pins. These
  are local source-contract tests; they do not execute GitHub Actions or
  qualify a published image.
- `python3 -m unittest scripts.test_kyverno_image_policy -v` — 3 tests passed
  for fail-closed policy fields, exact keyless workflow identity and SemVer
  matching, and Kustomize rendering. `bash
  scripts/test-kyverno-image-policy.sh` used the SHA-256-verified Kyverno
  1.18.0 CLI to reject an unsigned matching image digest and ignore an unrelated
  image. This is offline policy simulation; no cluster admission webhook or
  published Kordex signature was tested.
- Podman 5.8.2 built the control-plane, agent, operator and dashboard images
  locally from the digest-pinned Dockerfile bases. The dashboard build completed
  its production Next.js build. `npm audit --omit=dev --json` reported zero
  production dependency advisories in the current lockfile; `npm ci` reported
  seven moderate advisories in the full build dependency tree. Trivy was not
  installed in this local environment, so no vulnerability scan of these four
  freshly built images was run; the configured CI scan and release workflow
  were not executed for this snapshot.
- `HELM=/tmp/kordex-helm/linux-amd64/helm bash scripts/test-helm-production-image-pin.sh`
  — passed for all four application charts. Each chart kept its development
  tag behavior, rejected a missing/malformed production digest, and rendered
  all images by the supplied SHA-256 digest. This is Helm rendering evidence;
  it does not verify image signatures or deployed admission policy.
- The new compatibility registry tests enforce unqualified status and reject
  unsupported claims; strict K3s/RKE2/k0s version matching tests passed.
- Terraform 1.14.6 `fmt -check`, backend-free provider initialization with the
  committed lockfile, and `validate` passed for the self-managed lab module.
  This validates configuration syntax and provider schemas, not project
  access, a cloud plan, or infrastructure creation.
- Cluster summary tests cover missing and conflicting hints, unregistered
  distributions, and the invariant that advisory Node OS display strings never
  produce a qualified cluster. Fleet store/API integration tests passed with
  the summary query against PostgreSQL 17; the temporary container was removed.
- Agent CNI/CSI/admission/Pod Security inventory tests, bounded protocol
  validation, read-only agent RBAC Helm/Kustomize renders, and dashboard
  capability typecheck/build passed; these signals remain advisory.
- Agent liveness/readiness health-state tests passed. Readiness only indicates
  a recent successful agent sync; it is not host or operation evidence.
- Agent local file-state tests verify restrictive file modes, reject symlinks,
  writable state directories and partial identity records, and preserve first-
  run initialization when the private state directory does not yet exist. They
  also reject inconsistent Ed25519 key material and duplicate pending keys.
  Kubernetes Secret encryption and installed-agent key rotation remain
  deployment dependencies.
- `go test ./...` in `operator/` — passed, including fail-closed effective
  host-execution RBAC probe tests.
- PostgreSQL restore-drill guard tests pass for exact current migration
  checksums, stale/incomplete history, same/unknown-server refusal, and archive
  checksum and nonempty-target rejection. A disposable PostgreSQL 17-alpine
  backup and restore to a separate server passed, followed by the store test
  suite against the restored database. This does not qualify production HA
  failover, PITR, or RPO/RTO.
- Management-plane Helm lint and Helm/Kustomize render checks confirm API,
  scheduler, and dashboard PDBs (`minAvailable: 1`) and preferred hostname
  anti-affinity. Offline Kustomize configuration tests also pass. This is
  manifest evidence only; no cluster availability or failover drill was run.
- `HELM=/tmp/kordex-helm/linux-amd64/helm KUBECTL=kubectl python3 -m unittest scripts.test_egress_networkpolicy -v`
  — 9 tests passed for default-off Helm/Kustomize behavior, required hub and
  spoke peers, selector-to-workload matching, and rejection of all-address,
  empty-peer, or invalid-port rules. The new opt-in Kustomize spoke overlay
  renders agent and operator policies with documentation-only exact-address
  placeholders; the default self-managed overlay remains unrestricted. The
  agent and operator charts passed Helm lint, their values schemas parsed,
  Python compilation and `git diff --check` passed. No CNI or live cluster
  enforced these policies. Site endpoint addresses, DNS selectors, optional
  dependencies, and CNI behavior still require site review and validation.
- Scheduler health unit coverage verifies that liveness remains healthy while
  readiness fails before a successful DB-backed tick and after its 15-second
  freshness limit. Helm/Kustomize checks confirm startup, readiness, and
  liveness probe wiring across all three workloads. This is not multi-replica
  fault or database-availability qualification.
- OIDC identity/configuration tests cover compatible ID-token mode and the
  opt-in RFC 9068 access-token contract (type, exact audience, expiry/issued-at,
  subject, client ID, token ID, and required scopes). Dashboard token-selection
  tests, typecheck/lint/build, API/dashboard Helm lint, OIDC Helm/Kustomize
  rendering, and offline Kustomize configuration tests passed. No external OIDC
  provider login, scope mapping, or signing-key rotation was qualified.
- Fleet observability tests verify aggregate cluster/node gauges, stale versus
  ready/unready inventory classification, omission before the first DB snapshot,
  and absence of tenant/resource labels. The PostgreSQL snapshot query passed
  against a disposable local PostgreSQL 17 container. The Grafana JSON parses;
  no live Prometheus/Grafana scrape or dashboard import was performed.
- The exact-UID inventory filter rejects incomplete, duplicate, empty, and
  slash-containing selectors before storage access. PostgreSQL tests verify
  exact cluster+UID selection and no cross-organization result. Dashboard
  tests, typecheck, lint, and production build passed, including the dynamic
  node-detail route. No browser session or deployed identity flow was tested.
- The dashboard no longer assembles an unsigned client-side archive. The API
  fixes and validates a tenant high-water snapshot, enforces a 4 MiB NDJSON
  limit, and signs the bundle with Ed25519; the dashboard bounds the response
  and checks the tenant, signed-bundle shape, and records digest. API tests verify the signature,
  fixed checkpoint, ordering, tenant binding, and record integrity; dashboard
  tests cover bundle shape, unsigned/malformed/oversized responses, and error
  propagation. Helm leaves browser signing disabled unless explicitly
  configured; Kustomize mounts the separate audit key only into the API. The
  browser does not itself verify signatures. Verify downloads with
  `kordex-audit-verify -bundle` and an independently distributed trust bundle.
  Key custody, immutable retention, and deployed browser/API behavior remain
  unqualified.
- Audit verifier and signer tests cover globally interleaved organization event IDs,
  missing same-organization chain records, mismatched checkpoints, signature
  tampering, missing/untrusted keys, duplicate trust members, key-ID validation,
  and signed tenant checkpoint digest verification. Export tests cover private-
  key file permissions, tenant binding, signed manifests, global-ID gaps,
  incomplete pagination rejection, checksums, tamper rejection, no-overwrite
  behavior, and cleanup on handled failure. A mock-API script test builds a
  temporary key pair and successfully runs signer and verifier on the exported
  bytes. These are local tests only; they do not establish external immutable
  retention, KMS custody, or a live API export.
- The disposable-lab wrapper tests cover project allowlist and file permissions,
  exact apply/destroy confirmation, post-confirmation live project designation
  rechecks, project-state/label rejection, project confirmation before every
  GCP execution, state-project matching, exact Kubernetes context, target
  confirmation, bounded diagnostic collection and partial
  evidence retention, best-effort credential redaction, and archive checksums
  and overwrite refusal. These tests do not exercise GCP APIs or establish that
  the selected project is empty. No Terraform plan/apply, K3s deployment, host
  package operation, or reboot was run by this verification.
- Admission inventory tests cover served-resource counts and fail-closed
  permission errors. Agent permission-profile tests and rendered Helm/Kustomize
  RBAC checks confirm read-only list access to the four admission configuration
  resources. The collector uses Kubernetes `PartialObjectMetadata` responses
  and forwards counts only; this does not prove policies are bound, active, or
  effective on a live cluster.

The PostgreSQL-backed store and HTTP API integration tests passed against a
new ephemeral local PostgreSQL 17 container; it was stopped and removed after
the run. `KUBEBUILDER_ASSETS` was not configured, so API-server envtest was not
run. CI defines that job, but its configuration is not evidence it passed for
this worktree. No VM, cloud project, customer cluster, host package
transaction, reboot, storage mutation, or provider upgrade was run. The Ubuntu
and provider qualification matrices remain NOT RUN. Repository host-upgrade
and GKE upgrade gates remain disabled by default.

2026-11-19 campaign simulator report-contract increment (UPG-08, UPG-14):

- Synthetic fleet reports now include a fresh local ValidateOnly policy catalog
  and a valid `Pending` → `Validating` → `SafetyChecking` → `Succeeded` phase
  history. This keeps the simulator aligned with current campaign admission and
  action-bound report validation; every success remains explicitly synthetic.
- `go test ./control-plane/cmd/kordex-simulate -count=1` passed. A runtime run
  against a temporary loopback-only PostgreSQL 17 database with 40 nodes and 20
  clusters completed 40 synthetic ValidateOnly operations in six scheduler
  ticks. A separate 4-node/2-cluster run also completed all four synthetic
  operations, exercising rollout-stage sizing below the default stage counts.
  Both temporary database containers were removed after their runs.
- This is local simulation evidence only; no Kubernetes API, host maintenance,
  production capacity, or real recovery behavior was exercised. Qualification
  rows remain unchanged and NOT RUN.

2026-11-19 host-upgrade success evidence validation increment (UPG-02, UPG-03,
UPG-04, UPG-05, UPG-14, UPG-18):

- Hub operation-report validation now requires a successful host checkpoint to
  contain ordered preflight/apply receipts, an operation/plan/node/machine/boot
  bound `packages-verified` action marker, and a consistent no-reboot or
  verified-reboot outcome. Reboot success also requires the outer `Rebooting`
  event, changed boot ID, bound `reboot-verified` marker, and the pinned
  expected kernel and package versions across apply/reboot receipts when
  specified by the plan. This checks consistency of agent-relayed evidence; it
  is not an independent attestation channel.
- Protocol tests reject missing receipts, receipt reordering, mismatched action
  marker identity, contradictory reboot state, and checkpoint boot identity
  mismatch. `KORDEX_TEST_DATABASE_URL=<loopback-only disposable PostgreSQL 17
  DSN> go test ./control-plane/internal/store -count=1` passed, including
  campaign success-report fixtures. The temporary database was stopped and
  removed.
- `make test`, `make vet build contract`, and `git diff --check` passed. No VM,
  cloud resource, Kubernetes cluster, package transaction, or reboot was used;
  host-upgrade defaults remain off and qualification rows remain NOT RUN.
