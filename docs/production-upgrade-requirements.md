# Production upgrade requirements and delivery plan

This document tracks the production bar requested for Kordex as an infrastructure upgrade platform. A requirement is complete only when its code, failure behavior, audit evidence, and deployment evidence meet the acceptance criteria below. A Go interface or simulator alone does not count as an integration.

## Qualification status — authoritative record

M3 qualification controller increment — 2026-11-22 (partial UPG-09/UPG-18/UPG-25):
`scripts/m3_qualification.py` now composes explicit local/customer stages and
emits all 22 canonical scenario/platform rows as NOT RUN until separately
accepted. Its version-1 customer input contract rejects missing/unknown slots,
caller-supplied statuses, unsafe paths, expired references, and hash mismatch;
a matching hash remains UNVERIFIED. The controller never invokes GCP,
Terraform, registries, or hosts. `scripts/m3_trust_state.py` now provides a
customer-rooted signed-receipt CAS client, a root-signed backend configuration
binding, and an isolated namespace conformance harness. Synthetic Ed25519
tests cover concurrency, rollback, sequence reuse, outage, and lost
acknowledgment. No customer backend has been selected or independently
verified, the replay registry remains unimplemented as a customer service,
and no customer artifacts, connectivity, cloud review, deployment, or host
maintenance were performed. These are implementation/contract increments,
not customer verification or qualification; all 22 rows remain NOT RUN and M3
remains NOT COMPLETE.

This document is the single source of truth for capability and qualification
status. Roadmap phases describe implementation history, not release support.
**No upgrade executor is production-qualified. Both execution gates default off.**

Milestone 3 readiness audit — 2026-11-20: Ubuntu 24.04 OS identity is checked
consistently by the signed policy contract, operator admission, qualification
runner, fixed EE catalog, and Debian playbook. Offline artifact digest/tamper,
runner preflight/cancel/restart, and evidence-verifier contracts have local
automated coverage. A disposable Ubuntu VM and reachable hub are not available,
so package change, reboot, live recovery, and failure-matrix execution remain
**NOT RUN**; all qualification rows remain **NOT RUN** and execution gates
remain off.

M3 deployment identity increment — 2026-11-22 (partial UPG-12): Terraform
provisioning, lifecycle power/inventory, and VM workload identities are
separated. Terraform consumes pre-created server/worker service accounts and
has no service-account create/update/delete permissions. Conditionable Compute,
DNS-record, and Secret Manager Terraform permissions are split from project-
scoped network/subnetwork/managed-zone permissions; the latter require an
isolated disposable project. Lifecycle power is a two-permission custom role
bound per VM, with separate read-only inventory and per-instance IAP/OS Login
access. Local contract tests and Terraform formatting passed. IAM roles were
not created or exercised, migration 016 was not deployed, billing headroom was
not provided, and all 22 M3 host rows remain NOT RUN; this is not deployment or
qualification evidence.

M3 platform baseline update — 2026-11-21: the required OS evidence is Debian
13 Trixie at the latest stable point release verified when provisioned and
RHEL 9.8 or later (prefer the latest verified RHEL 9 minor). The verified
Debian point release and exact RHEL image/minor are bound through package
preflight, guarded Terraform inputs, startup checks, and qualification evidence.
Ubuntu 24.04 is supplemental only. No real-host qualification is implied.

M3 selected-OS binding increment — 2026-11-21 (partial UPG-02/UPG-09/UPG-25):
the maintenance policy digest now includes the selected Debian 13 point release
or exact RHEL 9 minor, and the EE host receipt and qualification verifier bind
that identity to package policy, machine/platform evidence, and the concrete
lab image. Local protocol, executor, preflight, lab, and evidence tests cover
the binding and rejection of old/unsupported profiles. This is implementation
and local-test evidence only; no customer image, signed package set, or
real-host execution was verified. These requirements and every qualification
row remain incomplete.

M3 created-image evidence increment — 2026-11-21 (partial UPG-02/UPG-09/UPG-18):
the guarded qualification path now checks the live server and both worker
instances after authorized lab creation, reads each attached boot disk's
`sourceImage` and `sourceImageId`, and requires the approved image self-link
and server-assigned ID. It repeats that read-only check immediately before a
qualification operation and binds the timestamped three-node result into the
evidence verified by the canonical matrix checker. Local Python regression
tests cover matching disks, image-ID substitution, missing/duplicate node
records, and a stale or post-start check; the complete Python infrastructure
suite, the 101 integration tests, all five Go module test/vet suites and race
tests, Terraform `validate`/format, and the rootless offline OCI test passed.
No Terraform plan/apply, GCP query, host operation, or external service call
was performed. GCE boot creation still references the image self-link/name,
so the check detects but does not eliminate substitution between the final
pre-apply resolution and disk creation. Customer image approval, risk
acceptance, trust/replay integration, artifacts, private connectivity, and all
22 real-host results remain outstanding; no qualification row or execution
gate changed.

Node-maintenance RBAC readiness increment — 2026-11-19 (partial UPG-04/UPG-14):
the operator now checks its effective drain/recovery permissions with
self-subject access reviews and publishes `nodeMaintenance` through its
capability Lease and agent report. Campaign preview and scheduler admission
fail closed when the capability is missing, stale, or false. The local
operator and Kubernetes API remain authoritative; the probe currently runs at
operator startup and is not a continuous RBAC-change monitor. Operator unit
tests and the complete PostgreSQL-backed control-plane store package passed,
including withdrawal before scheduler dispatch. No cluster or host operation
was used, and all qualification rows remain NOT RUN.

Recovery-queue increment — 2026-11-19 (partial UPG-14/UPG-16/UPG-18): the
management API and dashboard now provide an organization-scoped, read-only
queue for `Blocked`, `RecoveryRequired`, and `Failed` operations. It shows the
reported phase/checkpoint and freshness context; it does not authorize retry,
uncordon, or reservation release. PostgreSQL query, tenant filter, bounded
pagination, UI typecheck, and dashboard build tests passed locally. Helm
v3.19.0 chart lint, Helm/Kustomize workload parity, and management-plane
availability renders also passed. This is not a verified recovery workflow or
qualification evidence. Recovery acceptance remains incomplete and all
host/provider qualification rows remain NOT RUN.

Observability increment — 2026-11-19 (partial UPG-17): the operator exports
bounded terminal outcomes, RecoveryRequired counts, operation/drain/reboot
durations, oldest active reservation age, and aggregate active RecoveryRequired
count/oldest-age gauges from a leader-elected Kubernetes API snapshot; API and scheduler emit
low-cardinality OpenTelemetry spans. The operator maintenance reconciler also
emits spans with bounded phase/action/outcome and normalized error class. OTLP
export is explicitly configured and off by default in Helm/Kustomize. Local
unit, database, render, and contract checks passed, but no Prometheus/Grafana
stack or OTLP collector was deployed, no alert/SLO threshold was measured, and
no trace retention or cross-service trace behavior was qualified. Agent
allowlisted outbound API spans and W3C trace-context propagation are now
implemented, but the agent-to-API collector path has not been exercised and
operator reconciliation is not correlated to a hub trace. UPG-17 remains
incomplete; no upgrade matrix row or execution gate changes.

Dashboard concurrency-policy increment — 2026-11-19 (partial UPG-20/§19):
organization administrators can review and update organization, fleet, site,
zone, and site-unavailability admission limits through an explicit,
revision-checked dashboard flow. Cluster and node concurrency remain fixed at
one. The API continues to enforce administrator authorization, optimistic
revision checks, validation, and audit persistence; scheduler admission and
local operator safety checks remain authoritative. This is not the complete
typed maintenance policy editor or circuit-breaker implementation. No executor
gate or qualification row changes.

| Path | Available verification | Real disposable upgrade evidence | Qualification |
|---|---|---|---|
| Self-managed Debian 13 Trixie APT + reboot; Ubuntu 24.04 supplemental only | EE contract/simulator tests, guarded runner/evidence tests, controller API-server envtest (local record below) | None recorded | Incomplete; Debian 13 host evidence required; Ubuntu does not substitute |
| Self-managed RHEL 9.8+ DNF + reboot | Contract/simulator and shared controller API-server tests; no OS compatibility proof | None recorded | Incomplete; exact customer image and repository inputs plus RHEL host evidence required |
| GKE node-pool version upgrade | Contract/simulator and runner guardrail tests; API-server tests do not exercise GKE | None recorded | Incomplete; defer expansion until Ubuntu failure evidence |
| Self-managed offline package transfer/staging/install | Local artifact, digest, packaging, and policy contract tests | No disconnected-site or VM upgrade record | Incomplete; include in Debian 13 and RHEL 9.8+ qualification |

Historical Kubernetes registration, validation, or drain drills do not establish
host package/reboot or provider upgrade qualification. No requirement is marked
complete by the preparation work below.

Supply-chain implementation note — 2026-11-18: runtime image base references
are now digest-pinned and checked in CI. A manual, explicitly gated image
release path is configured to scan candidate digests, attach SBOM/provenance,
sign with Cosign, and publish only after the existing CI jobs pass. An opt-in
Kyverno policy verifies release-workflow image signatures and digest references,
but no live admission test has been run. The release workflow has not been
dispatched and has no release evidence. This tooling does not qualify the host EE,
playbooks, package artifacts, or any upgrade executor; UPG-01, UPG-06, UPG-09,
and UPG-25 acceptance remains unchanged, and all qualification matrix rows stay
NOT RUN.

Restricted-egress manifest note — 2026-11-19 (UPG-19): an opt-in Kustomize
spoke overlay now renders agent/operator egress policies with bounded DNS,
Kubernetes API, and management endpoint rules. Exact endpoint addresses are
documentation placeholders until replaced for a site; optional dependencies,
DNS selectors, and CNI enforcement still require site validation. Nine Helm and
Kustomize render-contract tests passed, including checks that default spoke
manifests remain unrestricted. This is manifest evidence only: no live network
policy enforcement or offline host-upgrade case was run, so UPG-19 acceptance
and all qualification matrix rows remain unchanged.

Customer agent mTLS transport prerequisite — 2026-11-21 (UPG-19 partial only):
the agent can opt into a fail-closed HTTPS client certificate mode with an
explicit server CA and DNS identity. A standalone relay now requires verified
client certificates, maps a single URI SAN to an enabled cluster, compares
that mapping with signed request cluster IDs or the enrollment body, and
forwards only the five existing agent method/path pairs to a fixed internal
API Service. It adds no identity header and makes no API authorization change.
Synthetic relay and certificate tests, integrations `go test ./...`, `go vet`,
and race tests pass. The Helm chart renders only a ClusterIP Service and
restricted NetworkPolicy by construction, but Helm is unavailable for chart
render validation. No customer PKI, image release, private route, live
NetworkPolicy enforcement, customer deployment, or offline deployment was
tested. UPG-19 remains incomplete and all host/provider qualification rows
remain NOT RUN.

Recovery reservation note — 2026-11-19 (UPG-05/UPG-10): the operator now checks
that a recovering operation still owns the durable cluster-slot Lease before it
performs recovery verification or removes its node cordon. A missing Lease or a
Lease held by another operation records `ReservationLost` and keeps the recovery
fence; recovery does not reacquire the reservation or alter its new owner. When
a new operation encounters a held slot, it checks whether the holder UID still
has a `NodeMaintenance` record. A missing record produces
`OrphanedClusterReservation`; a live record keeps the ordinary
`ClusterConcurrencyLimit` reason. Lookup errors remain errors, and neither case
releases the Lease automatically. Controller tests cover lost recovery
reservations, live and orphaned holders, and failed owner lookup. This is
controller-level evidence only; it does not qualify host package/reboot
execution, and qualification rows remain NOT RUN.

Recovery audit-capacity increment — 2026-11-19 (UPG-05/UPG-10/UPG-14/UPG-18):
the operator switches to `RecoveryRequired` at its 240-event safety threshold
and now keeps a stable `AuditCapacityReached` blocker instead of appending a
new phase event for every later recovery reason. A forced checkpoint still
persists its structured checkpoint without growing the phase history. The
controller refuses any unrecorded transition if the hard 256-event report
bound is reached. A regression test exercised repeated recovery reasons and a
forced checkpoint, then verified the persisted operation report remained
valid. This is local fake-client/controller evidence; it does not qualify
restart recovery on a live cluster or change any host-upgrade qualification
row.

Durable operation phase-transition increment — 2026-11-19 (UPG-04/UPG-05/UPG-14/UPG-18):
the protocol now defines the maintenance phase graph, including legal blocked
resumption, pre-mutation cancellation, and verified provider cancellation.
The operator emits the terminal-to-recovery exception only when the original
node identity and cordon-owner annotation still match; hub report validation
requires the corresponding `TerminalRecoveryIncomplete` reason and rejects
other impossible phase histories. The operator checks each new status against
the graph and its last durable event. A missing original-cordon checkpoint
now remains in `RecoveryRequired` instead of being reported as a terminal
failure. Tests cover legal and illegal edges, blocked resumption, hub report
rejection, and retention of the reservation when recovery metadata is missing.
Full local Go/store tests and build/contract checks passed. These are
code/database tests only; live restart/recovery qualification and all
host-upgrade qualification rows remain outstanding.

Phase-event chronology increment — 2026-11-19 (UPG-05/UPG-14/UPG-18):
shared operation-report validation now rejects backwards event times and
allows equal times for coarse-resolution clocks. Operator phase persistence
clamps event time to the preceding event when the wall clock moves backwards.
`make test`, `make vet build contract`, and the full control-plane store suite
against temporary loopback PostgreSQL 17 passed; the temporary container was
removed after the run. This is local contract/database evidence, not
clock-synchronization or live restart qualification; these requirement
acceptance criteria remain incomplete and all host-upgrade rows remain NOT RUN.

The hub also rejects report phase/checkpoint/receipt timestamps more than the
existing two-minute `ClockSkew` allowance ahead of PostgreSQL
`clock_timestamp()`. The operation-sync response returns current database time
using `clock_timestamp()` instead of transaction-start time. Protocol tests
cover future phase, host checkpoint, host receipt, and provider checkpoint
evidence; the PostgreSQL-backed operation test verifies a future-dated report
conflicts while a subsequent valid report is accepted. This is local input-
validation evidence, not clock-synchronization or live recovery qualification.
UPG-05, UPG-14, and UPG-18 remain incomplete; all host-upgrade rows remain NOT
RUN.

Hub report ingestion validates action-specific phase transitions and successful
terminal paths. Drain/host success requires recovery verification and uncordon;
host success also requires its terminal upgrade checkpoint. Provider success
requires workload verification and a terminal checkpoint with original node
identity evidence, except when the target version was already present. A
PostgreSQL-backed store test rejects drain phases attached to a ValidateOnly
request, while protocol tests exercise the accepted/rejected action matrix and
success paths. This is central audit-consistency evidence only; the operator's
local checks remain authoritative, and no qualification row changes.

Successful host-upgrade report acceptance additionally requires ordered
preflight and apply receipts, an apply action marker bound to the operation,
plan, node, machine, and boot identity, and agreement between the receipt,
checkpoint, and outer operation about whether a reboot occurred. When a reboot
was requested, the report must include the `Rebooting` phase and a verified
reboot receipt with the changed boot ID and matching action marker. Protocol
tests reject missing, reordered, or mismatched evidence, including an expected
kernel mismatch when the plan pins one or package-version drift across reboot;
PostgreSQL-backed store and campaign tests cover report ingestion and valid
success fixtures. Receipt
timestamps are independently bounded but are not ordered against operator
timestamps because they originate on different clocks. This strengthens audit
consistency; it does not independently attest cluster-local execution or
qualify package/reboot behavior. UPG-02/03/04/05/14/18 and all qualification
rows remain incomplete/NOT RUN.

Deployment-parity implementation note — 2026-11-19 (UPG-19): CI now renders
the five agent, operator, API, scheduler, and dashboard workloads through both
Helm and Kustomize, then compares their shared security, resource, probe, port,
service, disruption-budget, runtime image-tag, and default-off execution
contracts. Paired render inspection exposed stale Helm control-plane/dashboard
tags (`0.6.0` and `0.5.0`) relative to Kustomize/offline bundle `0.8.0`; the chart image
defaults and `appVersion` now match `0.8.0`, with chart package versions bumped.
Four local render-contract tests passed. The comparison excludes
packaging-specific environment references and optional metrics endpoints, and
is not a deployed availability or host-upgrade qualification; UPG-19 and every
qualification matrix row remain incomplete/NOT RUN.

Tenant-read isolation implementation note — 2026-11-19 (UPG-16, UPG-18): a
PostgreSQL integration now seeds two organizations and verifies that site,
fleet, cluster, node inventory, audit, and dashboard aggregate reads stay in
the requesting organization, including an explicit foreign-cluster filter.
The test passed against a temporary loopback-only PostgreSQL 17 container.
This adds local database evidence but does not complete UPG-16 or UPG-18,
prove concurrent isolation under load, or change any upgrade qualification row.

## M3 qualification — Debian 13 and RHEL 9 disposable hosts

The [Fleet Platform roadmap](KORDEX-FLEET-PLATFORM-ROADMAP.md) expands the product
direction in reviewable increments. The current read-only discovery/compatibility
foundation and security patches address UPG-04, UPG-12, UPG-14, UPG-18 and UPG-19;
[actual checks and limitations](KORDEX-PRODUCTION-READINESS.md) do not complete
those requirements or qualify any additional driver. Unsupported catalog entries
never become executable merely by registration. The former Ubuntu-first plan is
superseded: the M3 matrix requires all eleven cases on Debian 13 Trixie at the
latest approved stable point release and RHEL 9.8 or later, preferably the latest
verified 9.x minor. Ubuntu 24.04 is supplemental and cannot substitute.

Scope: run one selected OS profile at a time in a dedicated three-node K3s lab
with one control-plane server and two same-profile workers. The unmaintained
worker must remain a Ready, eligible peer while its counterpart is maintained.
Use the exact recorded image, architecture, OS point/minor, kernel, package and
repository snapshot, and pinned K3s release. Debian and RHEL results apply only
to their separately identified image/package combinations. Ubuntu remains
supplemental. Do not add executors/providers or expand GKE. A connected VM run
alone cannot qualify air-gapped delivery.

Traceability: UPG-01–06, UPG-09–10, UPG-12, UPG-14, UPG-18–19,
UPG-24–25. This is a qualification plan, not acceptance evidence for these IDs.

### Entry checklist

- [ ] Identify a dedicated disposable cluster and worker, independent reviewer,
  lab owner, VM snapshot/reset procedure, serial-console access, and network
  fault controls. Keep management/control-plane nodes out of the target set.
- [ ] For the GCP self-managed lab, review that the selected project contains
  no shared or non-disposable infrastructure before designation. The project
  must carry the live `kordex-disposable=qualification` label, appear in the
  Terraform `allowed_project_ids` allowlist, and match the separate
  `project_id_confirmation`. Review the saved plan before applying it. Before
  an upgrade, recheck the project designation and separately confirm the exact
  cluster/node/UID from preflight. These project checks are lab-entry safety
  controls, not production qualification evidence.
- [ ] Record source commit plus the hash and retained patch/archive of any
  uncommitted inputs, including any untracked dependencies; review and capture
  them before building a qualification release. Record UTC
  times, architecture, OS image digest, kernel, Kubernetes, runtime, EE image,
  playbook/collections digests, policy UID/generation/digest, cluster UID, node
  UID, machine-ID, boot-ID, timeout bounds, and workload baseline.
- [ ] Verify trusted signing keys, exact image allowlist, pinned SSH host keys,
  fixed local credentials, independent campaign approvals where applicable,
  and signed cancellation. Test altered/stale/wrong-target authorization and
  digest mismatch rejection with no host mutation; retain actual results.
  A signed manual operation is not evidence of independent campaign approval.
- [ ] Transfer and verify the signed offline bundle and policy-bound package
  archive; stage all dependencies on the worker. Record every artifact digest
  and exact target version, including a package that actually changes and a
  controlled reboot (`Always`, plus expected kernel for a kernel package plan).
- [ ] Deny public egress and package repositories during installation/recovery;
  retain firewall/DNS/flow logs proving this. Allow only documented site-local
  management, Kubernetes, registry, and EE-to-worker SSH flows. First-boot
  downloads in an optional cloud lab are not disconnected installation evidence.
- [ ] Configure and review the disposable lab target, enable host execution only
  on its operator, then run the read-only readiness preflight below and review
  its exact cluster/node/UID confirmation before submitting an operation. Leave
  repository defaults and provider execution gates disabled. Confirm a workload
  with a PDB can drain and recover and that the management plane survives the
  worker's loss.

### Exact case checklist and pending results

Start each independent case from the reviewed baseline with a new operation ID
and signed authorization; preserve the original operation and host journal
throughout a restart/recovery case. Do not reset the VM until evidence is saved.
`Runner` means the existing runner supports the case; `External` requires lab
fault injection and the recorder. Runner and manual supplements are outside
the pinned matrix and must be recorded separately, without relabeling them as
matrix cases. Every row is **NOT RUN** on both required platforms as of
2026-11-21.

| Case | Method / trigger | Required observation and safe result | Result / evidence |
|---|---|---|---|
| `clean-upgrade` | Runner; real package change and required reboot | Exact packages; same machine-ID/node UID; changed boot-ID; expected kernel; Ready node and workloads; owned cordon and reservation released; `Succeeded` | NOT RUN / none |
| `cancel-during-executing` | Runner `--cancel-on-phase Executing` | Signed cancellation observed; no repeat apply; verified `Cancelled` recovery or fenced `RecoveryRequired` | NOT RUN / none |
| `cancel-during-reboot` | Runner `--cancel-on-phase Rebooting` | Cancellation cannot assume reboot stopped; verify host identity/boot and recovery or retain fence/reservation | NOT RUN / none |
| `operator-restart-during-executing` | Runner; restart Deployment after durable `Executing` | Different Ready pod UID; same operation/checkpoint; no duplicate mutation; verified success or intervention | NOT RUN / none |
| `ssh-loss-during-apply` | External; block TCP/22 during `Executing`, then restore | Durable intent and timed drop/restore logs; read-only inspection; no apply replay; matrix requires `RecoveryRequired` | NOT RUN / none |
| `partial-package-application` | External; package-manager failure after one pin changes | Exact changed packages and exit code; no replay; `RecoveryRequired` with fence/reservation | NOT RUN / none |
| `reboot-never-returns` | External; prevent return after durable reboot intent | Record unavailable interval through configured timeout; `RecoveryRequired`; reservation retained | NOT RUN / none |
| `ssh-loss-after-reboot-request` | External; drop/restore SSH after reboot intent | Prove intent, network interval, boot/host observations; no second reboot; matrix requires `RecoveryRequired` | NOT RUN / none |
| `wrong-machine-id` | External; present a different machine during recovery | Identity mismatch rejected; `RecoveryRequired`, original ownership retained | NOT RUN / none |
| `node-replaced-during-recovery` | External; replace Node object | Changed UID rejected; replacement untouched; original reservation retained | NOT RUN / none |
| `wrong-kernel-after-reboot` | External; boot different kernel | Exact expected/observed kernel; `RecoveryRequired`, fence/reservation retained | NOT RUN / none |
| EE process interruption | Manual supplement; terminate runner process inside EE after `apply-intent` | Retain Job/process exit and journal; inspect same operation read-only; no repeat install; recover only with matching evidence, otherwise intervention | NOT RUN / none |
| Qualification observer restart/timeout | Manual supplement; stop local observer while apply/reboot continues | Observe the existing operation ID via API/kubectl after restart; timeout does not cancel or authorize another apply | NOT RUN / none |
| `cancel-before-apply` | Runner supplement; `--cancel-on-phase Draining` | No apply/reboot intent or package change; any acquired cordon/reservation released only after verified safe recovery | NOT RUN / none |
| `cancel-during-recovery` | Runner supplement; `--cancel-on-phase VerifyingWorkloads` | No premature uncordon/release; ready identity/packages/kernel/workloads required, otherwise intervention | NOT RUN / none |
| Reboot not issued / lost response | Manual supplement; block delivery after reboot intent or lose response | Distinguish unchanged boot-ID from completed reboot through read-only evidence; no blind reboot retry; unresolved state fenced | NOT RUN / none |
| Agent process restart | Manual supplement; restart agent during execution | Durable inbox/ack and same operation identity; no duplicate host action; verified recovery or intervention | NOT RUN / none |
| Offline transfer/staging tamper rejection | Manual supplement; alter one package/archive or signed digest before mutation | Digest/signature failure blocks install; retain rejection and no-mutation evidence, then restore baseline for other cases | NOT RUN / none |

For every ambiguous case, capture the root-owned action journal, immutable
receipt references/digests, local checkpoint and durable event history, Job UID
and logs, host package state, machine/boot/node identities, Node cordon owner,
and live `kordex-maintenance-cluster-slot` holder. Demonstrate that missing or
contradictory evidence retains the fence and reservation. Do not manually
uncordon, delete the journal/checkpoint, or resubmit mutation to obtain a pass.
After connectivity returns, use the documented read-only recovery procedure;
record the intervention and resulting state. `RecoveryRequired` proves safe
fencing only, not successful restoration or automatic rollback.

The runner's `--execute` always creates a new operation; it is **not** a resume
command. Execution now requires a new evidence output path and persists its
operation ID before the submission request, then saves redacted observations
while polling. After observer loss, inspect the existing operation with the
read-only command below. Process-interruption supplements still need reviewed
manual fault injection. Cancellation supplements now have runner triggers, but
their host journal, reboot, and workload evidence still requires review.

Use fresh baseline VMs and new evidence paths for the cancellation supplements:

```sh
python3 tests/integration/self_managed_upgrade_smoke.py --execute \
  --cancel-on-phase Draining --evidence ./qualification/cancel-before-apply-debian.json
python3 tests/integration/self_managed_upgrade_smoke.py --execute \
  --cancel-on-phase VerifyingWorkloads --evidence ./qualification/cancel-during-recovery-debian.json
```

Run one command per independently restored baseline, using the same exact
disposable-target confirmation required for other execution cases. These
reports have `qualificationScope: supplemental` and cannot satisfy a pinned
matrix case. Use controlled workload termination/readiness delays to make the
requested phase observable. If polling misses it, or the operation succeeds
instead of cancelling, the runner fails the cancellation drill rather than
reporting a pass. A pre-apply cancellation also fails if durable history or
receipts show host execution raced ahead. Retain the host journal to establish
absence of mutation; controller history alone cannot prove the host was untouched.

Cancellation intent and a redacted phase snapshot are persisted before the API
request. A lost response stays `SubmissionUnknown`; do not automatically repeat
cancellation or invoke a new execution to resolve it. Observe the same operation.

To observe an interrupted run without creating another operation:

```sh
python3 tests/integration/self_managed_upgrade_smoke.py \
  --observe-evidence ./qualification/clean-upgrade-debian.json \
  --timeout-seconds 14400 --evidence ./qualification/clean-upgrade-observation.json
```

Keep `KORDEX_API`, `KORDEX_ORG_ID`, `KORDEX_CLUSTER_ID`, and
`KORDEX_EXPECTED_CONTEXT` set to the original run and provide a valid API token.
The observer verifies the saved management origin, tenant, cluster UID, context,
node UID, policy identity, and exact request against read-only live observations.
It does not require current executor capability, policy availability, or node
schedulability, since the worker may be rebooting or fenced. A different Node
UID blocks this observer; use the separate replacement-node drill and manual
inspection rather than treating it as recovered. Original records lacking the
saved origin/organization/target fields also require manual inspection.

The new output is a separate `self-managed-linux-upgrade-observation` report,
not an execution case accepted by the qualification verifier. It cannot prove
an injection happened while the observer was down. Missing operations, lost
submission responses, and timeouts never authorize resubmission. No new
execution, signed cancellation, rollout restart, or recovery action is issued
by observation; host recovery itself still requires the existing operator and
verified recovery procedure.

### Evidence record and exit checklist

For each row, replace `NOT RUN / none` only with a measured result, UTC interval,
run/operation IDs, relative evidence path, SHA-256 manifest, reviewer, and
remaining limitations. Retain runner JSON, copied fault-control logs, host
journal/package/reboot evidence, Kubernetes snapshots, workloads, audit events,
and egress-denial evidence in a durable lab archive. Keep tokens, keys, and
signatures carrying reusable authority out of the archive. Unit-test fixtures
are synthetic and must never be used to fill these rows.

- [ ] Review every Debian and RHEL case and supplement against UPG-01–06,
  UPG-09–10, UPG-12, UPG-14, UPG-18–19, UPG-24–25; record unmet acceptance
  criteria.
- [ ] Use `<case-id>-debian.json` and `<case-id>-rhel.json` for the eleven
  existing matrix cases; retain supplemental Ubuntu reports separately. The
  pinned verifier requires **both** Debian 13 and RHEL 9.8+ evidence for every
  case. Do not change the matrix/digest or fabricate records to bypass this.
  A result from one required OS does not qualify the other.
- [ ] Have a second operator check raw fault logs, actual package changes,
  reboot identity, no repeated mutation, recovery/fencing, and offline egress
  evidence. Record failures as failures, including unsupported recovery paths.
- [ ] Record whether each fenced VM was subsequently restored or deliberately
  destroyed after evidence retention. Disable the lab execution gate and remove
  credentials/resources at teardown. Qualification does not change defaults or
  authorize a production rollout.

### Preparation verification — 2026-11-17

This session removed the accidental root `--digestfile` (synthetic digest),
classified all 77 initial untracked files, and preserved 76 substantive source,
test, documentation, and deployment files pending focused review. The proposed
commit contains only README, this document, and the historical roadmap; no
execution code or default gate changed. Untracked dependencies are not release
or qualification evidence.

Command: `python3 -m unittest discover -s tests/integration -p 'test_*upgrade*.py' -v`.
Result: **42 tests passed**, covering host/GKE runner guards, fault recorder,
evidence validation, and operator-restart tooling. These are local synthetic
checks only. `kubectl config get-contexts -o name` returned no configured
contexts; no disposable worker, host mutation, failure injection, disconnected
installation, or infrastructure qualification was performed this session.
All case results above remain pending; no requirement completion is claimed.

### Observer interruption preparation — 2026-11-17

Addresses tooling for UPG-04, UPG-05, UPG-09, UPG-10, and UPG-18; none is
complete. The qualification runner now uses mode-0600 atomic writes with file
and directory fsync, records the operation ID before submission, refuses to
reuse an existing evidence output, and checkpoints observations. Read-only
observation of a saved operation produces separate supplemental evidence.
Execution code, provider paths, default gates, and the pinned failure matrix
are unchanged.

Verification: `python3 -m unittest discover -s tests/integration -p 'test_*upgrade*.py' -v`
passed **56 tests**. Coverage includes lost submission responses, evidence-write
failure blocking submission, an actual child-process SIGKILL against a fake
transport with the ID retained, read-only observation, identity mismatch,
timeout/unknown outcomes, and live-fence/reservation requirements. These are
local synthetic tooling tests; the process kill did not interrupt a real EE,
host mutation, or Kubernetes operator.

A real read-only preflight invocation returned exit 1 at
`2026-11-18T00:50:40Z` because `KORDEX_ORG_ID` was unset, before any management
API request. Its local report is
`/tmp/kordex-ubuntu-qualification-2026-11-17/preflight-attempt.json`; it is a
prerequisite failure record, not a retained qualification archive. No
Kubernetes contexts, lab Terraform state, or lab variables were configured.
A read-only lookup in the configured GCP project found no VMs labelled
`application=kordex` and `purpose=disposable-qualification`; this does not
establish the absence of other infrastructure. The lab target, enrollment
identities, reviewed policy/artifacts, and disposable infrastructure must be
provided or prepared before execution. All VM results remain **NOT RUN**.

### Local reboot evidence validation — 2026-11-17

Cloud infrastructure remains off at the user's request. Local code changes
address qualification evidence checks for UPG-02, UPG-03, UPG-04, and UPG-24;
none is complete. The runner and standalone evidence verifier now require a
verified reboot for an `Always` policy even if the apply receipt says otherwise,
reject reboot or outstanding reboot requirements under `Never`, reject reboot
receipts that contradict apply evidence, and verify the exact package pins in
the reboot receipt. The verifier also rejects malformed or duplicate receipt
phases rather than silently overwriting evidence. Valid no-reboot results remain
accepted when the policy permits them and no reboot is required.

Verification command:
`python3 -m unittest discover -s tests/integration -p 'test_*upgrade*.py' -q`.
Result: **70 tests passed**. New regression tests first reproduced acceptance
of invalid reboot evidence, then passed with the stricter checks. These tests
use synthetic evidence only; they do not establish a real package change,
reboot, host recovery, or disconnected installation. The failure matrix,
execution gates, signed action protocol, and execution adapters are unchanged.
All disposable VM results remain **NOT RUN**. Resume infrastructure drills only
when the lab is available again; GKE is not required to qualify the self-managed
Ubuntu host executor.

### Cancellation drill automation — 2026-11-17

Addresses tooling for UPG-04, UPG-05, UPG-10, and UPG-18; no requirement is
complete. The runner now triggers signed cancellation through the existing hub
API during `Draining` and `VerifyingWorkloads`, in addition to `Executing` and
`Rebooting`. The two new case IDs remain supplemental; the pinned matrix and
its digest are unchanged. Cancellation phase, redacted operation snapshot, and
request intent are saved before submission. Missed phases, successful completion
after cancellation, stale terminal checkpoints, and observed pre-apply races
cannot produce a passing cancellation result.

Verification: `python3 -m unittest discover -s tests/integration -p 'test_*upgrade*.py' -q`
passed **79 tests**, including simulated full-runner tests for all four triggers,
fenced recovery/reservation checks, missing-phase and execution races, lost
cancellation response, CLI guards, and rejection of supplemental evidence by the
matrix verifier. All tests ran locally with fake API/Kubernetes observations.
No resources were started or cloud APIs contacted. Execution adapters, provider
paths, signed authorization, default gates, and actual recovery logic were not
changed. Real cancellation and host-journal evidence remains **NOT RUN**.

### Host qualification gap fixes — 2026-11-17

Addresses UPG-02, UPG-04, UPG-05, UPG-09, UPG-10, UPG-18, and UPG-24;
none is marked complete. A controller regression reproduced an outer
`Cancelled` operation whose upgrade checkpoint remained `Draining`. Cancellation
now checkpoints `CancelledBeforeApply` through the existing `RecoveryRequired`
and verified workload recovery/uncordon transitions. Signed cancellation tests
cover an available executor and a restart with execution disabled, retain the
owned cordon/reservation while safety is blocked, and verify eventual release.
Execution references, reboot intent, interrupted mutation, or mutating receipts
prevent this pre-apply recovery classification.

The Ubuntu EE's actual read-only host preflight queries installed versions with
fixed `dpkg-query` arguments and retains `baselinePackages` in its immutable
receipt. An empty version means not installed. This optional raw-receipt field
does not change signed-plan or CRD checkpoint schemas; older EE receipts remain
readable by the operator. Rebuild the reviewed EE, update playbook/image digest
pins and the allowlist, and regenerate the signed lab policy before qualification.
Old Ubuntu receipts without a baseline cannot qualify. The runner's default
readiness preflight does not launch an EE Job or query the host: the installed
package baseline is collected before cordon by the EE preflight within an
explicitly authorized execution.

The runner saves the baseline receipt JSON, reference, digest and host binding.
It snapshots healthy Deployment/StatefulSet/DaemonSet identities, generations,
replica targets and readiness counts before execution, then independently reads
them after recovery. The operator Deployment is excluded because its deliberate
restart has separate readiness evidence. At least one running workload controller
is required; other controller/pod kinds still require manual review. Success and
recovered cancellation require cordon-owner removal and release of this operation's
reservation, observed within a bounded 180-second follow-up. Another operation's
reservation is left untouched. Read-only observation uses the saved workload baseline.

The verifier rejects missing recovery/release evidence, missing or digest-invalid
Ubuntu package baselines, a clean-upgrade record with no package-version change,
and cancellation claims without a matching phase snapshot, host request,
acknowledgement, hub cancellation timestamp and preceding durable phase event.
Supplemental cases remain separate; the pinned matrix and digest are unchanged.

Verification: the initial regression failed with
`outer phase=Cancelled but upgrade checkpoint=Draining`, then passed after the fix.
`go test ./operator/internal/controller ./operator/internal/execution -count=1`
and `go vet ./operator/internal/controller ./operator/internal/execution` passed.
`python3 -m unittest discover -s tests/integration -p 'test_*upgrade*.py' -q`
passed **91 tests**. The Ansible EE contract suite passed **49 tests** with
Ansible Core 2.17.3 on PATH, including local task rendering against a fake
`dpkg-query` for installed/absent packages and query failure. The Ubuntu playbook
passed `ansible-playbook --syntax-check -i 'localhost,' integrations/ansible-ee/upgrade-debian.yml`.
Syntax checking also found and corrected an existing misplaced `fail_msg` in
the reboot-marker assertion. These are local synthetic/controller checks only;
no disposable host upgrade or failure drill was performed. All VM results remain
**NOT RUN**, execution defaults remain off, and no production qualification is claimed.

## kured interlock — optional, unqualified

Kordex can coordinate host package/reboot maintenance with an existing kured
DaemonSet using kured's documented [manual lock](https://kured.dev/docs/operation/).
Kured normally watches a sentinel, takes its own lock, drains, reboots and
uncordons. Its [single-owner annotation protocol](https://github.com/kubereboot/kured/blob/main/pkg/daemonsetlock/daemonsetlock.go)
is separate from Kordex's maintenance Lease. Reading that lock without acquiring
it would leave a race between the two controllers.

The interlock acquires the kured lock before host preflight/cordon and retains
it through package apply, the separately authorized reboot, cancellation,
ambiguity, operator loss, and verified recovery. The actual reboot remains the
existing signed Ansible EE phase. Kordex does not deploy kured or create a reboot
sentinel for it. Outside a Kordex-held lock, kured follows its own sentinel and
window policy; it does not validate Kordex permits. Sites requiring every reboot
to pass through Kordex approval must disable independent sentinel automation on
Kordex-managed nodes. Delegating reboot execution to kured needs a separate
signed handoff and qualification; it is not implemented by this interlock.

Enable only in a disposable lab, with an existing reviewed kured image pinned
by digest, one direct kured container, no envFrom, `--concurrency=1`,
`--lock-ttl=0`, and the default `weave.works/kured-node-lock` annotation. The
configured DaemonSet name/namespace must match kured's own arguments or explicit
environment. Every argument must use literal `--name=value` form, including
unrelated flags and booleans; split values, bare flags, positional arguments,
and any `$(...)` interpolation are rejected. Locking environment names must be
canonical uppercase and unique; their values must not use interpolation or
Secrets/ConfigMaps. The DaemonSet must be fully rolled out
and Ready before acquisition. No kured version has yet been compatibility-qualified.

Example operator Helm values (host execution remains independently opt-in):

```yaml
kured:
  enabled: true
  namespace: kube-system
  daemonSet: kured
  rbacEnabled: false
```

Equivalent operator environment: `KORDEX_KURED_ENABLED=true`,
`KORDEX_KURED_NAMESPACE=kube-system`, `KORDEX_KURED_DAEMONSET=kured`.
Other packaging must provide the same environment and a namespaced Role/Binding
allowing only get/patch on that named DaemonSet. Kubernetes RBAC limits the
resource, not individual patched fields; deployment security review must account
for the ability to patch this privileged DaemonSet.

The versioned `operations.kordex.local/kured-lock` operation annotation pins the
DaemonSet UID, spec digest, and unique `manual:kordex:<maintenance-UID>` holder.
Intent is persisted before the external CAS; acquired ownership is persisted
before host actions. The holder can never be an actual Kubernetes node name and
has no automatic expiry. Conflicts, foreign/malformed/expired locks, missing
objects, changed configuration/UID, or lost ownership block progress. A lost
acquisition response can be resolved by reading the exact holder, but a lock
lost after committed acquisition is never automatically reacquired. Recovery
keeps the cordon and local reservation until custody and host/workload evidence
are verified. Terminal cleanup removes only the exact owned annotation with a
UID/resource-version/value CAS; foreign owners are untouched.
If the DaemonSet is already absent during terminal cleanup, Kordex still releases
its local reservation. Reservation update errors retain the operation finalizer
for retry; only a successful release, an absent Lease, or a different Lease owner
allows cleanup to continue to the existing hub-acknowledgement check.

Keep the kured configuration and DaemonSet identity stable while operations are
pending. Do not remove this lock to bypass a fenced operation. After disabling
new interlock acquisition, existing operation references still require cleanup:
retain `kured.rbacEnabled: true` with the original name/namespace until all such
operations finish, then remove the optional RBAC. Do not delete the DaemonSet
before that cleanup. Default operator values enable neither the interlock nor
host mutation, and grant no kured patch permission.

Traceability: UPG-03, UPG-04, UPG-05, UPG-06, UPG-09, UPG-10. Implementation
and local fake-client tests are not acceptance evidence for these requirements.
Any future Debian/RHEL qualification that uses the optional kured interlock
must additionally retain the kured DaemonSet UID/spec/image/configuration,
manual-lock snapshots, and operation reference, and exercise competing
acquisition, restart, cancellation, API loss, changed ownership, and release
only after verified recovery. All real kured/VM cases remain **NOT RUN**; no
production qualification is claimed.

Local verification — 2026-11-17: `go test -race ./operator/internal/reboot ./operator/internal/controller ./operator/cmd/kordex-operator -count=1`
and `go vet ./operator/internal/reboot ./operator/internal/controller ./operator/cmd/kordex-operator`
passed. Fake-client cases cover intent/ownership persistence, signed host
cancellation with/without an executor and interlock, restart with acquisition
disabled, expired authorization before acquisition, foreign/malformed/expired
locks, CAS conflicts/concurrent ownership, lost acquire/release responses,
configuration/UID drift, custody loss during recovery, and owner-only cleanup.
`HELM=/tmp/kordex-helm/linux-amd64/helm bash scripts/test-kured-helm.sh` and Helm
lint with default and enabled interlock values passed. The Helm checks are also
part of CI and assert default-off permissions, resource-name-scoped patching,
cleanup-only RBAC, and independent host execution opt-in. These are local
contract/simulation checks; no kured Pod, VM, or cloud resource was started.

Local regression verification — 2026-11-18 (UPG-04, UPG-05, UPG-10): new
regressions first reproduced argument/configuration masking and terminal cleanup
removing the finalizer while retaining its reservation. After the fixes,
`go test -race ./operator/internal/reboot ./operator/internal/controller ./operator/cmd/kordex-operator -count=1`
and `go vet ./operator/internal/reboot ./operator/internal/controller ./operator/cmd/kordex-operator`
passed. Tests reject argument expansion, split/unprefixed forms, and duplicate or
noncanonical locking environment names, while accepting literal flags and an
explicit namespace field reference. Missing-DaemonSet cleanup covers reservation
release, an already absent Lease, and update conflict/NotFound errors retaining
the finalizer until a successful retry.
`HELM=/tmp/kordex-helm/linux-amd64/helm bash scripts/test-kured-helm.sh` passed;
both enablement defaults remain off. This is local fake-client evidence only:
all real kured/Ubuntu VM qualification cases remain **NOT RUN**.

## Current product boundary

Kordex supports inventory, approval-driven campaigns, constrained stateless-worker drain/recovery, opt-in Debian/Ubuntu and RPM-family Ansible EE package/reboot catalogs (including Amazon Linux 2023 through DNF), and an opt-in GKE node-pool Kubernetes version upgrade. `UpgradeFleet` freezes a concrete host or provider action per target, allowing one campaign to contain Debian/RPM-family host and GKE node-pool targets while sharing stages, approvals, windows, and concurrency budgets. The local operator remains authoritative and fail-closed. Both upgrade paths are unqualified: use disposable VMs or a disposable GKE cluster only. The operator consumes read-only Rook/Ceph health and manager metrics for OSD `up/in`, flags, and PG recovery/degradation evidence, plus optional live mTLS etcd membership/status evidence for self-managed clusters. OSD-host maintenance, control-plane execution, provider-native EKS/AKS managed-node-group upgrades, and real Rook/Ceph/etcd/GKE/Amazon-Linux compatibility qualification remain incomplete.

Self-managed host-upgrade OS identity is bound into the signed policy digest as normalized OS ID, major, minor, and the selected point release where applicable. For M3, the supported qualification targets are Debian major `13` (Trixie, current stable point release verified and recorded when the lab is provisioned) and RHEL major `9` with minor `9.8` as the minimum; prefer the latest verified RHEL 9 minor. Ubuntu `24.04` is supplemental only, and Amazon Linux `2023` remains a separate non-M3 compatibility target. Rocky Linux, AlmaLinux, CentOS Stream, and other derivatives do not satisfy RHEL qualification. Operator inventory matching, the qualification runner, the EE catalog, and live playbook preflight reject Debian 12 and RHEL earlier than 9.8. This tightens admission only; it does not qualify any release. All host-upgrade qualification matrix rows remain **NOT RUN** until real disposable-host evidence is recorded.

Amazon Linux 2023 uses the common SSH/DNF path and has no AWS API dependency. EKS managed node-group lifecycle operations are still unimplemented, and AL2023 host-upgrade compatibility still needs disposable VM failure and recovery drills.

### Local qualification tooling verification — 2026-11-17

The self-managed qualification harness passed its Ansible EE contract tests,
guarded drill tests, fault-evidence recorder tests, and failure-matrix verifier
tests. The verifier's pinned SHA-256 matches the checked-in failure matrix.
The controller package also passed envtest against a real Kubernetes API
server and etcd using the generated CRDs. These checks establish contract and
API-server behavior only; they do not establish that a host package update or
reboot succeeds. No disposable Debian/Ubuntu or RHEL VM was connected, no VM
failure case was executed, no database DSN was configured for this run, and no
disconnected-site installation was performed. The operator host-upgrade gate
therefore remains disabled by default and production qualification remains
incomplete.

Local lab-entry verification — 2026-11-18 (UPG-04, UPG-14, UPG-18):
`python3 -m unittest discover -s tests/integration -p 'test_*upgrade*.py' -q`
passed **96 tests**, including aggregate missing-setting/context diagnostics,
malformed digest rejection, execution-only confirmation, and observation-mode
requirements. A CLI invocation with an empty lab environment returned the
expected exit 1 and recorded all eight missing settings plus the context error
before any API access. Offline Helm rendering verified that the documented lab
override sets the operator host-execution flag while default rendering keeps
host/provider execution disabled. No Helm upgrade, operation submission, or
infrastructure creation was performed; all disposable Debian/RHEL results remain
**NOT RUN**, and none of these requirements is marked complete.

The current slice adds validated policy data to the shared protocol and `MaintenancePolicy` CRD, canonical policy digest binding in permits and campaign snapshots, and a durable operation checkpoint. The operator now has an opt-in execution path for fixed Debian and RHEL-family Ansible EE catalogs: read-only host identity and exact-package-resolution preflight, safe drain, exact package pins, a separate controlled reboot phase, receipt validation, and Kubernetes/workload recovery before uncordon. Package resolution uses the target's existing APT cache or DNF metadata in Ansible check mode before cordoning; it neither installs packages nor refreshes metadata. RHEL-family runs with `IfNeeded` or `Never` also require `dnf needs-restarting -r`: Kordex rejects a host that already needed a reboot during preflight, then checks again after package installation to detect update-triggered reboot requirements without enabling repositories. A missing or indeterminate DNF reboot detector fails closed. Kernel package plans must bind an exact `expectedKernelVersion`; the EE and operator verify the running kernel before reboot recovery can uncordon. Debian uses the kernel package set and `/var/run/reboot-required` marker when present. Each execution Job is deterministic, suspended until a local safety/authorization check passes, uses immutable request input, zero retries, a fixed catalog entrypoint, projected SSH key/known-hosts material, and a tokenless ServiceAccount. Verified phase receipts are now copied into immutable ConfigMaps in the retained `kordex-operations-ledger` namespace without a `NodeMaintenance` owner reference, so acknowledgement and deletion of the operation object do not garbage-collect its recovery evidence. Existing operation-owned receipts are read and migrated on access. This is cluster-local append-only evidence under the operator's get/create-only RBAC; it is not external immutable retention and does not protect against a cluster administrator deleting the ledger. An ambiguous mutating job first consumes a persisted completion receipt or runs a separate read-only inspection of exact packages and host identity; it never automatically retries package installation or reboot. Each inspection attempt pins an immutable snapshot of known-hosts data and includes a digest of the SSH credential input in its identity; the credential itself stays in the configured Secret. After host-key or SSH-authentication failure, changing either input permits a new read-only attempt with a distinct durable identity. After SSH transport failure, an administrator can set a fresh UUID in `operations.kordex.local/recovery-retry` after restoring connectivity; this permits exactly one new read-only attempt under a new immutable job identity. All inspection retries are capped at 100 attempts; they do not authorize package installation or reboot. Mismatched or missing inspection evidence keeps the node cordoned and reservation held. The execution gate defaults off. This path is not qualified for production: it has not passed disposable Debian 13 or RHEL 9.8+ VM upgrade, reboot, interruption, and recovery drills.

Maintenance policies now carry an explicit `allowedActions` list shared by the agent catalog, central campaign/operation admission, and local operator authorization. Missing, empty, duplicate, unknown, or mismatched action/plan configuration fails closed; a plan alone does not authorize an upgrade. The generated CRD and API contract expose the allowlist. Existing policies and older agent reports require an ordered migration; no qualification status changes as a result of this policy enforcement work. This advances implementation for UPG-04, UPG-06, UPG-08, and UPG-11; their full acceptance criteria and all host-upgrade qualification remain incomplete.

Policy target selection increment — 2026-11-19 (UPG-06/UPG-14): campaign assessment, central operation admission, operator policy status validation, local safety preflight, and the final local authorization boundary now use one pure Kubernetes `LabelSelector` evaluator. It returns stable allow/deny codes with human explanation and corrective actions; callers preserve their API-specific reason mappings. Tests cover label match, expression match, empty-selector Kubernetes semantics, mismatch, and invalid selector, plus local no-cordon denial. A PostgreSQL-backed campaign test against a temporary loopback-only PostgreSQL 17 container verified that changed selector evidence pauses an approved campaign before an operation is issued. This aligns target-selector semantics only; it is not the complete deterministic policy engine for windows, concurrency, approvals, PDB, quorum, storage, or recovery. It provides local code evidence and does not change qualification status.

Versioned maintenance-action decision increment — 2026-11-19 (UPG-04/UPG-06/UPG-11/UPG-14): the shared protocol evaluator now evaluates a requested action against an explicit allowlist and policy generation, returning an allow/deny result, stable reason code, explanation, evaluated generation and action, allowlist, and corrective actions. The operator checks it at reconciliation and authorization boundaries; campaign assessment and central admission use the same evaluator, with admission preserving its API reason contract. Protocol tests cover allowed, omitted, empty/malformed, unknown-action, and invalid-generation cases. A PostgreSQL-backed campaign test against a temporary loopback-only PostgreSQL 17 database verified that an approved campaign pauses without dispatch when fresh policy evidence removes its requested action. `make test` and `make vet build contract` passed. This is action-allowlist evaluation only; maintenance windows, fleet/zone concurrency, approval semantics, PDB, quorum, storage, and recovery are not covered by a complete shared policy engine. No qualification status changed, and host-upgrade defaults remain off.

Protected-node policy increment — 2026-11-19 (partial UPG-06/UPG-14): `MaintenancePolicy` now accepts an optional administrative `protectedNodeSelector`. A match is a hard maintenance veto in campaign assessment, central operation admission, local preflight, and the operator's final authorization boundary; a configured selector with missing label evidence also denies. A non-nil empty selector protects all nodes, while an omitted selector preserves existing policy behavior. The agent relays this selector in its fresh policy catalog, and the operator reports malformed selectors as an invalid policy. Protocol, agent-catalog, operator no-cordon, campaign admission, and generated CRD contract tests cover the behavior. This is one additional policy control, not the complete deterministic policy engine or protected-node dashboard workflow. No executor qualification or matrix status changed; host-upgrade defaults remain off.

Per-zone admission increment — 2026-11-19 (partial UPG-20/§12/§13): organization and campaign concurrency budgets now include a topology-zone slot limit. The scheduler binds each durable reservation to the fresh inventory zone, verifies that an approved snapshot still has the same zone, and applies the limit transactionally alongside organization, fleet, site, cluster, and node limits. Missing or contradictory zone observations are treated as overlapping every zone, which conservatively serializes them instead of allowing unknown topology to bypass a cap. Migration 013 backfills active reservation zones where possible and retains unknown values as wildcards. Tests cover distinct zones, same-zone blocking, unknown-zone blocking, legacy policy defaults, and zone-label conflicts. This is local PostgreSQL evidence, not fleet-scale or multi-replica qualification; UPG-20 remains incomplete and no executor qualification row changes.

Campaign concurrency UI increment — 2026-11-19 (partial UPG-20/§12/§13): draft creation now validates and sends the campaign's seven concurrency ceilings with both preview and create requests; users can inspect the same values during preflight review, persisted campaign detail, and start confirmation. Dashboard contract tests cover integer/range validation and fixed cluster/node limits; typecheck, lint, and production build pass. Server-side admission remains authoritative. This does not complete the shared policy engine, change any qualification row, or enable host-upgrade defaults.

Every executable host-upgrade plan requires `UpgradePolicy.actionMarkerVersion: 1`; markerless legacy plans are rejected. The signed plan and EE image bind this version to the root-owned host journal at `/var/lib/kordex/operations/<operation-id>.json`. The journal records `apply-intent` before package mutation, `packages-verified` only after package, machine-ID, boot-ID, and kernel checks, `reboot-intent` before reboot, and `reboot-verified` only after the host returns and postconditions pass. The EE catalog embeds its marker version, so the operator rejects a policy/image mismatch. Receipts include the marker's file SHA-256 and operation, plan, node, machine, boot, phase, and sequence identities. Replays of package apply are rejected when a journal already exists. Ambiguous outcomes use read-only inspection; an incomplete journal never authorizes a retry or a successful recovery by itself. This protocol has not yet been qualified on disposable VMs.

Provider-native GKE plans require a canonical project/location/cluster/node-pool path and matching Kubernetes provider ID, cluster name, topology, and node-pool label in fresh inventory. Campaign planning deduplicates a pool to one target. An opt-in GKE v1 REST adapter now uses attached Google Workload Identity, etag-guarded node-pool updates, durable pool-scoped checkpoints, operation observation, and replacement-node/workload verification. The plan pins SURGE settings (`maxSurge=1`, `maxUnavailable=0`) and the operator blocks unless the existing pool settings match; these limits apply per zone for regional pools. It is not yet production-qualified; cloud-operation correlation after a lost update response uses exact target and start-time correlation because the GKE update request does not expose a Kordex operation ID or client idempotency key. Keep it restricted to a disposable GKE cluster and a dedicated workload identity until the failure drills are completed. EKS/AKS remain unavailable. The self-managed executor supports fixed Debian/Ubuntu and RHEL-family catalogs; each still requires separate OS-family qualification. Host mutation must remain disabled except in a disposable qualification lab until the VM evidence below is recorded. Read-only inspection can verify exact package and host state after ambiguous execution, but it does not roll back partial package changes or replay mutation. Cases without matching inspection evidence still require operator intervention.

## Delivery sequence

### Upgrade 0 — immutable action contract (implemented; qualification ongoing)

Define policy pins, supported OS/EE catalog combinations, immutable EE image/playbook/collection digests, bounded timeouts/retries, fixed hook identifiers, canonical digest, durable checkpoint phases, host identity, and receipt formats. Bind the digest into signed permits, immutable campaign target snapshots, and local CRD policy. Maintain an explicit unsupported-action response until a complete executor vertical slice is qualified.

Acceptance: policy inputs reject shell fragments, floating package versions, duplicate packages, unsupported manager/OS pairs, unrecognized hooks, and unbounded timeouts; same logical policy produces the same digest; illegal checkpoint transitions are rejected; no executor can run from a validation permit.

### Upgrade 1 — self-managed Linux executor vertical slice (code path implemented; qualification incomplete)

The M3 matrix qualifies Debian 13 and RHEL 9.8+ catalogs on real disposable VMs; Ubuntu 24.04 is supplemental only. Run every canonical case separately on each required OS profile using the checklist above. The local Job adapter must recover ambiguous launches by operation and phase identity. Bind execution to the plan digest, node UID, machine-id, EE image digest, playbook digest, collections digest, and catalog ID. Enforce an operator-configured exact image-digest allowlist so policy authors cannot substitute another image that implements the same entrypoint. Keep SSH credentials in a fixed local Secret and never in campaign data or the dashboard. Do not accept arbitrary playbook text, role names, inventory, tags, extra-vars, or shell commands from users. Persist local/Kordex execution checkpoints and operation-owned markers. Policy schema v2 binds each offline package file digest; the executor verifies and installs only pre-staged artifacts without repository access. Offline archive generation and target staging tools are implemented and included in the generic release bundle. Operators must still transfer the policy and matching archive to the target site and stage it on the worker; qualify that workflow, package dependency closure, and recovery on disposable VMs before claiming a complete offline upgrade workflow. Require disposable VM failure drills before enabling package mutation in a deployment.

Acceptance: the executor proves the requested EE/playbook/collections digests and catalog ID match the signed policy; action is idempotent across process/runner/VM restart; duplicate, stale, wrong-host, wrong-policy, and altered-digest permits reject; package postcondition is verified; ambiguity remains reserved and blocked; no automatic retry repeats a partially applied operation without an explicit recovery policy. An offline package run must prove each installed artifact against its signed plan digest without contacting package repositories or public services, and the approved artifacts must have a repeatable signed transfer and staging workflow. Remaining evidence: run all eleven cases on Debian 13 and all eleven on RHEL 9.8+ disposable VMs and record them before enabling beyond the reviewed lab.

### Upgrade 2 — reboot and host recovery

Reboot is an explicit, separate action after package postconditions. Persist pre-reboot boot ID, machine-id, node UID, package receipt, marker sequence, and expected kernel before issuing reboot. On reconnect, require machine-id and node identity continuity; require boot-ID change only if reboot was requested; verify kernel/package versions and kubelet/Node readiness. A command success or node return alone never means success.

Acceptance: exercise reboot-not-issued, reboot-never-returns, network loss before/after reboot, machine replacement, wrong kernel, partial package state, operator/agent restart, and cancellation during each phase on disposable VMs. Every case ends succeeded, safely recovered, or explicitly intervention-required; reservation stays held otherwise.

### Upgrade 3 — provider-native node lifecycle paths

Add optional GKE, EKS, and AKS adapters as separate control-plane integrations. First support read-only discovery and preflight, then operation-owned provider requests. GKE COS uses provider node-image/node-pool lifecycle, not package commands inside COS. Cloud credentials use workload identity and narrowly scoped provider roles. Kubernetes-side drain, local safety veto, approval, campaign gates, and audit remain common.

Acceptance: each supported provider/version has a documented capability matrix and failure-injection record; provider operations are idempotent and correlated to Kordex operation IDs; out-of-band changes and provider timeouts become ambiguous/recovery states, never blind retries.

### Upgrade 4 — live storage/quorum safety

The read-only Rook/Ceph adapter is wired into local preflight, but its metric contract is not qualified against supported releases. A live etcd membership source is available when configured, but this is not permission to operate on control-plane nodes: static/mirror pod draining and topology-specific recovery are still unsupported. Next add storage enter/exit lifecycle with ownership tokens and verified recovery. Detect control-plane/provider-managed nodes explicitly; unknown topology blocks. Provider-managed control planes require provider-specific quorum semantics rather than inferred etcd membership.

Local preflight also recognizes OpenEBS LocalPV LVM/ZFS CSI provisioners and
legacy Hostpath PVs. It evaluates the PV's standard node affinity, blocks when
the PV is pinned to the target or its placement cannot be established, and
allows a target when the PV is pinned to another node. This is generic
placement evidence only; OpenEBS health/recovery, Mayastor and other replicated
engine health, and storage enter/exit mutation workflows remain unimplemented
and unqualified.

A read-only Longhorn v1beta2 adapter now checks node readiness timestamps,
volume health, expected replica count and placement, and rebuild, restore, and
migration signals. Missing, stale, contradictory, degraded, or active recovery
evidence blocks. It also blocks targets hosting Longhorn service pods, replicas,
or attached volumes because Kordex has no ownership-aware rebuild coordination
workflow. After Longhorn evidence passes, known remote Longhorn infrastructure
pods are omitted from the generic unknown-storage scan; unknown Longhorn pods
remain blocking. Helm and Kustomize grant only `get`/`list` on Longhorn nodes,
replicas, and volumes. Focused unit tests cover these decisions and Rook-path
composition. This is not Longhorn qualification; no real storage integration
or qualification row changed.

Acceptance: stale, absent, contradictory, degraded, and ownership-changed evidence blocks; noout/maintenance flags are removed only when Kordex owns them; recovery after operator loss is observable and safe.

### Upgrade 5 — campaign and dashboard upgrade workflows (partial foundation)

Bind campaign snapshot and each approval to exact action digest, target identity, policy generation, stage, and provider/host plan. Reuse canary/small/expanded/remaining gates; do not auto-advance on threshold breach. Fresh local policy catalog and executor-capability reporting, policy selection, organization switching with live membership validation, and upgrade checkpoint transport into campaign history are implemented. Upgrade campaign review exposes the pinned package versions, EE image, catalog, playbook and collection digests, reboot policy, retry count, timeouts, and aggregate plan digest. Simulation with per-node block explanations, upgrade-specific approvals, cancellation semantics during reboot, drift inventory, and full evidence freshness remain incomplete.

Acceptance: creator/approver separation is enforced in API and database paths; stale approvals and changed policy/action invalidate execution; dry-run has no side effects and explains every exclusion; cancellation during execution/reboot follows explicit recovery.

### Upgrade 6 — enterprise qualification

Complete immutable external audit retention, restore/HA drills, signed artifacts/SBOM/provenance, air-gapped delivery, global rate limits/circuit breakers, fleet-scale concurrency validation, topology-aware canaries, alerts/SLOs, and post-upgrade verification packs. Publish only measured compatibility and scale evidence.

Acceptance: independent security review, reproducible release, VM and cluster drill records, backup/restore evidence, and a documented support matrix exist for every claim.

## Requirement traceability

| ID | Requirement | Delivery |
|---|---|---|
| UPG-01 | Real node lifecycle executor, no general shell | Upgrade 1/3 |
| UPG-02 | Package/OS/kernel update and pinned target | Upgrade 0/1/3 |
| UPG-03 | Controlled reboot with boot/action marker verification | Upgrade 2 |
| UPG-04 | Explicit success/failure/ambiguous and fail-closed unknown | Upgrade 1/2 |
| UPG-05 | Durable checkpoints and idempotent restart recovery | Upgrade 1/2 |
| UPG-06 | Policy allowlists, hooks, timeout/retry/reboot controls | Upgrade 0/1 |
| UPG-07 | Live storage and quorum integrations | Upgrade 4 |
| UPG-08 | Campaign action binding and staged rollout gates | Upgrade 5 |
| UPG-09 | Immutable action ledger and host identity | Upgrade 1/2 |
| UPG-10 | Correct long-running reservations and recovery paths | Upgrade 1/2/5 |
| UPG-11 | Policy discovery/catalog | Upgrade 5 |
| UPG-12 | Separation of duties and exact approvals | Upgrade 5 |
| UPG-13 | Dashboard-led upgrade creation and controls | Upgrade 5 |
| UPG-14 | Fresh inventory, phase evidence, blocked explanations | Upgrade 5 |
| UPG-15 | Dry-run target simulation and blast-radius view | Upgrade 5 |
| UPG-16 | Multi-org and multi-fleet experience | Upgrade 5 |
| UPG-17 | Upgrade metrics, alerts, phase latency, reservations | Upgrade 6 |
| UPG-18 | Useful audit evidence and outcome | Upgrade 5/6 |
| UPG-19 | Backup, restore, HA, signed release, SBOM, air-gap | Upgrade 6 |
| UPG-20 | Fleet rate/concurrency controls and circuit breakers | Upgrade 5/6 |
| UPG-21 | Failure-domain-aware canaries | Upgrade 5 |
| UPG-22 | Optional GKE/EKS/AKS-native lifecycle adapters | Upgrade 3 |
| UPG-23 | Workload-aware PDB and critical-service reasoning | Upgrade 4/5 |
| UPG-24 | Post-upgrade verification packs | Upgrade 2/5 |
| UPG-25 | Offline package artifact digest binding, transfer, and staging | Upgrade 1 |

## Compatibility and release rules

Signed action payloads, campaign snapshots, CRD fields, and local journals require explicit schema versions. Adding a new action must not make existing `ValidateOnly` or `DrainAndVerify` permits mean something different. Control plane and operator must reject an unknown action until both advertise support. A migration or conversion strategy is required before changing a released persisted format.

The GKE cluster currently used for the pilot is not a host package-upgrade target: its nodes run Container-Optimized OS. Use it for provider-native lifecycle preflight and Kubernetes drain/recovery qualification. Use disposable Debian 13 VMs for Trixie APT evidence and RHEL 9.8-or-later VMs for RHEL DNF evidence; Ubuntu 24.04 is supplemental only. The opt-in Ansible path requires routed SSH from the operator namespace to the node, a dedicated SSH user with narrowly scoped passwordless sudo for the fixed playbook, a private key in a Kubernetes Secret, and pinned host keys in a ConfigMap. Never point it at the current GKE COS nodes.

### Self-managed Debian and RHEL qualification runner

In a source checkout, the guarded first-pass runner is
`tests/integration/self_managed_upgrade_smoke.py`. In a verified offline release
bundle, use `qualification/self_managed_upgrade_smoke.py`. It targets one disposable self-managed Debian/Ubuntu or RHEL-family
Kubernetes worker and checks that the live node OS matches the selected policy catalog. It compares the
registered cluster and node identities with the live API server, checks fresh
operator capability and policy catalog data, and in execution mode submits
one normal signed `UpgradePackages` operation through Kordex. It writes
redacted JSON evidence and checks the immutable operator checkpoint, exact
package receipt, reboot evidence when required, expected kernel, node UID,
readiness, and schedulability.

#### Disposable Debian 13 and RHEL 9 lab setup (human-run commands only)

For a workstation-local management API reached from a disposable VM, follow
the private route, mTLS, loopback API and relay procedures in
[`private-management-connectivity-architecture.md`](private-management-connectivity-architecture.md)
and [`private-agent-relay-operations.md`](private-agent-relay-operations.md).
A public Cloudflare tunnel does not satisfy this private-route requirement.
Source and fixture tests are not live connectivity or qualification evidence.

Use a separately baselined, enrolled disposable cluster whose server and two
workers all use the same selected profile: Debian 13 Trixie or RHEL 9.8+.
Ubuntu 24.04 is supplemental only. Use the repository's self-managed Kustomize overlay as the single
recommended packaging path for this lab; do not mix it with the operator Helm
chart. Complete the entry checklist,
including snapshot/console access, recovered workloads on another worker,
reviewed `Always` reboot policy, and pre-staged offline artifacts. These commands
do not provision a lab. Replace every example below with the reviewed lab values;
the plan digest must come from that exact policy, not an arbitrary 64-digit value.
Keep the API token out of shell history by reading it interactively in Bash:

```bash
export KORDEX_API=https://kordex.example.internal
read -r -s -p 'Short-lived lab operator token: ' KORDEX_ADMIN_TOKEN
export KORDEX_ADMIN_TOKEN
export KORDEX_ORG_ID='ORGANIZATION_UUID'
export KORDEX_CLUSTER_ID='REGISTERED_CLUSTER_UUID'
export KORDEX_NODE_NAME='APPROVED_DEBIAN_OR_RHEL_WORKER'
export KORDEX_HOST_POLICY='APPROVED_SELECTED_PLATFORM_POLICY'
export KORDEX_HOST_PLAN_DIGEST='64_CHARACTER_POLICY_DIGEST'
export KORDEX_EXPECTED_CONTEXT='disposable-self-managed-context'
export KORDEX_NAMESPACE='kordex-system'
export KUBECONFIG='/secure/lab/kubeconfig'
kubectl config use-context "$KORDEX_EXPECTED_CONTEXT"
kubectl --context "$KORDEX_EXPECTED_CONTEXT" get node "$KORDEX_NODE_NAME" -o wide
```

The runner lists all unset/blank required settings and unusable/mismatched kube
context errors together before contacting the management or Kubernetes API. It
also rejects a malformed plan digest locally. The default mode is read-only,
but its full readiness check requires the operator to advertise `hostUpgrades`:
it will fail while the lab operator's execution gate is closed.

For the **disposable lab only**, supply the reviewed SSH user, existing
credential Secret (`id_ed25519` key), pinned-host-key ConfigMap (`known_hosts`
key), and exact policy EE image digest. The SSH user must have the fixed
playbook's required sudo access. Configure private registry pull secrets in
`upgradeImagePullSecrets` if needed. There must be no pending host operations
when enabling the gate.

The default Kustomize overlay keeps both host and GKE upgrade gates false and
does not grant host-execution RBAC. Keep it that way in Git. Once the lab
operator and agent are installed and the SSH Secret and known-hosts ConfigMap
are ready, create a temporary lab overlay under the Kustomize overlays
directory. This reuses the reviewed self-managed resources, adds only the
optional host-execution RBAC component, and applies the gate settings as a
temporary ConfigMap patch. The example uses the component's fixed Secret name
`kordex-upgrade-ssh`; use that exact name because the component limits Secret
read permission to it. Keep this temporary directory until both gates have
been closed and verified.

```bash
mkdir -p ./qualification
LAB_OVERLAY="$(mktemp -d deployments/kustomize/overlays/.host-upgrade-lab.XXXXXX)"
export KORDEX_LAB_SSH_USER='kordex'
export KORDEX_LAB_SSH_SECRET='kordex-upgrade-ssh'
export KORDEX_LAB_KNOWN_HOSTS='kordex-upgrade-known-hosts'
export KORDEX_LAB_EE_IMAGE='registry.example.internal/kordex/ee@sha256:REVIEWED_64_HEX_IMAGE_DIGEST'
export KORDEX_LAB_IMAGE_PULL_SECRETS='kordex-registry'
[[ "$KORDEX_LAB_EE_IMAGE" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'EE image must use its reviewed SHA-256 digest' >&2; exit 2; }
cat > "$LAB_OVERLAY/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../self-managed
components:
  - ../../components/operator-host-execution
patches:
  - path: operator-host-execution.patch.yaml
    target:
      group: ""
      version: v1
      kind: ConfigMap
      name: kordex-operator-settings
  - path: agent-maintenance.patch.yaml
    target:
      group: ""
      version: v1
      kind: ConfigMap
      name: kordex-agent-settings
EOF
cat > "$LAB_OVERLAY/operator-host-execution.patch.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: kordex-operator-settings
  namespace: kordex-system
data:
  upgradeEnabled: "true"
  gkeUpgradeEnabled: "false"
  upgradeSSHUser: "$KORDEX_LAB_SSH_USER"
  upgradeSSHSecret: "$KORDEX_LAB_SSH_SECRET"
  upgradeKnownHosts: "$KORDEX_LAB_KNOWN_HOSTS"
  upgradeExecutionEnvironmentAllowlist: "$KORDEX_LAB_EE_IMAGE"
  upgradeImagePullSecrets: "$KORDEX_LAB_IMAGE_PULL_SECRETS"
EOF
cat > "$LAB_OVERLAY/agent-maintenance.patch.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: kordex-agent-settings
  namespace: kordex-system
data:
  maintenanceEnabled: "true"
EOF
```

Replace every example with reviewed lab values. Keep the operator settings
patch free of credential values; only Kubernetes Secret and ConfigMap names
belong here. Render and inspect the complete output, confirm the target context,
the single intended host-execution Role/RoleBinding, and the gate value before
applying. Because the temporary overlay deliberately references sibling
repository resources, render it with the load restriction used by CI, then
apply the reviewed output with an explicit context:

```bash
test "$(kubectl config current-context)" = "$KORDEX_EXPECTED_CONTEXT"
kubectl kustomize --load-restrictor=LoadRestrictionsNone "$LAB_OVERLAY" > ./qualification/host-upgrade-lab-rendered.yaml
grep -F 'upgradeEnabled: "true"' ./qualification/host-upgrade-lab-rendered.yaml
grep -F 'gkeUpgradeEnabled: "false"' ./qualification/host-upgrade-lab-rendered.yaml
kubectl --context "$KORDEX_EXPECTED_CONTEXT" apply -f ./qualification/host-upgrade-lab-rendered.yaml
kubectl --context "$KORDEX_EXPECTED_CONTEXT" rollout restart -n "$KORDEX_NAMESPACE" deployment/kordex-agent deployment/kordex-operator
kubectl --context "$KORDEX_EXPECTED_CONTEXT" rollout status -n "$KORDEX_NAMESPACE" deployment/kordex-agent --timeout=180s
kubectl --context "$KORDEX_EXPECTED_CONTEXT" rollout status -n "$KORDEX_NAMESPACE" deployment/kordex-operator --timeout=180s
```

This sets **the operator process environment** `KORDEX_ENABLE_HOST_UPGRADES=true`
and the corresponding executor inputs/RBAC on this disposable Kustomize lab
only. Exporting that flag in the runner's shell alone has no effect on the
operator. The temporary overlay is not a repository default. Never commit a
gate-on lab patch, and never use this overlay on GKE or a shared cluster.

At operator startup, an enabled host executor checks its own effective
Kubernetes permissions with self-scoped `SelfSubjectAccessReview` requests for
the configured SSH Secret, known-hosts ConfigMap, execution Jobs/Pods/Network
Policies, and durable receipt ledger. A denied, indeterminate, or unavailable
review disables the local executor and reports it unavailable to the hub. This
is an early capability check; each Kubernetes API request remains subject to
normal authorization when it is made.

Run the read-only readiness preflight; it checks context, registered cluster UID,
live node UID/OS, fresh host capability, exact named policy and plan digest, and
workload baseline. Wait for fresh operator capability/catalog observations after
the rollout if needed, then retry with a new evidence filename:

```bash
python3 tests/integration/self_managed_upgrade_smoke.py \
  --evidence ./qualification/preflight.json
```

For an offline bundle, replace the script path with
`./qualification/self_managed_upgrade_smoke.py`. Create the evidence directory on a
separate writable lab volume; do not modify the signed release bundle. The
qualification host needs Python 3 and network access only to the configured
Kordex management endpoint and the disposable cluster's Kubernetes API. It
does not need Google, AWS, Azure, or public registry access.

Only after the disposable project designation, cluster, VM snapshot, recovery
access, package repository snapshot, and policy have been reviewed, execute one
operation. For the GCP self-managed lab, use
`scripts/self_managed_lab.py execute --project-id ...`; the wrapper rechecks
the private project allowlist and live project ID, lifecycle, and disposable
label, then requires the interactive phrase
`EXECUTE IN DISPOSABLE PROJECT <PROJECT_ID>` for every case. This is separate
from the project's `project_id_confirmation` and the exact target confirmation.
Do not invoke the underlying smoke runner directly for that GCP lab. The
wrapper cannot replace the required human review that the project contains no
shared or non-disposable infrastructure. The runner refuses execution unless
the explicit target confirmation exactly matches the registered cluster UUID,
node name, and current node UID printed in the preflight evidence:

```sh
export KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM='CLUSTER_UUID/NODE_NAME/NODE_UID'
python3 scripts/self_managed_lab.py execute \
  --project-id kordex-fleet-platform-515416 \
  --target-confirmation "$KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM" \
  --qualification-case clean-upgrade --timeout-seconds 14400 \
  --evidence ./qualification/clean-upgrade-debian.json \
  --k3s-binary /verified/k3s \
  --k3s-artifact-lock /verified/k3s.artifact-lock \
  --k3s-artifact-signature /verified/k3s.artifact-lock.sig \
  --k3s-artifact-trust /trusted/customer-artifact.trust \
  --k3s-system-images-bundle /verified/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /verified/k3s-system-images.lock \
  --k3s-system-images-signature /verified/k3s-system-images.lock.sig \
  --k3s-system-images-trust /trusted/customer-artifact.trust \
  --m3-artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --m3-artifact-report /secure/m3/artifact-preflight.json
```

Replace every public artifact path with the file independently verified for
the selected platform; keep secrets out of the arguments and input map. Copy
the exact `targetConfirmation` from the successful preflight report into
`KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM`. Execution also requires this setting
at startup and rechecks the value against the live target before submission.
After all operations have completed recovery and released their reservations,
close the lab gate by changing only `upgradeEnabled` to `"false"` in the
temporary operator ConfigMap patch and `maintenanceEnabled` to `"false"` in the
temporary agent ConfigMap patch, then render, review, and re-apply the same
overlay with the expected context. Confirm the agent maintenance gate and
operator host-upgrade capability are disabled and the rendered settings still
have `gkeUpgradeEnabled: "false"`.
Do not delete the temporary overlay until that is verified. Remove the rendered
file only after review and off-host evidence retention is complete; it is a
deployment manifest and must not contain credentials. After confirming both
gates are off, remove only the optional host-execution Role and RoleBinding;
the rendered `kubectl apply` does not prune resources removed from a later
Kustomize output.

```bash
sed -i 's/upgradeEnabled: "true"/upgradeEnabled: "false"/' \
  "$LAB_OVERLAY/operator-host-execution.patch.yaml"
sed -i 's/maintenanceEnabled: "true"/maintenanceEnabled: "false"/' \
  "$LAB_OVERLAY/agent-maintenance.patch.yaml"
kubectl kustomize --load-restrictor=LoadRestrictionsNone "$LAB_OVERLAY" > ./qualification/host-upgrade-lab-rendered.yaml
grep -F 'upgradeEnabled: "false"' ./qualification/host-upgrade-lab-rendered.yaml
grep -F 'maintenanceEnabled: "false"' ./qualification/host-upgrade-lab-rendered.yaml
test "$(kubectl config current-context)" = "$KORDEX_EXPECTED_CONTEXT"
kubectl --context "$KORDEX_EXPECTED_CONTEXT" apply -f ./qualification/host-upgrade-lab-rendered.yaml
kubectl --context "$KORDEX_EXPECTED_CONTEXT" rollout restart -n "$KORDEX_NAMESPACE" deployment/kordex-agent deployment/kordex-operator
kubectl --context "$KORDEX_EXPECTED_CONTEXT" rollout status -n "$KORDEX_NAMESPACE" deployment/kordex-agent --timeout=180s
kubectl --context "$KORDEX_EXPECTED_CONTEXT" rollout status -n "$KORDEX_NAMESPACE" deployment/kordex-operator --timeout=180s
kubectl --context "$KORDEX_EXPECTED_CONTEXT" -n "$KORDEX_NAMESPACE" delete role/kordex-operator-host-execution rolebinding/kordex-operator-host-execution
```

Use `./qualification/self_managed_upgrade_smoke.py` in these commands when running
from the offline bundle. Set `KORDEX_HOST_POLICY` and `KORDEX_HOST_PLAN_DIGEST`
to the local policy for the matching OS family; the runner rejects a mismatch.

The same runner supports one signed cancellation injection after package
execution starts or when rebooting begins. Use a fresh disposable VM and
campaign permit for each run:

```sh
python3 scripts/self_managed_lab.py execute \
  --project-id kordex-fleet-platform-515416 \
  --target-confirmation "$KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM" \
  --qualification-case cancel-during-reboot --cancel-on-phase Rebooting \
  --timeout-seconds 14400 \
  --evidence ./qualification/cancel-during-reboot-debian.json \
  --k3s-binary /verified/k3s \
  --k3s-artifact-lock /verified/k3s.artifact-lock \
  --k3s-artifact-signature /verified/k3s.artifact-lock.sig \
  --k3s-artifact-trust /trusted/customer-artifact.trust \
  --k3s-system-images-bundle /verified/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /verified/k3s-system-images.lock \
  --k3s-system-images-signature /verified/k3s-system-images.lock.sig \
  --k3s-system-images-trust /trusted/customer-artifact.trust \
  --m3-artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --m3-artifact-report /secure/m3/artifact-preflight.json
```

For M3, execute every case once against the approved Debian 13 policy and once against the approved RHEL 9.8+ policy. Use distinct `<case>-debian.json` and `<case>-rhel.json` files, operation IDs, and independently restored VM state; do not reuse evidence or VM state across profiles. Ubuntu results use a separate supplemental filename and cannot fill either required platform record. The full matrix verifier requires both required platform records for every case.

The drill passes only if Kordex ends `Cancelled` with the original node
recovered and schedulable, or ends `RecoveryRequired` with that same node still
cordoned. The latter is a fenced intervention state, not successful recovery.
Do not manually uncordon it; use the recorded operation evidence and normal
recovery procedure.

The complete qualification set requires every case for both `debian` and `rhel`, as enumerated in
`tests/integration/host_upgrade_failure_matrix.json` in a checkout and
`qualification/host_upgrade_failure_matrix.json` in the bundle. The runner directly
produces the clean-upgrade, cancellation, and operator-restart cases. The
operator-restart case waits for the operation to reach `Executing`, restarts
only the `kordex-operator` Deployment in `KORDEX_NAMESPACE`, waits for a new
Ready pod UID, and then continues watching the same operation ID. The verifier
requires durable `Executing` history before the restart timestamp and distinct
old/new pod UIDs. Execute the manual cases one at a time on freshly restored
disposable VMs, with a new operation ID for each attempt.

Run the operator restart drill with the same exact disposable-target
confirmation used for other execution cases:

```sh
python3 tests/integration/self_managed_upgrade_smoke.py --execute \
  --qualification-case operator-restart-during-executing \
  --timeout-seconds 14400 \
  --evidence ./qualification/operator-restart-during-executing-debian.json
```

Use a disposable cluster where the runner's kubeconfig can restart the
`kordex-operator` Deployment in `KORDEX_NAMESPACE` (default
`kordex-system`). The runner does not change that Deployment's image or
configuration; it only triggers a rollout restart.

For manually injected cases, start the lab injector in a separate terminal
and tag runner evidence with the matching case ID, for example:

```sh
python3 tests/integration/self_managed_upgrade_smoke.py --execute \
  --qualification-case ssh-loss-during-apply \
  --timeout-seconds 14400 --evidence ./qualification/ssh-loss-during-apply-debian.json
```

Record each runner result as `<case-id>-<os-family>.json`, then copy the
relevant lab console or network-control log to a temporary file. Attach the
structured record to the runner output with the bundled recorder. It copies
and hashes that raw log, adds the exact fault type, start/end timestamps,
external reference, and case-specific observations. The verifier checks those
observations against the reviewed matrix and checks the expected phase against
the operation's durable phase event history: generic `RecoveryRequired`
records alone do not pass.

```sh
cp ./lab-logs/ssh-loss.log ./qualification/ssh-loss.log
python3 tests/integration/record_host_upgrade_fault.py \
  --evidence ./qualification/ssh-loss-during-apply-debian.json \
  --method 'temporary TCP/22 block from the lab firewall' \
  --started-at '2026-11-17T12:02:00Z' \
  --ended-at '2026-11-17T12:03:00Z' \
  --evidence-ref 'lab-run-17' \
  --log ./qualification/ssh-loss.log \
  --observations '{"phase":"Executing","blockedObserved":true,"restoredObserved":true}'
```

Use `./qualification/record_host_upgrade_fault.py` from the offline bundle.
The `--observations` object must match that case's `faultEvidence` definition;
the verifier rejects missing fields, wrong fault types, and phases absent from
the operation's durable event history.

The verifier checks that the copied file exists inside the evidence directory,
is not a symlink, and matches the recorded digest. Never put SSH private keys,
bearer tokens, or signing material in evidence files. For
`RecoveryRequired`, include the observed operation phase, original node UID,
cordoned node state, and live `kordex-maintenance-cluster-slot` holder evidence.

The verifier checks that every required case has evidence and that the
recorded outcome is an allowed safe result for that case:

```sh
python3 scripts/verify-host-upgrade-qualification.py ./qualification
```

The verifier accepts only the reviewed failure matrix whose SHA-256 is pinned
in the verifier code. It deliberately has no command-line matrix override, so
an evidence run cannot report complete against a reduced case list. Changing
the qualification matrix requires updating its pinned digest in the same
review.

From the bundle, run
`python3 ./qualification/verify-host-upgrade-qualification.py ./qualification`.

An evidence pass is an auditable checklist result, not proof that the
injection record is truthful or independent review. Have a second operator
review the external injection records and evidence before changing the host
upgrade feature gate.

Do not set this confirmation for a production or shared cluster. The runner
does not create infrastructure and does not inject failures. A successful
single-node run is only happy-path evidence; it does not qualify the executor
or permit enabling it beyond a disposable lab. Record the separate Upgrade 1
and Upgrade 2 failure cases above, including operator restart, runner timeout,
network loss during apply/reboot, partial package state, wrong machine ID,
node replacement, reboot that never returns, and cancellation. Keep the host
upgrade feature gate disabled until those cases have each reached a verified
safe terminal state or explicit operator intervention.

### Kubernetes compatibility registry increment — 2026-11-18

This read-only registry and distribution hint tightening provide partial
support for UPG-11 catalog discovery. The authenticated API and dashboard now
show known Kubernetes targets, required/optional RBAC profiles, CRDs, network
requirements, operation boundaries, automated test coverage, and limitations.
The `kordex-discover -kubernetes-matrix` output is also available for local
inspection. Every distribution/version/node-OS/architecture remains
unqualified; no row in this document's upgrade qualification matrix changed.

Verification: `make test`, `make vet build contract`, dashboard tests,
typecheck, lint and build, offline Kustomize configuration test, and default
versus optional host-RBAC render checks passed locally. Database-backed
integration and API-server envtest were not run because their local DSN/assets
were not configured. No VM, cloud project, cluster, package transaction, or
reboot qualification was run. These results do not complete UPG-11 or qualify
any executor.

Dashboard registry routing correction — 2026-11-19: the dashboard's
server-side organization-scoped proxy now explicitly permits the authenticated
read-only `GET /kubernetes-compatibility` request used by the compatibility
page. This fixes a proxy allowlist mismatch; it does not change registry data,
qualification status, or any upgrade matrix row. Regression evidence:
`dashboard/tests/proxy.test.mjs` verifies the request remains under the active
organization, and dashboard tests/typecheck/lint pass.

### Effective host-execution RBAC probe — 2026-11-18

When the host-upgrade flag is configured, the operator now checks its own
effective access to the named SSH Secret and known-hosts ConfigMap, execution
Jobs/Pods/NetworkPolicies, and receipt ConfigMaps/Lease before constructing the
host executor. An access review that is denied, indeterminate, fails to return,
or reports an evaluation error disables the local executor. Each subsequent
Kubernetes request remains subject to normal API-server authorization. Unit
tests cover allowed, denied, indeterminate, and failed review results. Helm
chart and Kustomize role renders were checked locally. This is preflight
capability evidence only; it does not qualify a package transaction or reboot,
and no upgrade matrix row changed.

### Cluster capability inventory — 2026-11-18

Traceability: partial UPG-14 inventory freshness and blocker context only; this
does not meet UPG-14 acceptance or qualify a Kubernetes integration.

The agent reports bounded, timestamped CNI name hints, CSI drivers, StorageClass
provisioners, read-only counts of served admission configuration objects, and
Pod Security labels from its own namespace. Permission or discovery failures
stay `Unknown` with reason codes. The API validates and persists these
observations, and the fleet view shows their state and freshness. They are
inventory hints only: they do not
enable an executor, establish storage health, or qualify a Kubernetes
distribution. CNI detection uses recognized DaemonSet names; admission counts
do not prove that configurations are bound, effective, or enforcing policy;
Pod Security labels do not describe enforcement in other namespaces. No
qualification matrix row changed.

Verification: `make test`, `make vet build contract`, dashboard tests,
typecheck, lint and build, OpenAPI validation, and Helm/Kustomize agent RBAC
render checks passed. PostgreSQL store and HTTP API integration tests passed
against a fresh ephemeral PostgreSQL 17 container, which was stopped and
removed afterward. No live cluster, cloud resource, package transaction, or
reboot was used.

Follow-up: admission inventory now lists only supported admission resource
collections through Kubernetes metadata-only requests and reports bounded
aggregate counts. The cluster-wide agent RBAC addition is read-only; denied
reads keep the complete observation `Unknown`
and discard partial counts. Local inventory/registry tests and the Helm plus
Kustomize RBAC render script passed. This remains a capability hint, not proof
of active admission enforcement; no qualification row changed.

Tenant membership safety increment — 2026-11-19 (UPG-16, UPG-18): organization
membership role changes now serialize on the organization's limits row, and
the store rejects demotion of the last administrator. The authenticated API
maps that condition to HTTP 409 `last_administrator_required`. Local API
coverage verifies the conflict response; a PostgreSQL-backed concurrent test
verified that exactly one of two simultaneous last-admin demotions is accepted,
then verified that adding a replacement administrator permits the former
administrator's demotion. The full store package and `go vet ./internal/store`
passed against a temporary loopback PostgreSQL 17 instance; the instance was
stopped and removed. `make test` and `make vet build contract` also passed,
including all Go binary builds and the 50-operation OpenAPI contract check.
This does not establish production database behavior or complete organization
isolation. No host-upgrade qualification matrix row changed; all host-upgrade
defaults and qualification statuses remain as previously recorded.

Persisted-membership API isolation increment — 2026-11-19 (UPG-16, UPG-18): a
PostgreSQL-backed HTTP API integration now authenticates a test subject against
the stored membership table. It verifies same-tenant site access, 403 on a
different organization, 404 when a foreign cluster ID is supplied within the
caller's organization, and tenant-scoped audit results. The focused test and
the full `internal/store` suite passed against loopback-only disposable
PostgreSQL 17; the container was stopped and removed. This is automated local
evidence only and does not qualify deployed OIDC or production tenant isolation.
No host-upgrade row or default changed.

The fleet API now includes a read-only cluster compatibility summary derived
from persisted node hints. It reports node count, distinct OS display strings,
distinct architectures, distribution hints, and stable status/reason codes.
Unknown or incomplete distribution identity stays `Unknown`; conflicting
known hints report `MixedSignals`; known targets without registry evidence
report `Unqualified`. Kubernetes OS display strings do not attest normalized
host `os-release` identity. This summary does not authorize maintenance and
cannot report a cluster as qualified. The Kubernetes distribution and host
upgrade qualification rows above remain unchanged and NOT RUN.

Agent retry-loop verification — 2026-11-19 (partial UPG-14): the runner now has
explicit saturation-safe retry-backoff and jitter helpers. Tests exercise a
transient report outage followed by a successful retry with monotonically
increasing inventory versions, bounded exponential delays/jitter, and context
cancellation while a retry timer is pending. `go test ./... -count=1` and
`go vet ./...` passed in the `agent` module. This is local unit evidence only;
it does not qualify real network partition/recovery, installed-agent behavior,
inventory freshness under outage, or key rotation. No host-upgrade matrix row
or default changed.

GCP lab designation recheck — 2026-11-19: the qualification wrapper now
revalidates the configured project ID, numeric project number, ACTIVE lifecycle
state, and live `kordex-disposable=qualification` label after typed apply or
destroy confirmation and before the saved plan is applied. Every GCP wrapper
upgrade case performs the same live designation check, then requires a separate
interactive project phrase before target confirmation and runner invocation.
Tests verify rejection of identity, lifecycle, and label mismatches and that
runner invocation cannot follow a failed project check. This is wrapper unit
evidence only; it does not enumerate project resources or prove an empty project.
The human project inventory review remains mandatory. No cloud API, project,
Terraform plan/apply, upgrade, or matrix row was used or changed.
