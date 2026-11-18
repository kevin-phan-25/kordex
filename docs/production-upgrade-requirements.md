# Production upgrade requirements and delivery plan

This document tracks the production bar requested for Kordex as an infrastructure upgrade platform. A requirement is complete only when its code, failure behavior, audit evidence, and deployment evidence meet the acceptance criteria below. A Go interface or simulator alone does not count as an integration.

## Qualification status — authoritative record

This document is the single source of truth for capability and qualification
status. Roadmap phases describe implementation history, not release support.
**No upgrade executor is production-qualified. Both execution gates default off.**

| Path | Available verification | Real disposable upgrade evidence | Qualification |
|---|---|---|---|
| Self-managed Ubuntu/Debian APT + reboot | EE contract/simulator tests, guarded runner/evidence tests, controller API-server envtest (local record below) | None recorded | Incomplete; Ubuntu LTS is the next milestone |
| RPM-family DNF + reboot, including AL2023 matching | Contract/simulator and shared controller API-server tests; no OS compatibility proof | None recorded | Incomplete; deferred until Ubuntu evidence |
| GKE node-pool version upgrade | Contract/simulator and runner guardrail tests; API-server tests do not exercise GKE | None recorded | Incomplete; defer expansion until Ubuntu failure evidence |
| Self-managed offline package transfer/staging/install | Local artifact, digest, packaging, and policy contract tests | No disconnected-site or VM upgrade record | Incomplete; include in Ubuntu qualification |

Historical Kubernetes registration, validation, or drain drills do not establish
host package/reboot or provider upgrade qualification. No requirement is marked
complete by the preparation work below.

## Next milestone — one disposable Ubuntu LTS qualification

Scope: one stateless self-managed Ubuntu 24.04 LTS worker on a recorded
architecture and pinned Kubernetes/K3s release, with the fixed Debian Ansible EE
catalog. Record the exact image and versions; results apply only to that tested
combination. Do not add executors/providers or expand GKE. Prioritize a private
management plane and signed, pre-staged offline package artifacts. A connected
VM run alone cannot qualify air-gapped delivery.

Traceability: UPG-01–06, UPG-09–10, UPG-12, UPG-14, UPG-18–19,
UPG-24–25. This is a qualification plan, not acceptance evidence for these IDs.

### Entry checklist

- [ ] Identify a dedicated disposable cluster and worker, independent reviewer,
  lab owner, VM snapshot/reset procedure, serial-console access, and network
  fault controls. Keep management/control-plane nodes out of the target set.
- [ ] Record source commit plus the hash and retained patch/archive of any
  uncommitted inputs. The checkout currently includes untracked dependencies;
  review and capture them before building a qualification release. Record UTC
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
- [ ] Run the read-only preflight below, review its exact cluster/node/UID
  confirmation, and enable host execution only in this disposable lab. Leave
  repository defaults and provider execution gates disabled. Confirm a workload
  with a PDB can drain and recover and that the management plane survives the
  worker's loss.

### Exact case checklist and pending results

Start each independent case from the reviewed baseline with a new operation ID
and signed authorization; preserve the original operation and host journal
throughout a restart/recovery case. Do not reset the VM until evidence is saved.
`Runner` means the existing runner supports the case; `External` requires lab
fault injection and the recorder; `Manual supplement` has no dedicated case in
the current pinned matrix and must be recorded separately, without relabeling
it as another case. Every row is **NOT RUN** as of 2026-11-17.

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
| Cancellation before mutation | Manual supplement; signed cancel at durable pre-apply phase | No apply/reboot intent or package change; any acquired cordon/reservation released only after verified safe recovery | NOT RUN / none |
| Cancellation during recovery | Manual supplement; signed cancel after reboot return, before recovery completion | No premature uncordon/release; ready identity/packages/kernel/workloads required, otherwise intervention | NOT RUN / none |
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
read-only command below. Dedicated
process/cancellation supplemental cases require reviewed manual steps before
injection; current tooling does not automate or verify their coverage.

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

- [ ] Review every Ubuntu case and supplement against UPG-01–06, UPG-09–10,
  UPG-12, UPG-14, UPG-18–19, UPG-24–25; record unmet acceptance criteria.
- [ ] Use `<case-id>-debian.json` for the eleven existing matrix cases; retain
  supplemental reports separately. The pinned verifier requires **both** Debian
  and RHEL evidence. An Ubuntu-only run cannot produce a full verifier pass.
  Do not change the matrix/digest or fabricate RHEL records to bypass this.
  Record Ubuntu results as a scoped manual review; RHEL remains unqualified.
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

## Current product boundary

Kordex supports inventory, approval-driven campaigns, constrained stateless-worker drain/recovery, opt-in Debian/Ubuntu and RPM-family Ansible EE package/reboot catalogs (including Amazon Linux 2023 through DNF), and an opt-in GKE node-pool Kubernetes version upgrade. `UpgradeFleet` freezes a concrete host or provider action per target, allowing one campaign to contain Debian/RPM-family host and GKE node-pool targets while sharing stages, approvals, windows, and concurrency budgets. The local operator remains authoritative and fail-closed. Both upgrade paths are unqualified: use disposable VMs or a disposable GKE cluster only. The operator consumes read-only Rook/Ceph health and manager metrics for OSD `up/in`, flags, and PG recovery/degradation evidence, plus optional live mTLS etcd membership/status evidence for self-managed clusters. OSD-host maintenance, control-plane execution, provider-native EKS/AKS managed-node-group upgrades, and real Rook/Ceph/etcd/GKE/Amazon-Linux compatibility qualification remain incomplete.

Amazon Linux 2023 is admitted by the RPM-family inventory matcher and the live DNF playbook checks (`distribution=Amazon`, major version `2023`). It uses the common SSH/DNF path and has no AWS API dependency. Amazon Linux 2 and AL2027 Preview are rejected. EKS managed node-group lifecycle operations are still unimplemented, and AL2023 host-upgrade compatibility still needs disposable EKS/VM failure and recovery drills.

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

The current slice adds validated policy data to the shared protocol and `MaintenancePolicy` CRD, canonical policy digest binding in permits and campaign snapshots, and a durable operation checkpoint. The operator now has an opt-in execution path for fixed Debian and RHEL-family Ansible EE catalogs: read-only host identity and exact-package-resolution preflight, safe drain, exact package pins, a separate controlled reboot phase, receipt validation, and Kubernetes/workload recovery before uncordon. Package resolution uses the target's existing APT cache or DNF metadata in Ansible check mode before cordoning; it neither installs packages nor refreshes metadata. RHEL-family runs with `IfNeeded` or `Never` also require `dnf needs-restarting -r`: Kordex rejects a host that already needed a reboot during preflight, then checks again after package installation to detect update-triggered reboot requirements without enabling repositories. A missing or indeterminate DNF reboot detector fails closed. Kernel package plans must bind an exact `expectedKernelVersion`; the EE and operator verify the running kernel before reboot recovery can uncordon. Debian uses the kernel package set and `/var/run/reboot-required` marker when present. Each execution Job is deterministic, suspended until a local safety/authorization check passes, uses immutable request input, zero retries, a fixed catalog entrypoint, projected SSH key/known-hosts material, and a tokenless ServiceAccount. Verified phase receipts are now copied into immutable ConfigMaps in the retained `kordex-operations-ledger` namespace without a `NodeMaintenance` owner reference, so acknowledgement and deletion of the operation object do not garbage-collect its recovery evidence. Existing operation-owned receipts are read and migrated on access. This is cluster-local append-only evidence under the operator's get/create-only RBAC; it is not external immutable retention and does not protect against a cluster administrator deleting the ledger. An ambiguous mutating job first consumes a persisted completion receipt or runs a separate read-only inspection of exact packages and host identity; it never automatically retries package installation or reboot. Each inspection attempt pins an immutable snapshot of known-hosts data and includes a digest of the SSH credential input in its identity; the credential itself stays in the configured Secret. After host-key or SSH-authentication failure, changing either input permits a new read-only attempt with a distinct durable identity. After SSH transport failure, an administrator can set a fresh UUID in `operations.kordex.local/recovery-retry` after restoring connectivity; this permits exactly one new read-only attempt under a new immutable job identity. All inspection retries are capped at 100 attempts; they do not authorize package installation or reboot. Mismatched or missing inspection evidence keeps the node cordoned and reservation held. The execution gate defaults off. This path is not qualified for production: it has not passed disposable Debian/Ubuntu or RHEL-family VM upgrade, reboot, interruption, and recovery drills.

Every executable host-upgrade plan requires `UpgradePolicy.actionMarkerVersion: 1`; markerless legacy plans are rejected. The signed plan and EE image bind this version to the root-owned host journal at `/var/lib/kordex/operations/<operation-id>.json`. The journal records `apply-intent` before package mutation, `packages-verified` only after package, machine-ID, boot-ID, and kernel checks, `reboot-intent` before reboot, and `reboot-verified` only after the host returns and postconditions pass. The EE catalog embeds its marker version, so the operator rejects a policy/image mismatch. Receipts include the marker's file SHA-256 and operation, plan, node, machine, boot, phase, and sequence identities. Replays of package apply are rejected when a journal already exists. Ambiguous outcomes use read-only inspection; an incomplete journal never authorizes a retry or a successful recovery by itself. This protocol has not yet been qualified on disposable VMs.

Provider-native GKE plans require a canonical project/location/cluster/node-pool path and matching Kubernetes provider ID, cluster name, topology, and node-pool label in fresh inventory. Campaign planning deduplicates a pool to one target. An opt-in GKE v1 REST adapter now uses attached Google Workload Identity, etag-guarded node-pool updates, durable pool-scoped checkpoints, operation observation, and replacement-node/workload verification. The plan pins SURGE settings (`maxSurge=1`, `maxUnavailable=0`) and the operator blocks unless the existing pool settings match; these limits apply per zone for regional pools. It is not yet production-qualified; cloud-operation correlation after a lost update response uses exact target and start-time correlation because the GKE update request does not expose a Kordex operation ID or client idempotency key. Keep it restricted to a disposable GKE cluster and a dedicated workload identity until the failure drills are completed. EKS/AKS remain unavailable. The self-managed executor supports fixed Debian/Ubuntu and RHEL-family catalogs; each still requires separate OS-family qualification. Host mutation must remain disabled except in a disposable qualification lab until the VM evidence below is recorded. Read-only inspection can verify exact package and host state after ambiguous execution, but it does not roll back partial package changes or replay mutation. Cases without matching inspection evidence still require operator intervention.

## Delivery sequence

### Upgrade 0 — immutable action contract (implemented; qualification ongoing)

Define policy pins, supported OS/EE catalog combinations, immutable EE image/playbook/collection digests, bounded timeouts/retries, fixed hook identifiers, canonical digest, durable checkpoint phases, host identity, and receipt formats. Bind the digest into signed permits, immutable campaign target snapshots, and local CRD policy. Maintain an explicit unsupported-action response until a complete executor vertical slice is qualified.

Acceptance: policy inputs reject shell fragments, floating package versions, duplicate packages, unsupported manager/OS pairs, unrecognized hooks, and unbounded timeouts; same logical policy produces the same digest; illegal checkpoint transitions are rejected; no executor can run from a validation permit.

### Upgrade 1 — one self-managed Linux executor vertical slice (code path implemented; qualification incomplete)

The next milestone qualifies only the Ubuntu LTS catalog on real disposable VMs using the checklist above. Qualify a supported RHEL-family release separately afterward. The local Job adapter must recover ambiguous launches by operation and phase identity. Bind execution to the plan digest, node UID, machine-id, EE image digest, playbook digest, collections digest, and catalog ID. Enforce an operator-configured exact image-digest allowlist so policy authors cannot substitute another image that implements the same entrypoint. Keep SSH credentials in a fixed local Secret and never in campaign data or the dashboard. Do not accept arbitrary playbook text, role names, inventory, tags, extra-vars, or shell commands from users. Persist local/Kordex execution checkpoints and operation-owned markers. Policy schema v2 binds each offline package file digest; the executor verifies and installs only pre-staged artifacts without repository access. Offline archive generation and target staging tools are implemented and included in the generic release bundle. Operators must still transfer the policy and matching archive to the target site and stage it on the worker; qualify that workflow, package dependency closure, and recovery on disposable VMs before claiming a complete offline upgrade workflow. Require disposable VM failure drills before enabling package mutation in a deployment.

Acceptance: the executor proves the requested EE/playbook/collections digests and catalog ID match the signed policy; action is idempotent across process/runner/VM restart; duplicate, stale, wrong-host, wrong-policy, and altered-digest permits reject; package postcondition is verified; ambiguity remains reserved and blocked; no automatic retry repeats a partially applied operation without an explicit recovery policy. An offline package run must prove each installed artifact against its signed plan digest without contacting package repositories or public services, and the approved artifacts must have a repeatable signed transfer and staging workflow. Remaining evidence: run these checks on disposable Ubuntu LTS VMs and record them before enabling beyond a lab.

### Upgrade 2 — reboot and host recovery

Reboot is an explicit, separate action after package postconditions. Persist pre-reboot boot ID, machine-id, node UID, package receipt, marker sequence, and expected kernel before issuing reboot. On reconnect, require machine-id and node identity continuity; require boot-ID change only if reboot was requested; verify kernel/package versions and kubelet/Node readiness. A command success or node return alone never means success.

Acceptance: exercise reboot-not-issued, reboot-never-returns, network loss before/after reboot, machine replacement, wrong kernel, partial package state, operator/agent restart, and cancellation during each phase on disposable VMs. Every case ends succeeded, safely recovered, or explicitly intervention-required; reservation stays held otherwise.

### Upgrade 3 — provider-native node lifecycle paths

Add optional GKE, EKS, and AKS adapters as separate control-plane integrations. First support read-only discovery and preflight, then operation-owned provider requests. GKE COS uses provider node-image/node-pool lifecycle, not package commands inside COS. Cloud credentials use workload identity and narrowly scoped provider roles. Kubernetes-side drain, local safety veto, approval, campaign gates, and audit remain common.

Acceptance: each supported provider/version has a documented capability matrix and failure-injection record; provider operations are idempotent and correlated to Kordex operation IDs; out-of-band changes and provider timeouts become ambiguous/recovery states, never blind retries.

### Upgrade 4 — live storage/quorum safety

The read-only Rook/Ceph adapter is wired into local preflight, but its metric contract is not qualified against supported releases. A live etcd membership source is available when configured, but this is not permission to operate on control-plane nodes: static/mirror pod draining and topology-specific recovery are still unsupported. Next add storage enter/exit lifecycle with ownership tokens and verified recovery. Detect control-plane/provider-managed nodes explicitly; unknown topology blocks. Provider-managed control planes require provider-specific quorum semantics rather than inferred etcd membership.

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

The GKE cluster currently used for the pilot is not a host package-upgrade target: its nodes run Container-Optimized OS. Use it for provider-native lifecycle preflight and Kubernetes drain/recovery qualification. Use disposable Ubuntu VMs for APT and a separate RHEL-family VM for DNF qualification and real reboot testing. The opt-in Ansible path requires routed SSH from the operator namespace to the node, a dedicated SSH user with narrowly scoped passwordless sudo for the fixed playbook, a private key in a Kubernetes Secret, and pinned host keys in a ConfigMap. Never point it at the current GKE COS nodes.

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

Run preflight first; the default is read-only:

```sh
export KORDEX_API=https://kordex.example.internal
export KORDEX_ADMIN_TOKEN='USE_A_SHORT_LIVED_OPERATOR_TOKEN'
export KORDEX_ORG_ID='ORGANIZATION_UUID'
export KORDEX_CLUSTER_ID='REGISTERED_CLUSTER_UUID'
export KORDEX_NODE_NAME='disposable-worker-01'
export KORDEX_HOST_POLICY='ubuntu-disposable-upgrade'
export KORDEX_HOST_PLAN_DIGEST='64_CHARACTER_POLICY_DIGEST'
export KORDEX_EXPECTED_CONTEXT='disposable-self-managed-context'
python3 tests/integration/self_managed_upgrade_smoke.py \
  --evidence ./qualification/preflight.json
```

For an offline bundle, replace the script path with
`./qualification/self_managed_upgrade_smoke.py`. Create the evidence directory on a
separate writable lab volume; do not modify the signed release bundle. The
qualification host needs Python 3 and network access only to the configured
Kordex management endpoint and the disposable cluster's Kubernetes API. It
does not need Google, AWS, Azure, or public registry access.

Only after the disposable cluster, VM snapshot, recovery access, package
repository snapshot, and policy have been reviewed, execute one operation.
The runner refuses execution unless the explicit confirmation exactly matches
the registered cluster UUID, node name, and current node UID printed in the
preflight evidence:

```sh
export KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM='CLUSTER_UUID/NODE_NAME/NODE_UID'
python3 tests/integration/self_managed_upgrade_smoke.py --execute \
  --timeout-seconds 14400 --evidence ./qualification/clean-upgrade-debian.json
```

Use `./qualification/self_managed_upgrade_smoke.py` in these commands when running
from the offline bundle. Set `KORDEX_HOST_POLICY` and `KORDEX_HOST_PLAN_DIGEST`
to the local policy for the matching OS family; the runner rejects a mismatch.

The same runner supports one signed cancellation injection after package
execution starts or when rebooting begins. Use a fresh disposable VM and
campaign permit for each run:

```sh
python3 tests/integration/self_managed_upgrade_smoke.py --execute \
  --cancel-on-phase Rebooting --timeout-seconds 14400 \
  --evidence ./qualification/cancel-during-reboot-debian.json
```

For the current milestone, execute each case only with the Ubuntu policy and use the `-debian` evidence suffix. In a later, separate RHEL qualification, repeat with the matching policy/digest and `-rhel` suffix; do not reuse operation IDs or VM state. The full matrix verifier still requires both records for every case, so an Ubuntu-only milestone remains a scoped evidence review rather than a full verifier pass.

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
