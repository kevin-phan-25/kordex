# Production upgrade requirements and delivery plan

This document tracks the production bar requested for Kordex as an infrastructure upgrade platform. A requirement is complete only when its code, failure behavior, audit evidence, and deployment evidence meet the acceptance criteria below. A Go interface or simulator alone does not count as an integration.

## Current product boundary

Kordex currently supports inventory, approval-driven validation, and constrained stateless-worker drain/recovery. It has no package, kernel, reboot, or provider node-upgrade executor. The local operator remains authoritative and fail-closed. No live upgrade action is enabled by the work tracked here.

The current slice adds validated policy data to the shared protocol and `MaintenancePolicy` CRD, canonical policy digest binding in permits and campaign snapshots, and a durable operation checkpoint. It also adds a cluster-local Kubernetes Job adapter and a fixed Debian-family Ansible EE artifact with read-only preflight, exact package pins, optional controlled reboot, and structured receipts. The Job uses a pinned image, immutable operation input, a deterministic name, zero retries, fixed catalog entrypoint, projected SSH key/known-hosts material, and a tokenless ServiceAccount. Failed or cancelled Jobs are ambiguous and require recovery.

The adapter and EE are not wired into `NodeMaintenance` reconciliation. Upgrade permits still receive `UpgradeExecutorUnavailable` before reservation or node changes. The current code has no qualified machine-identity preflight, package/reboot orchestration in the controller, full recovery integration, or disposable-VM evidence. Do not enable upgrades.

## Delivery sequence

### Upgrade 0 — immutable action contract (in progress)

Define policy pins, supported OS/EE catalog combinations, immutable EE image/playbook/collection digests, bounded timeouts/retries, fixed hook identifiers, canonical digest, durable checkpoint phases, host identity, and receipt formats. Bind the digest into signed permits, immutable campaign target snapshots, and local CRD policy. Maintain an explicit unsupported-action response until a complete executor vertical slice is qualified.

Acceptance: policy inputs reject shell fragments, floating package versions, duplicate packages, unsupported manager/OS pairs, unrecognized hooks, and unbounded timeouts; same logical policy produces the same digest; illegal checkpoint transitions are rejected; no executor can run from a validation permit.

### Upgrade 1 — one self-managed Linux executor vertical slice

Qualify the initial Debian-family catalog on real disposable VMs (Ubuntu LTS first). The local Job adapter must recover ambiguous launches by operation and phase identity. Bind execution to the plan digest, node UID, machine-id, EE image digest, playbook digest, collections digest, and catalog ID. Keep SSH credentials in a fixed local Secret and never in campaign data or the dashboard. Do not accept arbitrary playbook text, role names, inventory, tags, extra-vars, or shell commands from users. Persist local/Kordex execution checkpoints and operation-owned markers. Require disposable VM failure drills before wiring package mutation into reconciliation.

Acceptance: the executor proves the requested EE/playbook/collections digests and catalog ID match the signed policy; action is idempotent across process/runner/VM restart; duplicate, stale, wrong-host, wrong-policy, and altered-digest permits reject; package postcondition is verified; ambiguity remains reserved and blocked; no automatic retry repeats a partially applied operation without an explicit recovery policy.

### Upgrade 2 — reboot and host recovery

Reboot is an explicit, separate action after package postconditions. Persist pre-reboot boot ID, machine-id, node UID, package receipt, marker sequence, and expected kernel before issuing reboot. On reconnect, require machine-id and node identity continuity; require boot-ID change only if reboot was requested; verify kernel/package versions and kubelet/Node readiness. A command success or node return alone never means success.

Acceptance: exercise reboot-not-issued, reboot-never-returns, network loss before/after reboot, machine replacement, wrong kernel, partial package state, operator/agent restart, and cancellation during each phase on disposable VMs. Every case ends succeeded, safely recovered, or explicitly intervention-required; reservation stays held otherwise.

### Upgrade 3 — provider-native node lifecycle paths

Add optional GKE, EKS, and AKS adapters as separate control-plane integrations. First support read-only discovery and preflight, then operation-owned provider requests. GKE COS uses provider node-image/node-pool lifecycle, not package commands inside COS. Cloud credentials use workload identity and narrowly scoped provider roles. Kubernetes-side drain, local safety veto, approval, campaign gates, and audit remain common.

Acceptance: each supported provider/version has a documented capability matrix and failure-injection record; provider operations are idempotent and correlated to Kordex operation IDs; out-of-band changes and provider timeouts become ambiguous/recovery states, never blind retries.

### Upgrade 4 — live storage/quorum safety

Implement read-only Ceph/Rook/etcd evidence adapters first. Then add storage enter/exit lifecycle with ownership tokens and verified recovery. Detect control-plane/provider-managed nodes explicitly; unknown topology blocks. Provider-managed control planes require provider-specific quorum semantics rather than inferred etcd membership.

Acceptance: stale, absent, contradictory, degraded, and ownership-changed evidence blocks; noout/maintenance flags are removed only when Kordex owns them; recovery after operator loss is observable and safe.

### Upgrade 5 — campaign and dashboard upgrade workflows

Bind campaign snapshot and each approval to exact action digest, target identity, policy generation, stage, and provider/host plan. Reuse canary/small/expanded/remaining gates; do not auto-advance on threshold breach. Add catalog discovery, organization switching, simulation with per-node block explanations, approvals, cancellation semantics during reboot, drift inventory, and evidence freshness.

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

## Compatibility and release rules

Signed action payloads, campaign snapshots, CRD fields, and local journals require explicit schema versions. Adding a new action must not make existing `ValidateOnly` or `DrainAndVerify` permits mean something different. Control plane and operator must reject an unknown action until both advertise support. A migration or conversion strategy is required before changing a released persisted format.

The GKE cluster currently used for the pilot is not a host package-upgrade target: its nodes run Container-Optimized OS. Use it for provider-native lifecycle preflight and Kubernetes drain/recovery qualification. Use disposable Ubuntu VMs for the first APT executor and real reboot testing.
