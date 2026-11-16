# Production upgrade requirements

This is the user's prioritized direction for building Kordex into a trusted node
upgrade platform. These requirements extend the numbered implementation phases;
they are not a claim of current support. Existing foundations include campaigns,
signed permits, the local safety veto, durable delivery, drain/recovery, and the
dashboard. New capabilities must preserve those guarantees.

All items below remain acceptance gates until linked implementation and relevant
verification evidence establish completion. Some have partial implementation;
track that explicitly instead of assuming they are absent or complete. Real
cluster and VM evidence is required for physical lifecycle claims; kind,
synthetic reports, interfaces, and unit tests alone do not establish those claims.

## Tier 1: actual upgrades, highest priority

- [ ] **T1.1 — Real node lifecycle executor.** Support policy-authorized package,
  OS, and kernel updates plus controlled reboot on explicitly supported platforms.
  Verify boot ID and operation-owned action markers after reboot. Distinguish
  success, failure, and ambiguous outcomes. Unknown evidence blocks new disruption;
  never blindly replay an ambiguous update or reboot.
- [ ] **T1.2 — Durable execution phases.** Implement Executing → Rebooting →
  VerifyingNode → VerifyingWorkloads → Uncordoning. Persist intent before each
  side effect and evidence after it. Restart every component at each boundary in
  tests; returning from reboot alone must never establish success.
- [ ] **T1.3 — Policy-driven upgrade parameters.** Define allowed packages,
  versions/channels, reboot requirements, and action-specific timeouts/retries.
  Any pre/post hooks must be strictly allow-listed, narrowly authorized actions,
  never arbitrary shell commands supplied by a campaign.
- [ ] **T1.4 — Live storage and quorum safety.** Acquire actual Ceph/Rook or
  equivalent evidence; enter, observe, recover, and exit maintenance with explicit
  ownership. Acquire live etcd/control-plane quorum evidence and block unsafe
  disruption. Recognize storage and control-plane nodes and require their special
  handling. Pure evaluators are insufficient.
- [ ] **T1.5 — Upgrade campaigns.** Drive new actions through Canary → SmallBatch
  → Expanded → Remaining with independent approvals, failure gates, and shared
  reservations. Define and test signed withdrawal during execution and reboot:
  cancellation must remain durable, stop future interruptible disruption, and
  recover safely without promising to undo an irreversible action already started.

## Tier 2: production safety and correctness

- [ ] **T2.1 — Durable immutable action ledger.** Retain action identities,
  receipts, checkpoints, and outcomes across operator restarts and node replacement.
  Define the authoritative store and its failure/recovery model; node-local files
  alone cannot satisfy replacement durability.
- [ ] **T2.2 — Strong node identity.** Combine immutable infrastructure/node
  identity, boot ID, machine ID or equivalent, and operation-owned markers.
  Distinguish reboot from replacement; identity disagreement blocks action.
- [ ] **T2.3 — Long-running reservations.** Keep capacity reserved throughout
  updates, reboot, disconnection, and ambiguous recovery until verified terminal
  recovery. Timeouts alone cannot free uncertain capacity.
- [ ] **T2.4 — Explicit recovery matrix.** Implement and drill recovery for a
  missing reboot return, partially applied packages, wrong kernel/unexpected state,
  and network partition during Executing/Rebooting. Specify automatic versus
  operator-assisted recovery and retained reservations for each outcome.
- [ ] **T2.5 — Policy discovery/catalog.** Expose authorized local policies and
  their immutable identities/generations to the dashboard. Campaign authors must
  not need to copy CRD names, UIDs, and generations manually.
- [ ] **T2.6 — Separation of duties.** Preserve tenant authorization and denial
  of plan-participant self-approval for every new action and recovery control.

## Tier 3: operator experience

- [ ] **T3.1 — Dashboard-led upgrades.** Create and manage supported upgrade
  campaigns without kubectl; provide usable approval queues and correct
  pause/cancel/resume semantics.
- [ ] **T3.2 — Explain progress.** Show each node's phase, evidence age, blocking
  reason, and available recovery action. Stale evidence must never appear healthy.
- [ ] **T3.3 — Inventory and drift.** Show observed OS, kernel, and relevant
  package versions against desired policy, including evidence freshness.
- [ ] **T3.4 — Preflight preview.** Show the exact proposed target set, selection
  reasons, and blocked nodes/reasons without side effects. Revalidate at admission;
  a preview is not permission or a guarantee of future safety.
- [ ] **T3.5 — Organization/fleet navigation.** Support multi-organization
  switching and useful multi-fleet views while preserving tenant boundaries.

## Tier 4: observability and enterprise operations

- [ ] **T4.1 — Operational metrics and alerts.** Cover campaign progress,
  blockers, phase latency, evidence freshness, and reservation pressure. Validate
  that an operator can answer “why is this node not progressing?” within 10 seconds.
- [ ] **T4.2 — Useful audit.** Correlate requester/approver, exact authorized
  command, policy, safety evidence, action receipts, and verified outcome.
- [ ] **T4.3 — Drilled recovery/HA.** Exercise control-plane backup/restore,
  database failover, and component failures; retain measured recovery evidence.
- [ ] **T4.4 — Release/distribution trust.** Supply signed releases, SBOMs, and
  an exercised air-gapped installation and upgrade path.
- [ ] **T4.5 — Least privilege.** Keep executor permissions action-specific;
  introduce no general-purpose remote shell. Review the expanded privilege boundary.
- [ ] **T4.6 — Fleet protection.** Validate rate limits, global concurrency
  controls, and circuit breakers under representative fleet load and outages.

## Tier 5: differentiators

- [ ] **T5.1 — Topology-aware canaries.** Automatically cover relevant failure
  domains, racks, and zones with auditable target selection.
- [ ] **T5.2 — Provider-native upgrades.** Add optional GKE node-pool, EKS, and
  AKS paths under the same approval, safety, reservation, and recovery guarantees.
  Use an explicitly supported execution model for managed nodes; host package
  execution and provider-managed replacement are distinct lifecycle paths.
- [ ] **T5.3 — Workload awareness.** Account for PDBs, disruption budgets,
  critical services, scheduling capacity, and workload-specific recovery needs.
- [ ] **T5.4 — Verification packs.** Require approved post-upgrade health checks
  to pass before uncordon, with bounded execution and auditable evidence.
- [ ] **T5.5 — Blast-radius preview.** Visualize affected nodes, workloads,
  topology, and concurrent disruption before campaign start.

## Development order and acceptance evidence

The requested initial planning horizon is 4–8 weeks, subject to platform scope
and real test results; this is a priority order, not a delivery commitment.

1. Design and implement the narrow package/reboot executor and policy model
   (T1.1–T1.3), with ledger, identity, and recovery requirements (T2.1–T2.4)
   designed into it from the start. Select and document supported OS/provider
   combinations before enabling actions.
2. Make campaigns drive those actions (T1.5), retaining separation of duties
   and reservations (T2.3, T2.6). Exercise ambiguous delivery and cancellation
   at every execution/reboot boundary.
3. Wire basic live storage/quorum gates and owned maintenance lifecycle
   (T1.4). Unsupported topologies remain blocked.
4. Deliver policy discovery/catalog (T2.5), then expand the dashboard workflow
   (Tier 3) around the verified backend contract.
5. Continue operational qualification (Tier 4) throughout implementation, then
   prioritize differentiators (Tier 5) using pilot evidence.

For each milestone, record requirement IDs, supported environments, implementation
links, automated checks, real infrastructure drills, and remaining gaps. A real
upgrade acceptance drill must verify the intended version/kernel, boot identity,
action receipt, workload health, owned uncordon, durable hub outcome, and correct
reservation release. Include restart, partition, partial failure, and cancellation
cases. Successful inventory synchronization or draining alone does not satisfy it.
