# Failure and recovery model

The rule is fail closed for new disruptive work and preserve enough state to recover existing work. Transport acknowledgement, SSH exit status and reboot completion are never proof of maintenance success.

## kured custody intervention

Use an authorized cluster administrator and an independent reviewer. Record the
incident/change ID, actor and UTC interval in the retained evidence archive, and
retain Kubernetes audit events for any coordination patch. First capture the
NodeMaintenance JSON (including its persisted kured reference), original Node
UID/cordon owner, local reservation, kured DaemonSet UID/spec/annotation, EE Jobs,
immutable receipts and host journal. Use fixed read-only inspection to establish
host/package/boot state; never replay package apply or reboot to diagnose it.

Restore connectivity or the exact reviewed configuration first. A missing lock
after committed acquisition is not automatically reacquired. If ownership was
removed accidentally, restore only the exact saved `manual:kordex:<operation-UID>`
value on the original DaemonSet, after verifying that no independent kured reboot
or other maintenance owner is active. Use a JSON Patch with tests for the
DaemonSet UID, current resourceVersion and observed annotation state; a conflict
requires fresh investigation. Never overwrite a foreign lock or adopt a new
DaemonSet UID, and never remove the local reservation/finalizer or cordon to
bypass a blocked operation. The operator still validates its pinned spec and
signed authorization before any disruptive continuation.

A replacement/deleted DaemonSet during an active operation cannot be made the
original object by editing a reference. Keep the node fenced and escalate for
explicitly reviewed host recovery; automatic adoption is unsupported. If the
operation already reached verified terminal recovery and the DaemonSet is absent,
normal cleanup releases its local reservation and retains the finalizer if that
write fails. Close the incident only after independent reads establish workload
recovery, owned-cordon removal and reservation release. These instructions are
an intervention procedure, not evidence of a completed kured failure drill.

For fixed-catalog Debian and RHEL package upgrades, an exact package receipt that reports a reboot is still required is not sufficient to release the node. If cancellation withdraws the reboot or an ambiguous package apply is inspected before reboot, Kordex keeps the operation in `RecoveryRequired`, retains the operation-owned cordon and capacity reservation, and reports an operator-intervention reason. An interrupted reboot is recoverable only when read-only host inspection confirms the same machine and a changed boot ID. A returning SSH connection or successful Job alone does not prove reboot completion.

| Failure | Required behavior | Current implementation |
| --- | --- | --- |
| PostgreSQL unavailable | Refuse writes; readiness unhealthy; never fall back to memory | Startup fails; requests return 503; readiness 503 |
| API restart | Recover from database; no implicit execution | Organizations/sites/audits persist; graceful HTTP shutdown |
| Concurrent migrations | Serialize, transact, reject changed history | Advisory lock, checksum, transactional DDL |
| Unknown commit outcome | Inspect existing resource; do not assume failure implies no write | Unique names return conflict; clients list and verify |
| Agent disconnected | Stop starting cordon/drain/action; report stale health | Signed outbound inventory retries; connectivity and capability evidence are stale after their bounded freshness windows |
| Disconnect during disruption | Follow bounded preauthorized local recovery only; block new actions | Implemented for stateless drain/recovery; see maintenance-operator.md |
| Agent restart | Recover durable inbox and status; reject stale/duplicate command identities | Durable key/version state, pending rotation recovery and Kubernetes-backed operation inbox implemented |
| Operator restart | Reconcile intent/checkpoints with observed node/host/provider state before continuing | Implemented for stateless drain and opt-in Debian/GKE paths; executor paths remain unqualified |
| Failed/PDB-blocked drain | Stop before host changes; report blocker; no force deletion | Implemented for stateless drain/recovery; see maintenance-operator.md |
| Package update failure | Mark outcome ambiguous, cancel the deterministic EE Job, keep the operation reservation and owned cordon, inspect exact package and host identity read-only, and never retry mutation automatically | Opt-in Debian and RHEL EE catalogs implement the read-only recovery inspection and retains the cordon if evidence is unavailable or inconsistent; disposable VM qualification remains |
| Reboot failure/ambiguous ack | Keep reservation/cordon; inspect exact packages and current boot identity, then require Kubernetes/workload verification before recovery; never replay reboot blindly | Opt-in path persists immutable phase receipts and read-only inspection evidence; real reboot drills remain |
| Node does not return | Keep unavailable reservation, alert, RecoveryRequired | Real-VM gate |
| Storage degradation | Block new disruption; restore only operation-owned maintenance flags after recovery | Read-only Rook/Ceph evidence is wired to preflight; storage maintenance mutation and OSD-host execution remain blocked |
| Control-plane/quorum degradation | Block disruption and stage advancement; require live quorum evidence | Optional read-only etcd mTLS evidence is wired for self-managed topologies; control-plane maintenance remains unsupported |
| Workload recovery fails | Keep node out of service until recovery decision; do not declare success | Implemented for stateless drain/recovery; see maintenance-operator.md |
| Lease expires while disrupted | Fence old scheduler; reconcile actual target state before releasing capacity | Local and hub reservations retain offered work until verified terminal status; Phase 4 scheduler ownership is transaction-scoped |

Each future phase transition must include old/new phase, operation/attempt ID, generation, actor, UTC timestamp, reason, evidence freshness and policy version. Persist durable status before side effects. Delivery retries use bounded exponential backoff with jitter; safety blocks require new evidence, not blind retry. Stale commands are audited and rejected. A node UID replacement invalidates pending authorization even if its name matches.

Cancellation and pause revoke permission to start new mutating actions. They cannot undo an in-flight reboot. On cancellation, the local operator first checks for an already persisted, verified execution receipt. If the package phase completed and a reboot is required, the operator records that reboot as deferred, starts no later action, and keeps the node cordoned in `RecoveryRequired` for operator intervention. If no receipt exists, the operator starts a fixed read-only EE inspection after durably recording its reference. It verifies the exact signed package versions, machine identity, and boot identity; it cannot install packages or reboot. If that evidence shows reboot is still required, or an interrupted reboot did not change the boot ID, the operation stays reserved and cordoned for intervention. Reboot cancellation accepts a changed boot ID only as observed evidence, never as proof of a successful Kordex reboot by itself. Every path that can recover proceeds through local Kubernetes/workload checks, and VM failure-injection qualification remains open.

If an inspection is blocked specifically by `UpgradeRecoverySSHTransportUnavailable`, restore the approved SSH network path first. An administrator may then authorize one new **read-only inspection attempt** by setting a fresh UUID token on the `NodeMaintenance` object:

```sh
kubectl annotate nodemaintenance -n kordex-system op-<operation-uuid> \
  operations.kordex.local/recovery-retry=$(uuidgen) --overwrite
```

The token is recorded in the durable upgrade checkpoint and the attempt number gives the inspection Job a new immutable identity, even when SSH credentials and known-hosts data did not change. Reusing the same token does not cause another retry. This annotation cannot authorize package installation or reboot. The operation remains cordoned and reserved until the inspection and subsequent local recovery checks succeed.

Phase 1 has forward-only migrations and no automatic schema rollback. Back up PostgreSQL before upgrades, restore into a fresh instance, apply/validate schema, run readiness checks and verify audit continuity. Backup automation, point-in-time recovery, RPO/RTO and restoration drills remain hardening work. Do not downgrade a binary against an unknown schema. Retention, incident escalation and notification channels are unresolved operational policies.

Release 0.3.0 details are in [maintenance operator](maintenance-operator.md): signed short-lived permits, a durable CRD inbox, non-expiring reservation/receipt ledger, per-boundary freshness/ownership checks, restart-safe intent and terminal status retained until hub acknowledgement. Storage/control-plane/host integrations remain disabled.

## Phase 4 scheduler and campaign recovery

Scheduler transactions have no external effects before commit; process loss rolls back admissions and another replica continues from durable rows. Management/database outages stop new permits. User pause stops future admission; outstanding permits may finish within their authorization. Cancel persists a signed withdrawal and retains capacity until the local operator reports terminal verified recovery. Failed or blocked campaigns cannot advance through violated safety gates. Retries create fresh IDs only after terminal recovery; retained event history cannot be rewritten. See [campaigns](campaigns.md) for exact failure thresholds, safety resume acknowledgment and window expiry.
For fixed-catalog Debian and RHEL package upgrades, an exact package receipt that reports a reboot is still required is not sufficient to release the node. If cancellation withdraws the reboot or an ambiguous apply is inspected before reboot, Kordex keeps the operation in `RecoveryRequired`, retains the operation-owned cordon and capacity reservation, and reports `UpgradeRebootRequiresOperatorIntervention`. An interrupted reboot is recoverable only when read-only host inspection confirms the same machine and a changed boot ID. A returning SSH connection or successful Job alone does not prove reboot completion.
