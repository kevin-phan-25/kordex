# Failure and recovery model

The rule is fail closed for new disruptive work and preserve enough state to recover existing work. Transport acknowledgement, SSH exit status and reboot completion are never proof of maintenance success.

| Failure | Required behavior | Phase 1 implementation |
| --- | --- | --- |
| PostgreSQL unavailable | Refuse writes; readiness unhealthy; never fall back to memory | Startup fails; requests return 503; readiness 503 |
| API restart | Recover from database; no implicit execution | Organizations/sites/audits persist; graceful HTTP shutdown |
| Concurrent migrations | Serialize, transact, reject changed history | Advisory lock, checksum, transactional DDL |
| Unknown commit outcome | Inspect existing resource; do not assume failure implies no write | Unique names return conflict; clients list and verify |
| Agent disconnected | Stop starting cordon/drain/action; report stale health | Protocol not implemented |
| Disconnect during disruption | Follow bounded preauthorized local recovery only; block new actions | Future operator gate |
| Agent restart | Recover durable inbox and status; reject stale/duplicate command identities | Future agent gate |
| Operator restart | Reconcile intent/checkpoints with observed node/host state before continuing | Future operator gate |
| Failed/PDB-blocked drain | Stop before host changes; report blocker; no force deletion | Future operator gate |
| Package update failure | Record action evidence; stop campaign threshold advancement; require inspected recovery | Future executor gate |
| Reboot failure/ambiguous ack | Observe boot ID and executor ledger; never blindly replay reboot | Real-VM gate |
| Node does not return | Keep unavailable reservation, alert, RecoveryRequired | Real-VM gate |
| Storage degradation | Block new disruption; restore only operation-owned maintenance flags after recovery | Integration gate |
| Control-plane/quorum degradation | Block disruption and stage advancement; require live quorum evidence | Integration gate |
| Workload recovery fails | Keep node out of service until recovery decision; do not declare success | Future operator gate |
| Lease expires while disrupted | Fence old scheduler; reconcile actual target state before releasing capacity | Scheduler gate |

Each future phase transition must include old/new phase, operation/attempt ID, generation, actor, UTC timestamp, reason, evidence freshness and policy version. Persist durable status before side effects. Delivery retries use bounded exponential backoff with jitter; safety blocks require new evidence, not blind retry. Stale commands are audited and rejected. A node UID replacement invalidates pending authorization even if its name matches.

Cancellation and pause revoke permission to start new actions. They cannot undo an in-flight reboot. A narrow preauthorized recovery plan may finish verification and restore an operator-owned cordon without network access; no new package action or reboot may start offline. Approval expiry semantics must explicitly include this distinction before implementation.

Phase 1 has forward-only migrations and no automatic schema rollback. Back up PostgreSQL before upgrades, restore into a fresh instance, apply/validate schema, run readiness checks and verify audit continuity. Backup automation, point-in-time recovery, RPO/RTO and restoration drills remain hardening work. Do not downgrade a binary against an unknown schema. Retention, incident escalation and notification channels are unresolved operational policies.
