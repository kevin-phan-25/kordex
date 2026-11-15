# ADR 0007: Database-serialized campaign admission and signed withdrawal

Status: accepted for 0.4.0.

Use a separate continuous Go scheduler sharing PostgreSQL with the stateless REST API. Claim organization and campaign rows using short FOR UPDATE SKIP LOCKED transactions. Insert signed permits, capacity reservations and target attempts atomically. Persist a monotonically increasing organization scheduler epoch in audit events; never rely on process memory or an expiring external-work lease. Organization locking also covers manual admission and policy/control mutations. No Pub/Sub dependency is needed while the durable outbound agent inbox already provides retryable delivery.

Snapshot targets and local policy identities at start, before independent approval. Bind approvals to plan generation, digest, stage and epoch; reject approval from any plan participant. Recheck target identity/topology/selector evidence before each admission. Four explicit stages and absolute time-zone-validated windows provide predictable first-release behavior without a cron engine.

Pause stops new permits. Cancellation is an exact-command signed withdrawal, delivered durably to the local operator, followed by verified recovery. Offered work never releases reservations merely because time passed. This favors retained capacity and visible intervention over overlapping disruption after network ambiguity. Existing local safety remains authoritative.

Tradeoffs: admission throughput within an organization is serialized; the current operator limits cluster/node concurrency to one. Transactions create at most 16 operations per tick and examine at most 128 rotating candidates. Increasing throughput requires measurement, not replacing safety locks speculatively. Database outage stops new work. Historical audit/receipt growth and production database HA/backup drills remain hardening work. OS rollback is excluded because there is no OS executor.
