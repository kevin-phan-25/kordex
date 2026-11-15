# Campaign orchestration (API 0.4.0)

The management plane owns campaigns. The outbound agent delivers immutable signed NodeMaintenance commands into the local durable inbox; the operator retains the independent safety veto. The local MaintenanceCampaign CRD reports HubOrchestrationRequired and does not create a second scheduling authority.

Only ValidateOnly and DrainAndVerify are supported. These are validation and stateless-worker drain/recovery drills. No package, kernel, SSH, reboot, storage-node or control-plane executor is introduced. RecoveryAction is explicitly LocalVerifiedRecovery: stop disruption, verify the original node and workloads, and undo only the operation's own cordon. An OS rollback cannot be promised without an OS executor and verified rollback integration.

## Campaign contract

POST `/v1/organizations/{org}/campaigns` accepts a caller-generated UUID `id` and `spec`. Repeating the same ID and normalized spec returns the existing campaign; another spec conflicts. PUT the campaign with its `revision` and replacement `spec` while Draft. Every mutation increments the revision and writes campaign history and organization audit records in the same transaction.

A spec contains:

- `name`, `action`, and `selection`: clusterIds, fleetIds and siteIds are intersected; empty scope lists mean the whole organization. nodeSelector uses Kubernetes selector syntax. Control-plane nodes are excluded. Explicit `canaries` identify clusterId/nodeUid pairs within the selection.
- `policies`: a clusterId and immutable local policy name/UID/generation for every selected cluster. The local operator checks the policy again immediately before disruptive boundaries.
- `windows`: one to 64 nonoverlapping explicit start/end RFC3339 instants, each with an IANA timeZone. Each window lasts one minute to 24 hours. Supplied UTC offsets must match the IANA zone at both endpoints; callers must distinguish repeated DST times. Recurring cron rules are intentionally deferred. Start is inclusive, end exclusive. minimumWindowSeconds defaults to 60 (30–900).
- `stages`: exactly Canary, SmallBatch, Expanded, Remaining, in that order. Count is the number of targets assigned to that stage; Remaining count must be zero and means every target left. Defaults are 1, 5, 20, remainder; batch sizes 1, 2, 5, 10. Stages beyond a small snapshot's size are skipped. Selection is deterministic and interleaves sites and clusters; explicit canaries come first.
- `limits`: organization, fleet, site, cluster, node, maxUnavailablePerSite. Defaults are all one. Cluster and node remain fixed at one because the Phase 3 operator holds one cluster-wide local maintenance slot. Other limits support 1–1000. A campaign's limits can further restrict the organization's administrative concurrency policy, never enlarge it.
- `approvalMode`: AllStages (default), BeforeStart, or None. None is accepted only for ValidateOnly.
- `retry`: maxRetries 0–5 (default zero), backoffSeconds 1–3600 (default 30), and allowlisted reasons. Only terminal, locally recovered attempts can retry. Default reasons are AuthorizationExpired and AuthorizationExpiredBeforeDelivery. Explicitly supported transient reasons also include APIServerHealthUnknown, NodeHeartbeatStale, ManagementDisconnected, PDBBlocked, EvictionPDBBlocked and WorkloadRecoveryPending. Each retry gets a new operation ID with the same campaign target identity and an incrementing attempt number. Backoff is exponential, capped at an hour plus deterministic jitter up to 20%.
- `failure`: maxFailedAttempts, maxFailurePercent, minimumSamples and maxConsecutiveFailures. A threshold is breached when failures exceed the configured count/percentage; consecutive zero disables that particular limit. Percentage evaluation begins at minimumSamples (default one). Default count and percentage zero stop on the first failure. Hard safety failures always pause regardless of numeric tolerance. Blocked or RecoveryRequired active operations also pause admission immediately when observed by the scheduler.

Start uses POST `/{id}/start` with `revision`. It snapshots up to 10,000 ready worker nodes, ordered target stages, node identities, topology and policy bindings, hashes the snapshot and persists it. Inventory scans are bounded to 20,000 nodes; select narrower scopes above that. Snapshot creation never silently drops unhealthy matched nodes or incomplete selector evidence. The inventory collector rejects oversized label sets instead of truncating them (64 labels/4096 bytes per node). Legacy agents' missing label sets cannot satisfy nonempty selectors. Nodes added later are outside the approved snapshot. Changed identity, topology or selector membership pauses admission; create a new campaign to change the immutable plan.

GET campaign, campaigns, targets, events and approvals exposes durable progress. Collection endpoints accept limit 1–500 and offset 0–100000, including approvals. Targets include every attempt count and outcome; operation history remains under each cluster's operations endpoint. List progress is aggregated in bounded database queries, without querying each node separately.

## Roles and approvals

All reads require organization membership. Viewer reads only. Operator creates, edits and starts campaigns, pauses/resumes user pauses, cancels and requests manual node operations. Approver approves/rejects and acknowledges safety resumes. Administrator also manages memberships, inventory enrollment and the organization concurrency policy. Roles are stored in PostgreSQL and OIDC signature/issuer/audience checks remain mandatory for production access.

POST `/{id}/approve` or `/reject` with `revision`. Approval binds the snapshot digest, plan generation, stage and approval epoch. A participant who created, edited or started the plan cannot approve it, including an administrator. A global local-development bootstrap actor cannot provide two independent identities; use OIDC for disruptive campaigns. It is possible to exercise ValidateOnly with None in an isolated lab.

Approval rejection ends the campaign without executing the rejected stage. Later stages cannot start until earlier stage targets have terminal outcomes within thresholds and the next required approval is recorded. Failure acknowledgment retains historical failures and establishes a new evaluation baseline; it does not delete or rewrite prior attempts.

## Pause, cancellation and recovery

POST pause/resume/cancel with `revision`. A pause stops new permits. Already issued permits remain authorized until their own expiry and may finish; pause is not an immediate node-level interruption. Resume after UserPaused requires no new independent approval if the current stage approval still applies.

Safety resume requires an independent approver/administrator, no active operations, and `acknowledgedFailures` equal to the current failedAttempts count. It records a FailureResume approval for the new approval epoch. Persistently unsafe target evidence will pause again. A lost node or incomplete recovery retains capacity and prevents a safety resume; this release has no force-release endpoint. Restore health and local recovery or follow a separately reviewed incident procedure.

Cancellation ends pending targets. Never-offered commands can terminate centrally. Offered commands receive a signed, durable withdrawal bound to the exact operation ID, cluster and command digest. The agent persists the withdrawal annotation; the operator verifies it, stops further disruption and performs verified local recovery. Withdrawal never grants permission and remains valid for its exact command after a restart. Invalid withdrawal fails closed and also recovers an owned cordon. Cancellation remains Cancelling until all active attempts become terminal; an operation already completing successfully can remain Succeeded while its campaign becomes Cancelled. Never infer recovery from a delivered cancellation request.

POST `/clusters/{cluster}/operations/{operation}/cancel` with `{}` also withdraws a manual operation. Retries of a cancellation are safe. Campaign control commands use optimistic revisions: after an ambiguous response or 409, read current state before repeating the intended action.

Permits expire no later than 15 minutes or their issuing window's end, whichever is sooner. An operator rechecks authorization before cordon/eviction. Recovery may continue outside a window and during a management outage. When all windows expire, outstanding targets cancel and active permits withdraw; the campaign becomes Failed after verified recovery. No new disruptive work starts outside a window.

## Concurrency, durability and replicas

Run `kordex-scheduler` separately from the stateless API. Each process uses a random worker ID. A tick claims an eligible organization_limits row with FOR UPDATE SKIP LOCKED, then a campaign row; it performs only bounded PostgreSQL work and commits commands, reservations, target attempts, events and a monotonic scheduler epoch atomically. There is no external RPC inside a scheduling transaction. Database lock ownership ends at commit/rollback; a crashed process cannot keep a process-local lease alive. Another replica resumes from persisted state. One organization lock serializes admissions, organization limit changes and campaign control actions. Different organizations can schedule concurrently. Round-robin campaign ticks and a persisted target scan cursor prevent one saturated scope from permanently hiding later targets.

All operation admissions, including manual operations and other campaigns, consume shared organization/fleet/site/cluster/node reservations. A site's availability budget counts the union of unhealthy worker nodes and active reservations. Every registered cluster in that site must have a fresh inventory/heartbeat and an active identity. Unknown health defers admission. The local operator independently checks PDBs, workloads, storage classification, readiness and ownership; hub capacity never overrides it.

Only terminal verified status frees offered work. Command expiry, disconnected agents, scheduler restart and elapsed leases cannot free an uncertain reservation. Never-offered expired permits can fail centrally and retry under policy. Agent reports retain an immutable contiguous event prefix. Audit/event storage and operation receipts need an archival/retention plan before sustained production volume; this release does not garbage-collect safety receipts.

## Deployment and upgrade

Apply migrations with `kordex -migrate`; the API refuses an incomplete or unknown migration history. Quiesce admission during a 0.3→0.4 upgrade: old API replicas do not write shared reservations. Upgrade all hub replicas, agents and operators together before enabling campaign scheduling. Existing active manual operations are backfilled into reservations. Keep previous hub public keys while old commands or signed withdrawals remain outstanding. Never edit an applied migration.

The control-plane image contains `/kordex` and `/kordex-scheduler`. Both read DATABASE_URL; scheduler also requires KORDEX_MAINTENANCE_SIGNING_KEY_FILE. Outside isolated KORDEX_LOCAL_DEVELOPMENT=true, database sslmode=verify-full is required. Keys come from read-only secret files and are never baked into images. Scheduler logs identify campaign, worker, fence and admitted count; failures roll back the tick and retry with backoff without logging database contents.

The self-hosted `deployments/helm/kordex-control-plane` chart packages separate replicated API/worker Deployments, a ClusterIP Service and a serialized migration hook. Supply an existing credentials Secret with databaseURL and maintenanceSigningKey, and OIDC issuer/audience. PostgreSQL, HTTPS ingress, network policy, backups and initial organization bootstrap are external prerequisites. Bootstrap remains loopback-only: create the first organization/membership through a controlled local API process connected to the same database, then stop it. No Kubernetes credentials reach the dashboard. The hub chart does not install agents into remote clusters.

For local Compose, generate a development key using kordex-keygen, expose it read-only to UID 65532 (directory accessible, key readable within the isolated container), and add `-f deployments/local/compose.campaigns.yaml` to the base Compose command. Export KORDEX_MAINTENANCE_SIGNING_KEY_FILE as an absolute host path. Base Compose remains usable without maintenance credentials.

The API remains compatible with a stateless GCP deployment. Deploy the continuously running scheduler where its process receives continuous compute, initially Kubernetes or a VM. Request-scoped API compute alone is not the scheduler runtime. No GCP resources are provisioned by this release.

## Simulator and limits of evidence

`go run ./control-plane/cmd/kordex-simulate -nodes 4000 -clusters 100` requires KORDEX_SIMULATION_DATABASE_URL pointing to a dedicated disposable database. It applies migrations, creates four sites and synthetic agent identities/inventories, runs a ValidateOnly campaign, renews inventory, and submits explicitly synthetic success reports. It retains auditable history for inspection and emits measured timing with productionCapacityProven=false. It neither contacts Kubernetes nor validates host operations, workload disruption, WAN behavior, HA database failure or production scale.

The next milestone is Phase 5: a Next.js operations dashboard consuming these tenant-scoped contracts. Notifications, recurring windows, per-scope overrides, storage/control-plane maintenance and OS rollback remain future work.
