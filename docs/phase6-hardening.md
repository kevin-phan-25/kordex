# Phase 6 hardening (0.6.0)

This release adds a first self-hosted hardening slice. It does not claim a complete enterprise security certification or production HA posture. Complete the deployment checklist against the target environment before enabling maintenance.

## Audit integrity and retention

Migration `007_audit_integrity.sql` makes audit rows append-only with PostgreSQL triggers and removes UPDATE/DELETE/TRUNCATE from `PUBLIC`. The runtime-role example also revokes those privileges from `kordex_runtime`. Audit appends serialize on a per-organization chain head and store SHA-256 hashes over a versioned JSON event and its previous hash. Existing rows are retained as explicitly unchained legacy history; the first new event chains from the zero hash and exports include that legacy prefix. The chain detects modification, removal, reordering, or insertion within exported chained records, but it is not a signature and does not stop a database owner from rewriting a whole chain. Audit event IDs are a global PostgreSQL sequence, so gaps between one organization's events are expected and do not indicate tampering.

Configure separate migration and runtime database identities. The Helm migration hook reads Secret key `migrationDatabaseURL`; API and scheduler read `databaseURL`. Use the example grants as a starting point, apply them as the object owner, and validate the effective privileges for your PostgreSQL version and deployment. The migration identity must own/create schema objects; it is not used by steady-state API/scheduler pods.

Export an organization's audit history over HTTPS using `scripts/export-audit.sh`. The script takes a high-water ID, paginates ascending, writes NDJSON plus SHA-256 and a checkpoint manifest, and expects a protected curl config file. Store exports and manifests in an independently administered immutable/WORM destination with retention and access logging. Verify exports with the image's `/kordex-audit-verify -input export.jsonl -through-id CHECKPOINT` command, then compare the checkpoint to the manifest. Keep the export and manifest together. The verifier intentionally rejects mixed-organization exports and incomplete/interrupted chains.

## Backup and restore

`scripts/backup-postgres.sh` creates a mode-restricted PostgreSQL custom archive using a libpq service file. Protect that file with mode 0600 and supply credentials through the platform's secret mechanism. Replicate encrypted backups off-site under a documented retention policy. The script validates archive readability and emits a checksum and manifest; it does not configure continuous archiving or point-in-time recovery.

Run `scripts/restore-drill.sh` against a newly provisioned isolated target service. It verifies the checksum, refuses a target with the same database/server identity as the source, restores without dropping objects, and checks migration/schema data. Record the drill date, source backup, target isolation, restore duration, row counts, and application-level verification results. This script is a restore aid, not evidence that a drill has already run or a complete recovery test. Configure and validate PITR separately if required by the service RPO/RTO.

## API protection and metrics

API authentication now applies a token-bucket limit keyed by the verified OIDC subject or isolated bootstrap subject. Defaults are 20 requests/second with a burst of 600; configure `KORDEX_API_RATE_LIMIT_RPS` and `KORDEX_API_RATE_LIMIT_BURST` (Helm: `apiRateLimitRPS`, `apiRateLimitBurst`). Rejections use HTTP 429 and `Retry-After`. The limiter is process-local, so it is not a global tenant quota and the effective allowance grows with API replicas. Agent signed routes do not use user-subject limits. Put global controls at the trusted ingress/API gateway and set agent ingress quotas there; do not key limits to untrusted forwarded IP headers.

Prometheus text metrics are served on a separate listener at `KORDEX_METRICS_LISTEN_ADDRESS` (default `127.0.0.1:9090`). In the control-plane chart they remain loopback-only unless `metrics.enabled=true`, which exposes a separate ClusterIP Service and an ingress NetworkPolicy. NetworkPolicies are additive and depend on the installed CNI. Review `metrics.namespaceSelector` and the cluster's namespace labels; scrape only from a trusted monitoring namespace and do not publish the metrics Service through public ingress. Current metrics cover HTTP request count and latency with bounded labels; they do not yet report scheduler progress, queue age, retained reservations, blocked reasons, or recovery duration.

## Availability and deployment boundaries

The API and scheduler are separate replicated workloads and campaign claims are database-coordinated. This is not a measured HA/SLO claim. Validate database failover, backup recovery, ingress TLS, OIDC provider outage behavior, key rotation, and multi-replica campaign behavior in the target environment. The database remains a required central dependency. Agents continue to enforce local authorization and safety while disconnected; a disconnected cluster must not begin new authorized disruptive work.

Still outside this slice: PostgreSQL RLS, complete denied-access audit coverage, external immutable-retention provisioning, KMS-backed signing, release image signing/provenance, air-gapped artifact bundles, GCP Terraform/Cloud Run deployment, SLO alert rules, and measured production scale. No credentials or cloud resources are provisioned by these scripts or charts.

## Operator checklist

1. Configure HTTPS ingress and OIDC issuer/audience; test tenant isolation and role mapping.
2. Create separate least-privilege database migration/runtime roles and verify runtime cannot mutate audit rows or schema history.
3. Enable TLS verification for database connections; store both URLs and signing keys in the deployment secret manager.
4. Enable an authenticated, private metrics scrape path and configure gateway rate limits for users and agents.
5. Schedule encrypted backups and off-site immutable audit exports; alert on missed backup/export jobs.
6. Perform a restore drill against an isolated target and retain measured RPO/RTO evidence.
7. Validate agent trust rotation/revocation, network partitions, and campaign recovery before authorizing maintenance.
8. Review security advisories, image provenance, and the remaining hardening gaps listed above.
