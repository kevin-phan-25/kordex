# Infrastructure integrations

Kordex integrations supply evidence and narrowly scoped capabilities to the local operator. An integration must return **Pass**, **Block**, or **Unknown**, include evidence freshness, and fail closed when its API is unavailable. Integrations do not authorize maintenance: the signed operation grant, local policy, fresh cluster connection, Kubernetes checks, campaign reservation, and operation state machine remain mandatory.

## Implemented in the Phase 7 foundation

* Provider-neutral contracts for storage health/maintenance, control-plane quorum, node lifecycle, and package planning.
* Pure Ceph/Rook evidence evaluation: health must be `HEALTH_OK`, all expected OSDs must be up/in, no recovery/backfill is active, and maintenance ownership is explicit. No Ceph command or mutation is issued.
* Pure etcd membership/quorum evaluation: fresh membership evidence, healthy member count, and majority quorum are required. No etcd endpoint is contacted and no member is removed.
* GCP Terraform foundation, opt-in only: Artifact Registry repository and Secret Manager secret containers in an explicitly selected project. No project, identity, secret value, Cloud Run service, database, or Pub/Sub topic is created by default.

These are evidence evaluators and IaC building blocks, not production-ready integrations. Provider clients, authentication, evidence acquisition, mutation lifecycle, alert rules, and real infrastructure drills remain to be built and reviewed.

## Adapter rules

1. Missing, stale, contradictory, or unsupported evidence returns `Unknown` or `Block`; it never implies health.
2. Every state-changing provider call must be idempotent, operation-scoped, auditable, and paired with observe/recovery/exit steps.
3. A provider maintenance flag can only be set or cleared when the operation owns that exact change. Never clear a pre-existing flag.
4. Credentials stay in the managed cluster or deployment secret manager and are never sent to the dashboard or hub.
5. Provider-specific code stays behind interfaces in this directory or the local operator; the central API carries normalized status only.

See [Phase 7 implementation record](../docs/phase7-integrations.md) and [Phase 7 verification](../docs/phase7-verification.md).
