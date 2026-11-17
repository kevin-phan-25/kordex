# Infrastructure integrations

Kordex integrations supply evidence and narrowly scoped capabilities to the local operator. An integration must return **Pass**, **Block**, or **Unknown**, include evidence freshness, and fail closed when its API is unavailable. Integrations do not authorize maintenance: the signed operation grant, local policy, fresh cluster connection, Kubernetes checks, campaign reservation, and operation state machine remain mandatory.

## Implemented in the Phase 7 foundation

* Provider-neutral contracts for storage health/maintenance, control-plane quorum, node lifecycle, and Ansible EE based host upgrades.
* Initial upgrade path: digest-pinned Ansible EE policy and catalog, canonical policy digest, lifecycle phases, and durable local checkpoints. `integrations/ansible-ee` contains fixed Debian/Ubuntu and RPM-family catalog artifacts; the latter explicitly accepts Amazon Linux 2023 through DNF while rejecting Amazon Linux 2. `operator/internal/execution` contains an idempotent Kubernetes Job adapter with preflight/apply/reboot phases, suspended activation, immutable receipts, and strict validation. The operator path is wired behind a disabled-by-default gate. It is not VM-qualified and must not be enabled outside disposable qualification infrastructure.
* Read-only Rook/Ceph safety adapter in the local operator: reads fresh `CephCluster` status and scrapes the cluster-local Rook manager metrics endpoint. It checks `HEALTH_OK`, exact OSD `up/in` metrics against Rook OSD identities, noout flags, PG recovery/backfill/degradation metrics, and Kubernetes OSD pod readiness/placement. Explicit Prometheus timestamps on safety metrics must be no more than 60 seconds old or 5 seconds in the future; missing, stale, or inconsistent evidence blocks. Untimestamped samples are associated with the just-completed scrape. A target hosting an OSD is blocked pending an ownership-aware storage maintenance workflow. The operator does not change Ceph flags or perform storage mutation. It supports the Rook manager metrics Service on port 9283 over HTTP or HTTPS; HTTPS requires a mounted private CA configured through `KORDEX_ROOK_METRICS_CA_FILE` and uses certificate verification. Real Rook/Ceph release compatibility remains unqualified.
* etcd safety: a pure evidence evaluator plus an optional live operator adapter that uses mTLS to read membership and status from every configured endpoint. It validates cluster/member identity, member health errors, applied-versus-committed Raft index, a consistent leader/term view, and current majority before maintenance; a control-plane target is excluded from projected quorum only after its member ID is mapped. The adapter never removes a member or changes etcd state. Real topology compatibility remains unqualified.
* GCP Terraform foundation, opt-in only: Artifact Registry repository and Secret Manager secret containers in an explicitly selected project. No project, identity, secret value, Cloud Run service, database, or Pub/Sub topic is created by default.
* Prometheus scrape annotations, starter alert rules, and a Grafana dashboard for API rate, 5xx share, and request latency. These are examples and require local threshold/scrape validation.

These remain limited integration slices, not production-ready provider integrations. The Rook adapter is connected to the operator but has not been qualified against real Ceph/Rook versions; its required metric families must be present and verified for each supported release. The operator has an optional live etcd mTLS membership/status adapter for quorum evidence, but no self-managed control-plane upgrade is enabled by it. Operation-owned storage maintenance, EKS/AKS provider-native adapters, deeper alert coverage, and real infrastructure drills remain to be built and reviewed. The GKE adapter is optional and does not participate in the provider-neutral Ansible host-upgrade path.

## Adapter rules

1. Missing, stale, contradictory, or unsupported evidence returns `Unknown` or `Block`; it never implies health.
2. Every state-changing provider call must be idempotent, operation-scoped, auditable, and paired with observe/recovery/exit steps.
3. A provider maintenance flag can only be set or cleared when the operation owns that exact change. Never clear a pre-existing flag.
4. Credentials stay in the managed cluster or deployment secret manager and are never sent to the dashboard or hub.
5. Provider-specific code stays behind interfaces in this directory or the local operator; the central API carries normalized status only.

See [Phase 7 implementation record](../docs/phase7-integrations.md) and [Phase 7 verification](../docs/phase7-verification.md).
