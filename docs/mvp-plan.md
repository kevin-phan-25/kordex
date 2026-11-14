# Incremental implementation plan

## Phase 1 — foundation (current boundary)

Deliver repository boundaries, product/architecture/security/recovery documentation, ADRs, Go workspace, one runnable control-plane module, versioned REST contract, PostgreSQL migrations, local Compose, unit/API/database tests and CI. Stop and present verified results. No scaffolding is represented as an operational agent, operator, UI or integration.

Assumptions: private module namespace `kordex.local` until repository ownership is chosen; UUID identities; one bootstrap admin for isolated development; PostgreSQL 17; Go 1.26; no external messaging initially; explicit migrations, UTC database timestamps; organization/site create/list is the smallest durable API. Rename the module namespace before publishing public Go packages. API v1 is pre-release 0.1.0 and can change only with documented compatibility review. No host action can be issued by this foundation.

## Phase 2 — authenticated cluster registration (exact next milestone)

First design and test one-time enrollment, rotatable mTLS cluster identity and revocation. Add cluster/agent registration, fleet/site associations, freshness-aware heartbeats, bounded node inventory and health snapshots. Build an outbound-only agent with a durable Kubernetes-backed inbox design and Helm least-privilege RBAC. No maintenance execution. Exit: real kind registration, cross-cluster impersonation rejection, expired/replayed enrollment rejection, restart/reconnect behavior and stale heartbeat tests. Finalize tenant authorization and identity semantics before accepting externally connected agents.

## Phase 3 — maintenance operator

Introduce controller-runtime/client-go modules, CRD generation, envtest and kind tests. Build NodeMaintenance state transitions, safety providers, PDB-aware eviction, cordon ownership and durable recovery. Execution starts with an explicit no-host-change validation action; package/reboot executors remain disabled until real-VM tests. Required failures: degraded cluster, unknown quorum/storage, PDB block, lost authorization, restarts at each boundary and ambiguous action completion.

## Phase 4 — campaigns

Persist operations/outbox/reservations/leases. Implement windows, approval gates, snapshot targets, canaries and staged batches, pause/resume, retry limits and failure thresholds. Race multiple scheduler replicas and verify all concurrency scopes. Build deterministic fleet simulator; publish measured results and limitations.

## Phase 5 — dashboard

Next.js/React/TypeScript, configurable branding, accessible enterprise components, overview counts, fleet/site/cluster/node inventory, campaign forms, execution phases, approvals and audit. Production identity integration must precede public UI access. No kubeconfig exposure.

## Phase 6 — enterprise hardening

Complete OIDC/RBAC/multi-tenant defense in depth, immutable audit export, rate limits, HA, production TLS, backups/restore drills, SLOs, vulnerability gates, signed images and air-gapped deployment. Security is designed from Phase 1, not deferred in principle; all public production access is gated on these controls.

## Phase 7 — advanced integrations

Ceph/Rook, etcd, package managers/kernel lifecycle, Ansible, Prometheus/Grafana and expanded OpenTelemetry. First GCP integration environment: separate project, Artifact Registry, Secret Manager and stateless Cloud Run via Terraform. Add managed PostgreSQL and Pub/Sub only with demonstrated need. No cloud spending before local MVP verification. Real GCE VM clusters must exercise kernel changes, reboot, node return, network interruption and agent recovery. Kind cannot validate host kernel or physical reboot behavior.
