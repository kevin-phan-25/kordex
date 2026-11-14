# Incremental implementation plan

## Phase 1 — foundation (completed historical boundary)

Deliver repository boundaries, product/architecture/security/recovery documentation, ADRs, Go workspace, one runnable control-plane module, versioned REST contract, PostgreSQL migrations, local Compose, unit/API/database tests and CI. Stop and present verified results. No scaffolding is represented as an operational agent, operator, UI or integration.

Assumptions: private module namespace `kordex.local` until repository ownership is chosen; UUID identities; one bootstrap admin for isolated development; PostgreSQL 17; Go 1.26; no external messaging initially; explicit migrations, UTC database timestamps; organization/site create/list is the smallest durable API. Rename the module namespace before publishing public Go packages. API v1 is pre-release 0.1.0 and can change only with documented compatibility review. No host action can be issued by this foundation.

## Phase 2 — authenticated cluster registration (implemented 0.2.0)

Implemented single-use enrollment, rotatable Ed25519 workload identity over HTTPS, replay protection, revocation, OIDC membership authorization, tenant-scoped fleets/clusters, heartbeats and bounded node inventory. The shared API and agent have independent Go modules. Agent identity and sequence state persist in a compare-and-swap Kubernetes Secret or single-process local file. A Lease selects the Kubernetes agent leader. A least-privilege Helm chart and OCI image are included.

Verification includes real PostgreSQL, OIDC/JWKS TLS tests, replay/expiry/tenant-denial tests, eight-way enrollment contention, lost-response recovery and an actual kind cluster with the host-run agent restarting without an enrollment token. The full Helm pod/production ingress path remains a deployment test. No durable command inbox is implemented because there are no command endpoints; it remains required before maintenance delivery.

## Phase 3 — constrained maintenance operator (implemented 0.3.0)

Implemented controller-runtime reconciliation, generated v1alpha1 CRDs, signed manual permits, durable agent inbox/acknowledgements, global local reservation/receipts, live fail-closed safety gates, operation-owned cordon, UID-preconditioned PDB eviction and verified recovery. ValidateOnly has no disruptive side effects; DrainAndVerify is a stateless-worker drill with no host update. Package/reboot, storage and control-plane actions remain rejected.

Unit/failure tests, real API-server envtest and three-node kind verify PDB blocks, restarts/ambiguous responses, missing authorization, ownership, replay and workload recovery. MaintenanceCampaign exists as a reserved intent schema and explicitly reports OrchestrationNotImplemented. See maintenance-verification.md for results and deployment limits.

## Phase 4 — campaigns (next milestone)

Persist operations/outbox/reservations/leases. Implement windows, approval gates, snapshot targets, canaries and staged batches, pause/resume, retry limits and failure thresholds. Race multiple scheduler replicas and verify all concurrency scopes. Build deterministic fleet simulator; publish measured results and limitations.

## Phase 5 — dashboard

Next.js/React/TypeScript, configurable branding, accessible enterprise components, overview counts, fleet/site/cluster/node inventory, campaign forms, execution phases, approvals and audit. Production identity integration must precede public UI access. No kubeconfig exposure.

## Phase 6 — enterprise hardening

Complete OIDC/RBAC/multi-tenant defense in depth, immutable audit export, rate limits, HA, production TLS, backups/restore drills, SLOs, vulnerability gates, signed images and air-gapped deployment. Security is designed from Phase 1, not deferred in principle; all public production access is gated on these controls.

## Phase 7 — advanced integrations

Ceph/Rook, etcd, package managers/kernel lifecycle, Ansible, Prometheus/Grafana and expanded OpenTelemetry. First GCP integration environment: separate project, Artifact Registry, Secret Manager and stateless Cloud Run via Terraform. Add managed PostgreSQL and Pub/Sub only with demonstrated need. No cloud spending before local MVP verification. Real GCE VM clusters must exercise kernel changes, reboot, node return, network interruption and agent recovery. Kind cannot validate host kernel or physical reboot behavior.
