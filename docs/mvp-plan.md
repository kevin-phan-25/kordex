# Incremental implementation plan

The [production upgrade requirements](production-upgrade-requirements.md) are
the single source of truth for current capabilities, qualification evidence,
and delivery order. The phases below are historical implementation records;
completion does not establish production upgrade support. The current M3 exit
bar is all 11 scenarios on Debian 13 at the approved point release and genuine
RHEL 9.8 or later, with real-host recovery and independently accepted evidence.
Ubuntu is supplemental only. Provider upgrade qualification follows M3.

## Phase 1 — foundation (completed historical boundary)

Deliver repository boundaries, product/architecture/security/recovery documentation, ADRs, Go workspace, one runnable control-plane module, versioned REST contract, PostgreSQL migrations, local Compose, unit/API/database tests and CI. Stop and present verified results. No scaffolding is represented as an operational agent, operator, UI or integration.

Assumptions: private module namespace `kordex.local` until repository ownership is chosen; UUID identities; one bootstrap admin for isolated development; PostgreSQL 17; Go 1.26; no external messaging initially; explicit migrations, UTC database timestamps; organization/site create/list is the smallest durable API. Rename the module namespace before publishing public Go packages. API v1 is pre-release 0.1.0 and can change only with documented compatibility review. No host action can be issued by this foundation.

## Phase 2 — authenticated cluster registration (implemented 0.2.0)

Implemented single-use enrollment, rotatable Ed25519 workload identity over HTTPS, replay protection, revocation, OIDC membership authorization, tenant-scoped fleets/clusters, heartbeats and bounded node inventory. The shared API and agent have independent Go modules. Agent identity and sequence state persist in a compare-and-swap Kubernetes Secret or single-process local file. A Lease selects the Kubernetes agent leader. A least-privilege Helm chart and OCI image are included.

Verification includes real PostgreSQL, OIDC/JWKS TLS tests, replay/expiry/tenant-denial tests, eight-way enrollment contention, lost-response recovery and an actual kind cluster with the host-run agent restarting without an enrollment token. The full Helm pod/production ingress path remains a deployment test. No durable command inbox is implemented because there are no command endpoints; it remains required before maintenance delivery.

## Phase 3 — constrained maintenance operator (implemented 0.3.0)

Implemented controller-runtime reconciliation, generated v1alpha1 CRDs, signed manual permits, durable agent inbox/acknowledgements, global local reservation/receipts, live fail-closed safety gates, operation-owned cordon, UID-preconditioned PDB eviction and verified recovery. ValidateOnly has no disruptive side effects; DrainAndVerify is a stateless-worker drill with no host update. For subsequent upgrade execution capabilities and exclusions, see the production upgrade requirements.

Unit/failure tests, real API-server envtest and three-node kind verify PDB blocks, restarts/ambiguous responses, missing authorization, ownership, replay and workload recovery. MaintenanceCampaign exists as a reserved intent schema and explicitly reports HubOrchestrationRequired. See maintenance-verification.md for results and deployment limits.

## Phase 4 — campaigns (implemented 0.4.0)

Implemented PostgreSQL campaign snapshots, independent approvals, four stages, IANA windows, shared manual/campaign reservations, multi-replica scheduler, pause/resume, signed cancellation and verified recovery, bounded retries and failure gates. Includes API contracts, self-hosted worker packaging and a synthetic fleet exercise. See campaigns.md and campaign-verification.md for exact supported behavior and evidence.

## Phase 5 — dashboard (implemented 0.5.0)

Implemented server-rendered Next.js/React/TypeScript views for overview counts and freshness, fleets/sites/clusters/nodes, campaign creation and start review, phases/targets/approvals/controls, signed operation history and audit. Branding is configurable. OIDC authorization-code flow uses PKCE; encrypted HTTP-only cookies and a same-origin API proxy keep bearer tokens out of browser JavaScript. Organization authorization remains enforced by the control plane. The Helm chart runs without a service-account token, as non-root, and with a read-only root filesystem.

Known limits: the dashboard can discover policies only from a fresh agent catalog report; no OIDC provider is packaged; UI pagination is bounded; production-qualified host OS/kernel execution, storage actions, full cloud deployment, notifications and broad campaign scope authoring remain incomplete. The encrypted session supports switching among organizations after a live membership check. Production use still needs the remaining Phase 6 deployment/security gates and a configured HTTPS OIDC deployment.

## Phase 6 — enterprise hardening (initial slice implemented 0.6.0)

Added database append-only audit rows and versioned per-organization SHA-256 chains for new events, high-water audit export and a verifier, backup/isolated restore helper scripts, authenticated-subject process-local request limits, separate private Prometheus listener, and separate migration/runtime database URLs in the self-hosted chart. See [Phase 6 hardening](phase6-hardening.md) and [verification record](phase6-verification.md).

Remaining: provision immutable external audit retention, test database roles in each supported PostgreSQL deployment, configure global ingress limits (including signed agent traffic), perform and record recovery/HA drills, establish SLOs/alerts, sign images and provenance, complete security review, and verify production TLS/OIDC/tenant isolation. A signed offline artifact bundle and private-registry installation helpers have since been added and contract-tested; deployment into a genuinely disconnected site remains unqualified. Security is designed from Phase 1; the implementation and operations gates remain explicit.

## Phase 7 — advanced integrations (initial foundation implemented 0.7.0)

Added fail-closed provider-neutral storage/quorum/node/package interfaces, pure etcd evidence evaluation, a read-only Rook/Ceph metrics adapter wired into local preflight, and opt-in Terraform for Artifact Registry plus Secret Manager containers in an existing dedicated project. The storage adapter does not mutate Ceph or enable OSD-host maintenance and remains unqualified against live versions. See [integration details](phase7-integrations.md) and [verification record](phase7-verification.md).

Remaining: qualify Rook/Ceph metric compatibility and behavior against real clusters and qualify live etcd mTLS quorum evidence against supported self-managed topologies, implement operation-owned storage maintenance lifecycle, complete Ansible/package/kernel/reboot VM recovery qualification, expand OpenTelemetry, approve GCP project/remote Terraform state/workload identity, and decide whether Cloud Run/Cloud SQL/Pub/Sub are needed. The etcd adapter is read-only evidence and does not enable control-plane execution. Managed database and Pub/Sub remain conditional on demonstrated need. Kind cannot validate host kernel or physical reboot behavior. Phase 7 is the last numbered roadmap phase, not a claim that integration coverage or production validation is complete.

## Phase 8 — operational observability (initial slice)

Added bounded-cardinality scheduler metrics for due queue age, active reservations, blocked operations by normalized reason, scheduler tick outcomes/duration, and admitted operations. Added local operator metrics for recovery blockers and completed recovery duration. Metrics remain loopback-only by default; Helm can expose private scrape Services with monitoring-namespace NetworkPolicies. Added starter Grafana views and alerts. See [Phase 8 operational observability](phase8-operational-observability.md).

Remaining: exercise metric exposure and NetworkPolicies on each supported CNI; validate scrape behavior through scheduler/operator restarts and leader failover; derive and approve SLOs from pilot data; add active recovery age and storage evidence only after operational requirements are defined. Counters are process-local and reset on restart. This does not complete the Phase 6 production hardening gates or add any maintenance capability.

## Phase 9 — production upgrade contracts and reporting (historical implementation record)

Added typed host/provider plans, canonical digests, signed permit and campaign
snapshot binding, fresh policy discovery, durable checkpoints, and opt-in host
and GKE execution adapters. These are implementation milestones. Current
capabilities, exclusions, evidence, and the frozen Debian/RHEL qualification
checklist are maintained only in the [production upgrade requirements](production-upgrade-requirements.md).
