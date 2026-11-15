# Incremental implementation plan

## Phase 1 — foundation (completed historical boundary)

Deliver repository boundaries, product/architecture/security/recovery documentation, ADRs, Go workspace, one runnable control-plane module, versioned REST contract, PostgreSQL migrations, local Compose, unit/API/database tests and CI. Stop and present verified results. No scaffolding is represented as an operational agent, operator, UI or integration.

Assumptions: private module namespace `kordex.local` until repository ownership is chosen; UUID identities; one bootstrap admin for isolated development; PostgreSQL 17; Go 1.26; no external messaging initially; explicit migrations, UTC database timestamps; organization/site create/list is the smallest durable API. Rename the module namespace before publishing public Go packages. API v1 is pre-release 0.1.0 and can change only with documented compatibility review. No host action can be issued by this foundation.

## Phase 2 — authenticated cluster registration (implemented 0.2.0)

Implemented single-use enrollment, rotatable Ed25519 workload identity over HTTPS, replay protection, revocation, OIDC membership authorization, tenant-scoped fleets/clusters, heartbeats and bounded node inventory. The shared API and agent have independent Go modules. Agent identity and sequence state persist in a compare-and-swap Kubernetes Secret or single-process local file. A Lease selects the Kubernetes agent leader. A least-privilege Helm chart and OCI image are included.

Verification includes real PostgreSQL, OIDC/JWKS TLS tests, replay/expiry/tenant-denial tests, eight-way enrollment contention, lost-response recovery and an actual kind cluster with the host-run agent restarting without an enrollment token. The full Helm pod/production ingress path remains a deployment test. No durable command inbox is implemented because there are no command endpoints; it remains required before maintenance delivery.

## Phase 3 — constrained maintenance operator (implemented 0.3.0)

Implemented controller-runtime reconciliation, generated v1alpha1 CRDs, signed manual permits, durable agent inbox/acknowledgements, global local reservation/receipts, live fail-closed safety gates, operation-owned cordon, UID-preconditioned PDB eviction and verified recovery. ValidateOnly has no disruptive side effects; DrainAndVerify is a stateless-worker drill with no host update. Package/reboot, storage and control-plane actions remain rejected.

Unit/failure tests, real API-server envtest and three-node kind verify PDB blocks, restarts/ambiguous responses, missing authorization, ownership, replay and workload recovery. MaintenanceCampaign exists as a reserved intent schema and explicitly reports HubOrchestrationRequired. See maintenance-verification.md for results and deployment limits.

## Phase 4 — campaigns (implemented 0.4.0)

Implemented PostgreSQL campaign snapshots, independent approvals, four stages, IANA windows, shared manual/campaign reservations, multi-replica scheduler, pause/resume, signed cancellation and verified recovery, bounded retries and failure gates. Includes API contracts, self-hosted worker packaging and a synthetic fleet exercise. See campaigns.md and campaign-verification.md for exact supported behavior and evidence.

## Phase 5 — dashboard (implemented 0.5.0)

Implemented server-rendered Next.js/React/TypeScript views for overview counts and freshness, fleets/sites/clusters/nodes, campaign creation and start review, phases/targets/approvals/controls, signed operation history and audit. Branding is configurable. OIDC authorization-code flow uses PKCE; encrypted HTTP-only cookies and a same-origin API proxy keep bearer tokens out of browser JavaScript. Organization authorization remains enforced by the control plane. The Helm chart runs without a service-account token, as non-root, and with a read-only root filesystem.

Known limits: the first authorized organization is selected at sign-in and there is no organization switcher; policy references must be entered from each local cluster; no OIDC provider is packaged; UI pagination is bounded; no OS/kernel updates, reboot, storage actions, cloud deployment, notifications or broad campaign scope authoring are implemented. Production use still needs the remaining Phase 6 deployment/security gates and a configured HTTPS OIDC deployment.

## Phase 6 — enterprise hardening (initial slice implemented 0.6.0)

Added database append-only audit rows and versioned per-organization SHA-256 chains for new events, high-water audit export and a verifier, backup/isolated restore helper scripts, authenticated-subject process-local request limits, separate private Prometheus listener, and separate migration/runtime database URLs in the self-hosted chart. See [Phase 6 hardening](phase6-hardening.md) and [verification record](phase6-verification.md).

Remaining: provision immutable external audit retention, test database roles in each supported PostgreSQL deployment, configure global ingress limits (including signed agent traffic), perform and record recovery/HA drills, establish SLOs/alerts, sign images and provenance, provide air-gapped artifact bundles, complete security review, and verify production TLS/OIDC/tenant isolation. Security is designed from Phase 1; the implementation and operations gates remain explicit.

## Phase 7 — advanced integrations

Ceph/Rook, etcd, package managers/kernel lifecycle, Ansible, Prometheus/Grafana and expanded OpenTelemetry. First GCP integration environment: separate project, Artifact Registry, Secret Manager and stateless Cloud Run via Terraform. Add managed PostgreSQL and Pub/Sub only with demonstrated need. No cloud spending before local MVP verification. Real GCE VM clusters must exercise kernel changes, reboot, node return, network interruption and agent recovery. Kind cannot validate host kernel or physical reboot behavior.
