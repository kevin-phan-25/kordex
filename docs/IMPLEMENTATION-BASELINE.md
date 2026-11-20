# Kordex implementation baseline

Date: 2026-11-18  
Repository HEAD at audit start: `e47097e` (`adding upgrading and testing`).  
The audit began with five pre-existing modifications in the disposable GCP lab
Terraform module and `docs/production-upgrade-requirements.md`; those changes
were preserved. The worktree has since accumulated the implementation changes
listed in this baseline and subsequent readiness reports.

This is a source and deployment inventory, not a production approval. Status is
based on the checked-in code, deployment artifacts, tests, and qualification
records. A simulator, interface, chart render, or API-server test does not
establish real distribution or host-upgrade support.

## Existing implementation inventory

| Area | Present implementation | Current boundary |
|---|---|---|
| API and protocol | Go modules in `api/`; versioned agent/control/maintenance/upgrade protocols, OpenAPI, signature and digest validation, lifecycle discovery types | API is internal and versioned; wire compatibility still requires hub-first rollout for additive strict validation changes |
| Management plane | Go HTTP API, PostgreSQL migrations/store, OIDC validation, organization membership/roles, enrollment, inventory, operations, campaigns, audit chain/export, rate limits, metrics, scheduler process | Self-hosted API/scheduler use PostgreSQL; production DB HA, external immutable audit retention, deployment security, and restore qualification are operational blockers |
| Agent | Outbound HTTPS client, one-time enrollment, persistent Ed25519 identity/rotation state, replay protection, heartbeat/inventory/capability reporting, durable operation bridge, local health diagnostics | Kubernetes identity uses Secret resource-version compare-and-swap; local file state rejects unsafe permissions, symlinks, and writable state directories. Retry backoff, jitter bounds, transient report retry, and cancellation have runner unit coverage; installed-agent network-partition and key-rotation qualification remain incomplete |
| Operator | controller-runtime CRDs/reconcilers, local authorization and workload safety gates, durable checkpoints/leases, eviction drain, cancellation/recovery, metrics, effective node-maintenance and host-execution RBAC probes | Capability probes are advisory hub signals; Kubernetes authorizes every request and local checks remain authoritative. ValidateOnly and stateless drain/recovery have local and Kind coverage; broad Kubernetes distribution compatibility and production lifecycle evidence are absent |
| Host maintenance | Fixed Debian APT and RPM-family DNF Ansible EEs, explicit OS identity/release catalog, package/offline artifact checks, action journal, reboot and recovery verification; gates default off | Ubuntu/Debian, RHEL-family, and AL2023 implementation is opt-in and **not qualified on real VMs**; host-upgrade matrix remains NOT RUN |
| Provider maintenance | Optional GKE node-pool adapter with identity/settings checks and durable operation observation | Opt-in and unqualified; EKS and AKS adapters are not implemented; provider-managed upgrades are distinct from host package updates |
| Storage/quorum | Read-only Rook/Ceph and Longhorn v1beta2 evidence; OpenEBS LocalPV placement checks; optional mTLS etcd health/quorum checks | No storage mutation or Longhorn rebuild coordination; OpenEBS health/recovery, Ceph/Rook, Longhorn, and etcd variants are not qualified on real installations |
| Campaigns and policy | Immutable target snapshots, staged rollout, independent approvals, organization/fleet/site/zone/cluster/node concurrency reservations, windows, retry/failure policy, scheduler leasing and signed local permits | Campaign and organization concurrency ceilings are validated; zone limits use fresh node topology and durable reservations; unknown zones conservatively overlap every zone. Central admission is durable; local safety remains authoritative. Multi-replica scale and real fleet fault behavior lack qualification evidence |
| Dashboard | Next.js OIDC/PKCE session proxy, organization switch, fleet/compatibility, exact-UID node detail, campaign, approval, operation, audit, and bounded audit snapshot export views | Campaign creation exposes validated campaign concurrency ceilings and shows them in preflight review, persisted detail, and start confirmation. An administrator-only, revision-checked organization limits editor includes per-zone limits. No Kubernetes credentials are sent to the browser; broader typed policy editing, recovery actions, system administration, large-export streaming, browser-side signature verification, and immutable external evidence retention remain absent or partial. Audit downloads now come from a tenant-scoped API endpoint that signs a bounded snapshot |
| Deployment and supply chain | Local Compose; separate Helm charts; Kustomize hub and spoke overlays; operator CRDs; offline OCI/Helm/package tooling; Terraform GCP foundations; pinned application base indexes; manual image-release workflow with scan, SBOM, provenance and Cosign signing; opt-in Kyverno image-signature policy; configurable component-scoped management-plane and agent/operator egress policies | Production Helm profiles require digest-pinned app images. Release publication is manually gated and awaits all CI jobs; it has not been executed. Kyverno policy has CLI denial simulation but no live admission qualification; provenance/SBOM admission enforcement, controller/certificate/redirect configuration, site-specific peer configuration, spoke Kustomize egress policies, CNI enforcement, secret-manager/HA/DR operation remain site-owned or unqualified |
| Observability | Prometheus API, scheduler and operator metrics, alert examples, Grafana API/operations/fleet dashboards, structured logs, opt-in API/scheduler/maintenance-operator/agent OTLP/HTTP traces | Operator exports aggregate active RecoveryRequired count/oldest-age gauges with snapshot success, freshness, and completeness signals; fleet metrics are aggregate and private. No monitoring stack or external immutable audit destination is deployed by default; live trace continuity, SLOs and capacity claims are unmeasured |

## Missing and partial functionality

### Kubernetes compatibility

There is advisory Node metadata discovery for provider and selected distribution
hints, plus driver and Kubernetes distribution registries. The new
Kubernetes registry binds qualification status, versions/OS/architecture
qualified (currently none), required and optional permission profiles, CRDs,
network needs, operations, automated test coverage, and known limitations. It
rejects `Supported` and `Qualified` declarations by construction. Distribution-
specific live qualification remains absent for upstream Kubernetes, K3s, RKE2,
GKE, EKS, AKS, OpenShift, kubeadm, Talos, and MicroK8s. Unknown or conflicting
hints remain unqualified.

### Agent and operator

Core enrollment, signed outbound reports, local durable operation state,
reservations, drain/recovery, cancellation, and fail-closed unknown evidence
exist. Bounded CNI/CSI/StorageClass/admission/Pod Security inventory is now
reported and persisted, but remains advisory evidence. Remaining gaps include
cross-distribution qualification, comprehensive fault injection across
agent/operator/API/database/network restarts, stale reservation recovery under
real failures, and complete operational rotation/upgrade procedures for the
agent. Reservation admission now reports an orphaned holder UID when its
`NodeMaintenance` record is absent, but it retains the Lease and provides no
automatic reclaim path; real failure and operator-recovery procedures still
need qualification. No central action may bypass the local veto.
The operator now uses self-subject access reviews to check its effective
permissions for node/workload/eviction access, PV and service inventory,
Rook/Longhorn read-only checks, and the durable drain/recovery records. It
publishes `nodeMaintenance` through the capability Lease and agent report.
Missing or indeterminate permissions fail closed at campaign preview and
scheduler admission; the operator and Kubernetes API remain the final
boundary. The probe is startup
evidence and is not a live permission-change monitor; requests still receive
independent Kubernetes authorization. Local unit and PostgreSQL tests cover
the probe result and admission behavior, but the effective profile has not
been qualified on a live cluster.
The operator also freezes repeated `RecoveryRequired` phase-event noise at its
240-event safety threshold, keeps an `AuditCapacityReached` blocker, and
persists structured checkpoints without exceeding the 256-event report bound.
This protects report validity in local tests but does not replace external
immutable audit retention or live restart qualification.
Maintenance phase changes now use a shared transition graph in both operator
status writes and hub report validation. The accepted graph includes only
pre-mutation cancellation, verified provider cancellation, and terminal
re-entry to recovery when the old operation still owns a cordon. Missing
recovery ownership metadata is retained in `RecoveryRequired`, not converted
to terminal failure. The graph has automated local and PostgreSQL-store test
coverage; live restart and cluster failure qualification remain absent.
Hub ingestion additionally checks phase transitions and successful terminal
paths against the signed operation action: for example, a `ValidateOnly`
report cannot claim drain phases, and drain/host success must include verified
recovery and uncordon. Host and provider success also require their terminal
execution checkpoints. These checks prevent contradictory central audit
histories; they do not prove that cluster-local work occurred or qualify an
executor. This is partial progress on UPG-04, UPG-05, UPG-14, and UPG-18.
Host success ingestion now also requires ordered preflight/apply receipt
evidence, an action marker bound to operation/plan/node/machine/boot, and a
reboot receipt plus matching `Rebooting` phase when reboot was requested; a
pinned expected kernel and package versions must match the verified receipts.
The hub bounds receipt timestamps but avoids ordering host-clock timestamps
against operator-clock checkpoints. These are local contract/database checks,
not an independent attestation channel or real package/reboot qualification.

### Host execution and provider adapters

APT/DNF and GKE code paths exist behind default-off gates. Contracts, fixed
catalog tests, fake/simulated execution, runner guards, and Kubernetes
API-server tests do not prove a real package transaction, controlled reboot,
node recovery, disconnected installation, or provider upgrade. EKS/AKS,
additional OS families/majors, Fedora, image-based OS mutation, and general
control-plane maintenance are unsupported. Never retry an ambiguous destructive
operation without read-only evidence.

### Storage, quorum, and policy consistency

Ceph/Rook and etcd adapters provide read-only evidence. Generic preflight now
recognizes OpenEBS LocalPV LVM/ZFS CSI and legacy Hostpath PV identities and
uses standard PV node affinity to block target-local data or unknown placement;
this is not an OpenEBS health or recovery adapter. A read-only Longhorn v1beta2
adapter checks node readiness freshness, volume health, replica count and
placement, and rebuild/restore/migration signals. It continues to block
Longhorn service nodes and nodes with replicas or attached volumes because no
ownership-aware rebuild workflow exists. These checks are not qualified on a
real Longhorn installation. There is no safe automatic stateful maintenance
approval for an unknown storage system. Typed campaign policy and
local gates now share an explicit action allowlist at campaign
assessment, operation admission, signed-permit handling, and operator action
boundaries. Campaign assessment, operation admission, policy status validation,
and local preflight also use one pure target-selector evaluator with stable
reason codes and corrective actions. The action-allowlist decision is bound to
the policy generation and returns the requested action, evaluated allowlist,
reason, explanation, and corrective actions across campaign assessment,
central admission, and operator authorization. A complete deterministic policy
evaluator shared across API, scheduler, operator, and executor for windows,
concurrency, approvals, PDB, quorum, storage, and recovery, including broader
cross-layer conformance tests, has not been established.
Maintenance policies also support an optional `protectedNodeSelector` veto,
relayed through the agent catalog and checked at central campaign/operation
admission and both local operator safety boundaries. A matching target or
missing labels when protection is configured fails closed. Its local and
contract tests do not make the overall policy engine complete or qualify an
executor; the dashboard cannot yet edit this policy.
Organization and campaign admission now also enforce a zone concurrency budget
using durable reservation zone IDs. Campaign admission compares the approved
snapshot zone with fresh inventory; missing or conflicting topology is treated
as overlapping all zones. Migration 013 conservatively backfills existing
reservations. PostgreSQL contract tests exercise same-zone limits and distinct
zone concurrency, but multi-replica and fleet-scale behavior remain unqualified.
Campaign creation now sends explicit validated concurrency ceilings, displays
them in preflight review, and repeats persisted values on campaign detail and
start confirmation. This dashboard increment does not make the broader policy
engine complete or change qualification status.

### Enterprise operation and security

OIDC ID-token and opt-in RFC 9068 access-token contracts, tenant membership
checks, role checks, signing, TLS constraints, audit hash chaining, and
credential redaction have automated coverage. Remaining work includes an
independent review of the repository threat model, real provider-backed
login/scope mapping and key rotation, authenticated membership/role denial
records now have a separate append-only chain and bounded verifier-compatible
export, while unauthenticated failures remain log-only; PostgreSQL-backed
integration and independent immutable retention evidence remain, as do key
revocation/rotation operations, enterprise
secret-management integration, live image admission verification (a Kyverno
policy is available but not deployed or tested), provenance/SBOM admission
enforcement, site-specific egress configuration and CNI enforcement, and
demonstrated tenant isolation under concurrent campaign and evidence access.

### Deployment, dashboard, and air gap

Self-hosted manifests exist, but a production reference deployment with
PostgreSQL HA/backup/restore, migration and rollback procedure, scheduler
replica fault qualification, ingress/TLS, OIDC secrets, network policies, and
measured resource profiles is incomplete. Scheduler admissions already use
transactional PostgreSQL row locks, `SKIP LOCKED`, and per-organization epochs;
the replicas have not been fault-qualified against a real deployment. The
offline bundle is integrity-checked and signed;
site package artifacts are generated/staged separately and there is no tested
end-to-end disconnected installation or synchronization workflow. Dashboard
coverage does not yet include every requested administration, policy, recovery,
and compatibility workflow.

## Security gaps and non-negotiable constraints

- No production or customer cluster, existing GCP project, host, or cloud
  resource may be changed without explicit authorization.
- `kordex-fleet-platform` is not a disposable lab. The host-upgrade and GKE
  provider gates remain default off; no executor is production-qualified.
- The GCP lab Terraform module hard-denies `kordex-fleet-platform` both in the
  project variable validation and its resource precondition, independent of
  the user-provided allowlist and disposable label.
- The GCP self-managed lab module has an uncommitted project allowlist,
  designation-label, and project-bound confirmation guard. Its documented
  manual project inventory review is still required; it does not enumerate all
  project assets.
- A central signed command is necessary but not sufficient. Local operator
  checks, current identity, fresh evidence, exact policy and plan digests,
  ownership, durable checkpoints, and verified recovery remain mandatory.
- Exactly-once physical mutation cannot be promised. Ambiguous outcomes must
  remain fenced for read-only inspection or explicit intervention.
- Do not infer compatibility from package-manager similarity, cloud VM ID,
  distro family, simulator success, or a checked-in interface.
- The default Kustomize operator RBAC previously included host SSH Secret read
  and execution NetworkPolicy permissions while host upgrades were disabled.
  Those grants now live in an explicit `operator-host-execution` component;
  the default overlay no longer includes them. The component still does not
  enable the operator execution gate.

## Test and qualification baseline

`make test` runs Go unit/contract tests across `api`, `control-plane`, `agent`,
`operator`, and `integrations`. CI additionally defines PostgreSQL-backed race
tests, `go vet`/build/OpenAPI checks, API-server `envtest`, real Kind enrollment
and PDB-aware drain/recovery, Helm lint, Kustomize rendering, dashboard tests,
and offline artifact/build checks. These are code and disposable Kind checks;
they do not qualify every Kubernetes distribution, a package/reboot executor,
cloud provider operations, storage recovery, air-gapped customer deployment,
or production availability.

Local verification on Go 1.26.10: `make test` passed after the compatibility
change and again after agent local-state permission hardening; `make vet build contract` passed; dashboard `npm test`, typecheck, lint,
and production build passed; `bash scripts/test-configure-offline-kustomize.sh`
passed; the Kustomize default and optional host-RBAC render checks passed;
`python3 scripts/check-openapi.py` passed with 50 operations. `KORDEX_TEST_DATABASE_URL`
and `KUBEBUILDER_ASSETS` were unset, so database-backed integration and envtest
were not run by these commands. No cloud or cluster qualification command was
run for this baseline. CI job definitions are not evidence those jobs passed
for this worktree.

Agent local-state tests now reject group/world-readable state files, symlinks,
group/world-writable containing directories, partially initialized
identity/key/version records, and malformed or duplicate current/pending
Ed25519 private keys while preserving first-run initialization for a missing
private directory. This addresses master directive §§5 and 14 (durable agent
identity and secure local credential storage); it does not establish
Kubernetes Secret encryption at rest or key rotation qualification.

The qualification module's source-contract tests verify the explicit product
project deny in both Terraform validation layers. Terraform 1.14.6 format,
backend-free provider initialization, and validation now pass locally, and CI
runs the same checks without credentials or a cloud plan. No cloud plan/apply
or live qualification-project review was run.

The disposable qualification workflow now has a local command wrapper for
Terraform validation, read-only planning, saved-plan apply/destroy with a
project-bound interactive confirmation, existing runner preflight/execution,
context-checked diagnostic collection, evidence verification, and local
checksum-manifested archive creation. The wrapper requires a private
`terraform.tfvars`, exact single-project allowlist, and separate project
confirmation; it never automatically destroys after failure. Its project
designation is re-read from Cloud Resource Manager after saved-plan
confirmation and immediately before apply/destroy. Each GCP wrapper execution
also rechecks project identity, active state, allowlist, and disposable label,
then requires a separate typed project confirmation before the exact target
confirmation is used. These checks still do not enumerate or prove a project
empty; manual project-resource review remains mandatory. Diagnostic redaction
is best-effort and archives still require review and transfer to independently
administered retention. Wrapper unit tests and Terraform backend-free
validation are implemented; no lab project, cloud plan/apply, cluster, or
upgrade was used.

Cluster admission inventory now lists only the supported webhook and
ValidatingAdmissionPolicy configuration resources using Kubernetes
`PartialObjectMetadata` responses and sends aggregate object counts to the hub.
It does not fetch admission specs or send object metadata, webhook URLs, CA
bundles, or policy bodies. If discovery fails, a served resource cannot be
listed, or the bounded result exceeds the limit, the whole admission
observation is `Unknown` and partial counts are discarded. This makes the inventory more informative
for compatibility assessment without treating configuration presence as proof
of active or effective enforcement. The agent-inventory RBAC profile is
read-only and includes these list permissions in both Helm and Kustomize.

## Architectural dependencies

1. Qualified discovery and compatibility records must precede enabling an
   executor for a distribution/version.
2. Immutable typed policy and action binding must be consistent from API
   approval through scheduler, signed permit, local operator, and fixed EE.
3. Durable local checkpoints and ownership evidence must precede recovery,
   retry, cancellation completion, or reservation release.
4. Distribution/OS qualification requires isolated disposable infrastructure,
   captured host and Kubernetes evidence, independent review, and safe teardown.
5. Self-hosted production readiness depends on PostgreSQL operational design,
   secret and identity configuration, TLS/network boundaries, and restore/DR
   evidence; Helm/Kustomize manifests alone are insufficient.
6. Capacity and SLO decisions depend on measured API/scheduler/database load and
   restart/failure behavior, not the synthetic simulator alone.

## Implementation sequence

This sequence is incremental; no broad feature is marked complete by this
baseline.

1. **Milestone 1 — baseline and compatibility contract:** baseline and the
   read-only Kubernetes registry are implemented. Remaining work is
   distribution-specific automated qualification and real compatibility
   evidence; no matrix row is qualified.
2. **Milestone 2 — durable safety conformance:** extend cross-layer state,
   policy, authorization, ownership, cancellation, and restart tests; fix only
   demonstrated gaps without relaxing gates.
3. **Milestone 3 — Ubuntu/Debian qualification:** use a dedicated disposable
   project/VM lab only after it is explicitly authorized; execute the existing
   clean/failure matrix and archive reviewed evidence. Until then the rows stay
   NOT RUN.
4. **Milestone 4 — RPM/AL2023 qualification:** only after Ubuntu core cases
   have real recorded evidence; retain Fedora and unlisted releases as
   unsupported.
5. **Milestones 5–8 — execution supply chain, policy/campaign, provider, and
   storage integrations:** implement one adapter at a time with typed binding,
   tests, allowlists, local vetoes, and explicit qualification boundaries.
6. **Milestones 9–10 — security, tenancy, and self-hosted production
   deployment:** fill documented controls and exercise migrations, HA, backup,
   restore, and rollback in disposable infrastructure.
7. **Milestones 11–12 — observability, dashboard, and disconnected delivery:**
   implement remaining workflows and validate without external access.
8. **Milestone 13 — production readiness:** measure scale and SLOs; obtain
   independent security and operational review; qualify only the tested
   combinations.

## Risks and migration requirements

- Strict OS identity/catalog changes can reject previously accepted hosts;
  keep unknown IDs and majors fail-closed and review the policy digest.
- Additive agent inventory fields require hub-first deployment where older
  servers reject unknown data.
- CRD/API schema changes require generated CRD parity across operator source,
  Helm, and Kustomize; preserve stored objects and status across upgrades.
- Database changes require immutable forward migrations, migration checksums,
  backup and tested restore; never assume binary rollback is schema-safe.
- New provider/storage credentials require least privilege and are configured
  only on the local cluster where the adapter is explicitly enabled.
- Real host/provider tests can cause outages and cost. They require approved,
  isolated disposable targets, independent reviewer, recovery access, evidence
  retention, and explicit execution authorization.
- Documentation can become misleading if roadmap status is treated as
  qualification. `docs/production-upgrade-requirements.md` remains authoritative
  for upgrade qualification and every unperformed case remains NOT RUN.

## First implementation increment after baseline

The read-only Kubernetes compatibility contract is implemented in API,
discovery, control-plane, CLI, and dashboard layers. The authenticated registry
endpoint and `kordex-discover -kubernetes-matrix` expose ten named targets,
permission profiles, CRDs, network requirements, operations, test coverage,
and limitations. No target, version, node OS, or architecture is marked
qualified. K3s, RKE2, and k0s detection now matches complete version suffixes;
substring hints are rejected. Unknown and conflicting cluster hints remain
`unknown`. This increment does not alter execution gates or make external
infrastructure changes. The optional Kustomize host-execution permission
component is separated from the default overlay and covered by render checks.
The operator also verifies its effective host-execution Kubernetes permissions
with self-scoped access reviews before constructing the executor. Denied,
indeterminate, or failed reviews disable the executor and keep the published
capability false. This capability check does not qualify host package/reboot
behavior.

## Follow-up implementation increment — cluster compatibility summary

The fleet API and dashboard now show a read-only cluster summary computed from
persisted node inventory: distribution hints, node count, distinct OS display
strings, and architectures. Incomplete identity is `Unknown`, multiple known
distribution hints are `MixedSignals`, and known targets without evidence are
`Unqualified`. An unknown node hint alongside one known hint remains `Unknown`.
The summary never promotes a cluster to qualified and is not an input to
maintenance authorization. `Node.status.nodeInfo.osImage` is not normalized
host `os-release` identity. The compatibility catalog and host/provider
qualification rows remain unqualified/NOT RUN.

Follow-up verification: cluster assessment unit tests, full Go tests, `go vet`,
all Go binary builds, OpenAPI checks, dashboard tests/typecheck/lint/production
build, and PostgreSQL-backed store/API integration tests passed. The database
tests used a fresh local PostgreSQL 17 container that was removed after the
run. `KUBEBUILDER_ASSETS` remains unavailable, so envtest and real Kubernetes
distribution qualification were not run. No cloud, live-cluster, package,
reboot, or provider operation was performed.

Milestone 2 restart evidence follow-up (2026-11-20):
`TestEnvtestRestartPreservesCancelAndRecoveryFence` passes against the
API-server-backed envtest CRD. It reconstructs a reconciler over persisted
in-progress operation status, an existing eviction checkpoint, signed
cancellation, an operation-owned cordon, and the reservation Lease. Recovery
keeps ownership and the reservation fenced until safety checks pass, does not
repeat eviction, then releases only the owned cordon and reservation. This is
controller restart-pattern evidence in envtest, not a live-cluster restart or
distribution qualification. Host-upgrade gates remain off and the host-upgrade
qualification matrix remains NOT RUN.

## Follow-up implementation increment — aggregate fleet observability

The scheduler's database snapshot now exports aggregate cluster connectivity,
node readiness, oldest heartbeat/inventory age, and snapshot refresh time.
Readiness is `unknown` when inventory is stale or has no valid boolean readiness
value. These gauges carry no tenant, cluster, node, operation, or user labels,
and do not participate in maintenance authorization. Scheduler replicas export
the same global snapshot, so dashboards use `max` for these gauges. The new
Grafana fleet dashboard makes snapshot age visible so an absent or stale scrape
does not look healthy.

Qualification is limited to automated metric rendering tests and the
PostgreSQL-backed scheduler snapshot test. The dashboards and scrape/network
configuration have not been exercised against a deployed Prometheus/Grafana
stack; no SLO or alert threshold is asserted by this increment.

## Follow-up implementation increment — exact node detail lookup

The organization inventory API now accepts an exact `nodeUid` filter only when
paired with a cluster ID. The database query applies organization, cluster, and
UID predicates together, and the dashboard uses that bounded lookup for a new
read-only node detail page instead of searching the capped fleet list. The page
shows reported OS/kernel/runtime/Kubernetes attributes, freshness, scheduling
state, provider ID, zone, and labels. It labels this information as inventory;
none of it grants maintenance approval or compatibility status.

API filter validation, exact UID selection, and cross-organization scoping are
covered by tests. The new dashboard route still needs browser-level visual and
identity integration validation. It does not add node mutation or maintenance
controls.

## Follow-up implementation increment — restore schema integrity

The PostgreSQL restore drill previously required only schema version 7. The
current application has migrations through version 9, so an older archive
could pass that guard. The restore script now derives the complete contiguous
migration sequence from this checkout and compares every restored version and
SHA-256 checksum before reporting success. It retains same/unknown-server
refusal, rejects targets with existing user relations, verifies the archive
checksum, and uses a single-transaction no-drop restore. Guard tests cover
stale/incomplete histories and checksum failures with command doubles. A
subsequent disposable PostgreSQL 17-alpine run created
a backup, restored it to a separate empty database, verified all migration
checksums, and passed the store test suite against the restored database. The
source and target used separate PostgreSQL containers on a local Podman
network; this does not establish off-host isolation, production HA, PITR, or
RPO/RTO.

Verification for this increment: `bash -n scripts/restore-drill.sh scripts/test-restore-drill.sh`
and `bash scripts/test-restore-drill.sh` passed. The regression test is wired
into `make test` and CI. The temporary database container was removed; no
existing or customer database was restored or modified.

The backup path now also enforces private libpq service-file permissions,
creates unique same-second archive names, validates the archive before
publication, and uses no-replace hard links to publish the archive, checksum,
and manifest. Checksum entries are relative to the archive directory so the
bundle can be relocated together. Command-double tests cover mode enforcement,
same-second runs, existing-name collision refusal, checksum/manifest contents,
file modes, and failed-dump cleanup; they do not replace real DB or off-host
backup qualification.

## Follow-up implementation increment — hub disruption availability

For master directive requirement 16, both self-hosted management-plane
deployment methods now create `minAvailable: 1` PodDisruptionBudgets for the API,
scheduler, and dashboard and use preferred pod anti-affinity across node hostnames.
The Helm control-plane and dashboard charts provide matching budgets. The
anti-affinity remains soft so the hub can still schedule on a single-node or
capacity-constrained site; the PDB blocks voluntary disruption below one
available replica. Keep at least two schedulable nodes for voluntary node
maintenance while preserving one replica of each component. These controls do
not establish PostgreSQL failover, scheduler replica fault behavior, measured
SLOs, or production availability.

Verification: Helm v3.19.0 lint for both management-plane charts, Helm/Kustomize
rendered-selector checks, and offline Kustomize configuration tests passed. The
render test is wired into the Helm CI job. No cluster was
changed and no availability or failover qualification was performed.

## Follow-up implementation increment — scheduler probes

The scheduler now serves `/healthz` for process liveness and `/readyz` only
after a successful database-backed scheduling tick, becoming unready when no
successful tick has occurred for 15 seconds. Helm and self-hosted Kustomize
declare Kubernetes startup, liveness, and readiness probes. Successful idle
ticks count as healthy database interaction; a database outage makes the
scheduler pod unready while keeping it alive to resume after recovery. Startup
probes are also configured for the API and dashboard. This does not establish
API-level scheduler health, database HA, or replica failover under fault.

Verification: the new scheduler health unit test, management-plane Helm lint
and Helm/Kustomize render checks passed. No cluster was changed or used for a
health/failover drill.

## Follow-up implementation increment — self-hosted HTTPS ingress

Both self-hosted Helm workloads can now create opt-in `networking.k8s.io/v1`
Ingress resources with required host and pre-created TLS Secret values. The
Kustomize hub has a separate opt-in overlay with configurable API/dashboard
hosts, IngressClass, separate pre-created TLS Secrets, and matching HTTPS
dashboard API URLs; the default overlay remains Ingress-free. The templates
route distinct hosts to the corresponding ClusterIP Services and do not create
certificates or an Ingress controller. The Kustomize overlay also restricts
application ingress to the sample ingress-nginx namespace and pod labels. Helm
has configurable source-peer rules for the same ingress control; both chart
defaults remain disabled.

Verification: the ingress render test confirms default-off behavior, required
Helm host/TLS values and NetworkPolicy source peers, rejection of empty
allow-all selectors and universal CIDRs, both Kustomize routes/policies, and no
generated TLS Secret. It is wired into Helm CI. No cluster, DNS, certificate,
CNI, or ingress controller was changed or qualified.

## Follow-up implementation increment — restricted management-plane egress

The control-plane Helm chart now offers default-off egress policies for API,
scheduler, and migration pods. The dashboard chart separately restricts its
server-side pod. Enabling a chart requires shared and component-specific
destination/port rules; the values schema rejects empty selectors, universal
CIDRs, empty port sets, and invalid numeric ports. The Kustomize
`self-hosted-restricted-egress` overlay adds policies for DNS and in-cluster
PostgreSQL/OIDC peers selected by explicit namespace and pod labels. It remains
the deployer's responsibility to adapt peers for external dependencies,
NodeLocal DNS, metrics, and telemetry. NetworkPolicy policy union behavior and
CNI enforcement must be checked at the site.

Verification: six Helm/Kustomize contract tests passed for default-off
behavior, mandatory peer configuration, per-component rendering, invalid
destination/port rejection, and the restricted overlay. No CNI or cluster was
used, so effective traffic isolation is not qualified.

## Follow-up implementation increment — OIDC bearer token contracts

The existing ID-token mode remains the default and retains its configured
issuer/audience/signature/expiry/authorized-party validation. An explicit
RFC 9068 access-token mode now requires the `at+jwt` type, one exact API
audience, issued-at and expiry, subject, dashboard OAuth client ID, nonempty
token ID, and configured scopes. The dashboard requests those scopes, sends
the access token to the API, retains ID-token profile claims only for the
server session setup, and verifies both token subjects agree with the API's
membership identity. Agent Ed25519 credentials remain separate. Helm and
Kustomize expose the mode without changing defaults; the offline Kustomize
helper validates and writes the paired API/dashboard settings.

Verification: local Go verifier/config tests cover accepted and rejected token
contracts; dashboard unit tests cover mode/scope parsing and bearer selection;
dashboard test/typecheck/lint/build, Helm/Kustomize render checks, and the
offline Kustomize configuration test passed. CI runs the render test. No real
OIDC provider, login, scope mapping, JWKS rotation, or production identity
qualification was performed. Existing deployments remain in ID-token mode
until operators deliberately configure both API and dashboard.

## Follow-up implementation increment — recovery phase-journal capacity

Repeated blocker changes during a long `RecoveryRequired` operation could grow
phase events past the 256-event limit accepted by `OperationReport.Validate`.
The operator now fixes the visible reason to `AuditCapacityReached` after the
240-event threshold, stops adding duplicate capacity events, and still writes
forced structured checkpoints at the same phase and sequence. The regression
test verifies the stored checkpoint and that the complete report remains
valid. `make test` and `make vet build contract` passed; the focused test passed
again after adding the persisted-report assertion. This remains fake-client
evidence and does not qualify real operator restart, cluster recovery, or host
maintenance.

## Follow-up implementation increment — durable operation phase graph

The protocol now rejects invalid initial report phases and phase jumps, while
the operator validates status writes against the same transition graph and
checks that its current status still matches the last durable event. Repeated
`Blocked` events resume from the last non-Blocked phase; mutation-time
cancellation cannot jump directly to a terminal phase. A terminal operation
may re-enter `RecoveryRequired` only with reason `TerminalRecoveryIncomplete`;
the operator emits that transition after checking the original node UID and
cordon-owner annotation. The hub requires the reason but cannot independently
inspect that cluster-local evidence. If recovery lacks the original-cordon
checkpoint, it stays nonterminal and retains its slot.
`make test`, `make vet build contract`, and the full control-plane store suite
against a temporary loopback PostgreSQL 17 container passed. This is
automated state-contract evidence, not live operator restart or Kubernetes
recovery qualification.

## Follow-up implementation increment — phase-event chronology

The shared operation-report validator now rejects event timestamps that move
backwards while allowing equal timestamps for coarse-resolution clocks. The
operator clamps a newly persisted phase event to the previous event time if
its wall clock steps backwards, so its own reports continue to satisfy that
contract. The focused protocol and controller chronology tests passed. This
increment's `make test` and `make vet build contract` also passed. The full
`control-plane/internal/store` suite passed against temporary PostgreSQL 17
bound to loopback; the container was removed after the run. This verifies
event ordering and report ingestion, not clock accuracy or live restart
recovery; UPG-05/UPG-14/UPG-18 and qualification status remain incomplete.

The hub applies a two-minute future-clock bound to phase events and
host/provider checkpoint timestamps using PostgreSQL `clock_timestamp()`.
Reports outside the bound are rejected before sequence or audit updates. The
sync response uses the database wall clock rather than transaction-start
`now()`, keeping returned time current for long transactions. Protocol and
database-backed operation-ingestion tests cover this path. This does not
replace clock monitoring or live failure qualification.

Hub operation ingestion now checks the signed request action against every
reported phase transition and successful terminal path. ValidateOnly cannot
report a drain or executor phase; DrainAndVerify success must include drain,
recovery verification, and uncordon; host upgrade success must include
preflight, drain, execution, recovery, uncordon, and a terminal host checkpoint;
provider success must include post-update workload verification and a terminal
provider checkpoint with original node identity evidence (or a recorded
already-current version). The local operator remains authoritative. Protocol
and PostgreSQL-backed store tests cover accepted and rejected action histories;
this does not prove that reported work occurred on a live cluster.

## Follow-up implementation increment — organization recovery queue

The API now exposes a paginated, organization-scoped read of `Blocked`,
`RecoveryRequired`, and `Failed` operations with phase, checkpoint, inventory,
and agent-connectivity context. A database index supports the filtered queue.
The dashboard displays these results and links to campaign operation history;
it offers no retry, uncordon, or reservation-release control. This makes
failure evidence easier to find without changing cluster-local recovery
authority. API tests, a disposable PostgreSQL 17 query/tenant-isolation test,
OpenAPI checks, dashboard tests/typecheck/lint/build passed. Helm v3.19.0 lint,
workload parity, production image pin, egress, ingress, OIDC, offline-values,
and availability render tests passed using the CI-pinned version in a temporary
tooling directory. This is partial UPG-14/UPG-16/UPG-18 progress, not recovery
qualification; host-upgrade rows remain NOT RUN.

## Follow-up implementation increment — operation lifecycle metrics

UPG-17 now has bounded operator terminal-outcome counters, a separate
RecoveryRequired counter, terminal operation duration, verified drain-phase
duration, and reboot-to-host-verification histograms. The action label comes
from the immutable signed authorization and uses a fixed allowlist; arbitrary
values map to `other`. Durable scheduler
snapshots export the oldest active reservation age, and omit reservation
samples until a successful snapshot exists. The operations dashboard includes
the new metrics and the example reservation-age alert keeps the reservation as
a safety interlock. Its four-hour threshold needs review against local timeout
configuration before use.

Operator and telemetry unit tests passed, and the complete store integration
suite passed against a temporary loopback PostgreSQL 17 container, including
active reservation age. The test harness initializes the public migration
chain before per-test schemas because migration 011 binds its security-definer
function to `public`; API bearer tokens are unique per test so revocation
records do not leak across runs. The container was removed. No monitoring
stack, scrape, alert, or trace pipeline was qualified, and no SLO is asserted.
UPG-17 and production qualification remain incomplete.

The API HTTP middleware now records route-template spans with bounded methods,
status codes, and duration, continuing inbound W3C trace context. Scheduler
ticks have spans with bounded outcome/error class and admitted-operation count;
the scheduler initializes and shuts down the OTLP/HTTP exporter alongside the
API. Helm and Kustomize expose an explicit collector endpoint, empty by default.
Helm schema and runtime validation reject credentials, query strings, and
fragments in endpoint URLs. Focused tests verify trace propagation, bounded
attributes, invalid endpoint rejection without echoing the URL, and default-off
deployment wiring. The five Helm/Kustomize parity tests, control-plane Helm
lint, repository `make test`, and `make vet build contract` passed after runtime
endpoint validation was added. A collector, private TLS/egress path, retention
policy, and production trace continuity have not been validated. The
maintenance operator has bounded reconciliation spans; the agent has
allowlisted outbound API spans and propagates W3C context to the API, but no
collector-backed end-to-end trace has been observed. UPG-17 remains partial.
