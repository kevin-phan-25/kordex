# M3 qualification readiness — customer input and provisioning gate

Status snapshot: 2026-11-21. This document does not provision infrastructure,
enable maintenance, change the qualification matrix, or claim qualification.
The authoritative acceptance criteria and matrix remain in
[`production-upgrade-requirements.md`](production-upgrade-requirements.md).
The current deployment gate and complete customer input inventory are in
[`m3-deployment-readiness.md`](m3-deployment-readiness.md). Its local report
does not contact GCP or replace the guarded Terraform preflight.

## Decision

**NOT READY for lab provisioning.** Existing artifact/trust tooling can accept
customer inputs, and the agent's opt-in mTLS transport plus standalone
management-cluster relay are implemented locally. The customer route is not
provisioned or tested. No real artifact
approval, release handoff, private route/relay, enrolled self-managed cluster,
or host evidence is available. The lab Terraform has now been changed locally
to remove Cloud NAT and destination-wide public HTTPS, allow only explicit
customer RFC1918 destinations plus the restricted Google APIs VIP, and route
Ubuntu apt through a required customer mirror. These are source-level changes,
not live network evidence. No Terraform plan/apply or network test has run.
Private route and K3s/container-image mirror readiness remain unresolved.
Owner-specific decisions, evidence, verification and secure transfer are listed in
[`m3-customer-input-checklist.md`](m3-customer-input-checklist.md).

The repository now has consolidated artifact intake and read-only private OCI
registry verification. Guarded lab planning requires every intake row to pass
and regenerates the report before planning, applying, and qualification
execution. These are local implementations only: no customer trust,
release/package artifacts, registry
contents, or private endpoint has been supplied or verified. See
[`m3-artifact-intake.md`](m3-artifact-intake.md).

The private-connectivity design review is recorded in
[`private-management-connectivity-architecture.md`](private-management-connectivity-architecture.md).
The standalone relay and Helm chart now exist and have local synthetic tests.
No private route, customer PKI, published relay image, or live CNI enforcement
has been verified. The architecture is not ready to provision.

The replacement GCP project was inspected with explicit project flags on
2026-11-21. The active identity was `kphan25@gmail.com`. Project
`kordex-fleet-platform-515416` (number `209068399397`) is `ACTIVE`; billing is
enabled, and the `kordex-disposable=qualification` label was applied and
verified. Service Usage is enabled. Compute Engine, IAM, Cloud Resource
Manager, IAP, Secret Manager, and Cloud DNS APIs are not enabled; Artifact
Registry is also not enabled. The Compute Engine resource inventory could not
be queried because its API is disabled, so the existence of networks, VMs,
disks, or firewall rules is NOT VERIFIED. The K3s lab does not require GKE's
Container API. No APIs or IAM grants were changed during this inspection.

Billing is enabled, but actual billed usage and remaining promotional credit
were not inspected. The only cloud mutation was applying the
`kordex-disposable=qualification` project label. No API, IAM, infrastructure,
Terraform plan/apply, deployment, or maintenance changes were made. The ignored
`terraform.tfvars` was not read, modified, formatted, or inspected.

## M3 acceptance boundary

M3 is real host-maintenance evidence: register and enroll the disposable
infrastructure; create and approve a signed host plan; apply a real package
change; safely drain one worker; perform controlled host maintenance and
reboot; verify the original host and Kubernetes node recover, workloads are
healthy, and the owned cordon/reservation are released; exercise failure
handling; and archive independently reviewable evidence.

The lab is one K3s server and two Ubuntu 24.04 workers. The workers are eligible
peers for one another; the control-plane server is not a maintenance target.
The canonical matrix in
[`host_upgrade_failure_matrix.json`](../tests/integration/host_upgrade_failure_matrix.json)
has 11 cases and requires both `debian` and `rhel` evidence. Ubuntu 24.04
results belong to the Debian-family column only. They must not be represented
as RHEL evidence or as a full matrix pass. The Ubuntu-only run is scoped M3
evidence; the existing matrix and all qualification rows remain **NOT RUN**.

## Network isolation decision

The self-managed module creates its own VPC and private-only VM interfaces;
there are no VM external IPs. The repository change removes Cloud NAT and the
TCP/443 `0.0.0.0/0` allow. It now allows DNS to the metadata resolver, HTTPS to
explicit customer RFC1918 CIDRs (TCP/443 for private mirrors and TCP/18443 for
the workstation relay), and HTTPS to the restricted Google APIs VIP
needed for the runtime Secret Manager token workflow. A private Cloud DNS zone
maps `*.googleapis.com` to that VIP. Ubuntu bootstrap replaces image-provided
apt sources with a required customer mirror and retains Ubuntu archive-key
verification. A deny-all egress rule remains. This is a code-level design only;
Cloud DNS, firewall precedence, routes, and DNS behavior have not been applied
or tested live.

Firewall rules enforce destination IP ranges, not FQDNs. The network owner must
confirm private mirror and relay DNS answers stay within the explicitly
approved CIDRs. TLS hostname verification and signed artifact digests remain
separate controls. The customer artifact-approval trust now also supports a
separate signed K3s system-image manifest and digest-verified OCI archive. No
real customer lock, archive, signature, or trust bundle has been supplied.

The canonical M3 entry checklist in
[`production-upgrade-requirements.md`](production-upgrade-requirements.md)
requires public/package-repository egress to be denied during installation and
recovery, with only documented site-local management, Kubernetes, registry,
and execution-environment-to-worker SSH flows allowed. Therefore a public
Cloudflare endpoint cannot be counted as compliant merely because Access
service-token authentication is enabled. No route or egress exception is
authorized here.

The detailed comparison of direct VPN routing, a workstation-side relay, a
management-cluster relay, and a customer private-service endpoint is in
[`private-management-connectivity-architecture.md`](private-management-connectivity-architecture.md). Its outcome is:

- Cloudflare Tunnel + Access uses a public edge and does **not** meet current
  M3 requirements. A public HTTPS proxy has the same limitation.
- Direct VPN routing is private, but direct access to the API is broader than
  necessary and still needs a customer TLS/mTLS terminator.
- A private relay in the management cluster is the recommended customer
  deployment target. The standalone Go relay and Helm chart locally implement
  server-side mTLS, URI-SAN-to-cluster mapping, five-route forwarding, and a
  private ClusterIP/NetworkPolicy profile. Customer PKI, image release, private
  routing/DNS, enforcing CNI, and live tests remain outstanding.
- A customer private-service endpoint can carry that relay across networks;
  it does not replace mTLS or Kordex application authorization. No endpoint
  exists or is priced.

For the current workstation-hosted M3 lab, the standalone relay now has an
opt-in workstation mode that binds to an explicit private interface, enforces
an explicit private source-CIDR allowlist, requires the existing customer mTLS
and certificate-to-cluster mapping, and forwards only to the loopback API at
`127.0.0.1:8080`. This closes the relay-code gap but does not supply the
customer private route, private DNS, host firewall policy, or customer PKI.
There is still no currently verified private route that satisfies M3. The new
private-egress Terraform source does not prove route reachability or deny
behavior until reviewed and tested in the approved lab.
Price any approved private endpoint, VPN, and relay before review; those costs
are not included in the existing lab estimate.

The workstation relay now has a distinct loopback-only health listener
(`127.0.0.1:18444` by default); its readiness check probes only the fixed
loopback API `/readyz`, while health paths remain absent from the agent-facing
TCP/18443 listener. The agent image also includes
`/kordex-agent connectivity-check`, a read-only probe that verifies approved
private DNS answers, pins the connection to an approved address, uses the
mounted mTLS material, and sends a signed agent identity request. These are
local code/test capabilities only; no private route, customer certificates,
or live connectivity has been verified.

Acceptance evidence for any selected route must include reviewed firewall and
routing rules, DNS and certificate checks, successful enrollment/reporting to
the intended endpoint, and negative tests proving arbitrary public hosts, IP
literals, redirects, and unapproved package repositories are blocked during
maintenance/recovery. Preserve firewall, proxy, DNS, and flow logs. An
authenticated public endpoint alone does not prove network isolation.

## Prerequisite inventory

Status values describe the actual inputs/evidence, not merely code existence.
“Repository complete” means local implementation exists; it is not live
qualification.

| Area | Prerequisite | Status | Owner and current evidence |
|---|---|---|---|
| Artifact trust | Organization-controlled customer artifact-approval Ed25519 key and independently verified key identity | CUSTOMER INPUT REQUIRED | Supply-chain custodian. The customer lock/tool is implemented; no production key or independently delivered public trust bundle is present. Never send private keys or seeds to Kordex developers. |
| Artifact trust | Approved K3s `v1.36.6+k3s1` `linux/amd64` binary, signed lock, detached signature, acquisition evidence, approval reference | CUSTOMER INPUT REQUIRED | Supply-chain custodian. Upstream standalone binary provenance is not independently established. Customer approval is not upstream provenance. No real binary approval was verified. |
| Artifact trust | Customer HTTPS mirror containing the exact approved bytes, reachable from lab VMs | CUSTOMER INPUT REQUIRED | Supply-chain custodian/network owner. Mirror URL and digest are signed and matched by the guarded plan helper; no mirror is configured. |
| Artifact trust | Offline lock/signature/trust verification and binary digest, ELF architecture, and version checks | REPOSITORY COMPLETE | `api/artifactlock`, `api/cmd/kordex-artifact-lock`, and guarded lab helper; local tests use synthetic fixtures only. Real artifact verification is NOT VERIFIED. |
| Artifact intake | Consolidated separate-domain trust/artifact report with fail-closed bootstrap and execution binding | REPOSITORY COMPLETE | `scripts/m3_artifact_preflight.py` composes the existing verifiers; guarded `plan`/`apply` and qualification `execute` require PASS and bind report K3s hashes to operation inputs. Local tests use synthetic fixtures; no production report exists. |
| Private registry | K3s and Kordex locked images exist in the approved private registry at the expected digests and architecture | CUSTOMER INPUT REQUIRED | `scripts/verify-private-registry.py` performs read-only Skopeo inspection through a customer auth file; no real registry image has been inspected or pushed. |
| Package intake | Approved Ubuntu 24.04 package plan and `.deb` archive match policy, versions, architecture, baseline delta, kernel/reboot policy, and private source | CUSTOMER INPUT REQUIRED | Preflight fetches the exact archive from its private TLS URL, checks it matches the selected archive SHA-256, then validates policy-bound package contents. No production package, baseline, policy approval digest, or mirror is available. |
| Artifact trust | Existing maintenance signing key and matching public operator bundle, with rotation overlap | CUSTOMER INPUT REQUIRED | Authorized maintenance-key custodian must use `docs/m3-trust-recovery-handoff.md` and provide only independently checked public material. No production bundle is available; no replacement key may be generated. |
| Artifact trust | Kordex signed offline bundle, image lock, package artifacts/policy, release public key, tool-provenance key, and Helm signer allowlist | CUSTOMER INPUT REQUIRED | Release owner. No actual signed release package or Ubuntu package set was verified. Release trust, tool provenance, maintenance trust, and customer artifact trust must remain separate. |
| Management plane | Local API and database availability | REPOSITORY COMPLETE | In this session `127.0.0.1:8080/readyz` and `127.0.0.1:8081/readyz` returned `{"status":"ready"}`; a PostgreSQL listener is present. This does not verify database records or remote reachability. |
| Management plane | Secure local configuration for the qualification runner | LOCAL CONFIGURATION REQUIRED | No `KORDEX_*` environment names were set in the current shell. Runner requires `KORDEX_API`, `KORDEX_ADMIN_TOKEN`, `KORDEX_ORG_ID`, `KORDEX_CLUSTER_ID`, `KORDEX_EXPECTED_CONTEXT`, `KORDEX_NODE_NAME`, `KORDEX_HOST_POLICY`, and `KORDEX_HOST_PLAN_DIGEST`; execution additionally requires `KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM`. Supply secrets interactively or through an approved secret store; never put them in shell history or evidence. |
| Management plane | Existing organization/fleet/site selection and registered self-managed cluster identity | CUSTOMER INPUT REQUIRED | Previously supplied records (not queried from PostgreSQL in this review): organization `Kordex GCP Test` `733ff86d-5dd0-4ad9-8476-0910f9eac046`, fleet `gcp-test-fleet` `1d08cef8-e5a3-443a-a5d1-9c871d9c2617`, site `gcp-test-site` `e8d9d100-aecb-4fb7-a284-55983998a588` (recorded `us-central1`). The existing GKE cluster record is not the self-managed K3s lab identity. An authorized administrator must confirm whether to reuse this organization/fleet/site and register a new cluster ID; do not create a tenant or membership implicitly. No self-managed lab cluster is registered. |
| Management plane | Short-lived cluster enrollment token and durable agent identity | LOCAL CONFIGURATION REQUIRED | After cluster registration, request one token through `POST /v1/organizations/{org}/clusters/{cluster}/enrollment-tokens`, store it mode 0600, enroll once, then verify agent identity/heartbeat. No token exists. The token expires after ten minutes and is single-use. |
| Management plane | Agent inventory/heartbeat and operation synchronization from the lab | NOT VERIFIED | Agent protocol and cluster-scoped signature validation are implemented and tested locally. No agent is enrolled or reporting. |
| Gateway | Agent-only HTTPS gateway and Cloudflare service-token support | REPOSITORY COMPLETE | `integrations/agentgateway` and the agent client implement five exact routes, loopback origin, TLS checks, and additional Kordex signature/authentication. Local fixture tests do not establish a Cloudflare deployment. |
| Gateway | Cloudflare Tunnel + Access public endpoint | NOT ACCEPTED FOR CURRENT M3 | This is a prepared public-edge option only. It requires a Cloudflare-managed domain and Access policy, but even if correctly configured its public transport does not satisfy canonical site-local/no-public-egress M3 criteria. No account, tunnel, DNS, or token was configured. |
| Gateway | Private mTLS relay and customer route | PARTIAL — LOCAL IMPLEMENTATION | `integrations/agentrelay` supports the management-cluster Service mode and opt-in workstation mode. Workstation mode requires a private interface bind, private peer-CIDR allowlist, fixed `http://127.0.0.1:8080` upstream, verified client certificates, URI-SAN-to-cluster mapping, signed cluster matching, and the exact five-route allowlist. Synthetic Go tests cover mode boundaries and forwarding. The existing chart remains cluster-Service mode. Customer PKI, immutable image release, private routing/DNS, workstation firewall, enforcing CNI for the chart mode, and live network tests remain NOT VERIFIED. The API still validates Kordex Ed25519/proof, identity, tenant/cluster authorization, and operation controls independently. |
| Agent transport | Fail-closed mTLS client transport configuration | REPOSITORY COMPLETE (LOCAL TESTS) | `agent/internal/client` loads customer-mounted client cert/key and dedicated server CA, verifies the expected DNS name, rejects invalid/expired material, and does not fall back; Helm values and an opt-in self-managed Kustomize patch mount Secrets. Synthetic certificate tests pass. Customer PKI, server-side certificate-to-cluster policy, reload/rotation lifecycle, and live relay use remain NOT VERIFIED. |
| Gateway | Actual VM-to-hub connectivity and TLS validation | NOT VERIFIED | No Kubernetes contexts are configured locally, and no Cloudflare/private route was configured. The agent requires `KORDEX_CONTROL_PLANE_URL`, `KORDEX_CLUSTER_ID`, an enrollment-token file, and durable identity state. The legacy Cloudflare path additionally requires gateway authentication and its Secret; private mTLS requires `KORDEX_MTLS_ENABLED=true`, client cert/key, server CA, and matching DNS name. TLS client support is implemented; end-to-end connectivity is absent. |
| GCP | Correct disposable project and live qualification label | VERIFIED | Read-only verification passed for active project `kordex-fleet-platform-515416`; label `kordex-disposable=qualification` was applied at the user's request. This is not approval to provision. |
| GCP | Compute, IAM, Cloud Resource Manager, Service Usage APIs | CLOUD APPROVAL REQUIRED | Service Usage is enabled; Compute, IAM, and Cloud Resource Manager APIs are disabled. Exact API enablement approval is required before enabling them. |
| GCP | IAP, Secret Manager, and Cloud DNS APIs | CLOUD APPROVAL REQUIRED | All three are disabled. IAP supports private VM administration; Secret Manager supports runtime-only K3s join-token delivery; Cloud DNS supplies the restricted Google APIs mapping. |
| GCP | Artifact Registry API/repository | CUSTOMER INPUT REQUIRED | API is disabled and no repository inventory was available. If customer-approved images will use Artifact Registry, choose an approved repository and separately approve enabling its API; do not reuse the old product project. |
| GCP | VM service accounts and least-privilege IAM | CLOUD APPROVAL REQUIRED | Terraform creates separate server/worker identities and secret-scoped permissions. Provisioning also requires reviewed Compute/VPC/firewall/Cloud DNS/service-account/Secret Manager IAM permissions and `iam.serviceAccounts.actAs`. Current user has project Owner, but permission is not approval. IAP operator requires narrowly scoped tunnel, OS Login admin, service-account use, and instance/project discovery access. No IAM was changed. |
| GCP | Private custom VPC, IAP-only SSH, no VM external IP, three-node Ubuntu/K3s topology | REPOSITORY COMPLETE | Terraform module defines separate VPC, IAP ingress, private VMs, one server/two Ubuntu workers and peer outputs. No plan/apply or live verification occurred. Do not use the existing default VPC. |
| GCP | Public/package egress restriction during package apply and recovery | IMPLEMENTED — STATIC, NOT LIVE VERIFIED | Terraform source removes NAT and public TCP/443. Required private RFC1918 CIDRs are validated and used for HTTPS; restricted Google APIs use a private DNS zone, Private Google Access, and a specific VIP firewall rule. Ubuntu apt is forced to a supplied HTTPS mirror with signed repository metadata. Startup now verifies and installs the customer-signed K3s system-image archive and disables public registry fallback. Customer CIDRs, DNS, route reachability, mirror contents, host behavior, and deny tests are still required. |
| GCP | Ubuntu apt, K3s system images, and Kordex image source | REPOSITORY COMPLETE / CUSTOMER INPUT REQUIRED | Local signed-manifest verification and atomic private-file-mirror staging are implemented. Startup binds K3s version, `linux/amd64`, archive digest, content-addressed HTTPS URL, and private registry configuration; it imports the archive before starting K3s and disables public registry fallback. Customer must provide the real approved archive/lock/signature/trust, mirror, populated private registry, Ubuntu mirror, and immutable agent/operator/Ansible EE images. No production artifact or live bootstrap has been verified. |
| GCP | Snapshot/reset strategy for independent failure cases | IMPLEMENTED — LOCAL TESTS; NOT LIVE VERIFIED | `scripts/self_managed_lab_recovery.py` and `self_managed_lab.py recovery` capture a fresh three-node healthy/idle baseline, create and verify complete labelled snapshots only while all VMs are stopped, and restore only the full server/two-worker topology via a reviewed Terraform plan. Restore checks machine ID, new boot ID, Kubernetes node UIDs and workload health. Partial snapshot sets are unusable; failures preserve resources and produce audit records. The recovery inputs persist in a mode-0600 ignored file so regular plans do not silently revert disks. No GCP operation or restore was run. Snapshot pricing is not included in prior session estimates; see the lab README and verify current pricing before approval. |
| GCP | Serial-console and out-of-band recovery access | CONFIGURED IN SOURCE; NOT LIVE VERIFIED | Terraform sets only each VM's `serial-port-enable=TRUE`; no project-wide setting or IAM grant is made. The guarded diagnostic helper validates the lab instance, captures bounded redacted output and records a digest. Required `compute.instances.getSerialPortOutput` access and real serial/boot recovery remain customer approval and live verification. |
| GCP | Network fault injection and independent fault logs | IMPLEMENTED — LOCAL TESTS; NOT LIVE VERIFIED | The opt-in helper verifies a private endpoint is reachable, applies one exact-lab/tag TCP deny rule for at most 900 seconds, observes disconnection, removes it, verifies restoration, and retains a per-lab lock when automatic recovery fails. Manual recovery verifies and removes only the exact recorded rule. Evidence binds to an independently retained SHA-256. The VM has one TCP/18443 path to the relay/API chain, so relay and API path interruptions are not independently distinguishable; mirror interruption uses TCP/443. These are supplemental to, and do not complete, canonical matrix rows. No fault was applied. |
| GCP | Cleanup and budget | NOT VERIFIED | Guarded destroy and resource checks are documented. Compute resource inventory was unavailable because Compute Engine API is disabled. Billing data, budget remaining, and future cleanup success are NOT VERIFIED. |
| Maintenance | Worker-peer eligibility and local safety checks | REPOSITORY COMPLETE | Operator requires an eligible Ready peer; Terraform provides two workers. Unit/API-server tests do not verify this live lab. |
| Maintenance | SSH execution account, private key, known-host pin, EE digest/pull credentials | LOCAL CONFIGURATION REQUIRED | Customer must provision the exact disposable worker SSH credential and pinned `known_hosts`, verify sudo scope, and select an immutable EE digest. No credentials or image allowlist are configured. |
| Maintenance | Ubuntu policy, package baseline, signed plan, approval and execution credentials | CUSTOMER INPUT REQUIRED | Release owner supplies verified package artifacts/policy; authorized Kordex admin selects OS identity allowlist, plan digest and operation approval. Reboot policy must require a controlled reboot and kernel expectation if the plan updates the kernel. |
| Maintenance | Drain, real package update, reboot, recovery, workload checks | NOT VERIFIED | Implemented code and local tests exist. No live worker, operation, package change, reboot, recovery, reservation release, or workload check occurred. |
| Maintenance | Cancellation/failure cases and evidence verifier | REPOSITORY COMPLETE | Runner, failure recorder, evidence verifier, and matrix have local tests. External fault injection and all actual outcomes remain NOT RUN. |
| Maintenance | Qualification evidence and second review | CUSTOMER INPUT REQUIRED | Independent reviewer must inspect host journal, actual package delta, reboot identity, workload state, fences/reservations, fault logs, and archived checksums. No evidence exists. |
| Customer deployment | Independent install/operate/troubleshoot readiness | NOT VERIFIED | Customer deployment guides and Helm/Kustomize/Compose paths exist, but no independent team has completed an installation rehearsal. This is an M6 readiness item, not an excuse to broaden M3. |
| Customer deployment | Self-managed spoke Kustomize trust and immutable images | CUSTOMER INPUT REQUIRED | The overlay requires `keys.json`, intentionally absent from production configuration, and example image references are placeholders. The maintenance custodian supplies the existing public JSON trust map; release owner supplies digest-pinned images. A temporary-fixture render test verifies packaging only; real trust and image verification remain blocked. |

## Self-managed overlay trust input

The overlay's generated ConfigMap `kordex-hub-trust` mounts `keys.json` at
`/var/run/kordex-trust/keys.json`, consumed through
`KORDEX_HUB_PUBLIC_KEYS_FILE`. It must be a JSON object mapping each existing
maintenance signing key ID (lowercase SHA-256 of the raw Ed25519 public key)
to that key encoded as unpadded standard Base64. Multiple entries preserve
rotation overlap. The authorized maintenance-key custodian supplies only this
public bundle, derived from the existing key by
[`m3-trust-recovery-handoff.md`](m3-trust-recovery-handoff.md) and independently
checked against its key inventory. The private key/seed is never requested or
transferred. Artifact-approval, Kordex release, tool-provenance, and
maintenance-operation trust remain separate.

The production overlay intentionally has no checked-in `keys.json`; do not
create a placeholder or trust material to make a normal production render
succeed. `tests/infrastructure/test_self_managed_kustomize_trust_fixture.py`
copies only tracked overlay inputs to a temporary sibling directory and adds a
clearly marked invalid synthetic value solely to exercise Kustomize packaging.
It verifies that the generated ConfigMap and agent/operator resources render
and both upgrade gates remain false. The temporary value is not a valid key,
is never installed, and is not evidence of trust. A real render/deployment
requires the custodian's independently verified public bundle and reviewed,
digest-pinned release images.

## Execution window and cost planning

The GCP lab module uses three `e2-standard-2` VMs, three 40 GiB
`pd-balanced` disks, and one private Cloud DNS zone. Its updated planning
estimate is about `$0.217747/hour`: `$0.87` for four hours and `$1.74` for eight
hours. DNS queries, private route/VPN, mirror transfer, taxes, and services
outside the estimate are additional. Thirty days is about `$156.78`; 90 days is
about `$470.33` before variable costs and exceeds the `$300` M3–M6 target.
Stopped VMs still leave billable disks and the private DNS zone. This estimate
is not billing data or a spend cap.

| Work | Planning window | GCP baseline estimate |
|---|---:|---:|
| Customer trust, artifact review, private route and API preparation | Several days may be needed; no lab resources | `$0` lab runtime |
| Create/bootstrap, registration, inventory, preflight, and clean-upgrade | Reserve 4–8 hours; use 8 hours for the first session | `$0.87`–`$1.74` plus variable costs |
| One independent failure case and fresh-baseline recovery | Reserve 4–8 hours per case until measured | `$0.87`–`$1.74` plus variable costs |
| Full Ubuntu set of 11 pinned matrix cases | At least 11 independently baselined cases; likely multiple sessions | About `$9.57`–`$19.14` base if each case uses 4–8 hours, excluding resets/variable costs |

Reset/rebuild duration and full-run cost are NOT VERIFIED. Do not leave the lab
between sessions. RHEL evidence is outside the Ubuntu-only lab and remains
required by the canonical full-matrix verifier.

Recovery snapshots are additional and were not included in those VM estimates.
For planning only, the current regional standard snapshot rate in `us-east1` is
`$0.05/GiB-month`, prorated with a one-hour minimum. The three 40-GiB disks
have a 120-GiB provisioned ceiling, so a conservative full-data one-set bound
is about `$6/month` (`~$0.033` for four hours); actual compressed incremental
storage is based on changed blocks and may be lower. Snapshot chains and
configured recycle-bin retention can keep storage billable after deletion.
Verify current [Google Compute Engine snapshot pricing](https://cloud.google.com/compute/disks-image-pricing),
project snapshot location/retention, and actual billing. No snapshots exist or
were created by this task.

## Exact customer inputs and approvals

Use [`m3-customer-input-checklist.md`](m3-customer-input-checklist.md) as the
owner-by-owner handoff; it records the required evidence, independent
verification, sensitivity, transfer channel, and blocked work. The dependency
order is:

1. Customer decisions: network/domain owner and independent reviewer identify
   a compliant private network path or report that none exists. The Kordex
   administrator confirms the existing organization/fleet/site association.
2. Trust and artifact verification: supply-chain custodian and release owner
   deliver independently verified public trust, signed artifact approval,
   release/tool trust, and Ubuntu package/policy artifacts.
3. Network and repository readiness: implement and test the approved private
   relay and agent mTLS path; approve exact private routes, firewall,
   DNS/TLS, and mirror flows. Public Cloudflare transport does not satisfy
   current M3 criteria; any request to alter that boundary is a separate
   product decision and is not approved here.
4. GCP API and IAM approval: project owner explicitly approves required API
   enablement and scoped service-account/IAP/OS Login grants. The current
   snapshot lists IAP, Secret Manager, and Cloud DNS as disabled.
5. Pre-provisioning review: independent reviewer checks project, topology,
   allow/deny design, recovery plan, cleanup, and remaining `$300` M3–M6
   allocation.
6. Separately authorized Terraform plan: only after the prior inputs and
   approvals are verified; review every resource, endpoint, and cost. A plan
   is not apply approval.
7. Separately authorized apply: obtain distinct approval for the exact reviewed
   plan and session window.
8. M3 qualification and cleanup: execute the real maintenance/reboot/recovery
   and failure cases, archive and independently verify evidence, destroy the
   disposable resources, and inspect actual billing.

Before an independent fault case, the lab owner captures a healthy idle
baseline, records its SHA-256 independently, stops all three VMs, and creates a
complete labelled snapshot set with the guarded `recovery snapshot` command.
After restore, all three machine IDs, new boot IDs, Kubernetes node UIDs, and
workload readiness must match the verified recovery contract before the next
case. The standalone lab README contains exact command templates. Network
faults require a live TCP probe before/during/after and are supplementary; the
current single relay/API TCP/18443 path cannot distinguish a relay-path fault
from an API-path fault. When snapshots are no longer required, remove only the
exact set after separately confirming retention policy, verify active
snapshots are absent, and inspect actual billing/recycle-bin retention.

Condensed inputs to obtain and independently verify:

1. From the artifact custodian: the real organization-controlled artifact trust
   bundle delivered independently, approved K3s binary from the approved
   mirror, signed lock, detached signature, checksum/acquisition evidence, and
   customer approval reference. This is customer approval, not upstream
   provenance.
2. From the maintenance-key custodian: the existing matching public trust
   bundle, independently checked key IDs and rotation overlap. **Never send
   private keys or seeds to the development team.**
3. From the release owner: signed Kordex release bundle, image digest lock,
   Ubuntu 24.04 package artifacts and signed policy, release/tool public trust
   roots, Helm signer allowlist, source revision/version, and verification
   instructions.
4. From the network/domain owner: confirm an existing private VPN/route to the
   workstation relay, with endpoint, routes, DNS/TLS, firewall, and validation
   evidence. Supply the exact customer RFC1918 egress CIDRs (no broader than
   /24), HTTPS Ubuntu mirror root, K3s binary and system-image mirror/artifact
   location, and approved private image source. If the route is absent, report
   the blocker and identify the private route/relay required; public Cloudflare
   transport does not satisfy current M3.
5. From the Kordex administrator: select an existing organization/fleet/site,
   supply a short-lived authorized admin credential through a secure local
   workflow, and approve registration of this new self-managed cluster. No
   membership or organization change is implied.
6. From the GCP project owner/network owner: approve enabling IAP, Secret
   Manager, and Cloud DNS APIs; approve the exact Terraform plan, three VM
   resources, custom VPC, private DNS, destination-limited firewall rules, and
   service accounts; approve scoped IAM and IAP/OS Login grants. Confirm budget
   and remaining $300 M3–M6 allocation. Artifact Registry API/repository approval is conditional on the
   chosen image distribution path.
7. From the lab owner/reviewer: define out-of-band serial-console recovery,
   baseline reset between failure cases, network/package fault controls,
   independent log retention, target selection, and who approves the signed
   maintenance plan and each execution.

Do not proceed if a custodian cannot produce existing trust material. Do not
generate replacement production keys, reuse the old product project, create
new organizations automatically, or turn on execution gates in repository
defaults.

## Staged execution plan (commands are future, gated steps)

Every mutation below requires its own approval. No command in this section was
run during this readiness review.

### 0. Zero-cost local preparation

Use a reviewed checkout. Do not inspect or edit the ignored `terraform.tfvars`
through a separate command. The validation helper enumerates tracked and
non-ignored Terraform source files, then uses backend-disabled initialization:

```sh
python3 scripts/self_managed_lab.py validate
python3 -m unittest discover -s tests/infrastructure -p 'test_*.py'
(cd tests/integration && \
  python3 -m unittest test_self_managed_upgrade_smoke test_host_upgrade_qualification_evidence)
```

Collect the source revision and dirty-tree patch in the protected evidence
workspace. Do not include credentials, private keys, Kubeconfig, or ignored
Terraform variables in the archive.

### 1. Trust and offline artifacts

The authorized customer custodian completes
[`m3-trust-recovery-handoff.md`](m3-trust-recovery-handoff.md) and
[`m3-customer-artifact-approval.md`](m3-customer-artifact-approval.md). Verify
actual supplied files from a reviewed checkout; never trust a key included
only in the bundle it verifies. Example offline K3s check:

```sh
cd api
go run ./cmd/kordex-artifact-lock verify \
  --binary /approved-transfer/k3s \
  --lock /approved-transfer/k3s.artifact-lock \
  --signature /approved-transfer/k3s.artifact-lock.sig \
  --trust-bundle /independent-trust/k3s-artifact-approval.trust
cd ..
```

This verifies local supplied bytes only. Record signer ID, version, architecture,
digest, mirror URL, approval reference, verifier source revision, and command
result. The lab helper re-verifies the binary and binds digest and mirror URL
to Terraform. Do not copy private signing material to the lab.

### 2. Network and GCP approval gates (no provisioning)

Before planning, resolve the network decision in “Network isolation decision”
and obtain its evidence. Verify the approved private endpoint, routes, DNS,
TLS, and deny tests. If no compliant private path exists, stop; public
Cloudflare transport is not an alternate that passes current M3 criteria.
Separately obtain project-owner approval for any required API enablement and
exact least-privilege IAM changes; approval is not applied by this runbook.
Then perform the pre-provisioning review of project, topology, firewall
destinations, recovery, cleanup, and budget. The project/service commands below
are read-only checks.

Continue to pass the project explicitly; do not change global gcloud project:

```sh
gcloud projects describe kordex-fleet-platform-515416 \
  --project=kordex-fleet-platform-515416
gcloud services list --enabled --project=kordex-fleet-platform-515416
```

Only after written network/API/IAM approval, customer trust inputs, and the
independent pre-provisioning review, prepare private variables from the
reviewed example without printing them. The ignored
file must remain mode 0600 and must contain the same digest and mirror URL as
the signed lock. The guarded command is:

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id kordex-fleet-platform-515416 \
  --k3s-binary /approved-transfer/k3s \
  --k3s-artifact-lock /approved-transfer/k3s.artifact-lock \
  --k3s-artifact-signature /approved-transfer/k3s.artifact-lock.sig \
  --k3s-artifact-trust /independent-trust/k3s-artifact-approval.trust \
  --k3s-system-images-bundle /approved-transfer/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /approved-transfer/k3s-system-images.lock \
  --k3s-system-images-signature /approved-transfer/k3s-system-images.lock.sig \
  --k3s-system-images-trust /independent-trust/k3s-artifact-approval.trust
```

Review every planned resource, egress rule, project, region, zone, image, and
cost. The plan is a separate, explicitly authorized step after that review; it
is not approved by this document. Apply only after a second, separate human
review and explicit authorization, using the same eight artifact inputs and
the exact interactive confirmation requested by the helper. Never invoke raw
`terraform plan/apply` for provisioning; it bypasses the customer signature
preflight.

### 3. Bootstrap, inventory, and management-plane connection

After an approved apply, use only project `kordex-fleet-platform-515416`, zone
`us-east1-b`. The module outputs `k3s_node_names`, `worker_names`, and private
IPs. Retrieve kubeconfig only through IAP, keep it outside Git at mode 0600,
set `KORDEX_EXPECTED_CONTEXT` to the exact returned context, then verify. Read
the output commands before running them; run the IAP tunnel command in a
dedicated terminal while using kubectl. Do not redirect kubeconfig to a tracked
path:

```sh
LAB_TF_DIR=infrastructure/terraform/gcp/self-managed-lab
terraform -chdir="$LAB_TF_DIR" output -json k3s_node_names
terraform -chdir="$LAB_TF_DIR" output -json worker_names
terraform -chdir="$LAB_TF_DIR" output -raw kubeconfig_read_command
terraform -chdir="$LAB_TF_DIR" output -raw iap_k3s_tunnel_command
SERVER_NAME="$(terraform -chdir="$LAB_TF_DIR" output -raw server_name)"
gcloud compute ssh "$SERVER_NAME" \
  --project=kordex-fleet-platform-515416 --zone=us-east1-b \
  --tunnel-through-iap \
  --command='sudo cat /etc/rancher/k3s/k3s.yaml' > ./kubeconfig
chmod 600 ./kubeconfig
export KUBECONFIG="$PWD/kubeconfig"
kubectl config get-contexts
kubectl --context "$KORDEX_EXPECTED_CONTEXT" get nodes -o wide
```

Confirm exactly one server and two Ubuntu 24.04 workers, stable cluster UID,
K3s/API readiness, and both workers Ready/schedulable. Confirm K3s join-token
expiry/revocation. A VM name/OS image from Terraform is not proof of the live
OS/kernel/runtime or eligible peer checks.

Select an existing authorized organization/fleet/site, then use the existing
authenticated cluster-registration endpoint
`POST /v1/organizations/{org}/clusters` with `provider: self-managed` and the
live Kubernetes UID. Use the existing enrollment endpoint
`POST /v1/organizations/{org}/clusters/{cluster}/enrollment-tokens`; store the
single-use token in a protected file and enroll the agent once. Do not use
bootstrap development auth for qualification. Configure the agent with its
cluster ID, HTTPS management URL, customer client certificate/key, server
CA trust, enrollment-token file, and durable identity Secret. Verify fresh
inventory and heartbeat before installing the maintenance overlay.

Before lab deployment, `kubectl kustomize deployments/kustomize/overlays/self-managed`
must render from real customer trust and digest-pinned release images. It
currently fails because `keys.json` is absent. Do not fabricate the file.
Keep `maintenanceEnabled`, `upgradeEnabled`, and `gkeUpgradeEnabled` false until
all host credentials, pinned `known_hosts`, approved EE digest, policy, offline
artifacts, and clean baseline are reviewed. Create the temporary lab-only
host-execution overlay exactly as documented in the canonical runbook; render,
review and pin every write to `--context "$KORDEX_EXPECTED_CONTEXT"`.

Do not use the legacy public Cloudflare gateway for M3. It does not meet the
private-route/no-public-egress requirement. After a private route, DNS,
customer PKI, and Kordex registration exist, follow
[`private-agent-relay-operations.md`](private-agent-relay-operations.md) to
configure the workstation relay and agent. Verify connectivity before enabling
the lab-only execution overlay; do not open a public listener.

Both processes are currently absent/unconfigured. Startup alone does not prove
VM-to-hub connectivity or satisfy the unresolved public-egress policy.

### 4. Preflight, approval, and one clean operation

The API/admin token below is a short-lived credential. Obtain it through the
approved identity flow, enter it without echo, and unset it after the session.
The host policy name and digest must come from the verified policy, never a
placeholder:

```sh
export KORDEX_API='https://APPROVED_MANAGEMENT_HOST'
read -r -s -p 'Short-lived Kordex administrator token: ' KORDEX_ADMIN_TOKEN
export KORDEX_ADMIN_TOKEN
export KORDEX_ORG_ID='EXISTING_ORGANIZATION_UUID'
export KORDEX_CLUSTER_ID='REGISTERED_SELF_MANAGED_CLUSTER_UUID'
export KORDEX_EXPECTED_CONTEXT='EXACT_SELF_MANAGED_CONTEXT'
export KORDEX_NODE_NAME='APPROVED_UBUNTU_WORKER'
export KORDEX_HOST_POLICY='APPROVED_UBUNTU_POLICY'
export KORDEX_HOST_PLAN_DIGEST='DIGEST_FROM_APPROVED_POLICY'
export KORDEX_NAMESPACE='kordex-system'
export KUBECONFIG='/protected/path/kubeconfig'
mkdir -p ./qualification
python3 scripts/self_managed_lab.py preflight \
  --evidence ./qualification/preflight.json
```

Review the live cluster UID, worker UID, OS image/version, peer eligibility,
workload/PDB baseline, signed policy and exact `targetConfirmation`. Preflight
is read-only. Stop if any state is stale, unknown, mismatched, or unsafe.
Have the independent reviewer approve the exact plan/target. For each execution
case, use the guarded wrapper, not the raw runner:

```sh
export KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM='EXACT_CLUSTER_UUID/NODE_NAME/NODE_UID_FROM_PREFLIGHT'
python3 scripts/self_managed_lab.py execute \
  --project-id kordex-fleet-platform-515416 \
  --target-confirmation "$KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM" \
  --qualification-case clean-upgrade \
  --timeout-seconds 14400 \
  --evidence ./qualification/clean-upgrade-debian.json
```

The helper checks the disposable project designation and prompts for its
project-bound execution confirmation. Append the same `--m3-artifact-inputs`,
`--m3-artifact-report`, and eight K3s artifact path options shown in the
pre-provisioning command above. The helper requires every consolidated report
row to pass, verifies that report binds those exact K3s files, and reruns and
compares the report after the project confirmation immediately before starting
the runner. Execution still requires separate human approval after all
preflights succeed. Do not run it in this readiness phase.

### 5. Failure handling, verification, and archival

Run each independent case from a restored baseline with a new operation ID and
evidence path. The runner-supported matrix cases are clean upgrade, cancellation
during execution, cancellation during reboot, and operator restart during
execution. The external/manual matrix cases are SSH loss during apply, partial
package application, reboot never returning, SSH loss after reboot request,
wrong machine ID, Node replacement during recovery, and wrong kernel after
reboot. The existing runner can also inject cancellation before apply or during
recovery as supplemental cases; keep those outside the pinned matrix.

For every case capture UTC times, source revision/patch digest, operation ID,
policy UID/generation/digest, target/cluster/node UIDs, machine-ID and boot-ID,
exact package old/new versions and exit status, reboot intent/receipt, expected
and observed kernel, Node readiness/schedulability, workload snapshots, owned
cordon and reservation holder, durable checkpoints/journal, operator/agent
identity and logs, and for external injection the raw independent control/log
record. `RecoveryRequired` means a safe fence, not successful restoration.
Never manually uncordon or resubmit a mutation to obtain a pass.

| Matrix case | Expected safe result |
|---|---|
| `clean-upgrade` | `Succeeded`; actual package change, required reboot, same host/node identities, expected kernel, healthy workloads, and operation-owned cordon/reservation released. |
| `cancel-during-executing` | No apply replay; `Cancelled` only after verified recovery, otherwise `RecoveryRequired` with fence/reservation retained. |
| `cancel-during-reboot` | Cancellation never assumes reboot stopped; verify boot/host recovery or remain `RecoveryRequired` and fenced. |
| `operator-restart-during-executing` | Different Ready operator Pod UID resumes the same checkpoint; no duplicate package mutation; verified success or `RecoveryRequired`. |
| `ssh-loss-during-apply` | `RecoveryRequired`; timed block/restore evidence; no automatic apply replay. |
| `partial-package-application` | `RecoveryRequired`; exact partial package delta and exit code; no replay. |
| `reboot-never-returns` | `RecoveryRequired`; unavailable interval meets matrix minimum; reservation and cordon stay held. |
| `ssh-loss-after-reboot-request` | `RecoveryRequired` unless reboot/recovery is fully proven; no second reboot due to lost response. |
| `wrong-machine-id` | Reject host substitution; `RecoveryRequired`; original target ownership remains. |
| `node-replaced-during-recovery` | Reject replacement UID; replacement untouched; original reservation/cordon remains. |
| `wrong-kernel-after-reboot` | `RecoveryRequired`; exact expected/observed kernel evidence; retain fence/reservation. |

Runner-executable cases use the guarded `scripts/self_managed_lab.py execute`
wrapper with the exact case, project, target confirmation and new evidence
path. External cases additionally require the reviewed lab fault controller
and the existing `tests/integration/record_host_upgrade_fault.py` recorder;
their safe execution is not automated by this readiness task. Use the exact
case-specific fields in the canonical matrix and runbook.

Verify and archive after all required records are present:

```sh
python3 scripts/verify-host-upgrade-qualification.py ./qualification
python3 scripts/self_managed_lab.py archive \
  --source ./qualification \
  --destination /durable/off-cluster/kordex-m3-ubuntu-qualification.tar.gz
```

The pinned full-matrix verifier will remain incomplete for an Ubuntu-only run
because it requires both Debian and RHEL records for the matrix. Preserve
Ubuntu evidence as scoped review; leave broader OS rows and every unrun case
NOT RUN. A second reviewer verifies the archive checksums and raw fault evidence
before any result is proposed for the canonical matrix.

### 6. Disable, tear down, and check actual billing

First disable both host gates on the disposable overlay and agent, verify the
live settings, revoke lab client certificates, remove only lab credential
Secrets, and retain evidence off-cluster. Then use the guarded destroy helper
after separate destroy approval:

```sh
python3 scripts/self_managed_lab.py destroy \
  --project-id kordex-fleet-platform-515416
```

Verify no lab instances, disks, addresses, custom VPC, firewall
rules, private DNS zone, service accounts, Secret Manager entries, or Kordex
credentials remain. Preserve the default VPC and its unrelated default rules.
For snapshot sets, separately use the guarded `recovery snapshot-delete`
command, verify its three-item cleanup evidence and active snapshot list, then
check snapshot recycle-bin/retention billing because active-list absence alone
does not prove all snapshot storage charges ended.
Review actual Cloud Billing data for the complete qualification window; budget
alerts and free credits are not spending caps. The updated lab README estimate
is about `$0.87` for 4 hours and `$1.74` for 8 hours for the 3-VM/private-DNS
baseline, plus DNS queries, private route/VPN costs, transfer, taxes, and other
unmodeled services. A 30-day baseline is about `$156.78`, and a 90-day baseline
about `$470.33` before variable costs, exceeding the total `$300` M3–M6 target.
Stopped VMs can still leave billable disks and the DNS zone. Destroy after
every session.

## Explicit stop conditions

Stop before plan/apply if any of these holds:

- customer artifact/maintenance/release trust is missing, comes from the same
  channel as the artifact, or fails signature/digest/identity verification;
- there is no customer-approved Ubuntu/K3s/image mirror, the configured private
  CIDRs do not contain their resolved destinations, or the lab cannot reach
  them over verified HTTPS;
- the private route, workstation relay, DNS, client/server PKI, or end-to-end
  authenticated agent path is unavailable;
- either required API remains disabled without explicit approval, project ID
  or label changes, or the planned resources use the default VPC or wrong
  project/region/zone;
- serial console, out-of-band recovery, baseline reset, or independent fault
  injection/log capture is not ready;
- the management plane, DB, organization authorization, or trusted maintenance
  signer is not ready; cluster registration or agent heartbeat is stale;
- `keys.json`, digest-pinned release images, immutable EE image, approved
  policy, host key pin, SSH credential, or offline package artifacts are
  missing;
- live preflight fails any node identity/OS/peer, PDB/workload, capability,
  freshness, plan digest, or reservation check;
- the saved plan, egress exposure, project budget, reviewer, or exact execution
  target has not been approved.

Do not enable repository defaults, use GKE/COS/GKE Ubuntu as the target, expand
to another OS/provider, claim air-gapped qualification from connected egress,
or mark any matrix row RUN without real evidence and independent review.
