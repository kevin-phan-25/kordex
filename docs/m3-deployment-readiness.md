# M3 disposable lab deployment readiness

**Audit date: 2026-11-21. Status: NOT READY FOR A SAFE TERRAFORM PLAN. M3 is
NOT QUALIFIED.** This is a customer handoff and a local read-only readiness
gate. It does not authorize a plan, apply, deployment, registry write, or host
maintenance. The canonical matrix in
[`production-upgrade-requirements.md`](production-upgrade-requirements.md)
is unchanged; every M3 row remains **NOT RUN**.
The owner-by-owner request and sign-off packet is in
[`m3-customer-handoff.md`](m3-customer-handoff.md).
For the current external owner roles, secure delivery paths and per-input
validators, see [`m3-external-owner-delivery.md`](m3-external-owner-delivery.md)
and [`m3-external-delivery-manifest.json`](m3-external-delivery-manifest.json).

The canonical matrix continues to require Debian and RHEL evidence for all 11
scenarios. The lab has selectable Ubuntu 24.04 supplemental, Debian 13 Trixie,
and RHEL 9.8-or-later profiles. Canonical Debian and RHEL profiles require an
exact image self-link and server-assigned image ID; Terraform compares the
customer-approved ID to live image metadata during planning. Independent image
owner evidence is still required to establish exact in-guest OS release and
architecture. Debian also requires the approved Debian 13.8 point release
and signed Trixie archive/security mirrors. RHEL requires a customer-approved
exact RHEL image and signed private RPM repository; no derivative distribution
is accepted. Ubuntu is supplemental only. These profiles have not been
deployed or real-host-tested; all canonical matrix rows remain **NOT RUN**.

| Lab profile | Tracked image/bootstrap | Local status | Real-host qualification |
|---|---|---|---|
| Ubuntu 24.04 | `ubuntu-os-cloud` / `ubuntu-2404-lts-amd64`; Ubuntu private APT source | Implemented; locally validated only | Not run; supplemental only |
| Debian 13 Trixie | Exact `debian-cloud` image self-link and unique ID; signed private Trixie archive/security sources and exact approved point release | Implemented; locally validated only | Not run; customer image owner must verify OS release/architecture and an independent reviewer must accept the approval evidence |
| RHEL 9.8+ | Exact customer-approved RHEL image self-link and unique ID; PAYG/EUS license identity; signed private RPM source and key fingerprint | Terraform checks image licenses; post-creation verification checks boot-disk image ID and license URIs; startup checks release/vendor/RHUI client; local tests only | Blocked until an exact image and entitlement are approved and the guest checks run on a real host; not run |

This audit did not contact GCP, a private mirror, a registry, a relay, or a
customer identity provider. The prior readiness note records project
`kordex-fleet-platform-515416` as active and labeled, but its live label,
enabled APIs, IAM, resource inventory, and billing status have not been
rechecked for this audit. Do not treat a prior observation or this document as
current cloud evidence.

## Readiness gate command

The schema-version 2 readiness report distinguishes `PASS`, `PROVIDED`,
`NOT PROVIDED`, `BLOCKED`, and `FAIL`. Each prerequisite includes a requirement
ID, platform applicability, safe input reference, method, timestamp when
meaningful, reason, and independent-review requirement. `PROVIDED` never means
independently verified. The command performs local validation only; it does
not make cloud/network calls or open registry credential files. It binds the
complete non-secret Terraform input document, network inputs, artifact input
map and report, Terraform source/embedded files, exact image approval, and
artifact digests through canonical SHA-256 values. See
[`m3-readiness-plan-binding.md`](m3-readiness-plan-binding.md) for input
schema, image approval format, plan command, and verification limitations.

```sh
python3 scripts/m3_deployment_readiness.py \
  --project-id kordex-fleet-platform-515416 \
  --network-inputs /secure/m3/network-inputs.json \
  --artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --artifact-report /secure/m3/artifact-preflight.json \
  --terraform-inputs /secure/m3/terraform-inputs.json \
  --image-approval /secure/m3/image-approval.json \
  --output /secure/m3/deployment-readiness.json
```

The output file is created mode `0600`; the command refuses to overwrite an
existing file. Omit `--output` to print the JSON to the terminal. Exit status
is zero only when every reported check is `PASS`; customer inputs may remain
`PROVIDED`, while external approvals remain `BLOCKED`. A local report that is
not all PASS cannot be described as deployment readiness. The guarded plan
requires only its explicit input-bound checks to pass and separately performs
live plan-time checks; neither path authorizes apply.

The network input JSON is non-secret but contains sensitive internal topology.
Keep it outside Git and transfer it through the customer's approved channel.
Its schema is exact and rejects unknown fields:

```json
{
  "schemaVersion": 1,
  "projectId": "kordex-fleet-platform-515416",
  "region": "us-east1",
  "zone": "us-east1-b",
  "labId": "kordex-m3-lab",
  "osFamily": "debian-13",
  "nodeRoles": ["server", "worker-1", "worker-2"],
  "subnetCIDR": "10.76.0.0/24",
  "labSourceCIDR": "10.76.0.0/24",
  "approvedPrivateMirrorCIDRs": ["<customer-private-mirror-cidr>"],
  "approvedPrivateRelayCIDRs": ["<customer-private-relay-cidr>"],
  "restrictedGoogleApisCIDR": "199.36.153.4/30",
  "mirrorPort": 443,
  "relayPort": 18443,
  "noVMExternalIPs": true,
  "noCloudNAT": true,
  "relayDNSName": "<customer-private-relay-dns-name>",
  "mirrorDNSNames": ["<customer-private-mirror-dns-name>"]
}
```

Replace placeholders only in the customer's local file. Mirror and relay
CIDRs must be canonical RFC1918 IPv4 ranges no broader than `/24`, mutually
disjoint, and non-overlapping with the fixed lab subnet and restricted Google
APIs VIP. The relay uses TCP/18443; private mirrors use TCP/443. This validates
syntax and consistency only. It does not resolve DNS, prove a route, test a
firewall, or verify certificate SANs. When a complete non-secret
`--terraform-inputs` JSON document is supplied, readiness validates every
declared Terraform variable and binds its canonical values together with the
network document. `actualTerraformInputs` and `planInputBinding` become
`PROVIDED` and `PASS` respectively; the customer values are not promoted to
independently reviewed cloud facts. The guarded plan rechecks those exact
inputs and the live project before invoking Terraform. Ignored local
`terraform.tfvars` is not opened by the readiness command or helper.

The gate requires a fresh artifact report (maximum local file age four hours),
all 16 required artifact rows `PASS`, the expected K3s version/architecture,
current approval age, and hashes matching the exact local K3s binary, locks,
signatures, trust bundles, and other bound inputs. File modification time is
only a local freshness signal. The report is unsigned, and its temporary
registry inspection report is not retained; therefore this command does not
make the report an attestation. The guarded `self_managed_lab.py plan` command
reruns the full verifiers and private endpoint/registry checks, checks report
bytes and K3s bindings, validates the live project designation through
Terraform's read-only data sources, and then creates the Terraform plan. It
never applies it.

**Artifact-review and image coverage update (2026-11-23):** the 16-row
artifact report now has distinct structural, repository-signature, SBOM,
provenance, and `independentApproval` checks. The approval must be a detached
Ed25519 signature over a canonical report-bound record conforming to
[`m3-artifact-review-v1.json`](../schemas/m3-artifact-review-v1.json). It binds
the selected OS campaign, all six image digests and their SBOM/provenance and
builder/source/material identities, signed repository snapshots/signatures,
all verified input digests, preflight report digest, and trust root/config
identities. The reviewer must be currently root-authorized with role
`reviewer`, distinct from the artifact-owner roles and verified signers. The
separate image identity approval is not a substitute. Follow the two-pass
process in [`m3-artifact-intake.md`](m3-artifact-intake.md#independent-artifact-review-record).

The `.github/workflows/ci.yaml` release matrix now covers all six locked M3
images plus supplemental `agent-relay`. Static workflow coverage is tested;
no release run or image artifacts were verified here. `ansible-ee` and
`postgres` use pinned base-image repository variables; their values and
release outputs remain owner inputs. The release/build owner must designate
each component owner in the signed trust configuration and provide the exact
verified resolved materials. A missing/untrusted owner, SBOM, provenance, or
review keeps artifact readiness from passing. The preflight preserves SBOM and
provenance outcomes as separate rows: provenance failure does not relabel a
verified SBOM as failed, and missing provenance remains `NOT PROVIDED`.

The earlier local snapshot below is historical and is not a fresh readiness
result. In the current local environment, Skopeo 1.24.0 is installed. The
current checkout still has no customer network or artifact input/report; the
`gh` executable required by offline GitHub attestation verification is not
installed here. The actual Terraform variables were deliberately not
inspected in this documentation update. Do not interpret any local result as
approval to run `plan`.

## Customer input inventory

“Repository mechanism exists” means local validation code/documentation is
present; it does not mean real customer material is available or verified.
No customer trust, release, package, OCI, registry, PKI, or network artifacts
were found in this checkout. Test fixtures are synthetic and are never
production inputs.

| Required input | Owner, consumer, required form and verification | Availability and how to obtain | Needed for |
|---|---|---|---|
| Existing maintenance public trust bundle (`keys.json`) and current key IDs | Maintenance-key custodian; operator consumes through `KORDEX_HUB_PUBLIC_KEYS_FILE`. JSON maps SHA-256 public-key IDs to canonical unpadded Base64 Ed25519 public keys. Independently compare IDs/fingerprints with the custodian inventory; `python3 scripts/m3_artifact_preflight.py --inputs ... --report ...` checks format and expected IDs. | **CUSTOMER INPUT REQUIRED.** Custodian recovers the existing key through approved secret management and uses `api/cmd/kordex-trust-export`; only the independently checked public bundle is delivered. Never send the private key/seed. | Deployment, operation signature verification, artifact preflight. |
| Maintenance key rotation/revocation evidence and overlap | Maintenance custodian; the operator trusts the supplied public bundle. Provide old/new IDs, rotation dates, revocation decision, retention/overlap window, and outstanding-operation handling. Compare bundle entries with the independent key inventory. | **CUSTOMER INPUT REQUIRED.** No machine-verifiable rotation record is configured in the preflight schema; independent reviewer must attest it. | Deployment and qualification approval. |
| Customer artifact-approval public trust bundle and key ID | Supply-chain custodian; verifies K3s binary and system-image locks in separate signature domains. Format `KORDEX-CUSTOMER-ARTIFACT-TRUST-V1`; run both offline verification commands below with the independently delivered trust. | **CUSTOMER INPUT REQUIRED.** Obtain existing organization-controlled public key/trust through a channel independent of the mirror. No key generation or substitute trust. | Artifact preflight, Terraform planning, bootstrap. |
| K3s binary `v1.36.6+k3s1`, signed lock, detached signature, acquisition/review/approval records | Supply-chain custodian; lock binds exact binary digest, `linux/amd64`, source, mirror URL, approval reference, signer ID, UTC approval time. Run: `cd api && go run ./cmd/kordex-artifact-lock verify --binary /verified/k3s --lock /verified/k3s.artifact-lock --signature /verified/k3s.artifact-lock.sig --trust-bundle /trusted/k3s-artifact-approval.trust`. Customer approval is not upstream provenance. | **CUSTOMER INPUT REQUIRED.** Acquire and approve using the customer's supply-chain process, then verify the mirror copy; upstream does not provide independently verified provenance for this standalone binary. | Terraform plan, bootstrap, artifact preflight. |
| K3s system-image archive, signed lock/signature and independent artifact trust | Supply-chain custodian; archive contains the exact eight-image `v1.36.6+k3s1` `linux/amd64` set. Run: `cd api && go run ./cmd/kordex-artifact-lock system-images verify --bundle /verified/k3s-airgap-images-amd64.tar --lock /verified/k3s-system-images.lock --signature /verified/k3s-system-images.lock.sig --trust-bundle /trusted/k3s-artifact-approval.trust --json`. The separate `system-images stage` verifies and stages locally but does not populate a registry. | **CUSTOMER INPUT REQUIRED.** Acquire through approved process, approve/sign, transfer with independent trust, and stage per [`m3-k3s-system-image-staging.md`](m3-k3s-system-image-staging.md). | Terraform plan, bootstrap, artifact preflight. |
| Signed Kordex offline release bundle, manifest/checksums, source revision/version and release public key/fingerprint | Release owner; bundle signature plus checksums: `scripts/verify-offline-bundle.sh BUNDLE RELEASE_PUBLIC_KEY`; confirm fingerprint independently of bundle. | **CUSTOMER INPUT REQUIRED.** Release owner supplies actual signed release package and independent public-key identity. | Deployment, artifact preflight. |
| Signed six-image Kordex digest lock and detached signature | Release owner; binds agent, operator, control-plane, dashboard, Ansible EE, and PostgreSQL images. Verify with `scripts/verify-image-lock.sh LOCK LOCK.sig RELEASE_PUBLIC_KEY`; inspect registry content with the consolidated preflight. | **CUSTOMER INPUT REQUIRED.** No real image lock or image content is present. | Deployment, private registry, artifact preflight. |
| Tool-provenance public key/fingerprint and signed offline tool lock | Release/tool owner; independent fingerprint plus `scripts/verify-offline-tools-lock.sh LOCK LOCK.sig TOOL_KEY HELM_ALLOWLIST`. | **CUSTOMER INPUT REQUIRED.** Separate from maintenance, Kordex release, and artifact-approval trust. | Local tool acquisition and artifact preflight. |
| Helm signer allowlist | Release/tool owner; approved signing fingerprints. Validate syntax with `scripts/verify-offline-tools-lock.sh --check-helm-signers FILE`; verify archive signatures through the tool lock. | **CUSTOMER INPUT REQUIRED.** No allowlist from an authoritative customer/release source is present. | Offline packaging/tool acquisition, artifact preflight. |
| Selected-profile package repository metadata, package policy, exact `.deb`/`.rpm` archive and baseline versions | Package custodian and Kordex administrator; policy binds package names, versions, architecture, SHA-256, expected update and kernel/reboot behavior. Debian requires Trixie packages and the approved Debian 13.8 point release recorded in the profile; RHEL requires 9.8 or later and a signed private RPM snapshot. Ubuntu 24.04 is supplemental. `python3 scripts/m3_artifact_preflight.py --inputs ... --report ...` runs policy/artifact checks and fetches the exact archive over the private HTTPS mirror. | **CUSTOMER INPUT REQUIRED.** Must produce at least one real package-version delta, selected OS point/minor, immutable repository snapshot, and expected kernel/reboot results. No production package archive or policy approval is available. | Artifact preflight, plan approval, real host qualification. |
| Eight K3s images and six Kordex OCI images | Supply-chain custodian owns eight signed K3s mappings; release owner owns six Kordex mappings. Customer-operated registry ingestion is separate from archive staging. The report must cover all 14 exact approved digest references for `linux/amd64`. | **CUSTOMER INPUT REQUIRED.** No production image archive/lock/registry contents. Stage the K3s archive; ingest the six Kordex release images using the release procedure. | Bootstrap, deployment, artifact preflight. |
| Private registry destination mappings and populated registry | Supply-chain/release owners; signed lock maps source references to private references and digests. The customer pushes approved content using documented `skopeo copy --preserve-digests`; `python3 scripts/verify-private-registry.py ...` is read-only and verifies 14 images, digests and architecture. | **CUSTOMER INPUT REQUIRED.** Staging is not registry ingestion. Do not provide credentials to Kordex; keep a mode-0600 auth file in customer secret management. The readiness gate reads only the auth-file path string and never opens the file. | Artifact preflight, bootstrap. |
| Workstation relay server certificate/key, client certificate/key, CA bundle and URI SAN→cluster mapping | Customer PKI owner; mTLS server cert DNS SAN must equal the relay hostname, client cert has clientAuth EKU and one URI SAN, mapping identifies exactly one enabled cluster. Keys are mounted from customer-controlled secrets. Relay health is local `curl http://127.0.0.1:18444/{livez,readyz}`; after deployment run agent `connectivity-check` with `--allowed-cidr` for each approved relay prefix. | **CUSTOMER INPUT REQUIRED.** No certificates, CA, mapping or relay process is configured/tested. Do not place private keys in JSON or report files. | Deployment, agent connectivity, qualification. |
| Organization/fleet/site association, management API origin, cluster registration and agent enrollment | Kordex administrator; confirm existing organization/fleet/site UUIDs, then register one distinct `self-managed` cluster through the authorized organization-scoped `POST /v1/organizations/{org}/clusters` API. Issue a single-use 10-minute enrollment token via the existing enrollment workflow. Verify persisted association, token consumption, agent identity, inventory and fresh heartbeat through the authenticated tenant-scoped API/dashboard. | **CUSTOMER DECISION/CONFIGURATION REQUIRED.** No association selection, registration, enrollment, or heartbeat is verified. Keep API and enrollment tokens in protected secret files; never put values in JSON/report files, shell history, or Git. | Deployment, agent connectivity, inventory and later maintenance. |
| Host execution SSH user, trusted host-key pin, sudo scope and immutable Ansible EE image | Lab owner and release owner; provide the target worker's SSH credential through the existing protected secret mechanism, exact `known_hosts` entry, reviewed sudo scope and digest-pinned EE image. Independently verify the host public-key fingerprint and that the other worker remains an eligible peer. | **CUSTOMER INPUT/LOCAL CONFIGURATION REQUIRED.** No host key, credential, policy or EE image is available. The readiness report does not read SSH private keys. | Maintenance preflight and execution. |
| Private DNS, routes, relay/mirror destination CIDRs and firewall evidence | Network owner; relay TCP/18443, mirror TCP/443, restricted Google APIs VIP TCP/443, DNS and return route. The lab source is `10.76.0.0/24`. The readiness command checks customer JSON syntax/disjoint CIDRs only; live DNS, route, firewall and deny tests require the customer route. | **CUSTOMER INPUT REQUIRED.** No live route/DNS/firewall evidence. Cloudflare public access does not satisfy the site-local/no-public-egress requirement. | Terraform plan, bootstrap, agent connectivity. |
| Project identity/designation | Project owner; exact ID `kordex-fleet-platform-515416`, region `us-east1`, zone `us-east1-b`, label `kordex-disposable=qualification`. The guarded helper verifies live `ACTIVE` project identity/label using explicit `--project` and checks the configured allowlist/confirmation. | **NOT VERIFIED IN THIS AUDIT.** Prior repository notes record the ID/label, but live state must be rechecked: `gcloud projects describe kordex-fleet-platform-515416 --project=kordex-fleet-platform-515416`. Never change global gcloud project. | Terraform plan and apply. |
| Required GCP APIs and service identities/IAM | Project owner approves APIs: Compute, IAM, Cloud Resource Manager, IAP, Secret Manager, Cloud DNS, and Service Usage if enabling services. Artifact Registry is conditional on choosing it as the customer registry. Terraform creates distinct server/worker service accounts and narrowly scoped secret IAM; operator/IAP permissions are separate. Check services read-only with `gcloud services list --enabled --project=kordex-fleet-platform-515416`. | **CLOUD APPROVAL REQUIRED; LIVE STATE NOT VERIFIED.** No API or IAM change was made. Review exact roles and API needs in the lab README; do not infer approval from existing permissions. | Terraform plan/apply, IAP access, bootstrap. |
| IAP/OS Login access and serial recovery | Project owner grants narrow, separately approved IAP TCP tunnel, OS Login admin and instance/service-account access. Serial diagnostics need `compute.instances.getSerialPortOutput`; the module sets per-instance serial metadata only. `gcloud compute ssh ... --project=kordex-fleet-platform-515416 --zone=us-east1-b --tunnel-through-iap` is the documented route. | **CLOUD APPROVAL REQUIRED; NOT VERIFIED.** No user IAM grant or serial access test occurred. | Lab access and recovery. |
| Terraform operator and runtime IAM | Project owner reviews the Compute/VPC/firewall/Cloud DNS/VM/disk/service-account/Secret Manager permissions and `iam.serviceAccounts.actAs` described in the lab README. Terraform grants the server and worker identities only the secret-scoped join-token permissions. The IAP operator needs narrowly scoped `roles/iap.tunnelResourceAccessor`, `roles/compute.osAdminLogin` (or an appropriately narrower OS Login role), and `roles/iam.serviceAccountUser` on the VM identity. | **CLOUD APPROVAL REQUIRED; NOT VERIFIED.** Terraform does not grant user IAP/OS Login roles; IAM was not queried or changed in this audit. | Terraform plan/apply, IAP access and runtime bootstrap. |
| Billing controls and short-lived session approval | Billing owner reviews current spend, budget remaining, resource pricing, snapshots, storage, DNS queries, logs, network transfer and any private route costs. Budget alerts are not a hard spending cap. | **CUSTOMER INPUT REQUIRED; NOT VERIFIED.** No billing data was queried during this audit. | Plan/apply approval and session scheduling. |
| Actual private Terraform inputs and reviewed saved plan | Project owner supplies a complete non-secret JSON variable document with every declared variable. Readiness validates its shape and profile bindings and fingerprints the canonical values; the guarded plan repeats verification and uses those explicit values. `python3 scripts/self_managed_lab.py validate` checks tracked Terraform sources, backend-disabled initialization, and validation. | **LOCAL CONFIGURATION REQUIRED; not supplied or inspected here.** Keep customer values outside Git. Ignored variable files were not read. No plan was run. | Terraform plan and apply. |
| Recovery baseline, snapshots, serial, and fault controls | Lab owner/reviewer; use `python3 scripts/self_managed_lab.py recovery --help` and the exact baseline/snapshot/restore/serial/fault subcommands in the lab README. Recovery tools require project/lab/zone/three-node identity and typed confirmation; no operation ran. | **REPOSITORY TOOLING EXISTS; CUSTOMER/INFRASTRUCTURE NOT VERIFIED.** Snapshot retention and recovery access need approval and pricing. | Safe fault qualification and cleanup. |

## GCP architecture, cost drivers, and guardrails

The tracked module defines one `e2-medium` K3s server plus two `e2-medium`
workers using the selected OS profile, each with a 40-GiB `pd-balanced` boot disk (120 GiB total),
a dedicated VPC/subnet (`10.76.0.0/24`), private DNS for restricted Google APIs,
scoped firewall rules, separate service accounts, and one short-lived
Secret Manager join secret. It has no Cloud NAT, public NAT IP, VM external IP,
or dependency on the default VPC. Egress is limited to private mirror CIDRs on
TCP/443, private relay CIDRs on TCP/18443, the restricted Google APIs VIP on
TCP/443, DNS/metadata, lab-internal flows, and an explicit deny for other
destinations. This is source evidence, not deployed enforcement.

Price a session from current `us-east1` rates and the approved session duration:

| Cost driver | Quantity/configuration to price | Continues after VM stop? |
|---|---|---|
| Compute Engine | Three-node OS profile at a time plus one disposable `wrong-machine-id` host during that case; bill Debian and RHEL runtime separately | No VM runtime after stop; RHEL licensing treatment must be bounded separately. |
| Boot disks | Three 40 GiB `pd-balanced` cluster disks per sequential OS profile plus the extra host disk; include provisioned time and retained disks | Yes, until disks are deleted. |
| VPC/firewall/subnet | Dedicated VPC, subnet and firewall rules | No direct per-rule charge expected; verify any attached services separately. |
| Cloud DNS | One private zone and query volume | Zone persists and is billed until deleted; queries add variable cost. |
| Snapshots | Price actual stored/incremental GiB for every baseline, including the extra-host baseline, and its retention window | Yes, until snapshots and any recycle/retention copies expire. |
| Artifact Registry/private mirror | Stored OCI/package/K3s bytes, requests and inter-region or internet transfer | Yes for retained storage. The mirror may be customer-owned outside this project. |
| Network | Bytes via approved private route/VPN, mirrors and registry; price customer connectivity and any egress/transfer | Can persist as route/VPN service fees. |
| Logging/monitoring | Ingested byte volume and retention, if enabled | Retained logs continue to incur storage/retention cost. |
| Secret Manager | Active secret versions and access operations | Usually small for this short token flow; check account-level pricing/free quotas. |

The tested `scripts/m3_cost_model.py` prices the selected `e2-medium` profile
and requires reviewed upper bounds for sequential Debian/RHEL runtime,
cleanup/restoration, the extra wrong-machine-ID host, disk/snapshot retention,
DNS queries, logging, network, artifact and registry storage, and other costs.
A deliberately incomplete floor illustration with zero scenario time and
zero variable-cost bounds is `$282.72` including its reserve. That is not a
campaign estimate: required scenario, cleanup, extra-host, snapshot and other
cost inputs remain unbounded, and actual billing headroom is unknown.
Recalculate from current regional SKU prices and owner-reviewed inputs. Keep
the total M3–M6 project ceiling at `$300`; an alert does not cap spending. Use
one scheduled short session, take snapshots only at approved safe points,
export evidence off-cluster, then run guarded teardown. Confirm zero lab VMs,
disks, snapshots, temporary firewall rules, addresses, DNS zones/records,
secrets, and project-local artifacts using explicit `--project` commands and
verify delayed actual billing after the reporting lag. Never delete the
default VPC or unrelated resources.

## Ordered customer actions and stop conditions

1. **Supply-chain and maintenance custodians:** deliver existing public trust
   bundles/key IDs, rotation/revocation evidence, signed release and image
   locks, tool-provenance trust/lock, Helm allowlist, K3s binary and system
   image approvals, Debian policy/package archive for canonical Debian runs
   (Ubuntu artifacts remain supplemental). Stop on any unknown key,
   signature, digest, age, version or architecture mismatch.
2. **Network/PKI owner:** approve site-local route, split DNS, mTLS certificate
   identities/mapping, mirror and relay CIDRs, firewall allow/deny evidence,
   and no-public-egress tests. Stop if the lab cannot route privately to both
   approved mirrors and workstation relay.
3. **Release/supply-chain owners:** ingest the eight K3s and six Kordex images
   through the customer registry path, then run read-only registry verification.
   Stop if any of 14 digests/architectures is missing or changed.
4. **Project owner:** recheck the project ID/label, active lifecycle, APIs,
   IAM, IAP/OS Login, recovery access and current bill. Approve any API/IAM
   changes through the customer's normal change process. This audit did not
   perform those changes.
5. **Local administrator:** prepare the non-secret readiness JSON and
   customer artifact input path map outside Git; keep credential files in the
   approved secret store. Run the local readiness gate and full
   `m3_artifact_preflight.py` over the approved private route. Stop unless all
   required rows are `PASS` and the readiness report has no `FAIL`/`NOT
   PROVIDED` entries relevant to the planned step.
6. **Pre-provisioning reviewer:** review the exact current configuration,
   resources, regions, firewall egress/ingress, recovery plan, cost estimate,
   cleanup commands and evidence destination. Preserve `terraform.tfvars` as
   a protected ignored file; the readiness gate does not read it.
7. **Separate approval:** only after the above, request explicit approval for
   the guarded `python3 scripts/self_managed_lab.py plan --project-id
   kordex-fleet-platform-515416 ...` command. Review and archive the plan; do
   not apply without a second explicit approval. This audit did not run plan.
8. **Later lab approval:** after a separately approved apply, verify all three
   selected-profile nodes, private flows, inventory/heartbeat, signed plan,
   actual package delta, drain/reboot/recovery, each approved failure scenario,
   evidence verification, teardown and billing. Keep both host-upgrade gates
   off except under the separately reviewed lab-only qualification procedure.

## Current blockers and evidence boundary

* Customer maintenance, artifact-approval, release, and tool-provenance trust
  roots and real signed artifacts are not available in the repository.
* No approved Debian package delta/policy/archive (Ubuntu is supplemental),
  eight-image K3s bundle, six
  immutable Kordex images, or populated private registry is available.
* No live customer private DNS/route, relay, PKI, firewall deny evidence,
  management-plane connection or agent enrollment has been verified.
* Current live GCP project label/APIs/IAM/billing and actual Terraform values
  have not been checked in this audit; ignored Terraform variables were not
  read. No Terraform plan/apply was run.
* The existing tracked lab source contains the three-node, no-NAT, no-external-IP
  design. It has not been applied or tested on GCP. In the current local
  environment Skopeo 1.24.0 is installed; the `gh` executable required for
  offline GitHub attestation verification is absent.
* `qualification/preflight.json` is a prior host-runner preflight failure
  caused by missing `KORDEX_*` runtime configuration/context. It is not the
  consolidated artifact-preflight report and cannot satisfy it.
* No real host package operation, reboot, recovery, failure injection, or
  evidence archive exists. M3 remains **NOT QUALIFIED** and every canonical
  matrix row remains **NOT RUN**.

## Implementation and verification record

This readiness gate supports lab-entry preparation related to UPG-19
(restricted/private deployment and signed release material) and UPG-25
(offline package artifact binding/staging). It does not change either
requirement's acceptance status or any M3 matrix row. Local evidence for this
audit: `scripts/m3_deployment_readiness.py` performs no network calls; 11
focused readiness tests and all 112 infrastructure Python tests passed;
`python3 scripts/self_managed_lab.py validate` completed Terraform source
format, backend-disabled initialization and validation successfully; Python
syntax and `git diff --check` passed. The actual artifact report, registry,
customer network, cloud project state and real-host qualification remain
unverified.
