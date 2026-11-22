# M3 Debian and RHEL qualification handoff

**M3 is NOT COMPLETE.** All 11 canonical scenarios remain **NOT RUN** on both
required platforms. This packet collects customer inputs for disposable
Debian 13 Trixie and Red Hat Enterprise Linux 9 (minimum 9.8); Ubuntu 24.04 is
supplemental only. It does not authorize a Terraform plan/apply, deployment, or
host operation. Keep both host/provider execution gates disabled; this packet
does not authorize enabling either gate.

Use this focused platform packet with the broader [customer handoff](m3-customer-handoff.md),
[artifact intake guide](m3-artifact-intake.md), [readiness gate](m3-deployment-readiness.md),
[readiness and plan binding contract](m3-readiness-plan-binding.md),
[private connectivity operations guide](private-agent-relay-operations.md), and
the [canonical qualification requirements](production-upgrade-requirements.md#exact-case-checklist-and-pending-results).
The canonical case IDs, acceptance criteria, and `tests/integration/host_upgrade_failure_matrix.json`
are authoritative and must not be edited to obtain a pass.

## 1. Required platform profiles

### Debian 13 Trixie

Canonical planning does not use a moving Debian image family. The customer
selects an exact image from Google's official `debian-cloud` project and records
its Compute Engine self-link and server-assigned numeric image ID on
`linux/amd64` ([Google image catalog](https://docs.cloud.google.com/compute/docs/images/os-details)). Terraform resolves that exact image and fails
if its current server-assigned ID differs from the owner approval record. The
image owner independently establishes the in-guest OS identity and latest
approved stable point release because Google image metadata alone does not
prove those facts. The package custodian confirms the current stable point
release from the [official Debian release information](https://www.debian.org/releases/).
The VM must report `ID=debian`, major `13`, and the latest
approved Debian 13 stable point release selected for that session. The package
policy, signed host-upgrade policy digest, Terraform startup check, and final
evidence must bind the same point release. The profile does not permanently
pin a point release; Debian 12 policy or artifacts are rejected.

The customer package owner supplies private HTTPS roots for
`debian_archive_mirror_url` (Trixie and Trixie-updates) and
`debian_security_mirror_url` (Trixie-security), plus independently approved
archive signing trust, signed repository metadata, immutable snapshot identity,
and the actual `.deb` files. The package policy identifies each package name,
version, `amd64`/`all` architecture, SHA-256, baseline version, expected
package delta, kernel target, and reboot policy. Public APT fallback is not
permitted. The verifier requires at least one real package version change for
`clean-upgrade`.

Select Terraform profile `qualification_os_profile=debian-13` and
`os_family=debian`; the profile-specific inputs are
`debian_archive_mirror_url`, `debian_security_mirror_url`, and the
policy-bound `qualification_os_point_release`. Bind the exact image self-link,
unique ID, OS evidence reference, and owner approval record using the schema in
the [readiness/plan binding guide](m3-readiness-plan-binding.md). The reviewed
plan and qualification record retain both the image self-link and unique ID.

The selected image must pass the implemented checks for systemd, supported
cgroups, amd64, machine identity, kernel and networking prerequisites before
K3s bootstrap. The customer must verify K3s `v1.36.6+k3s1` compatibility with
the exact image/kernel and supply its signed binary lock, detached signature,
independent customer artifact trust, and signed eight-image system-image
bundle/lock/signature. No Debian package, image, or repository artifact is
currently supplied by this checkout.

### Red Hat Enterprise Linux 9

The customer supplies an exact approved Compute Engine RHEL image self-link;
an image family is not accepted. The image must identify as Red Hat Enterprise
Linux, use `linux/amd64`, and be at least 9.8. Prefer the latest RHEL 9 minor
verified at provisioning using the [Red Hat release schedule](https://access.redhat.com/kb/red-hat-enterprise-linux-release-dates).
Record the exact image self-link and server-assigned unique image ID, product identity,
OS version/minor, architecture, kernel, image owner, and entitlement/subscription
basis. Rocky Linux, AlmaLinux, CentOS Stream, Oracle Linux, and other
substitutes do not count as RHEL evidence.

The customer RPM owner supplies a private HTTPS repository for the selected
minor, an independently verified signing-key fingerprint and public key,
signed `repomd.xml`/repository metadata, immutable repository snapshot ID, and
actual `.rpm` artifacts. Repository configuration must use `gpgcheck=1` and
`repo_gpgcheck=1`; package policy binds name, exact EVR, `x86_64`/`noarch`,
SHA-256, baseline, expected changes, kernel target and reboot behavior. The
RHEL image must already contain the approved repository public key and required
bootstrap RPMs. Public subscription repositories are not an implicit fallback.

Select Terraform profile `qualification_os_profile=rhel-9` and
`os_family=rhel`; the profile-specific inputs are `rhel_image_self_link`,
`qualification_image_unique_id`,
`rhel_repository_baseurl`, `rhel_repository_gpg_key_path`,
`rhel_repository_gpg_fingerprint`, `qualification_os_minor`, and
`qualification_os_point_release`. The selected image must exactly match the
approved self-link; the repository endpoint and resolved destination CIDRs
must be covered by the approved private mirror allowlist.

Bootstrap and maintenance must preserve SELinux Enforcing, require the
approved active firewall policy, and verify systemd, supported cgroups,
networking, kernel/modules, and the container runtime prerequisites used by
the pinned K3s release. Do not disable SELinux or silently install packages.
The customer must verify K3s compatibility for the exact RHEL image and supply
the same customer-approved K3s binary and eight-image artifacts as for
Debian. Kordex requires its separately signed release bundle, signed six-image
digest lock, tool provenance, and private image destinations too. No approved
RHEL image, entitlement evidence, RPM repository, or package set is currently
supplied.

### Artifact verification command

After all customer inputs are in the customer-local input map, run the
read-only consolidated gate from a trusted checkout:

```sh
python3 scripts/m3_artifact_preflight.py \
  --inputs /secure/m3/customer-artifact-inputs.json \
  --report /secure/m3/artifact-preflight.json
```

The selected platform profile and point/minor release must match that report.
The guarded lab helper binds the report to the exact K3s inputs and selected OS
policy; do not hand-edit Terraform digests or URLs to bypass that binding.
`PASS` from local synthetic tests is not customer artifact approval.

## 2. Customer inputs and owners

No customer trust bundle, signed release, production package set, registry
content, customer PKI, private route, or live GCP authorization has been
verified for this handoff. Each absent deliverable below is `NOT PROVIDED`;
dependent work is **BLOCKED** until the named owner supplies and independently
verifies it. `PROVIDED` means the value was supplied for review, not that it
has passed verification. Transfer public artifacts and evidence only through
customer-approved channels. Private keys, seeds, passwords, enrollment tokens,
registry credentials, SSH private keys, and other secrets must stay in
customer secret management and must never enter this packet, Git, ordinary
email, shell history, Terraform state, or reports.

| Required input / evidence | Responsible owner | Verification and acceptance | Blocks | Status |
|---|---|---|---|---|
| Latest approved Debian 13 image: exact self-link, server-assigned image ID, amd64, OS point-release evidence and approval record | Customer cloud/image owner | Compare self-link/ID with Terraform's exact-image data source; verify the booted image and `/etc/debian_version` against package policy; independently review owner evidence | Debian | NOT PROVIDED |
| Debian archive and security mirrors; Trixie/Trixie-updates/Trixie-security signed metadata, key identity, immutable snapshot | Debian repository custodian | Independently verify archive key/fingerprint, metadata signatures, TLS/DNS destination and snapshot; ensure private CIDR coverage | Debian | NOT PROVIDED |
| Debian package policy and actual `.deb` baseline/target artifacts, versions, architectures, hashes, package delta, kernel/reboot expectations | Debian package custodian | `m3_artifact_preflight.py`; require exact policy/archive digests and at least one real package-version change | Debian | NOT PROVIDED |
| Approved RHEL 9.8+ exact image self-link and server-assigned image ID, source owner and subscription/entitlement basis | RHEL image and subscription owner | Verify product identity, exact image self-link and ID, minor >=9.8, amd64, kernel, support and licensing basis | RHEL | NOT PROVIDED |
| RHEL private RPM endpoint, signed metadata, repository key/fingerprint/trust chain and immutable snapshot | RHEL repository/security custodian | Verify signer independently; require signed metadata and `gpgcheck` plus `repo_gpgcheck`; reject public fallback | RHEL | NOT PROVIDED |
| RHEL package policy, actual `.rpm` baseline/target artifacts, EVRs, architectures, hashes, package delta, SELinux/kernel/reboot policy | RHEL package custodian | `m3_artifact_preflight.py`; inspect package identity and hashes; verify Enforcing SELinux and exact OS/image binding | RHEL | NOT PROVIDED |
| Existing maintenance public bundle `keys.json`, key IDs, rotation/overlap/revocation evidence | Maintenance signing custodian | Use the approved trust exporter only in custodian environment; independently compare public key IDs/fingerprints. Never deliver private seed/key | Both | NOT PROVIDED |
| Customer artifact-approval public trust and signed K3s binary lock/signature/acquisition approval | Supply-chain custodian | Offline `kordex-artifact-lock verify`; confirm key ID independently, exact v1.36.6+k3s1, linux/amd64 and mirror digest | Both | NOT PROVIDED |
| Signed K3s system-image bundle, lock, signature and eight approved image mappings | Supply-chain custodian | Offline `kordex-artifact-lock system-images verify`; then stage and verify each destination digest; staging alone does not populate a registry | Both | NOT PROVIDED |
| Kordex release signing public key/fingerprint, signed release bundle and signed six-image digest lock | Kordex release owner | Independently verify release key fingerprint, bundle signature/checksums and `scripts/verify-image-lock.sh`; lock must include agent, operator, control-plane, dashboard, Ansible EE and PostgreSQL | Both | NOT PROVIDED |
| Tool-provenance public key/fingerprint, signed tool lock, Helm signer allowlist | Release/tool provenance owner | Verify using `scripts/verify-offline-tools-lock.sh`; keep trust separate from release and maintenance signing | Both | NOT PROVIDED |
| Populated private OCI registry and exact source-to-destination mappings for eight K3s plus six Kordex images | Customer registry administrator and release owners | Customer publishes with approved Skopeo process; read-only verifier must report all 14 expected digests and linux/amd64. Keep registry credentials outside input/report | Both | NOT PROVIDED |
| Relay/server and client PKI, CA bundle, DNS SAN, clientAuth EKU, URI SAN-to-enabled-cluster mapping and rotation/revocation plan | Customer PKI owner | Independently verify certificate chain, hostname, expiry, key match and unique URI SAN mapping; private keys installed only through secret management | Both | NOT PROVIDED |
| Private route, DNS/address pinning, source/destination CIDRs, firewall allow/deny evidence | Network owner | Prove bidirectional private route; allow lab-to-relay TCP/18443 and private mirrors TCP/443 only; prove arbitrary public egress denied | Both | NOT PROVIDED |
| Management API org/fleet/site association, registered self-managed cluster, enrollment and authenticated inventory/heartbeat | Kordex administrator | Verify tenant-scoped association, cluster UUID, consumed enrollment, fresh signed identity, inventory and heartbeat | Both | NOT PROVIDED |
| Designated project ID `kordex-fleet-platform-515416`, region `us-east1`, zone `us-east1-b` | GCP project owner | Reconfirm the intended disposable project and location using explicit `--project=kordex-fleet-platform-515416`; repository examples do not change global gcloud configuration | Both | PROVIDED |
| Project ownership/designation, required API approval, IAM/IAP/OS Login, serial recovery, quota, current billing headroom and session cost review | GCP project/billing owner | Read-only confirmation of project label, APIs, permissions, quotas and current cost; separate written approval before any cloud change | Both | NOT PROVIDED |
| Workload/PDB baseline, SSH principal and host-key pin, constrained sudo, snapshots/reset, fault-control authority and independent reviewer | Lab owner and independent reviewer | Review disposable target identity, peer eligibility, recovery plan and evidence checklist; validate access only after separate lab authorization | Both | NOT PROVIDED |

The full owner-specific formats and transfer details are in
[the detailed customer packet](m3-customer-handoff.md). Do not include secret
values in the input JSON; use protected file/secret references accepted by the
current preflight implementation.

## 3. Private connectivity acceptance

The intended path is:

```text
K3s agent in private lab VPC
  -- private route, HTTPS/mTLS, TCP 18443 --> workstation relay private interface
  -- fixed loopback upstream --> Kordex API at 127.0.0.1:8080

Relay health: 127.0.0.1:18444 only
Private package/K3s/OCI mirrors: approved private addresses, TCP 443 only
```

Source code supports the loopback API, private relay mode, allowlisted routes,
mTLS and the loopback-only health listener. These are **implemented, not
deployed or live-verified**. The customer network owner must provide split DNS
that resolves the relay name only to explicitly approved private addresses,
address pinning, bidirectional routing, and ingress filtering to TCP/18443 from
the approved lab source. Agent client certificate URI SAN must map to exactly
one enabled registered cluster; the relay does not replace API Ed25519
signatures, enrollment proof, or tenant authorization.

On the approved workstation, verify local relay health:

```sh
curl --fail --silent --show-error http://127.0.0.1:18444/livez
curl --fail --silent --show-error http://127.0.0.1:18444/readyz
```

After the spoke is installed, enrolled, and the actual private route and
customer PKI are active, run the agent check from its pod (using the approved
private CIDR, repeated for each allowed relay prefix):

```sh
kubectl --context "$KORDEX_CONTEXT" -n kordex-system exec deploy/kordex-agent -- \
  /kordex-agent connectivity-check \
  --allowed-cidr "$APPROVED_PRIVATE_RELAY_CIDR"
```

Acceptance requires the check to report `status: verified`, successful signed
identity response, valid server TLS name/CA and client certificate mapping,
plus independent firewall allow/deny evidence. This command has not been run
over customer networking. A public tunnel does not meet this requirement.

The tracked lab rules require outbound TCP/18443 only to
`approved_private_relay_cidrs`, outbound TCP/443 only to
`approved_private_mirror_cidrs`, and outbound TCP/443 to the restricted Google
APIs VIP `199.36.153.4/30`. IAP administration is inbound from
`35.235.240.0/20` to lab TCP/22; VM external addresses, Cloud NAT, public SSH,
and public HTTPS egress are not part of the design. Internal K3s/Kubelet/Flannel
flows are limited to the lab subnet. The project owner/network owner must
validate actual routing and firewall enforcement; source configuration is not
deployment evidence. TCP/18444 is never a remote health port.

## 4. Canonical qualification matrix

Start every case from its independently reviewed disposable baseline with fresh
operation and evidence IDs. Use the exact guarded command/arguments in the
[readiness runbook](m3-qualification-readiness.md#4-preflight-approval-and-one-clean-operation)
and case metadata in `tests/integration/host_upgrade_failure_matrix.json`.
For each platform, retain platform/image identity, architecture, exact OS
release and kernel, package baseline and repository snapshot, artifact report
and policy digests, operation/checkpoint/reservation state, UTC phase times,
machine/boot/node identities, host and workload health, raw fault evidence,
recovery decision, final state and evidence-file checksums. A separate reviewer
must validate the archived evidence with
`python3 scripts/verify-host-upgrade-qualification.py <evidence-directory>`.

| Canonical scenario | Setup and injection procedure | Expected safety behavior (unchanged) | Evidence required | Debian 13 | RHEL 9.8+ |
|---|---|---|---|---|---|
| `clean-upgrade` | Fresh baseline; execute exact approved package pins with a real package delta and required reboot. | `Succeeded`; actual package change, safe drain, same host/node identities, changed boot ID when rebooted, expected kernel and healthy workloads; release only the operation-owned cordon/reservation after verification. | Before/after package versions, host/node/machine/boot IDs, kernel, drain/workload checks, reboot receipt, terminal checkpoint and reservation release. | NOT RUN | NOT RUN |
| `cancel-during-executing` | Start guarded runner with `--cancel-on-phase Executing`; confirm durable Executing before cancellation. | No apply replay; outcome is `CancellationRecovered` after verified recovery or `CancellationFenced` with fence/reservation retained. | Signed cancellation request/ack, Executing checkpoint, package/journal state, operation events, recovery checks and reservation. | NOT RUN | NOT RUN |
| `cancel-during-reboot` | Start with `--cancel-on-phase Rebooting`; request cancellation after reboot intent is durable. | Cancellation does not assume reboot stopped; result is `CancellationRecovered` only after verified recovery or `CancellationFenced` with the reservation/fence retained. | Reboot intent and response, cancellation acknowledgment, machine/boot IDs, operation checkpoint, health and reservation state. | NOT RUN | NOT RUN |
| `operator-restart-during-executing` | After apply Job starts and Executing is durable, restart the operator Deployment using the approved lab control procedure. | New Ready operator resumes the same operation/checkpoint without duplicate mutation; verified safe terminal state or `RecoveryRequired`. | Old/new operator pod UIDs, same operation/checkpoint, package journal proving no replay, final health and reservation state. | NOT RUN | NOT RUN |
| `ssh-loss-during-apply` | During Executing, block EE-to-target TCP/22 through the reviewed disposable-lab fault controller, record the timed block, then restore it. | `RecoveryRequired`; no blind package replay; retain fence and reservation. | Independent block/restore log and times; `blockedObserved`/`restoredObserved`; operation, journal and read-only host observations. | NOT RUN | NOT RUN |
| `partial-package-application` | Inject a package-manager failure only after at least one approved package pin changes. | `RecoveryRequired`; record partial state and exit code; never replay the package apply automatically. | Changed package names/versions, exact manager exit code, journal, fence and reservation state. | NOT RUN | NOT RUN |
| `reboot-never-returns` | After durable reboot intent, use the approved lab fault controller to prevent the disposable VM from returning for the matrix minimum (120 seconds). | `RecoveryRequired`; reservation and cordon stay held. | Reboot intent, measured unavailable interval >=120 seconds, console/recovery observations and retained reservation/fence. | NOT RUN | NOT RUN |
| `ssh-loss-after-reboot-request` | After persisted reboot intent, drop EE-to-target TCP/22, observe, then restore the approved path. | `RecoveryRequired` unless reboot and recovery are fully proven; no second reboot due to lost response. | Reboot intent, blocked/restored evidence, before/after boot ID and machine identity, operation/journal and reservation state. | NOT RUN | NOT RUN |
| `wrong-machine-id` | During recovery, present only the designated disposable replacement host with a different machine ID; never target a production/shared host. | Reject substitution; `RecoveryRequired`; original target ownership/fence remains. | Expected and observed machine IDs, exact lab target identity, rejection event, unchanged reservation/fence. | NOT RUN | NOT RUN |
| `node-replaced-during-recovery` | In the disposable cluster, replace the Kubernetes Node object while recovery is pending. | Reject changed Node UID; leave replacement untouched; retain original reservation/cordon evidence. | Original and replacement UIDs, API audit/events, replacement state, operation and reservation evidence. | NOT RUN | NOT RUN |
| `wrong-kernel-after-reboot` | Boot the disposable worker with a kernel that differs from the exact approved policy target. | `RecoveryRequired`; expected/observed kernel mismatch; retain fence/reservation. | Approved target and observed kernel, boot identity, rejection event, workload/node health and retained reservation. | NOT RUN | NOT RUN |

The seven host-level manual cases must follow the disposable-only entry gate,
case-specific injection controls, abort conditions, recovery and evidence
instructions in [`m3-manual-failure-procedures.md`](m3-manual-failure-procedures.md).
The external customer mechanism and its approval remain required; the
repository's `tests/integration/record_host_upgrade_fault.py` validates and
attaches evidence but does not inject a fault. No manual case has been run.
A local fixture or simulator result never changes a `NOT RUN` cell.

## 5. Dependency and approval sequence

1. Security, release, tool-provenance, Debian/RHEL package and registry owners
   deliver the public trust and approved artifacts listed above through
   independent customer channels.
2. Custodians verify signatures, key identities, package/image digests,
   architecture, selected OS version and immutable repository snapshots.
3. Registry administrator publishes the approved eight K3s and six Kordex
   OCI images; the read-only verifier confirms every destination digest.
4. Network/PKI owner supplies private routing, DNS, mTLS identities and
   firewall allow/deny evidence; Kordex administrator proves authenticated
   inventory and relay connectivity.
5. GCP owner verifies the designated project, APIs, IAM, IAP/OS Login, serial
   recovery, quotas, billing headroom and the session cost estimate. `$300` is
   a spending ceiling, not confirmed credit.
6. Independent reviewer inspects all input reports and the exact Terraform
   inputs/plan. Planning and provisioning require separate explicit approval;
   this packet grants neither.
7. Only after separate approval, provision the disposable lab, execute every
   matrix row on both platforms, export evidence, verify the archive, destroy
   the lab and confirm actual billing/resource cleanup.

Keep host-upgrade gates off until all prerequisites and approvals are accepted.
M3 remains **NOT COMPLETE** until all 22 real-host platform/scenario results
pass and an independent reviewer accepts their evidence.
