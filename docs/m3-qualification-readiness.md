# M3 qualification readiness — customer input and provisioning gate

Status snapshot: 2026-11-20. This document does not provision infrastructure,
enable maintenance, change the qualification matrix, or claim qualification.
The authoritative acceptance criteria and matrix remain in
[`production-upgrade-requirements.md`](production-upgrade-requirements.md).

## Decision

**NOT READY for lab provisioning.** Repository tooling is ready for customer
review and accepts the required trust inputs, but no real artifact approval,
release handoff, Cloudflare path, enrolled self-managed cluster, or host
evidence is available. The current Terraform lab permits TCP/443 egress to
`0.0.0.0/0`; that does not prove the canonical requirement to deny public and
package-repository egress during installation/recovery. The planned
Cloudflare Access management path also exits through a public Cloudflare
endpoint. A customer/network owner must decide how to satisfy the egress
requirement before provisioning. Do not use the current broad egress rule as
evidence of restricted egress.

The requested GCP project was inspected read-only with explicit project flags.
The active identity was `kphan25@gmail.com`. Project
`kordex-fleet-platform-515323` (number `927924290991`) is `ACTIVE`, has the
`kordex-disposable=qualification` label, and billing is enabled. Compute,
IAM, Cloud Resource Manager, Service Usage, and OS Login APIs are enabled;
IAP and Secret Manager are disabled. There are no VMs, disks, routers, NATs,
addresses, or custom VPCs in the project. Only the default VPC and its default
firewall rules exist; those include public SSH and RDP rules and must not be
used by this lab. The self-managed module creates a separate custom VPC.
Container Engine is disabled and is not required for the K3s lab. Artifact
Registry is not enabled in this project; use a customer-approved image source,
not a repository in the product project.

Billing is enabled, but actual billed usage and remaining promotional credit
were not inspected. No cloud mutation, Terraform plan/apply, deployment, or
maintenance operation was performed. The ignored `terraform.tfvars` was not
read, modified, formatted, or inspected.

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
| Artifact trust | Existing maintenance signing key and matching public operator bundle, with rotation overlap | CUSTOMER INPUT REQUIRED | Authorized maintenance-key custodian must use `docs/m3-trust-recovery-handoff.md` and provide only independently checked public material. No production bundle is available; no replacement key may be generated. |
| Artifact trust | Kordex signed offline bundle, image lock, package artifacts/policy, release public key, tool-provenance key, and Helm signer allowlist | CUSTOMER INPUT REQUIRED | Release owner. No actual signed release package or Ubuntu package set was verified. Release trust, tool provenance, maintenance trust, and customer artifact trust must remain separate. |
| Management plane | Local API and database availability | REPOSITORY COMPLETE | In this session `127.0.0.1:8080/readyz` and `127.0.0.1:8081/readyz` returned `{"status":"ready"}`; a PostgreSQL listener is present. This does not verify database records or remote reachability. |
| Management plane | Secure local configuration for the qualification runner | LOCAL CONFIGURATION REQUIRED | No `KORDEX_*` environment names were set in the current shell. Runner requires `KORDEX_API`, `KORDEX_ADMIN_TOKEN`, `KORDEX_ORG_ID`, `KORDEX_CLUSTER_ID`, `KORDEX_EXPECTED_CONTEXT`, `KORDEX_NODE_NAME`, `KORDEX_HOST_POLICY`, and `KORDEX_HOST_PLAN_DIGEST`; execution additionally requires `KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM`. Supply secrets interactively or through an approved secret store; never put them in shell history or evidence. |
| Management plane | Existing organization/fleet/site selection and registered self-managed cluster identity | CUSTOMER INPUT REQUIRED | Previously supplied records (not queried from PostgreSQL in this review): organization `Kordex GCP Test` `733ff86d-5dd0-4ad9-8476-0910f9eac046`, fleet `gcp-test-fleet` `1d08cef8-e5a3-443a-a5d1-9c871d9c2617`, site `gcp-test-site` `e8d9d100-aecb-4fb7-a284-55983998a588` (recorded `us-central1`). The existing GKE cluster record is not the self-managed K3s lab identity. An authorized administrator must confirm whether to reuse this organization/fleet/site and register a new cluster ID; do not create a tenant or membership implicitly. No self-managed lab cluster is registered. |
| Management plane | Short-lived cluster enrollment token and durable agent identity | LOCAL CONFIGURATION REQUIRED | After cluster registration, request one token through `POST /v1/organizations/{org}/clusters/{cluster}/enrollment-tokens`, store it mode 0600, enroll once, then verify agent identity/heartbeat. No token exists. The token expires after ten minutes and is single-use. |
| Management plane | Agent inventory/heartbeat and operation synchronization from the lab | NOT VERIFIED | Agent protocol and cluster-scoped signature validation are implemented and tested locally. No agent is enrolled or reporting. |
| Gateway | Agent-only HTTPS gateway and Cloudflare service-token support | REPOSITORY COMPLETE | `integrations/agentgateway` and the agent client implement five exact routes, loopback origin, TLS checks, and additional Kordex signature/authentication. Local fixture tests do not establish a Cloudflare deployment. |
| Gateway | Named Cloudflare Tunnel, dedicated hostname, Access application, Service Auth-only policy, short-lived token, trusted origin certificate | CUSTOMER INPUT REQUIRED | Customer must confirm account, domain ownership/management, service-token eligibility and any cost. Do not assume the customer owns a Cloudflare domain. Gateway process config requires `KORDEX_GATEWAY_CLIENT_ID`, `KORDEX_GATEWAY_CLIENT_SECRET`, `KORDEX_GATEWAY_TLS_CERT_FILE`, `KORDEX_GATEWAY_TLS_KEY_FILE`, and `KORDEX_GATEWAY_TLS_SERVER_NAME` (loopback listen address is optional). No gateway listener was found at `127.0.0.1:18443`; tunnel, DNS, Access policy, certificate, and token are NOT VERIFIED. |
| Gateway | Actual VM-to-hub connectivity and TLS validation | NOT VERIFIED | No Kubernetes contexts are configured locally, and no Cloudflare path was configured. Agent requires `KORDEX_CONTROL_PLANE_URL`, `KORDEX_CLUSTER_ID`, `KORDEX_GATEWAY_AUTH_REQUIRED=true`, gateway client ID/secret from a Secret, `KORDEX_CA_FILE` when using a private CA, an enrollment-token file, and durable identity state. Agent TLS verification is implemented; end-to-end connectivity is absent. |
| GCP | Correct disposable project and live qualification label | REPOSITORY COMPLETE | Read-only verification passed for `kordex-fleet-platform-515323`; project is active and correctly labeled. This is not approval to provision. |
| GCP | Compute, IAM, Cloud Resource Manager, Service Usage APIs | REPOSITORY COMPLETE | Read-only API list shows enabled. No API changes were made. |
| GCP | IAP and Secret Manager APIs | CLOUD APPROVAL REQUIRED | Both are currently disabled. Explicit approval is required before enabling. Secret Manager supports runtime-only K3s join-token delivery; IAP supports private VM administration. |
| GCP | Artifact Registry API/repository | CUSTOMER INPUT REQUIRED | API is disabled in the qualification project. No repository exists there. If customer-approved images require Artifact Registry, choose an approved repository and approve enabling its API; do not reuse `kordex-fleet-platform`. |
| GCP | VM service accounts and least-privilege IAM | CLOUD APPROVAL REQUIRED | Terraform creates separate server/worker identities and secret-scoped permissions. Provisioning also requires reviewed Compute/VPC/firewall/router/NAT/service-account/Secret Manager IAM permissions and `iam.serviceAccounts.actAs`. Current user has project Owner, but permission is not approval. IAP operator requires narrowly scoped tunnel, OS Login admin, service-account use, and instance/project discovery access. No IAM was changed. |
| GCP | Private custom VPC, IAP-only SSH, no VM external IP, three-node Ubuntu/K3s topology | REPOSITORY COMPLETE | Terraform module defines separate VPC, IAP ingress, private VMs, one server/two Ubuntu workers and peer outputs. No plan/apply or live verification occurred. Do not use the existing default VPC. |
| GCP | Public/package egress restriction during package apply and recovery | NOT IMPLEMENTED | The current module allows TCP/443 to `0.0.0.0/0` through Cloud NAT. It is temporary and documented, but not destination-restricted. The Cloudflare agent route also uses a public edge. This conflicts with the canonical site-local-only maintenance/recovery flow unless the customer/network owner supplies an approved compliant path or an explicit reviewed requirements decision. Stop before provisioning. |
| GCP | Snapshot/reset strategy for independent failure cases | NOT IMPLEMENTED | The module has no snapshot lifecycle. Safest current reset is preserve evidence, destroy and recreate the entire disposable lab per independent baseline; this needs repeated approvals and costs. Do not restore a worker disk alone without reconciling K3s Node identity and durable operation history. |
| GCP | Serial-console and out-of-band recovery access | NOT VERIFIED | No VM exists to test it. Before apply, the lab owner must confirm serial-console IAM/access and a tested recovery procedure. |
| GCP | Network fault injection and independent fault logs | NOT IMPLEMENTED | Matrix cases include SSH loss, host non-return, package failure, wrong machine ID/kernel, and Node replacement. The recorder exists, but the lab has no approved fault injector or independently retained network-control/console logs. |
| GCP | Cleanup and budget | REPOSITORY COMPLETE | Guarded destroy and resource checks are documented. Project has no visible lab compute resources now. Billing data, budget remaining, and future cleanup success are NOT VERIFIED. |
| Maintenance | Worker-peer eligibility and local safety checks | REPOSITORY COMPLETE | Operator requires an eligible Ready peer; Terraform provides two workers. Unit/API-server tests do not verify this live lab. |
| Maintenance | SSH execution account, private key, known-host pin, EE digest/pull credentials | LOCAL CONFIGURATION REQUIRED | Customer must provision the exact disposable worker SSH credential and pinned `known_hosts`, verify sudo scope, and select an immutable EE digest. No credentials or image allowlist are configured. |
| Maintenance | Ubuntu policy, package baseline, signed plan, approval and execution credentials | CUSTOMER INPUT REQUIRED | Release owner supplies verified package artifacts/policy; authorized Kordex admin selects OS identity allowlist, plan digest and operation approval. Reboot policy must require a controlled reboot and kernel expectation if the plan updates the kernel. |
| Maintenance | Drain, real package update, reboot, recovery, workload checks | NOT VERIFIED | Implemented code and local tests exist. No live worker, operation, package change, reboot, recovery, reservation release, or workload check occurred. |
| Maintenance | Cancellation/failure cases and evidence verifier | REPOSITORY COMPLETE | Runner, failure recorder, evidence verifier, and matrix have local tests. External fault injection and all actual outcomes remain NOT RUN. |
| Maintenance | Qualification evidence and second review | CUSTOMER INPUT REQUIRED | Independent reviewer must inspect host journal, actual package delta, reboot identity, workload state, fences/reservations, fault logs, and archived checksums. No evidence exists. |
| Customer deployment | Independent install/operate/troubleshoot readiness | NOT VERIFIED | Customer deployment guides and Helm/Kustomize/Compose paths exist, but no independent team has completed an installation rehearsal. This is an M6 readiness item, not an excuse to broaden M3. |
| Customer deployment | Self-managed spoke Kustomize trust and immutable images | CUSTOMER INPUT REQUIRED | The overlay requires `keys.json`, which is intentionally absent, and example image references are placeholders. A real maintenance public trust bundle and approved digest-pinned images/release bundle are required. Rendering the current overlay fails on missing `keys.json`; do not fabricate it. |

## Execution window and cost planning

The GCP lab module uses three `e2-standard-2` VMs, three 40 GiB
`pd-balanced` disks, temporary Cloud NAT and one ephemeral NAT IP. Its checked-in
planning estimate is about `$0.226673/hour`: `$0.91` for four hours and `$1.81`
for eight hours. NAT processing, internet egress, taxes, and services outside
the estimate are additional. Thirty days is about `$163.20`; 90 days is about
`$490` before variable costs and exceeds the `$300` M3–M6 target. Stopped VMs
can leave billable disks/NAT/IP resources. This estimate is not billing data or
a spend cap.

| Work | Planning window | GCP baseline estimate |
|---|---:|---:|
| Customer trust, artifact review, Cloudflare/domain and API preparation | Several days may be needed; no lab resources | `$0` lab runtime |
| Create/bootstrap, registration, inventory, preflight, and clean-upgrade | Reserve 4–8 hours; use 8 hours for the first session | `$0.91`–`$1.81` plus variable traffic |
| One independent failure case and fresh-baseline recovery | Reserve 4–8 hours per case until measured | `$0.91`–`$1.81` plus variable traffic |
| Full Ubuntu set of 11 pinned matrix cases | At least 11 independently baselined cases; likely multiple sessions | About `$9.97`–`$19.95` base if each case uses 4–8 hours, excluding resets/traffic |

Reset/rebuild duration and full-run cost are NOT VERIFIED. Do not leave the lab
between sessions. RHEL evidence is outside the Ubuntu-only lab and remains
required by the canonical full-matrix verifier.

## Exact customer inputs and approvals

Before any plan review, obtain and independently verify:

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
4. From the network/domain owner: confirm Cloudflare account and managed
   domain, dedicated hostname, service-token policy support, approved
   workstation tunnel operation, and how its public endpoint satisfies the
   canonical egress restriction. If it cannot, provide an approved private
   management route. No domain purchase or tunnel setup is authorized here.
5. From the Kordex administrator: select an existing organization/fleet/site,
   supply a short-lived authorized admin credential through a secure local
   workflow, and approve registration of this new self-managed cluster. No
   membership or organization change is implied.
6. From the GCP project owner/network owner: approve enabling IAP and Secret
   Manager APIs; approve the exact Terraform plan, three VM resources, custom
   VPC, firewall rules, Cloud Router/NAT and service accounts; approve scoped
   IAM and IAP/OS Login grants. Confirm budget and remaining $300 M3–M6
   allocation. Artifact Registry API/repository approval is conditional on the
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

### 2. GCP review and plan (no apply until a separate approval)

Continue to pass the project explicitly; do not change global gcloud project:

```sh
gcloud projects describe kordex-fleet-platform-515323 \
  --project=kordex-fleet-platform-515323
gcloud services list --enabled --project=kordex-fleet-platform-515323
```

Only after written API/IAM/network approval and customer trust inputs, prepare
private variables from the reviewed example without printing them. The ignored
file must remain mode 0600 and must contain the same digest and mirror URL as
the signed lock. The guarded command is:

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id kordex-fleet-platform-515323 \
  --k3s-binary /approved-transfer/k3s \
  --k3s-artifact-lock /approved-transfer/k3s.artifact-lock \
  --k3s-artifact-signature /approved-transfer/k3s.artifact-lock.sig \
  --k3s-artifact-trust /independent-trust/k3s-artifact-approval.trust
```

Review every planned resource, egress rule, project, region, zone, image, and
cost. The current plan is **not approved**. Apply only after a separate human
review and explicit authorization, using the same four artifact inputs and
the exact interactive confirmation requested by the helper. Never invoke raw
`terraform plan/apply` for provisioning; it bypasses the customer signature
preflight.

### 3. Bootstrap, inventory, and management-plane connection

After an approved apply, use only project `kordex-fleet-platform-515323`, zone
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
  --project=kordex-fleet-platform-515323 --zone=us-east1-b \
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
cluster ID, HTTPS management URL, required Cloudflare Access mode if approved,
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

After the customer has configured the named Cloudflare Tunnel and approved the
service-token policy, load gateway secrets from the approved local secret
store (never inline them in command history), start the gateway, and run the
named tunnel using the reviewed configuration in
[`m3-cloudflare-agent-gateway.md`](m3-cloudflare-agent-gateway.md):

```sh
go run ./integrations/cmd/kordex-agent-gateway
cloudflared tunnel --config /protected/path/config.yml run APPROVED_TUNNEL_NAME
```

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
  --project-id kordex-fleet-platform-515323 \
  --target-confirmation "$KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM" \
  --qualification-case clean-upgrade \
  --timeout-seconds 14400 \
  --evidence ./qualification/clean-upgrade-debian.json
```

The helper checks the disposable project designation and prompts for its
project-bound execution confirmation. Execution requires a separate human
approval after preflight succeeds. Do not run it in this readiness phase.

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
live settings, revoke the Cloudflare service token, remove only lab credential
Secrets, and retain evidence off-cluster. Then use the guarded destroy helper
after separate destroy approval:

```sh
python3 scripts/self_managed_lab.py destroy \
  --project-id kordex-fleet-platform-515323
```

Verify no lab instances, disks, snapshots, addresses, routers/NAT, custom VPC,
firewall rules, service accounts, Secret Manager entries, or Kordex/Cloudflare
credentials remain. Preserve the default VPC and its unrelated default rules.
Review actual Cloud Billing data for the complete qualification window; budget
alerts and free credits are not spending caps. The planning model in the lab
README is about `$0.91` for 4 hours and `$1.81` for 8 hours for the 3-VM/NAT
baseline, plus NAT data processing, egress, taxes, and any services not in that
model. A 30-day baseline is about `$163.20`, and a 90-day baseline about `$490`
before variable costs, exceeding the total `$300` M3–M6 target. Stopped VMs
can still leave billable disks/NAT/IP resources. Destroy after every session.

## Explicit stop conditions

Stop before plan/apply if any of these holds:

- customer artifact/maintenance/release trust is missing, comes from the same
  channel as the artifact, or fails signature/digest/identity verification;
- there is no customer-approved mirror or lab VMs cannot reach it over
  verified HTTPS;
- the Cloudflare domain/Access token is unavailable, the gateway path fails,
  or the customer cannot reconcile it with the site-local/no-public-egress
  acceptance requirement;
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
