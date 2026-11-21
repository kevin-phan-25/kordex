# Disposable self-managed Kordex qualification lab

This module prepares a three-VM K3s lab in a dedicated custom VPC for a
supplemental self-managed Ubuntu 24.04 run: one control-plane server and two
separate Ubuntu workers. Each worker can be the other's eligible maintenance
peer. It does not satisfy the canonical Debian and RHEL evidence requirements.
This is separate from GKE and never uses the default VPC. The current
task is local preparation only: no plan, apply, API enablement, IAM grant, or
VM operation has been performed.

## Design

```text
Workstation --IAP TCP/SSH--> private K3s server --private VPC--> Ubuntu workers
     |                         |                                  |
     |                         +-- restricted.googleapis.com      +-- private package/K3s/API mirrors
     +-- existing private route --> workstation mTLS relay <------+
```

- Dedicated custom VPC `10.76.0.0/24`; no default-VPC dependency.
- Ubuntu 24.04 image family `ubuntu-2404-lts-amd64` for `os_family=debian`.
- Both startup scripts verify `ID=ubuntu` and `VERSION_ID=24.04` before
  replacing package sources. This protects the moving Ubuntu image family from
  silently changing the package manager/repository contract.
- Debian 12 and RHEL 9.5 lab image/repository bootstrap is not implemented.
  The package artifact verifier accepts supported Debian/RPM policy profiles,
  but that is not VM bootstrap support. Do not use Ubuntu evidence for either
  canonical platform family.
- One K3s server and two Ubuntu 24.04 worker VMs, each `e2-standard-2` with a
  40 GiB `pd-balanced` boot disk by default. The server is not a maintenance
  target. Either Ubuntu worker can be maintained while the other remains an
  eligible Ready peer.
- None of the VMs has an external IP. No public SSH/RDP ingress exists.
- IAP TCP forwarding is allowed to SSH (TCP/22) only from Google's IAP
  forwarding range `35.235.240.0/20`. OS Login is enabled and project SSH keys
  are blocked. The administrator receives access through separately granted
  IAP and OS Login IAM roles; Terraform does not grant user IAM.
- Internal firewall allows TCP 22/6443/10250 and UDP 8472 only within the lab
  subnet. Egress allows DNS to the metadata resolver, TCP/443 for private HTTPS
  mirrors and TCP/18443 for the workstation relay, each only to explicit
  RFC1918 CIDRs supplied by the customer, and TCP/443 to the restricted Google
  APIs VIP (`199.36.153.4/30`) for the runtime Secret Manager token workflow.
  A private Cloud DNS `googleapis.com` zone maps Google API names to that VIP;
  the subnet enables Private Google Access. A higher-priority deny blocks all
  other destinations. There is no Cloud NAT, public VM address, or public
  HTTPS allow rule. Private mirrors are allowed only on TCP/443 through
  `approved_private_mirror_cidrs`; the workstation relay is allowed only on
  TCP/18443 through `approved_private_relay_cidrs`. The customer must verify
  that mirror and relay DNS answers fall within their respective CIDRs; firewall rules enforce the IP ranges,
  not DNS names. Ubuntu apt sources are replaced with one customer mirror
  containing the Noble suites and are still verified with Ubuntu's archive
  signing key. The mirror, K3s binary mirror, image mirror, and workstation
  relay must be reachable through an already-approved private route. No
  internet fallback is configured.
- Before a future plan, the owner must set `approved_private_mirror_cidrs` to
  the canonical RFC1918 destinations for Ubuntu, K3s binary, OCI, and package
  mirrors and `approved_private_relay_cidrs` to the private relay destination;
  each CIDR must be no broader than `/24`. Set `ubuntu_apt_mirror_url` to the
  HTTPS Ubuntu archive root. Terraform rejects missing or public CIDRs, a
  missing mirror URL, or a non-Ubuntu profile. The workstation relay's source
  CIDR allowlist and host firewall ingress are separate: they must use the
  actual lab source address/range observed at the workstation (the lab subnet
  default is `10.76.0.0/24`). Confirm DNS answers are in the matching
  destination set; no hostname-based firewall claim is made.
- Dedicated server and worker service accounts have no project roles. Each
  receives only a secret-level role for the temporary K3s join credential.
  The worker can access the payload and read only version metadata on that
  secret; it cannot create or manage versions. Both use the `cloud-platform`
  OAuth scope, constrained by IAM.
- K3s is pinned to `v1.36.6+k3s1`, using the upstream `k3s` artifact for
  `linux/amd64` at
  `https://github.com/k3s-io/k3s/releases/download/v1.36.6%2Bk3s1/k3s`.
  Upstream's matching checksum asset is
  `https://github.com/k3s-io/k3s/releases/download/v1.36.6%2Bk3s1/sha256sum-amd64.txt`;
  its standard line format is 64 lowercase hexadecimal characters, two spaces,
  then `k3s`. The pinned upstream release workflow creates this manifest from
  the binary checksum and uploads both as release assets, but does not sign
  the manifest or publish a binary artifact attestation. A GitHub release
  asset's API digest is also metadata from that same distribution service, not
  an independent signer. Therefore the adjacent checksum does not authenticate
  the binary independently. Both VMs reject a host whose `uname -m` is not
  `x86_64`; Terraform has no digest default. No independently verifiable K3s
  binary signing key, fingerprint, or provenance identity is currently
  configured here. M3 instead requires customer-controlled artifact approval
  with a separately provisioned organization key and internal mirror, as
  documented in `docs/m3-customer-artifact-approval.md`. This is customer
  approval, not upstream provenance. The verifier checks a signature before
  using the lock digest, validates the local binary's digest/ELF architecture/
  reported version offline, and does not fetch URLs. The lab's startup scripts
  fetch only `k3s_binary_mirror_url` without redirects and compare the required
  digest. Verify the mirror copy and source both values from that signed lock
  before approving a Terraform plan. `scripts/self_managed_lab.py plan` and
  `apply` now require the local mirror copy, signed lock, detached signature,
  and independent trust bundle; they compare the verified digest and URL to
  protected tfvars, pass those exact values to Terraform, filter Terraform
  environment overrides, and bind the reviewed apply plan to unchanged lock /
  signature / trust inputs. Direct Terraform plan/apply bypasses this gate and
  is unsupported.
- K3s system images use a separate customer-signed fixed-order manifest under
  the same independently provisioned artifact-approval trust bundle. The
  verifier accepts only the exact eight `linux/amd64` references in the
  pinned K3s release image list, validates each OCI manifest/config/layer
  digest and rejects missing, unexpected, or wrong-architecture content. It
  also binds each image's original Docker Hub reference to a customer private
  registry reference and digest. This is customer approval, not upstream
  provenance; no production bundle, digest, lock, or signature is in Git.
- `kordex-artifact-lock system-images stage` verifies the detached signature
  and complete local archive before atomically staging the archive, lock,
  signature, deterministic inventory, and generated `registries.yaml` beneath
  an existing private HTTPS artifact-mirror root at
  `k3s/<version>/linux-amd64/<archive-sha256>/`. The URL in the signed lock
  must resolve to that exact content-addressed path. Existing identical
  output is idempotent; conflicting output is rejected. A partial temporary
  directory is never accepted as staged output.
- The guarded `plan` and `apply` commands require the local bundle, signed
  system-image lock, signature, and independent trust bundle in addition to
  the already required signed binary inputs. They verify both approvals
  offline, snapshot and fingerprint the inputs, and pass only the lock-bound
  version, architecture, digest, URL, and registry host to Terraform. The
  image manifest must be version 1 for K3s `v1.36.6+k3s1` on `linux/amd64`.
  The Terraform variables have no defaults and a precondition checks their
  cross-field binding. Direct Terraform plan/apply remains unsupported.
- On all three new VMs, startup validates the exact archive digest, installs
  it under `/var/lib/rancher/k3s/agent/images/` before starting K3s, and
  installs only the registry mapping derived from the signed lock. A
  mismatched cached archive, unexpected file in the image staging directory,
  or conflicting registry config stops bootstrap. K3s runs with
  `--disable-default-registry-endpoint`; public Docker Hub fallback is
  disabled. If an imported image is absent, only the configured customer
  registry can be tried, and failure is closed. Customer must ensure the
  private registry contains the approved tags/digests before use; the airgap
  archive itself is the node-local, digest-verified source.
- `docs/m3-k3s-system-image-staging.md` contains the manifest signing,
  verification, staging, mirror, and bootstrap workflow. Do not restore broad
  egress or pull unapproved images to work around missing inputs.
- Bootstrap installs the binary directly under `/usr/local/bin` and creates
  explicit systemd units; it does not execute `get.k3s.io` or another remote
  installer. A root-only recovery record stores only the token ID and Secret
  Manager version reference so a startup-script rerun does not mint duplicate
  credentials. GCE startup scripts use a completion marker and are idempotent
  after bootstrap succeeds.
- The server creates a K3s agent bootstrap token at runtime with a 30-minute
  TTL, adds it to the one lab Secret Manager secret, and deletes the K3s token
  and secret version only after both named workers are Ready. The Secret Manager secret has
  a four-hour TTL as a backstop. If bootstrap fails, the K3s token expires in
  30 minutes and the Secret Manager secret expires within four hours.
- Secret payload is stored in Secret Manager while active, then in a
  root-only (`0700` directory, `0600` file) worker file at
  `/var/lib/kordex/agent-token` so the K3s agent service can start after VM
  reboot. K3s parses a non-empty token input during agent startup; therefore
  this local copy remains until the worker disk is destroyed. The server
  deletes the bootstrap token after both workers are Ready and the token also
  expires after 30 minutes, so the retained string is revoked/expired and
  cannot authorize another join. K3s node-password and client identity are
  persisted separately for reconnects. A real reboot must verify that path.
  The token payload is never a Terraform variable, state value, instance
  metadata value, command-line argument, or startup-script log output. K3s
  creates its own server token on the server; that credential is retained
  locally by K3s for cluster operation and is not shared with a worker.
- Each worker has a fixed local `kordex` executor account with passwordless
  sudo because the disposable host executor requires it. Its SSH key and
  known-host pin must be provisioned later through the existing Kordex Secret
  workflow. IAP/OS Login administration is separate.
- `deletion_protection` remains false so the guarded destroy helper can remove
  the lab. Preserve and verify evidence off-cloud before teardown.

## Project targeting and prerequisites

The approved target for future commands is:

```text
project: kordex-fleet-platform-515416
number:  209068399397
region:  us-east1
zone:    us-east1-b
```

The Terraform Google provider receives `project_id` explicitly. The guarded
Python helper also passes the selected ID to `gcloud projects describe` as
both the resource argument and `--project`. Do not use `gcloud config set
project`; the global gcloud project is intentionally unchanged. The tracked
`terraform.tfvars.example` contains the approved ID and exact one-project
allowlist. Before a future plan, the ignored `terraform.tfvars` supplies the
K3s binary digest and mirror URL from a verified signed lock; the file remains
mode 0600. System-image values are not hand-entered there: the guarded
plan/apply helper requires the local OCI archive, signed image lock, signature,
and independent trust file, verifies them offline, and passes their exact
version, architecture, digest, URL, and registry host to Terraform. It
rechecks binary and image approvals before applying the saved plan. Terraform
and startup scripts do not independently verify signatures; direct Terraform
plan/apply is unsupported.

Required APIs (not enabled by this task):

- `compute.googleapis.com`
- `iam.googleapis.com`
- `cloudresourcemanager.googleapis.com`
- `secretmanager.googleapis.com`
- `iap.googleapis.com`
- `dns.googleapis.com` for the private restricted Google APIs zone
- `serviceusage.googleapis.com` to enable APIs, if it is not already enabled

The prior inspection found Compute, IAM, and Cloud Resource Manager enabled;
IAP, Secret Manager, and Cloud DNS were disabled. Recheck status before any
future plan. API enablement requires separate owner approval and
`serviceusage.services.enable`.

The Terraform operator needs reviewed permissions to create/use/delete the
custom VPC, subnet, firewall rules, private DNS zone and records, VM
instances/disks, service accounts, Secret Manager secret and secret-level IAM
policy, plus `iam.serviceAccounts.actAs`. A future plan will report exact
permission failures; do not broaden IAM automatically.

The IAP administrator needs `roles/iap.tunnelResourceAccessor` on the target
VM, `roles/compute.osAdminLogin` for sudo on the target VM, and
`roles/iam.serviceAccountUser` on the VM's service account. For the `gcloud compute ssh`
command, also grant the minimum project/instance discovery permissions
(`compute.projects.get` and `compute.instances.get`) at the narrowest supported
scope. `roles/compute.osLogin` is sufficient only when sudo is not needed.
Google documents OS Login roles and IAP tunnel access as instance- or
project-level grants; this module creates no user IAM bindings. See [OS Login
setup](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin) and
[IAP TCP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding).

## Workstation-to-API path

The Kordex API remains bound to `127.0.0.1`; PostgreSQL, Keycloak, dashboard,
health/readiness, organization administration, and metrics are not routed. The
agent client supports opt-in mTLS and the local relay rejects any request route
outside these exact method/path pairs:

| Method | Path |
|---|---|
| GET | `/v1/agent/identity` |
| POST | `/v1/agent/enroll` |
| POST | `/v1/agent/report` |
| POST | `/v1/agent/rotate` |
| POST | `/v1/agent/operations/sync` |

Private-route flow (not yet configured):

1. The lab VPC reaches a customer-approved private route to a workstation
   private interface; split DNS resolves the relay name to that private
   address. No public tunnel is in this M3 path.
2. The workstation relay binds only to the configured private interface,
   checks the source peer against an explicit private CIDR allowlist, requires
   a customer-issued client certificate, and maps its URI SAN to one enabled
   registered cluster.
3. The relay forwards only the five method/path pairs above to the fixed
   `http://127.0.0.1:8080` API upstream. It does not forward caller-supplied
   identity headers. The API independently verifies enrollment, Ed25519
   signatures, agent identity, tenant/cluster ownership, and operation scope.
4. The agent verifies the relay server CA and DNS identity and presents its
   customer-issued mTLS certificate. Certificate trust does not replace Kordex
   identity or authorization.

The workstation private route, DNS, firewall policy, customer PKI, certificates,
and live end-to-end connectivity remain customer-owned and unverified. See
`docs/private-agent-relay-operations.md` and
`docs/agent-mtls-configuration.md`.

After those inputs are provisioned in a separately approved environment, check
relay process health locally with `curl http://127.0.0.1:18444/livez` and
`curl http://127.0.0.1:18444/readyz`. From the enrolled agent Pod, verify the
actual split-DNS, TCP/18443, server certificate, client certificate mapping,
and Kordex signed identity path with:

```sh
kubectl --context "$KORDEX_CONTEXT" -n kordex-system exec deploy/kordex-agent -- \
  /kordex-agent connectivity-check \
  --allowed-cidr <approved-private-relay-cidr>
```

Use one repeatable `--allowed-cidr` flag for each approved relay-address
prefix. The check fails unless all resolved addresses are private and within
the supplied ranges, pins the socket to a checked address, and reports
credential-safe JSON. It does not configure DNS, routes, firewall rules, TLS
Secrets, or the relay mapping. A successful check verifies only the transport
and agent identity endpoint, not M3 maintenance qualification.

## Cost model

Planning rates for three `e2-standard-2` VMs, three 40 GiB `pd-balanced`
disks, and one private Cloud DNS zone. There is no Cloud NAT or public NAT IP:

| Component | Approximate rate | 4 hours | 8 hours | 1 week | 30 days |
|---|---:|---:|---:|---:|---:|
| VM runtime (3 × $0.06701142/h) | $0.201034/h | $0.80 | $1.61 | $33.77 | $144.74 |
| Boot disks (120 GiB × $0.000136986/GiB-h) | $0.016438/h | $0.07 | $0.13 | $2.76 | $11.84 |
| Private Cloud DNS zone | $0.000274/h | <$0.01 | <$0.01 | $0.05 | $0.20 |
| **Estimated subtotal** | **$0.217747/h** | **$0.87** | **$1.74** | **$36.58** | **$156.78** |

DNS queries are extra at current Cloud DNS rates; network mirror traffic and
any customer VPN/route charges are not included. No VM external-IP charge
applies. Logging and Monitoring agents are not installed, so no such ingestion
is budgeted. Stopped VMs still retain billable disks. A 30-day accidental
retention of disks and the DNS zone costs about `$12.04` at these assumptions.
A 90-day continuously running baseline is about `$470` before query charges,
network transfer, taxes, or optional route costs, so it exceeds the $300 total
budget. These published on-demand rates are estimates,
not billing data or a spending cap. Free-trial credits and budget alerts do
not limit accrued charges.

Cloud DNS zone pricing is prorated by hour and queries are billed separately;
see [Cloud DNS pricing](https://cloud.google.com/dns/pricing). The customer
private route itself is not provisioned or priced by this module.

Sources: [Compute Engine E2 pricing](https://cloud.google.com/products/compute/pricing/general-purpose),
[Persistent Disk pricing](https://cloud.google.com/compute/disks-image-pricing),
[Cloud DNS pricing](https://cloud.google.com/dns/pricing),
[Secret Manager pricing](https://cloud.google.com/secret-manager/pricing).
Secret Manager currently includes up to six active versions and 10,000 access
operations per month per billing account at no charge; the join version is
short-lived and destroyed after worker enrollment. It is not material to the
estimate under those account-wide limits.

## Prepare and validate locally

Terraform/OpenTofu 1.6+, Python 3, and gcloud are required. Copy the example
only when preparing a later plan; it contains no credentials:

```sh
cp infrastructure/terraform/gcp/self-managed-lab/terraform.tfvars.example \
  infrastructure/terraform/gcp/self-managed-lab/terraform.tfvars
chmod 600 infrastructure/terraform/gcp/self-managed-lab/terraform.tfvars
python3 scripts/self_managed_lab.py validate
```

The local read-only summary checks the tracked profile, installed tools,
customer-supplied private CIDRs/ports, and freshness/hash bindings for an
artifact report without network or cloud access. It never reads the ignored
`terraform.tfvars` or opens the registry credential file. The guarded plan
still performs the authoritative full artifact verification and live project
check, and validates the real Terraform inputs without printing them:

```sh
python3 scripts/m3_deployment_readiness.py \
  --project-id kordex-fleet-platform-515416 \
  --network-inputs /secure/m3/network-inputs.json \
  --artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --artifact-report /secure/m3/artifact-preflight.json \
  --output /secure/m3/deployment-readiness.json
```

The summary is not a signed attestation or an approval to plan/apply. Missing
customer or cloud evidence remains `NOT PROVIDED`.

Before a separately authorized plan, review the target project, APIs, IAM,
private route and DNS, private egress CIDRs, Ubuntu mirror and the actual
`terraform.tfvars`. That ignored file must include a customer-verified K3s lock,
the exact mirror URL, and all non-secret private-network inputs. Use the
designated project ID shown below; do not change gcloud's global project.
Then the exact future plan command is:

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id kordex-fleet-platform-515416 \
  --m3-artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --m3-artifact-report /secure/m3/artifact-preflight.json \
  --k3s-binary /verified-transfer/k3s \
  --k3s-artifact-lock /verified-transfer/k3s.artifact-lock \
  --k3s-artifact-signature /verified-transfer/k3s.artifact-lock.sig \
  --k3s-artifact-trust /independent-trust/k3s-artifact-approval.trust \
  --k3s-system-images-bundle /verified-transfer/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /verified-transfer/k3s-system-images.lock \
  --k3s-system-images-signature /verified-transfer/k3s-system-images.lock.sig \
  --k3s-system-images-trust /independent-trust/k3s-artifact-approval.trust
```

Replace only the file paths with the reviewed customer locations. The consolidated
preflight verifies maintenance, customer artifact, release, and tool trust
separately; the signed release/image locks; the K3s binary and system-image
bundle; private registry digests/architecture; and policy-bound Ubuntu package
inputs. It checks mirror DNS/TLS and package deltas, downloads and digest-checks
the package archive from its private HTTPS source, verifies all registry blobs
through a temporary local OCI layout, emits no credential values, and returns
nonzero unless every row is `PASS`. The guarded helper
regenerates the report before plan/apply and binds its K3s hashes to the
Terraform command inputs. It retains the existing direct K3s signature checks,
rejects auto-loaded Terraform variable files, and strips Terraform environment
overrides. Apply regenerates the report again after typed confirmation and
before applying the saved plan. Direct Terraform plan/apply bypasses these
checks and is unsupported. No real customer inputs are present, so the
workflow has not passed against a production artifact or registry. Do not run
apply until a saved plan has been separately reviewed and explicitly approved.
Qualification `execute` also requires the same preflight inputs and eight K3s
artifact paths. It reruns and compares the report after disposable-project
confirmation immediately before launching the runner. Direct Terraform or
qualification-runner invocation bypasses these checks and is unsupported.

## IAP administration and K3s access

After an approved deployment, open a terminal and run the IAP-backed SSH
tunnel command:

```sh
gcloud compute ssh kordex-lab-server \
  --project=kordex-fleet-platform-515416 --zone=us-east1-b \
  --tunnel-through-iap -- -N -L 6443:127.0.0.1:6443
```

In a second terminal, retrieve the kubeconfig through IAP. It contains a
cluster credential, so keep it outside Git and mode 0600:

```sh
gcloud compute ssh kordex-lab-server \
  --project=kordex-fleet-platform-515416 --zone=us-east1-b \
  --tunnel-through-iap \
  --command='sudo cat /etc/rancher/k3s/k3s.yaml' > ./kubeconfig
chmod 600 ./kubeconfig
export KUBECONFIG="$PWD/kubeconfig"
kubectl config get-contexts
kubectl get nodes -o wide
```

The Terraform outputs explicitly identify all three K3s nodes and both
maintenance peers. Review them before enrollment or qualification:

```sh
terraform output -json k3s_node_names
terraform output -json k3s_node_internal_ips
terraform output -json worker_names
terraform output -json worker_internal_ips
```

The compatibility outputs `worker_name` and `worker_internal_ip` identify
`worker-1`; use the plural outputs when selecting a target and its peer.

The kubeconfig server address is loopback and works only while the first
terminal's IAP SSH tunnel is alive. The in-cluster Kordex operator reaches the
worker on its private address and SSH port. The agent uses the customer private
route and workstation mTLS relay described above; no public endpoint is used.

## Session and teardown procedure

1. Apply only after reviewing and approving the exact plan.
2. Wait for all three K3s nodes (server and both workers), bootstrap-token
   revocation, and Secret Manager version destruction. Verify startup did not
   report a failure. Confirm each worker is Ready while the other is Ready and
   schedulable, and that the control-plane server is never selected as a host
   maintenance target.
3. Confirm denied public egress and required private mirror/relay flows using
   the approved network test plan; do not add a general HTTPS exception.
4. Close both repository and operator host-upgrade gates and verify them off.
5. Archive qualification evidence off-cloud and verify its SHA-256 manifest.
6. Remove lab Kordex workloads and SSH credential Secrets, revoke lab client
   certificates, and disable the separately approved private route after
   evidence is archived.
7. Run the guarded teardown; it shows a destroy plan, rechecks the project
   designation, and requires the exact project-bound confirmation:

   ```sh
   python3 scripts/self_managed_lab.py destroy \
     --project-id kordex-fleet-platform-515416
   ```

Teardown removes VMs/disks, custom VPC/firewalls, private DNS zone/records,
service accounts, secret IAM bindings, and the expiring Secret Manager secret. Do not use raw
`terraform destroy`. Preserve the Terraform state until teardown is verified;
it contains resource metadata but no K3s token value. After successful
teardown and evidence checks, remove local state and kubeconfig only according
to the approved evidence-retention procedure.

## Recovery baseline, snapshots, and controlled faults

The repository now contains guarded recovery helpers. They are not live-tested
and do not authorize cloud operations. The project owner must separately approve
all GCP access, and an operator must independently inspect every target and
confirmation before using these commands. Every command pins project
`kordex-fleet-platform-515416`, lab identity `kordex-lab`, zone `us-east1-b`,
and the exact Terraform node names. It rejects other projects, zones, lab IDs,
resource names, missing project labels, and incomplete topology. All local JSON
evidence and audit files are created with mode 0600 and are never overwritten.

Capture a healthy baseline only when all three nodes and workloads are Ready
and the operator has checked that no Kordex operation is active or ambiguous.
The explicit attestation is an operator statement, not an API-derived proof:

```sh
python3 scripts/self_managed_lab.py recovery baseline \
  --project-id kordex-fleet-platform-515416 --lab-id kordex-lab --zone us-east1-b \
  --server kordex-lab-server --worker-1 kordex-lab-worker --worker-2 kordex-lab-worker-2 \
  --context <explicit-k3s-context> --idle-attestation NO_ACTIVE_MAINTENANCE \
  --output ./qualification/baseline-<id>.json --audit ./qualification/recovery-audit.jsonl
```

For a snapshot safe point, first verify maintenance is idle again, gracefully
stop the K3s services/VMs using the approved operator runbook, and confirm all
three VMs are `TERMINATED`. Baselines expire after two hours. Snapshot creation
requires a second explicit idle attestation and typed confirmation. The helper
verifies each instance label, role, VPC, private IP, instance identity, attached
boot disk, and snapshot label/source/READY state. Snapshots are explicitly
stored regionally in `us-east1`, independent of project default snapshot
location settings. It writes a usable manifest
only after all three snapshots verify. If snapshotting is interrupted, it
preserves completed snapshots and records the incomplete set; do not restore a
partial set.

```sh
python3 scripts/self_managed_lab.py recovery snapshot \
  --project-id kordex-fleet-platform-515416 --lab-id kordex-lab --zone us-east1-b \
  --server kordex-lab-server --worker-1 kordex-lab-worker --worker-2 kordex-lab-worker-2 \
  --baseline ./qualification/baseline-<id>.json --safe-point before-failure \
  --idle-attestation NO_ACTIVE_MAINTENANCE \
  --output ./qualification/snapshot-set-<id>.json --audit ./qualification/recovery-audit.jsonl
python3 scripts/self_managed_lab.py recovery snapshot-verify \
  --project-id kordex-fleet-platform-515416 --lab-id kordex-lab --zone us-east1-b \
  --server kordex-lab-server --worker-1 kordex-lab-worker --worker-2 kordex-lab-worker-2 \
  --manifest ./qualification/snapshot-set-<id>.json
```

Restoration is intentionally all-or-nothing for the K3s topology: a server
datastore and two workers are restored from the same set. Partial worker-only
restore is rejected. All existing VMs must be stopped and verified as the
named lab resources. The helper reviews a Terraform plan, requests a separate
typed `RESTORE-APPLY <project>/<lab>/<operation>` confirmation, verifies the
project designation again, and only then applies that exact saved plan. The
recovery inputs are stored in the ignored, mode-0600
`.kordex-recovery-state.tfvars.json`; normal plan/apply/destroy helpers reuse
these non-secret snapshot IDs, private IPs, and operation ID so a later plan
cannot silently revert to fresh boot images. The ignored `terraform.tfvars` is
not changed by recovery tooling. After apply, the tool compares machine IDs,
requires a new boot ID, and verifies the same Kubernetes node UIDs and workload
readiness. A failed or unverified restore preserves disks/snapshots and writes a
failure record; use serial diagnostics and inspect Terraform state before any
retry. No reset was run for this implementation task.

Instance serial access is enabled only through per-instance metadata in the
Terraform source; no project-wide serial setting or IAM grant is made. A future
authorized administrator can query bounded serial output for a named lab VM:

```sh
python3 scripts/self_managed_lab.py recovery serial \
  --project-id kordex-fleet-platform-515416 --lab-id kordex-lab --zone us-east1-b \
  --server kordex-lab-server --worker-1 kordex-lab-worker --worker-2 kordex-lab-worker-2 \
  --role worker-1 --reason boot-failure \
  --output ./qualification/worker-1-serial-redacted.txt --audit ./qualification/recovery-audit.jsonl
```

The helper rejects instances without `serial-port-enable=TRUE`, stores at most
1 MiB of redacted output with mode 0600, and records the hash. Successful output
retrieval establishes that the caller could retrieve serial output at that
time; it does not prove that an interactive serial connection or host recovery
will work. Required Google permissions include instance discovery and
`compute.instances.getSerialPortOutput`; access must be approved separately and
least-scoped by the project owner. Never include raw serial logs in an evidence
archive until secrets and host identifiers have been reviewed.

Network fault injection is opt-in, limited to one exact private IPv4 `/32`, one
verified lab VM, and a duration of 1–900 seconds. It confirms the TCP endpoint
works before injection, installs a uniquely named priority-700 deny rule scoped
to a unique instance tag, verifies the endpoint becomes unreachable, removes
the rule, and verifies reachability before releasing a per-lab lock. The
baseline allow must explicitly include the destination and port. A failure to
remove/verify the deny rule retains the lock and requires the explicit
`fault-recover` command; do not start another fault or destroy the VPC until
recovery is verified.

```sh
python3 scripts/self_managed_lab.py recovery fault \
  --project-id kordex-fleet-platform-515416 --lab-id kordex-lab --zone us-east1-b \
  --server kordex-lab-server --worker-1 kordex-lab-worker --worker-2 kordex-lab-worker-2 \
  --role worker-1 --scenario relay-connectivity --destination-cidr <approved-private-ip>/32 \
  --duration-seconds 30 --output ./qualification/fault-<id>.json \
  --audit ./qualification/recovery-audit.jsonl
```

The current VM network has one private relay path on TCP/18443; the API is
behind that relay and is not a separately reachable network destination from
the VM. Consequently `api-connectivity` presently interrupts the same TCP path
as `relay-connectivity`; it is not evidence that an API-process-only failure
was isolated. Private-mirror faults use TCP/443 and an approved mirror `/32`.
Do not describe these network disruptions as satisfying any canonical M3
failure case unless the independent reviewer maps observed behavior to that
matrix row. Network faults are supplemental evidence only.

For interrupted faults, get the operation ID from the confirmation prompt and
use the exact project/lab/operation confirmation to recover. The command checks
the lock and temporary rule identity, verifies the target instance has not
changed, removes only that rule, probes restoration, and only then releases the
lock. Evidence verification requires the SHA-256 copied to an independent
review record:

```sh
python3 scripts/self_managed_lab.py recovery fault-recover \
  --project-id kordex-fleet-platform-515416 --lab-id kordex-lab --zone us-east1-b \
  --operation-id <12-hex-id> --output ./qualification/fault-recovered-<id>.json \
  --audit ./qualification/recovery-audit.jsonl
python3 scripts/self_managed_lab.py recovery verify-evidence \
  --file ./qualification/fault-recovered-<id>.json --sha256 <independently-recorded-sha256>
```

If `fault-recover` cannot reach the target through IAP, it deliberately keeps
the lock and temporary deny rule. Use serial-console diagnostics, then have the
approved project operator independently compare the exact project, rule name,
description operation ID, destination `/32`, target tag, protocol, and port in
the retained evidence and Cloud Console. Only after that comparison, remove
that one temporary deny rule (never the lock or baseline egress rules), restore
the VM/IAP path, and rerun `fault-recover`. The helper removes the inert lock
only after it can prove the target endpoint is reachable again. Do not use a
project-wide firewall reset or Terraform destroy to recover an interrupted
fault.

Snapshots remain billable after VMs stop and are not removed by Terraform lab
destroy. Google currently lists standard snapshot storage in `us-east1` at
`$0.000068493/GiB-hour` (`$0.05/GiB-month`, prorated, with a one-hour minimum).
The three 40-GiB disks have a 120-GiB provisioned ceiling: a deliberately
conservative full-data upper estimate is about `$6/month` for one complete
three-node set (about `$0.033` for four hours), before any recycle-bin
retention. Actual standard snapshots are compressed and incremental, so
charged stored blocks can be lower; deleting an incremental snapshot can shift
referenced blocks to another snapshot. Verify the account's snapshot location,
retention/recycle-bin settings, and actual Billing data. Snapshot pricing is not
included in the VM session estimate above. See [current Compute Engine disk and
snapshot pricing](https://cloud.google.com/compute/disks-image-pricing) and
[snapshot behavior](https://cloud.google.com/compute/docs/disks/snapshots).

The project owner must separately authorize the narrowly required Compute
permissions, including VM/disk/snapshot get/list, `compute.disks.createSnapshot`,
`compute.snapshots.create`, `compute.snapshots.delete`, and
`compute.instances.getSerialPortOutput`. Restore also requires the same
reviewed Terraform permissions as lab apply. No IAM grant is made by this
package. Delete
only a complete set verified from its manifest, using the explicit
`recovery snapshot-delete` command and a typed `DELETE-SNAPSHOTS` confirmation.
Verify all three are absent and archive the cleanup record/checksum. Never
manually delete similarly named snapshots or resources without validating
project, lab labels, source disk, role, and recovery-set ID.

## Limits

This is a temporary functional lab, not an HA management plane or production
network design. The single K3s server is a control-plane availability and
recovery single point; the two workers provide a maintenance peer but not
control-plane HA. The VPC firewall enforces destination IP CIDRs, not FQDN
identity; TLS and signed artifact digests remain required. The module does not
enable APIs, grant administrator IAM, configure the private route or customer PKI, run Terraform plan/apply, register Kordex clusters,
deploy the operator, or execute maintenance. Host-upgrade and GKE-upgrade gates
remain off by default; no qualification matrix row is marked RUN by preparing
this package.

Use the self-managed Kustomize overlay as the one lab packaging path; do not
mix it with the operator Helm chart. Checked-in defaults keep both host and
GKE upgrade gates false and do not grant host-execution RBAC. Any temporary
host-execution overlay belongs only on the approved disposable lab and must be
removed after both gates are closed and verified.
