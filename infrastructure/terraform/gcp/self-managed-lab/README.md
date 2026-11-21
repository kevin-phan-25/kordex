# Disposable self-managed Kordex qualification lab

This module prepares a three-VM K3s lab in a dedicated custom VPC for the
self-managed Ubuntu 24.04 host-upgrade matrix: one control-plane server and two
separate Ubuntu workers. Each worker can be the other's eligible maintenance
peer. This is separate from GKE and never uses the default VPC. The current
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
- The private-only startup profile rejects `os_family=rhel`; Rocky/DNF mirror
  bootstrap has not been implemented. This is an Ubuntu M3 lab, and canonical
  RHEL matrix rows remain unqualified.
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
  HTTPS allow rule. The customer must verify that private mirror and relay DNS
  answers fall within the approved CIDRs; firewall rules enforce the IP ranges,
  not DNS names. Ubuntu apt sources are replaced with one customer mirror
  containing the Noble suites and are still verified with Ubuntu's archive
  signing key. The mirror, K3s binary mirror, image mirror, and workstation
  relay must be reachable through an already-approved private route. No
  internet fallback is configured.
- Before a future plan, the owner must set `approved_private_egress_cidrs` to
  the exact canonical RFC1918 CIDRs no broader than `/24` serving those endpoints and
  `ubuntu_apt_mirror_url` to the HTTPS Ubuntu archive root. Terraform rejects a
  public/malformed CIDR set, missing mirror URL, or non-Ubuntu profile. Confirm
  DNS answers are within the CIDR set; no hostname-based firewall claim is
  made.
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
- Only the standalone K3s executable is currently staged from the approved
  mirror. K3s system/container images are not staged or imported, so default
  public registry pulls fail under this profile's deny-public-egress rules.
  A customer-approved, digest-bound airgap image bundle or private registry
  mapping plus startup support is still required before a real cluster can
  bootstrap. Do not restore broad egress to work around this gap.
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
project: kordex-fleet-platform-515323
number:  927924290991
region:  us-east1
zone:    us-east1-b
```

The Terraform Google provider receives `project_id` explicitly. The guarded
Python helper also passes the selected ID to `gcloud projects describe` as
both the resource argument and `--project`. Do not use `gcloud config set
project`; the global gcloud project is intentionally unchanged. The tracked
`terraform.tfvars.example` contains the approved ID and exact one-project
allowlist. Before a future plan, the ignored `terraform.tfvars` must also
supply `k3s_binary_sha256` and `k3s_binary_mirror_url` from a successfully
verified customer artifact lock; neither has a default. The file must remain
mode 0600. The guarded plan/apply helper verifies the lock signature and
cross-checks those values before Terraform runs. Terraform and startup scripts
do not independently verify the signature; do not invoke them directly for
lab provisioning.

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

Before a separately authorized plan, review the target project, APIs, IAM,
private route and DNS, private egress CIDRs, Ubuntu mirror and the actual
`terraform.tfvars`. That ignored file must include a customer-verified K3s lock,
the exact mirror URL, and all non-secret private-network inputs.
Then the exact future plan command is:

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id CUSTOMER_DISPOSABLE_PROJECT \
  --k3s-binary /verified-transfer/k3s \
  --k3s-artifact-lock /verified-transfer/k3s.artifact-lock \
  --k3s-artifact-signature /verified-transfer/k3s.artifact-lock.sig \
  --k3s-artifact-trust /independent-trust/k3s-artifact-approval.trust
```

Replace the project and file paths with reviewed values. The helper verifies
the customer signature and local binary, binds the signed digest and mirror
URL to the protected Terraform inputs, and passes those exact values to the
plan. It rejects auto-loaded Terraform variable files and strips Terraform
environment overrides. The separately authorized apply command requires the
same four artifact paths, repeats verification, displays a saved plan, and
checks the approval files again before applying. Direct Terraform plan/apply
does not enforce this signature boundary and is unsupported. This command was
not run in this preparation task. Do not run apply until the saved plan is
separately reviewed and explicitly approved.

## IAP administration and K3s access

After an approved deployment, open a terminal and run the IAP-backed SSH
tunnel command:

```sh
gcloud compute ssh kordex-lab-server \
  --project=kordex-fleet-platform-515323 --zone=us-east1-b \
  --tunnel-through-iap -- -N -L 6443:127.0.0.1:6443
```

In a second terminal, retrieve the kubeconfig through IAP. It contains a
cluster credential, so keep it outside Git and mode 0600:

```sh
gcloud compute ssh kordex-lab-server \
  --project=kordex-fleet-platform-515323 --zone=us-east1-b \
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
     --project-id kordex-fleet-platform-515323
   ```

Teardown removes VMs/disks, custom VPC/firewalls, private DNS zone/records,
service accounts, secret IAM bindings, and the expiring Secret Manager secret. Do not use raw
`terraform destroy`. Preserve the Terraform state until teardown is verified;
it contains resource metadata but no K3s token value. After successful
teardown and evidence checks, remove local state and kubeconfig only according
to the approved evidence-retention procedure.

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
