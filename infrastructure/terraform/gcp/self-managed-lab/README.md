# Disposable self-managed Kordex qualification lab

This optional Terraform module creates a small Linux and K3s environment for
qualifying the **self-managed Linux host executor**. Choose Ubuntu 24.04 for
the Debian catalog or Rocky Linux 9 for the RHEL-family catalog. It is separate from the
managed GKE node-pool adapter and does not change Kordex's provider-neutral
runtime architecture. It creates two regular GCE VMs: one K3s server and one
worker to use as the upgrade target.

This module creates billable cloud resources. Review the Terraform plan and
your project's current pricing before applying it. This document does not
apply Terraform or enable Google APIs for you.

## What this lab does and does not prove

- Gives you a disposable Ubuntu 24.04 or Rocky Linux 9 worker for package and
  reboot drills.
- Runs K3s at a pinned `v1.36.6+k3s1` release, independent of GKE APIs.
- Restricts SSH and Kubernetes API ingress to one administrator CIDR.
- Gives the nodes a dedicated service account with no project IAM roles or
  OAuth access scopes.
- Keeps worker SSH private to the lab subnet, where the Kordex operator can
  reach it if the operator is deployed on this K3s cluster.
- Requires outbound internet during initial VM bootstrap to download OS
  packages and the pinned K3s installer. **This is not an air-gapped bootstrap
  test.** For disconnected sites, mirror the OS packages, K3s binaries, OCI
  images, and Ansible Execution Environment using the offline bundle guidance
  in [`docs/air-gapped-deployment.md`](../../../../docs/air-gapped-deployment.md).
- Does not install Kordex. Follow
  [`docs/production-upgrade-requirements.md`](../../../../docs/production-upgrade-requirements.md)
  after the cluster is ready to configure the operator and execute the
  disposable-VM failure matrix.

The K3s release pin is intentional: it gives the test cluster a known,
repeatable baseline. It is independent of whatever version GKE currently runs.

## Prerequisites

1. Use a dedicated disposable GCP project, separate from product, customer,
   and shared development infrastructure. Before using it, review the project
   and confirm it contains no non-disposable resources. The project must have
   billing configured.
2. Enable the Compute Engine API, IAM API, and Cloud Resource Manager API in
   that project. This module intentionally does not enable services
   automatically.
3. Install Terraform 1.6 or newer, Python 3, `gcloud`, and `kubectl`.
4. Authenticate `gcloud` and set the project:

   ```sh
   gcloud auth login
   gcloud config set project YOUR_DEDICATED_PROJECT_ID
   gcloud services enable compute.googleapis.com iam.googleapis.com \
     cloudresourcemanager.googleapis.com
   ```

   Designate the reviewed project with the live project label required by the
   module. This is an explicit owner action; Terraform only reads and checks
   the label, and does not label or otherwise modify the project itself:

   ```sh
   gcloud projects describe YOUR_DEDICATED_PROJECT_ID \
     --format='yaml(projectId,projectNumber,lifecycleState,labels)'
   gcloud projects update YOUR_DEDICATED_PROJECT_ID \
     --update-labels=kordex-disposable=qualification
   gcloud projects describe YOUR_DEDICATED_PROJECT_ID \
     --format='yaml(projectId,projectNumber,lifecycleState,labels)'
   ```

   Apply the designation only after the project review. The module requires
   the live `kordex-disposable=qualification` label, an explicit
   `allowed_project_ids` set containing the exact `project_id`, and
   `project_id_confirmation` equal to that ID. The confirmation is a separate
   provisioning check; inspect the saved plan before applying it. The module
   hard-rejects `kordex-fleet-platform` even if it is accidentally added to the
   allowlist or labeled disposable. The module
   does not prove that the project is empty, so the project review and narrow
   allowlist remain mandatory.

5. The deployer needs permission to read the selected project metadata
   (`resourcemanager.projects.get`), create a service account and attach it to
   Compute Engine instances (including `iam.serviceAccounts.actAs`), plus the
   network and instance permissions Terraform reports during planning. The
   module grants no roles to the VM service account.
6. Create a dedicated SSH key and obtain your current public IPv4 address.
   Set `ADMIN_CIDR` to that address with `/32` (or use your organization's
   narrow approved range):

   ```sh
   ssh-keygen -t ed25519 -f "$HOME/.ssh/kordex-lab" -C kordex-disposable-lab
   curl -4 https://ifconfig.me
   ```

Do not use `0.0.0.0/0` for `admin_cidr`. The module rejects it.

## Create the lab

Run these commands from this directory. Replace the project ID, CIDR, and key
path with your values:

```sh
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set:

- `project_id` to the dedicated project ID.
- `allowed_project_ids` to the narrowly scoped, reviewed project ID allowlist.
- `project_id_confirmation` to exactly `project_id`, only after confirming the
  disposable designation and reviewing the target project.
- `os_family` to `debian` for Ubuntu 24.04 or `rhel` for Rocky Linux 9.
- `admin_cidr` to your trusted public IPv4 CIDR.
- `ssh_public_key` to the contents of `~/.ssh/kordex-lab.pub`.
- `k3s_token` to a unique secret generated for this lab.

After editing, restrict the file because the Terraform state and variables
contain the bootstrap token:

```sh
chmod 600 terraform.tfvars
```

Generate the token in a terminal without printing it into shell history:

```sh
openssl rand -hex 32
```

Terraform state and GCE instance metadata contain the K3s token. Keep
`terraform.tfvars` and the state private; do not commit either. The guarded
helper validates a fresh plan and prompts for the exact project ID before
applying it. Do not run raw `terraform apply` for this lab:

```sh
# Run these helper commands from the Kordex repository root.
python3 scripts/self_managed_lab.py validate
python3 scripts/self_managed_lab.py plan --project-id YOUR_DEDICATED_PROJECT_ID
python3 scripts/self_managed_lab.py apply --project-id YOUR_DEDICATED_PROJECT_ID
```

The apply command displays a newly generated saved plan and requires you to
type `APPLY YOUR_DEDICATED_PROJECT_ID` in an interactive terminal. After that
confirmation, it re-reads the live project ID, number, lifecycle state, and
`kordex-disposable=qualification` label immediately before applying the saved
plan. It deletes its temporary plan afterward. A failed apply may leave
resources in Terraform state; inspect them and recover explicitly. The helper
never runs destroy as cleanup.

The plan fails closed if the project is not in the explicit allowlist, the
project confirmation differs, the live project cannot be read, or the
disposable project label is missing. These checks do not inspect all project
resources; never designate or allowlist a project that contains shared or
otherwise non-disposable infrastructure.

The plan resolves the selected OS image family to one exact image self-link
and stores that selection in the saved plan. Record the OS family and image ID
with every qualification run:

```sh
terraform -chdir=infrastructure/terraform/gcp/self-managed-lab output -raw os_family
terraform -chdir=infrastructure/terraform/gcp/self-managed-lab output -raw boot_image_id
```

Rebuild from the same saved plan to recreate the identical initial OS image.

The plan creates a VPC, subnet, two ingress firewall rules (administrator
access, private node traffic), a dedicated service account without IAM role
bindings, and two regular `e2-standard-2` Linux VMs with 40 GiB balanced
disks and external IPv4 addresses. Check current GCP pricing for your chosen
zone before applying; costs vary and are not estimated here.

## Connect and verify

Wait for both startup scripts to finish. The first boot installs OS
packages and K3s, so it can take several minutes. Copy the server kubeconfig:

```sh
terraform -chdir=infrastructure/terraform/gcp/self-managed-lab output -raw kubeconfig_copy_command
```

Run the displayed `gcloud compute scp` command, then:

```sh
chmod 600 ./kubeconfig
export KUBECONFIG="$PWD/kubeconfig"
kubectl get nodes -o wide
```

Wait for both the server and worker to show `Ready`. The worker's private IP is
available as:

```sh
terraform -chdir=infrastructure/terraform/gcp/self-managed-lab output -raw worker_internal_ip
```

Use that private address as the Ansible target from an operator running inside
this K3s cluster. The worker's startup script creates the supplied SSH user
and grants it passwordless sudo for the disposable host-upgrade workflow. The
operator must use a dedicated SSH credential and pinned host key configured
through the existing Kordex secret and host-executor settings. Do not enable
the upgrade feature gates on another cluster as part of this qualification.

## Connect the lab cluster to Kordex

The hub must already be running at an HTTPS URL reachable from the K3s nodes.
The local development API bound to `127.0.0.1` is not reachable from GCP VMs;
for an air-gapped test, follow the self-hosted hub procedure in
[`docs/kustomize-hub.md`](../../../../docs/kustomize-hub.md). The agent opens
an outbound connection to the hub. The hub does not connect to the Kubernetes
API.

### Register and issue an enrollment token

Use an administrator token for the hub's API. Keep it out of command history
and terminal output; the example uses a mode-0600 curl config file. Set the
hub origin and organization/site/fleet IDs for your test environment:

```sh
read -r -s -p 'Kordex administrator token: ' KORDEX_ADMIN_TOKEN
printf '\n'
export KORDEX_ADMIN_TOKEN
export KORDEX_API=https://kordex.example.internal
export ORG_ID=YOUR_ORGANIZATION_UUID
export SITE_ID=YOUR_SITE_UUID
export FLEET_ID=YOUR_FLEET_UUID
umask 077
mkdir -p "$HOME/.kordex-lab"
printf 'header = "Authorization: Bearer %s"\n' "$KORDEX_ADMIN_TOKEN" \
  > "$HOME/.kordex-lab/curl.conf"
chmod 600 "$HOME/.kordex-lab/curl.conf"
```

Register this cluster with provider `self-managed`:

```sh
CLUSTER_JSON=$(curl --fail --silent --show-error \
  --config "$HOME/.kordex-lab/curl.conf" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"kordex-self-managed-lab\",\"siteId\":\"$SITE_ID\",\"fleetId\":\"$FLEET_ID\",\"provider\":\"self-managed\"}" \
  "$KORDEX_API/v1/organizations/$ORG_ID/clusters")
export CLUSTER_ID=$(printf '%s' "$CLUSTER_JSON" | jq -er '.id')
unset CLUSTER_JSON
```

Issue a single-use enrollment token shortly before applying the workload
overlay. The token expires after ten minutes:

```sh
TOKEN_JSON=$(curl --fail --silent --show-error \
  --config "$HOME/.kordex-lab/curl.conf" -X POST \
  "$KORDEX_API/v1/organizations/$ORG_ID/clusters/$CLUSTER_ID/enrollment-tokens")
printf '%s' "$TOKEN_JSON" | jq -er '.token' > "$HOME/.kordex-lab/enrollment-token"
chmod 600 "$HOME/.kordex-lab/enrollment-token"
unset TOKEN_JSON
unset KORDEX_ADMIN_TOKEN
rm -f "$HOME/.kordex-lab/curl.conf"
```

If the hub already has its maintenance signing key configured, use that
key's public trust JSON. Never generate a different key just for the operator:
it must trust the key that signed hub permits. The private key stays on the
hub. For a new isolated test hub only, generate the key once with
`kordex-keygen`, configure the hub with its private file, and distribute only
the resulting public JSON file.

### Install agent and operator

From a Kordex source checkout, first copy the hub's public key JSON to
`deployments/kustomize/overlays/self-managed/keys.json` (this file is ignored
by Git). Edit `agent-settings.patch.yaml` to set the cluster UUID and HTTPS
hub URL, and edit `operator-settings.patch.yaml` to set the same cluster UUID.
Keep `maintenanceEnabled` and `upgradeEnabled` set to `"false"` initially.
Set both overlay images to immutable agent/operator references from the same
Kordex release. For an offline bundle, use
`scripts/configure-offline-kustomize.sh` as described in
[`docs/air-gapped-deployment.md`](../../../../docs/air-gapped-deployment.md);
it renders mirrored images and keeps the gates disabled.

If the registry requires authentication, create the referenced
namespace-local image-pull Secret before applying the overlay. If the hub uses
a private CA, use `overlays/self-managed-private-ca` and create
`kordex-management-ca` in `kordex-system` with the trusted certificate at
`ca.crt`.

Apply the base CRDs and namespace, create the enrollment Secret from the
protected token file, then apply the spoke overlay:

```sh
kubectl apply -k deployments/kustomize/base
kubectl wait --for=condition=Established --timeout=120s \
  crd/maintenancepolicies.operations.kordex.local \
  crd/maintenancecampaigns.operations.kordex.local \
  crd/nodemaintenances.operations.kordex.local
kubectl create secret generic kordex-enrollment -n kordex-system \
  --from-file=token="$HOME/.kordex-lab/enrollment-token"
kubectl apply -k deployments/kustomize/overlays/self-managed
kubectl rollout status -n kordex-system deployment/kordex-agent --timeout=180s
kubectl rollout status -n kordex-system deployment/kordex-operator --timeout=180s
```

The agent consumes the enrollment token once and persists its identity in a
Kubernetes Secret. Confirm the cluster is connected and node inventory is
fresh in the hub before starting any operation. To permit signed maintenance
commands to reach this disposable cluster, edit `agent-settings.patch.yaml`
to set `maintenanceEnabled: "true"`, reapply the overlay, and restart the
agent Deployment so its environment is refreshed:

```sh
kubectl apply -k deployments/kustomize/overlays/self-managed
kubectl rollout restart -n kordex-system deployment/kordex-agent
kubectl rollout status -n kordex-system deployment/kordex-agent --timeout=180s
```

The operator's host-upgrade gate remains independently disabled until you are
ready to run the guarded qualification procedure below. Never apply these
gate changes to a shared or production cluster.

Before host-upgrade qualification, create the named SSH Secret and known-hosts
ConfigMap using a verified worker host key, configure the exact digest-pinned
EE allowlist and private registry pull Secret, then enable the host gate only
in this disposable lab. The setup details and guarded execution command are in
[`docs/production-upgrade-requirements.md`](../../../../docs/production-upgrade-requirements.md).

For the second catalog, use a fresh Terraform state/workspace or destroy the
current lab, change `os_family` to `rhel`, then plan and apply again. Changing
OS family replaces both VMs. Capture evidence before teardown and use the
matching RHEL-family policy for that run.

Continue with the failure and recovery drills in
[`docs/production-upgrade-requirements.md`](../../../../docs/production-upgrade-requirements.md).
The helper exposes the existing runner and evidence tools without relaxing
their checks:

```sh
# Run these helper commands from the Kordex repository root.
python3 scripts/self_managed_lab.py preflight --evidence ./qualification/preflight.json
python3 scripts/self_managed_lab.py execute \
  --project-id YOUR_DEDICATED_PROJECT_ID \
  --target-confirmation "$KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM" \
  --qualification-case clean-upgrade \
  --timeout-seconds 14400 \
  --evidence ./qualification/clean-upgrade.json
python3 scripts/self_managed_lab.py collect \
  --output-dir ./qualification/diagnostics
python3 scripts/self_managed_lab.py verify ./qualification
python3 scripts/self_managed_lab.py archive \
  --source ./qualification \
  --destination /secure/off-cluster/kordex-ubuntu-qualification.tar.gz
```

Each failure-matrix case must be run as a separate `execute` command using its
stable case ID and the reviewed baseline procedure. The runner requires the
exact cluster/node/UID confirmation and verifies the selected target again.
Before launching it, the wrapper verifies that the project remains in the
private Terraform allowlist, is `ACTIVE`, and still carries the live
`kordex-disposable=qualification` label, then requires the exact interactive
phrase `EXECUTE IN DISPOSABLE PROJECT YOUR_DEDICATED_PROJECT_ID`. This is
separate from the target confirmation and is repeated for every execute case.
For this GCP lab, invoke the runner through the wrapper so the project check
cannot be skipped accidentally.
Cancellation cases also require their corresponding phase:

| Case | `--cancel-on-phase` |
|---|---|
| `cancel-before-apply` | `Draining` |
| `cancel-during-executing` | `Executing` |
| `cancel-during-reboot` | `Rebooting` |
| `cancel-during-recovery` | `VerifyingWorkloads` |

For example:

```sh
python3 scripts/self_managed_lab.py execute \
  --project-id YOUR_DEDICATED_PROJECT_ID \
  --target-confirmation "$KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM" \
  --qualification-case cancel-during-reboot \
  --cancel-on-phase Rebooting \
  --timeout-seconds 14400 \
  --evidence ./qualification/cancel-during-reboot.json
```

`collect` checks the current kubectl context against `KORDEX_EXPECTED_CONTEXT`, collects
node/pod/PDB/event and Kordex resource output plus agent/operator logs with
best-effort redaction, and keeps partial files if collection fails. Review
collected logs before retention; regex redaction cannot prove that every
credential or sensitive value has been removed. `archive` refuses symlinks,
known secret-bearing filenames,
and overwrites; it writes a mode-0600 archive, SHA-256, and file manifest. Copy
these artifacts to independently administered off-cluster retention. It does
not upload or configure immutable storage. Terraform creation alone is not
qualification evidence.

## Delete the lab

After exporting required evidence and removing test credentials, destroy the
VMs and network explicitly:

```sh
# Run from the Kordex repository root.
python3 scripts/self_managed_lab.py destroy --project-id YOUR_DEDICATED_PROJECT_ID
```

The helper verifies that the recorded Terraform state's project ID matches,
shows a fresh destroy plan, and requires the exact interactive phrase
`DESTROY YOUR_DEDICATED_PROJECT_ID`. It is never called automatically after a
qualification failure. Do not run raw `terraform destroy` for this lab.

Destroying the infrastructure does not erase a remote Terraform state copy or
local backups. Securely delete the state and `terraform.tfvars` according to
your organization's secret-handling policy. The state includes the cluster
bootstrap token.

## Offline environment notes

This GCP module is a convenient VM lifecycle drill target, not a requirement
for Kordex. Core operation must continue to work without Google APIs or cloud
identity. A truly disconnected installation must mirror OCI images, Helm
charts, Kustomize artifacts, CRDs, binaries, the digest-pinned Ansible EE, and
the allowed OS package artifacts onto private registry/storage or offline
media. See [`docs/air-gapped-deployment.md`](../../../../docs/air-gapped-deployment.md)
for the offline delivery path.
