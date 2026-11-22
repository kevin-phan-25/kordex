# Persistent M3 lab lifecycle

The self-managed lab is persistent infrastructure. `lab stop` stops only the
three approved Compute Engine VMs; it does not destroy the Terraform stack,
boot disks, VPC, firewall rules, DNS, service accounts, or qualification state.
There is no scheduled shutdown. Destruction remains a separate guarded
Terraform workflow.

## Durable admission barrier

PostgreSQL migration `016_lab_lifecycle_barrier.sql` adds cluster-scoped
lifecycle state. Every transition locks the existing `clusters` row. Manual
operation admission and campaign scheduling already lock that same row in
`createOperationTx`; admission checks the lifecycle state before creating an
operation or reservation. Therefore, if admission commits first, stop observes
its operation; if stop commits first, the later admission sees `DRAINING` (or a
later fenced state) and is rejected. The barrier is shared by independent
control-plane instances and survives process restart.

The states are `RUNNING`, `DRAINING`, `READY_TO_STOP`, `STOPPING`, `STOPPED`,
and `STARTING`. A terminal `Succeeded` or `Cancelled` agent report is stored and
its reservation released in the same database transaction. A `Failed`,
`Blocked`, `RecoveryRequired`, pending operation, unreleased reservation, or
terminal operation without its persisted final report prevents `READY_TO_STOP`.
No timeout releases a reservation or clears the barrier.

This control plane gate proves that Kordex operation reports have been
persisted. It is not independent M3 evidence-package acceptance and does not
turn an operation into qualification PASS. The operator must separately retain
the qualification evidence package before ending the test session. A failed
operation needs the existing explicit recovery process; the lab lifecycle does
not clear its safety fence.

Only organization administrators may mutate lifecycle state. API transitions
are recorded in the existing chained audit log. A stop remains fenced in
`STOPPING` until all three exact VMs are observed stopped and their persistent
disks remain present. A start remains fenced in `STARTING` until the exact
Terraform VM/disk/image identities, machine IDs, exact OS release, Kubernetes
Node UIDs, and Ready/workload health have been checked. Partial start/stop or
lost API acknowledgement leaves the fence in place. `lab start` resumes an
interrupted start or stop by starting and re-verifying the same three VMs.
The store rejects lifecycle mutations for GKE, EKS, and AKS clusters; this
barrier applies only to self-managed clusters.

## Operator commands

These commands require a deployed control-plane migration, an administrator
token stored in a private file, the dedicated Terraform impersonation target,
the exact cluster and organization UUIDs, an independently retained hash for
the post-create image/VM identity record, and a recovery baseline plus its
independently retained hash, and a customer-pinned control-plane TLS
certificate SHA-256. The OS release must be the exact customer-approved
Debian point release (for example `13.x`) or RHEL minor (`9.8` or later). The
identity and baseline records must be private regular files. No token belongs
on the command line.

Set the repeated arguments in a local shell without putting token contents in
the shell history:

```sh
export KORDEX_TOKEN_FILE=/secure/path/kordex-admin-token
LAB_ARGS=(
  --project-id kordex-fleet-platform-515416
  --project-number 209068399397
  --zone us-east1-b
  --lab-id "$KORDEX_LAB_ID"
  --terraform-principal-email "$KORDEX_TERRAFORM_SERVICE_ACCOUNT"
  --lifecycle-principal-email "$KORDEX_LAB_LIFECYCLE_SERVICE_ACCOUNT"
  --organization-id "$KORDEX_ORGANIZATION_ID"
  --cluster-id "$KORDEX_CLUSTER_ID"
  --control-plane-url "$KORDEX_CONTROL_PLANE_URL"
  --control-plane-cert-sha256 "$KORDEX_CONTROL_PLANE_CERT_SHA256"
  --token-file "$KORDEX_TOKEN_FILE"
  --identity-evidence "$KORDEX_IMAGE_VM_IDENTITY_JSON"
  --identity-sha256 "$KORDEX_IMAGE_VM_IDENTITY_SHA256"
  --recovery-baseline "$KORDEX_RECOVERY_BASELINE_JSON"
  --baseline-sha256 "$KORDEX_RECOVERY_BASELINE_SHA256"
  --os-id debian
  --os-release "$KORDEX_APPROVED_DEBIAN_POINT_RELEASE"
  --kube-context "$KORDEX_KUBE_CONTEXT"
)
```

Read status (live, read-only GCP inventory):

```sh
python3 scripts/self_managed_lab.py lab status "${LAB_ARGS[@]}"
```

Start only the exact three stopped VMs, then validate machine identity, OS,
image/disk identity, Kubernetes Node UIDs, readiness, and workloads:

```sh
python3 scripts/self_managed_lab.py lab start "${LAB_ARGS[@]}"
```

The CLI requires an interactive exact confirmation `START kordex-fleet-platform-515416 <lab-id>`.

Stop first persists the database barrier, waits for active operations and
reservations to resolve, checks the healthy cluster, stops workers before the
server, and confirms VM and disk state:

```sh
python3 scripts/self_managed_lab.py lab stop "${LAB_ARGS[@]}"
```

The CLI requires an interactive exact confirmation `STOP kordex-fleet-platform-515416 <lab-id>`.

Restart runs the same stop and start protocols:

```sh
python3 scripts/self_managed_lab.py lab restart "${LAB_ARGS[@]}"
```

The CLI requires an interactive exact confirmation `RESTART kordex-fleet-platform-515416 <lab-id>`.

If an operation remains active until the bounded wait expires, the command
returns nonzero and leaves VMs running with lifecycle `DRAINING`. If stopping
partially succeeds, state remains `STOPPING`; run `lab start` to restore all
three VMs and pass the identity/health checks before admission is reopened. If
startup partially succeeds, retry `lab start`; it starts only terminated nodes
and rechecks the complete topology. Never edit lifecycle database rows by hand.

## Cost view

```sh
python3 scripts/self_managed_lab.py lab cost \
  --vm-hours-per-vm 0 \
  --snapshot-stored-gib-hours 0 \
  --monthly-logging-gib 0 0 0 \
  --network-bound-usd 0 \
  --artifact-storage-bound-usd 0 \
  --registry-storage-bound-usd 0 \
  --rhel-subscription-bound-usd 0 \
  --other-bound-usd 0
```

The output is a public-list-price estimate and reports actual billing evidence
as `NOT_PROVIDED`. Zero bounds do not mean those services are free. The report
keeps both runtime-only and continuous-while-stopped RHEL PAYG scenarios; a
billing owner must verify the selected RHEL image/license behavior and provide
actual headroom before apply. This command does not enforce a spend cap. Do not
apply if the bounded worst case plus reserve exceeds $300 or billing headroom
has not been independently verified.

## Dedicated deployment and lifecycle identities

Terraform, VM power operations, and workload execution use separate identities.
The project IAM owner creates the service accounts and applies the bindings;
this repository does not create identities or mutate IAM. The project role is
intentionally usable only in a dedicated disposable qualification project:
network/subnetwork and managed DNS zone permissions do not have supported
resource-name conditions in the current IAM Conditions resource-attribute
catalog. The separate Terraform resource role is bound with a condition for the
three lab VMs/disks, lab firewalls, private DNS records, and exactly one join
secret. If the project contains shared or production resources, do not bind the
project setup role there.

The permission files split the access paths:

| Purpose | Principal and grant scope | Permission source |
|---|---|---|
| Terraform project setup | `kordex-m3-lab-terraform`, project role, dedicated disposable project only | `terraform-deployer-role.json` (networks, subnetworks, managed zone, operation/discovery and service usage) |
| Terraform lab resources | `kordex-m3-lab-terraform`, project role with exact resource-name condition | `terraform-lab-resources-role.json` (instances/disks/firewalls, DNS record sets, join secret) |
| Attach workload identities | Terraform principal, direct on each pre-created server/worker service account | `roles/iam.serviceAccountUser` |
| Secret runtime access | Server version manager and worker reader, direct on the one join secret | Terraform-managed `google_secret_manager_secret_iam_member` resources |
| Lifecycle inventory | `kordex-m3-lab-lifecycle`, read-only project role | `lab-inventory-role.json` |
| VM start/stop | Lifecycle principal, direct on each of the three exact instances | `lab-lifecycle-power-role.json` (only `compute.instances.start/stop`) |
| IAP and OS Login | Lifecycle principal, direct on each exact VM; `actAs` direct on both attached workload accounts | `roles/iap.tunnelResourceAccessor`, `roles/compute.osAdminLogin`, `roles/iam.serviceAccountUser` |
| Human impersonation | Approved human, direct on Terraform and lifecycle service accounts | `roles/iam.serviceAccountTokenCreator` |

The Terraform resource role does not include VM start/stop. The lifecycle
principal is distinct and is the only principal used by `lab status/start/stop`
for Compute access. The Terraform project role has no `iam.serviceAccounts.*`
permissions: the server and worker accounts must exist before planning.
Terraform checks that their IDs exactly equal `${name_prefix}-server` and
`${name_prefix}-worker`; use the reviewed `kordex-m3-lab` prefix so its IAM
condition matches the module. Terraform then adds runtime access on the
single join secret, not project-level roles for either VM identity.

Google documents direct-per-instance IAP and OS Login grants and the
service-account `actAs` requirement in [IAP TCP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding)
and [OS Login setup](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin).
`roles/compute.osAdminLogin` grants root-equivalent access; only an approved
operator account should be able to impersonate the lifecycle identity.

The following are customer IAM-owner commands, not executed here. They create
four accounts and four custom roles. Review the IAM policy and verify the
project is dedicated and disposable before running them. Do not substitute
Owner, Editor, Compute Admin, or project-wide SSH roles.

```sh
set -eu
PROJECT=kordex-fleet-platform-515416
EXPECTED_PROJECT_NUMBER=209068399397
LAB_PREFIX=kordex-m3-lab
TF_SA="${LAB_PREFIX}-terraform@${PROJECT}.iam.gserviceaccount.com"
LIFECYCLE_SA="${LAB_PREFIX}-lifecycle@${PROJECT}.iam.gserviceaccount.com"
SERVER_SA="${LAB_PREFIX}-server@${PROJECT}.iam.gserviceaccount.com"
WORKER_SA="${LAB_PREFIX}-worker@${PROJECT}.iam.gserviceaccount.com"
IAM_DIR=infrastructure/terraform/gcp/self-managed-lab
: "${APPROVED_OPERATOR_EMAIL:?set the IAM-approved human operator email}"

ACTIVE_PRINCIPAL="$(gcloud auth list --filter=status:ACTIVE --format='value(account)')"
ACTUAL_PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
test "$ACTUAL_PROJECT_NUMBER" = "$EXPECTED_PROJECT_NUMBER"
printf 'IAM operator principal: %s\nProject identity: %s (%s)\n' \
  "$ACTIVE_PRINCIPAL" "$PROJECT" "$ACTUAL_PROJECT_NUMBER"

gcloud iam service-accounts create "${LAB_PREFIX}-terraform" --project="$PROJECT"
gcloud iam service-accounts create "${LAB_PREFIX}-lifecycle" --project="$PROJECT"
gcloud iam service-accounts create "${LAB_PREFIX}-server" --project="$PROJECT"
gcloud iam service-accounts create "${LAB_PREFIX}-worker" --project="$PROJECT"

gcloud iam roles create kordexM3TerraformProject --project="$PROJECT" \
  --file="$IAM_DIR/terraform-deployer-role.json"
gcloud iam roles create kordexM3TerraformResources --project="$PROJECT" \
  --file="$IAM_DIR/terraform-lab-resources-role.json"
gcloud iam roles create kordexM3LabInventory --project="$PROJECT" \
  --file="$IAM_DIR/lab-inventory-role.json"
gcloud iam roles create kordexM3LabLifecyclePower --project="$PROJECT" \
  --file="$IAM_DIR/lab-lifecycle-power-role.json"

# This first binding includes network/subnetwork and managed-zone permissions;
# use it only in the isolated disposable qualification project.
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${TF_SA}" \
  --role="projects/${PROJECT}/roles/kordexM3TerraformProject"

# Bind conditionable writes only to the approved resource names. The module's
# name_prefix must be this exact value; review the CEL expression before use.
TF_SCOPE_CONDITION="(resource.type == 'compute.googleapis.com/Instance' && resource.name.startsWith('projects/${PROJECT}/zones/us-east1-b/instances/${LAB_PREFIX}-')) || (resource.type == 'compute.googleapis.com/Disk' && resource.name.startsWith('projects/${PROJECT}/zones/us-east1-b/disks/${LAB_PREFIX}-')) || (resource.type == 'compute.googleapis.com/Firewall' && resource.name.startsWith('projects/${PROJECT}/global/firewalls/${LAB_PREFIX}-')) || (resource.type == 'dns.googleapis.com/ResourceRecordSet' && resource.name.startsWith('projects/${PROJECT}/managedZones/${LAB_PREFIX}-googleapis/rrsets/')) || (resource.type == 'secretmanager.googleapis.com/Secret' && resource.name == 'projects/${PROJECT}/secrets/${LAB_PREFIX}-agent-join')"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${TF_SA}" \
  --role="projects/${PROJECT}/roles/kordexM3TerraformResources" \
  --condition="expression=${TF_SCOPE_CONDITION},title=Kordex M3 lab resources only,description=Restrict conditional Terraform permissions to the approved lab resources"

gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${LIFECYCLE_SA}" \
  --role="projects/${PROJECT}/roles/kordexM3LabInventory"

# Grant actAs/get on exactly the two pre-created workload service accounts.
for SA in "$SERVER_SA" "$WORKER_SA"; do
  gcloud iam service-accounts add-iam-policy-binding "$SA" --project="$PROJECT" \
    --member="serviceAccount:${TF_SA}" --role=roles/iam.serviceAccountUser
  gcloud iam service-accounts add-iam-policy-binding "$SA" --project="$PROJECT" \
    --member="serviceAccount:${LIFECYCLE_SA}" --role=roles/iam.serviceAccountUser
done

# Permit the approved human to impersonate only the two automation identities.
gcloud iam service-accounts add-iam-policy-binding "$TF_SA" --project="$PROJECT" \
  --member="user:${APPROVED_OPERATOR_EMAIL}" --role=roles/iam.serviceAccountTokenCreator
gcloud iam service-accounts add-iam-policy-binding "$LIFECYCLE_SA" --project="$PROJECT" \
  --member="user:${APPROVED_OPERATOR_EMAIL}" --role=roles/iam.serviceAccountTokenCreator
```

After Terraform creates the instances, the IAM owner must review their exact
names, then bind lifecycle power, IAP, and OS Login rights per instance. These
bindings are deliberately not included at project scope:

```sh
for VM in "${LAB_PREFIX}-server" "${LAB_PREFIX}-worker" "${LAB_PREFIX}-worker-2"; do
  gcloud compute instances add-iam-policy-binding "$VM" --project="$PROJECT" --zone=us-east1-b \
    --member="serviceAccount:${LIFECYCLE_SA}" \
    --role="projects/${PROJECT}/roles/kordexM3LabLifecyclePower"
  gcloud compute instances add-iam-policy-binding "$VM" --project="$PROJECT" --zone=us-east1-b \
    --member="serviceAccount:${LIFECYCLE_SA}" --role=roles/compute.osAdminLogin
done
```

Grant IAP TCP access on each of those same instances from the Cloud Console:
open **Identity-Aware Proxy → SSH and TCP Resources**, select one exact VM,
add `serviceAccount:${LIFECYCLE_SA}` with `roles/iap.tunnelResourceAccessor`,
and repeat for the other two. Google documents the VM-specific IAP policy
resource separately from the Compute Engine instance IAM policy; do not use
`gcloud compute instances add-iam-policy-binding` for the IAP role. Keep the
existing IAP firewall path restricted to TCP/22 from `35.235.240.0/20`.

Set the protected local Terraform inputs (do not commit `terraform.tfvars`):

```hcl
terraform_principal_email = "kordex-m3-lab-terraform@kordex-fleet-platform-515416.iam.gserviceaccount.com"
server_service_account_id = "kordex-m3-lab-server"
worker_service_account_id = "kordex-m3-lab-worker"
name_prefix               = "kordex-m3-lab"
```

Pass both principal emails to the lifecycle CLI: `--terraform-principal-email`
is checked as the deployment identity input, while lifecycle gcloud requests
impersonate only `--lifecycle-principal-email`.

The IAM owner can review the roles and bindings without exposing credentials:

```sh
gcloud iam roles describe kordexM3TerraformProject --project="$PROJECT"
gcloud iam roles describe kordexM3TerraformResources --project="$PROJECT"
gcloud iam roles describe kordexM3LabInventory --project="$PROJECT"
gcloud iam roles describe kordexM3LabLifecyclePower --project="$PROJECT"
gcloud projects get-iam-policy "$PROJECT" --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${TF_SA} OR bindings.members:serviceAccount:${LIFECYCLE_SA}" \
  --format="table(bindings.role,bindings.members,bindings.condition.expression)"
gcloud iam service-accounts get-iam-policy "$TF_SA" --project="$PROJECT"
gcloud iam service-accounts get-iam-policy "$LIFECYCLE_SA" --project="$PROJECT"
gcloud auth print-access-token --impersonate-service-account="$TF_SA" >/dev/null
gcloud auth print-access-token --impersonate-service-account="$LIFECYCLE_SA" >/dev/null
```

The customer must additionally use IAM Policy Troubleshooter for each required
permission/resource pair and review inherited policy. Do not proceed if a
permission requires a broader project role, a custom-role permission is
unsupported, the resource condition does not match the provider's request
resource name, or the project has shared/production resources. No IAM mutation
or live permission test was performed during this repository task.

## Persistence and remaining qualifications

No command schedules shutdown or deletes the lab. Boot disks are retained
across VM stop/start, and the module's custom VPC remains separate from the
default VPC. A full lab teardown remains a distinct, separately confirmed
Terraform destroy operation.

The lifecycle implementation is repository code and local tests only until the
database migration is deployed, authenticated API access is configured, the
dedicated IAM identity is granted, and the actual lab/identity/baseline inputs
are verified. No GCP VM was started or stopped by implementation tests. These
commands do not qualify Debian or RHEL hosts and do not change host-upgrade
defaults.
