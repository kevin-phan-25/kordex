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

## Dedicated Terraform identity

The existing Terraform provider requires an explicit `terraform_principal_email`
and impersonates that service account. Do not use a human Owner identity as the
Terraform principal. The service account and IAM bindings are deliberately not
created by this repository command and no IAM mutation was performed here.

The project owner must create a dedicated service account, define a custom
project role from the exact read/write permissions used by the pinned Google
provider for this module's Compute network/subnetwork/firewall/instance/disk,
Cloud DNS, Secret Manager, and service-account resources, and grant only that
role plus `roles/iam.serviceAccountUser` (`iam.serviceAccounts.actAs`) on the
two workload service accounts. The human deployment operator receives
`roles/iam.serviceAccountTokenCreator` only on the dedicated Terraform service
account for impersonation. The deployment identity must not receive Owner,
Editor, project IAM administration, or permission to change project labels,
billing, or APIs. The exact custom-role permission set must be reviewed against
the module/provider version before granting; broad predefined Admin roles are
not an approved substitute. This remains a customer IAM-owner action.

The lifecycle CLI also uses the approved impersonated principal for read-only
inventory, VM start/stop, and IAP SSH identity checks. Because the instances
enable OS Login, the IAM owner must separately review and grant the minimum
access needed for this path: `roles/iap.tunnelResourceAccessor` and
`roles/compute.osAdminLogin` on only the three lab instances, plus
`roles/iam.serviceAccountUser` on the attached server/worker service accounts.
Google documents these as the IAP TCP forwarding, OS Login, and attached-VM
service-account access roles. Prefer instance-level bindings for the three
exact VM resources; do not grant project-wide SSH/root access. These additional
bindings were not applied or live-tested. If customer policy disallows
impersonated service-account OS Login, use its approved operator identity path
and update command principal verification before deployment.

The repository includes a candidate permission manifest at
`infrastructure/terraform/gcp/self-managed-lab/terraform-deployer-role.json`.
The project owner must review every permission against the pinned provider and
the actual resource methods before using these exact command templates. These
are IAM mutations and were not run:

```sh
PROJECT=kordex-fleet-platform-515416
TF_SA=kordex-m3-terraform@${PROJECT}.iam.gserviceaccount.com
gcloud iam service-accounts create kordex-m3-terraform --project="$PROJECT"
gcloud iam roles create kordexM3Terraform --project="$PROJECT" \
  --file=infrastructure/terraform/gcp/self-managed-lab/terraform-deployer-role.json
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${TF_SA}" \
  --role="projects/${PROJECT}/roles/kordexM3Terraform"
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${TF_SA}" --role="roles/iam.serviceAccountUser" \
  --condition='expression=resource.name.startsWith("projects/kordex-fleet-platform-515416/serviceAccounts/kordex-m3-lab-"),title=Kordex lab VM service accounts only,description=Allow attachment only to lab server and worker identities'
gcloud iam service-accounts add-iam-policy-binding "$TF_SA" \
  --project="$PROJECT" --member="user:DEPLOYER_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator"
```

After VM creation, and only after reviewing each exact instance resource name,
the IAM owner must separately grant the lifecycle principal per-instance IAP
and OS Login access. Run these commands once per reviewed
`kordex-m3-lab-{server,worker,worker-2}` instance; they are IAM mutations and
were not run:

```sh
gcloud compute instances add-iam-policy-binding VM_NAME \
  --project=kordex-fleet-platform-515416 --zone=us-east1-b \
  --member="serviceAccount:${TF_SA}" --role=roles/iap.tunnelResourceAccessor
gcloud compute instances add-iam-policy-binding VM_NAME \
  --project=kordex-fleet-platform-515416 --zone=us-east1-b \
  --member="serviceAccount:${TF_SA}" --role=roles/compute.osAdminLogin
```

These grants allow privileged access to disposable VMs, so the customer must
approve the principal, exact resource scope, and audit logging before the
lifecycle CLI can be considered deployable. Refer to Google's [OS Login role
requirements](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin)
and [IAP TCP forwarding roles](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding).

Replace `DEPLOYER_EMAIL` only with the approved human operator identity. The
project owner must confirm the Terraform `name_prefix` is exactly
`kordex-m3-lab` for the conditional attachment grant; otherwise have the IAM
owner derive an exact prefix condition from the reviewed inputs. Do not grant
the condition broadly. After identity setup, the operator must independently
verify impersonation and project scope before planning. The custom-role file
is a candidate; its creation may be rejected if Google marks any listed
permission unsupported in custom roles, and that is a stop condition requiring
review rather than broadening the role.

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
