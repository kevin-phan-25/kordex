# Isolated private management-plane lab (prepared; not applied)

This separate module is for a disposable, single-zone GKE Standard lab. It
does not reference or modify `kordex-fleet-platform` or its existing GKE
cluster. It requires an already-created, separately approved project. It does
not enable APIs, create the GCP project, grant human IAM roles, deploy
application manifests, restore data, publish images, or create backup payloads.
It does prepare two service accounts and narrowly scoped IAM bindings for the
future node pool and image pulls.

The module uses an explicit project allowlist, exact project confirmation, and
the live `kordex-disposable=qualification` project label. The cluster has
deletion protection enabled. A reviewed change must disable that protection
before Terraform can destroy the cluster. No Terraform command has been run
against GCP for this design.

## Architecture

- GKE Standard, zonal in `us-east1-b`, regular release channel.
- GKE Dataplane V2 (`ADVANCED_DATAPATH`) enabled at cluster creation. Standard
  Kubernetes `NetworkPolicy` is built in and enforced; do not set the legacy
  Calico `network_policy` block as well.
- VPC-native cluster with dedicated node, Pod, Service, and control-plane CIDR
  ranges; private nodes have no external IP addresses.
- Private IP-based GKE control-plane endpoint only. The DNS-based endpoint has
  external traffic disabled. No public GKE API IP endpoint is enabled.
- A small Debian IAP tunnel host has no external IP. Firewall ingress permits
  SSH only from the Google IAP TCP forwarding range, to that host only. The
  workstation authenticates to IAP and OS Login; an SSH local forward through
  the host reaches the private control-plane IP. This supports local
  `kubectl port-forward` without a public GKE endpoint, public node IP, public
  application Service, or public load balancer.
- Dedicated GKE node service account has only
  `roles/container.defaultNodeServiceAccount` plus read-only access to this
  lab's Artifact Registry repository. Application Pods should use Kubernetes
  service accounts and do not need Google Cloud IAM identities for this lab.
- Artifact Registry is in the disposable project and same region. Mirror
  approved, digest-pinned Postgres, Keycloak, API, and proxy images there before
  deploying workloads. The module does not publish images.
- PostgreSQL data should use one zonal `pd-balanced` RWO volume, provisioned at
  20 GiB, with a Retain PV reclaim policy verified after binding. This volume
  is a single point of failure. Keep encrypted, checksummed database backups
  outside the cluster and retain an independent copy before deleting the lab.
- Kordex API, Keycloak, and PostgreSQL use private ClusterIP Services. Apply
  the namespace's default-deny ingress and egress policies only after verifying
  Dataplane V2/`anetd`; explicitly allow DNS and the required app-to-app ports.
  Workstation access uses port-forward and does not require NodePort, Ingress,
  Gateway, or LoadBalancer Services.

Policy intent is default-deny ingress and egress for the management namespace;
allow DNS to kube-system DNS Pods, PostgreSQL TCP/5432 only from API and
Keycloak Pods, Keycloak TCP/8443 only from the API and approved workstation
port-forward path if enforcement requires an explicit rule, and API egress to
PostgreSQL TCP/5432 and Keycloak TCP/8443. Confirm port-forward and node
health-probe paths with live policy tests; do not widen rules to node or VPC
ranges without evidence.

### Port-forward workflow

After a future approved deployment, obtain private-endpoint credentials and
open an SSH tunnel from the workstation (replace placeholders with Terraform
outputs):

```sh
gcloud container clusters get-credentials CLUSTER --project PROJECT --zone ZONE --internal-ip
gcloud compute ssh BASTION --project PROJECT --zone ZONE --tunnel-through-iap \
  -- -N -L 127.0.0.1:16443:PRIVATE_CONTROL_PLANE_IP:443
```

The workstation kubeconfig's server can then be pointed at
`https://127.0.0.1:16443` while retaining the private endpoint IP as
`tls-server-name` and the GKE CA data. Validate the tunnel with a read-only
`kubectl get nodes`. Run `kubectl port-forward` locally through that context,
for example API `127.0.0.1:8081` and Keycloak `127.0.0.1:8443`. The services
remain ClusterIP-only. The exact kubeconfig edit should be scripted and tested
with the selected GKE version before first use; do not disable TLS checks.

Run these forwards in separate workstation terminals after the IAP and
Kubernetes API tunnels are established:

```sh
kubectl -n kordex-management port-forward svc/kordex-keycloak 8443:8443
kubectl -n kordex-management port-forward svc/kordex-api 8081:8443
```

Keep the existing issuer `https://keycloak.localhost:8443/realms/kordex` and
callback URL unchanged. The workstation resolves `*.localhost` to loopback for
the browser. In-cluster API Pods use the existing `hostAliases` mapping from
`keycloak.localhost` to the Keycloak ClusterIP, preserving that hostname for
TLS SNI and certificate validation. The API proxy certificate includes
`127.0.0.1` for the workstation API URL. Verify both paths using the mounted CA
and normal hostname verification before login.

The bastion is a private VM but IAP is a Google-hosted externally reachable
access broker. Its access is gated by IAM, OS Login, the IAP-only firewall
source range, and the lack of an external VM IP. If policy forbids even a
brokered IAP path, replace this with an approved private VPN/Interconnect or a
managed workstation inside the VPC; those options add cost and are not created
by this module.

## One node or three

| Shape | Capacity | Use | Failure behavior |
| --- | --- | --- | --- |
| 1 x `e2-standard-4` | 4 vCPU, 16 GiB | Recommended lowest-cost functional management-plane lab | Any node failure takes all three services offline until the node returns; zonal GKE control plane and single Postgres PVC are also single points of failure. |
| 3 x `e2-standard-2` | 6 vCPU, 24 GiB total | Optional rescheduling and one-node-loss exercise | The workloads can reschedule only if replica/placement settings permit; current DB is one replica and RWO, so the management plane is still not HA. One zone and one control-plane location remain failure domains. |

The prepared application requests total about 475m CPU and 928 MiB memory
(API plus TLS proxy 125m/160Mi, PostgreSQL 100m/256Mi, Keycloak 250m/512Mi).
Container memory limits total about 3.2 GiB. The one-node recommendation leaves
reasonable request and memory-limit headroom for GKE system Pods on a 16 GiB
node. A single 8 GiB node might schedule the requests, but provides less room
for Keycloak startup, cache growth, GKE system workloads, and concurrent
restore work; it is not the recommended one-node shape. Three 8 GiB nodes have
more aggregate headroom, but do not make the singleton database highly
available.

## APIs, IAM, and network prerequisites

Enable these APIs only after project approval; this module intentionally does
not enable them:

- `container.googleapis.com`, `compute.googleapis.com`
- `iam.googleapis.com`, `cloudresourcemanager.googleapis.com`,
  `serviceusage.googleapis.com`
- `artifactregistry.googleapis.com`, `iap.googleapis.com`
- `logging.googleapis.com` and `monitoring.googleapis.com` if those GKE
  integrations are enabled; `storage.googleapis.com` if an approved backup
  bucket is used.

The Terraform identity needs project metadata read, GKE cluster/node-pool
create and delete, VPC/subnetwork/firewall/instance administration, service
account create/act-as, the narrowly required project IAM binding permission for
the node service-account role, Artifact Registry repository create and IAM
binding permissions, and IAP-related API access. Prefer custom roles scoped to
the disposable project and repository rather than project Owner. API enablement
requires `serviceusage.services.enable`; Terraform does not perform it.

The node service account requires the GKE default node role described above.
Its repository grant is resource-scoped. The operator using the workstation
requires `roles/compute.osLogin`, `roles/iap.tunnelResourceAccessor`, and
`roles/iam.serviceAccountUser` scoped to the no-role bastion service account.
For a least-privilege custom role, include `compute.instances.get/list` and
`compute.projects.get` with `iap.tunnelInstances.accessViaIAP`; do not grant
Compute Instance Admin solely for port-forward access. The operator also needs
`container.clusters.get` and a namespace-scoped Kubernetes role for intended
lab actions (plus `container.clusters.connect` only if using the DNS endpoint).
The private
control-plane IP must be reachable from the bastion subnet; GKE-managed
firewall rules must remain intact. The module adds only an IAP-source TCP/22
ingress rule to the bastion. It does not create Cloud NAT. Private Google
Access handles GKE and Artifact Registry Google API traffic; public image and
package downloads must be mirrored or otherwise explicitly approved.

For Kubernetes authorization, separate the person who provisions GCP resources
from the workload operator where possible. The latter needs read-only cluster
discovery plus namespaced permissions to manage the approved management-plane
resources and create `pods/portforward`; it must not receive `cluster-admin`
for routine access.

## Monthly cost estimate

Planning estimate for 730 hours in `us-east1`, on-demand Linux pricing, no
discounts, and no Cloud NAT. Verify the live calculator and billing account
before approval. GKE's $74.40 monthly zonal-cluster credit can offset its
management fee only if unused in the same billing account. The table shows
gross control-plane fees before that credit.

| Cost item | 1-node shape | 3-node shape | Assumption |
| --- | ---: | ---: | --- |
| GKE cluster management | $73.00 | $73.00 | $0.10/hour; zonal free-tier credit may reduce this to $0. |
| GKE worker compute | $97.84 | $146.76 | 1 x e2-standard-4 at $0.13402284/hour; or 3 x e2-standard-2 at $0.06701142/hour. |
| Worker boot disks | $4.00 | $12.00 | 40 GiB/node `pd-balanced`, about $0.10/GiB-month. |
| PostgreSQL data disk | $2.00 | $2.00 | 20 GiB `standard-rwo`, which maps to `pd-balanced`, not `pd-standard`. |
| IAP bastion compute + boot disk | $6.91 | $6.91 | e2-micro at $0.008376428/hour plus 20 GiB `pd-standard`; free-tier eligibility not assumed. |
| Artifact Registry | $0.20 | $0.20 | Assumes about 2 GiB stored at roughly $0.10/GiB-month; account-level free storage may reduce it. |
| Encrypted backup copy | $0.40 | $0.40 | One 20 GiB Cloud Storage Standard regional copy, about $0.02/GiB-month; additional retained copies scale with size. |
| **Estimated gross monthly total** | **$184.35** | **$241.27** | Before possible zonal GKE credit; excludes variable logs, monitoring, IAP/network egress, backup operations, and taxes. |

No NAT baseline cost is included because no NAT gateway is proposed. If public
egress is later approved, Google lists Public NAT at $0.0014 per VM-hour for up
to 32 assigned VMs, $0.005 per NAT external-IP-hour, and $0.045/GiB processed,
plus ordinary egress. For a one-node pool plus one bastion this is about $5.69
per 730-hour month before traffic; for three nodes plus the bastion it is about
$7.74. Mirroring images and avoiding public package pulls keeps this expense
out of the baseline.

Budget the full $73 GKE fee: the existing test cluster may already consume the
billing account's $74.40 monthly zonal credit. Any free-tier reductions are
upside, not assumed savings. Prices and credits are estimates, not observed
billing. E2 prices are taken
from Google's published general-purpose VM pricing; disk, GKE, Artifact
Registry, Cloud Storage, and NAT rates are linked below. Resource pricing can
change and billing-account free tier is shared across projects.

## Terraform and lifecycle sequence

The module requires an existing dedicated project and does not create a GCP
project. Naming convention: project ID `kordex-pmlab-<date>-<random>`, resource
prefix `kordex-pmlab`, cluster `kordex-pmlab-gke`. Set the `expires-on`
resource label to the planned review date; it is a reminder, not an automatic
deletion. Apply project label
`kordex-disposable=qualification` only after the project owner verifies it has
no non-disposable resources. Never use `kordex-fleet-platform`.

The owner must enable the APIs above and grant the Terraform identity the
reviewed least privileges. Then copy `terraform.tfvars.example`, set the
disposable project ID in all three guard variables, run `terraform init`,
`terraform fmt -check`, `terraform validate`, and create/review a saved plan.
Do not run `apply` until a human separately approves the project, resources,
cost, and IAM changes. This module does not have an apply helper yet; add and
test an interactive exact-project confirmation helper before any execution.
No remote Terraform backend is configured. Keep local state and variable files
outside Git with owner-only permissions; use an approved encrypted, locked
backend before shared or long-running use. State is required to destroy only
the resources created by this module.

Cleanup sequence after the test:

1. Stop the test and create an encrypted, checksummed PostgreSQL backup outside
   the cluster. Verify decryption, archive integrity, schema, and expected
   organization/membership records without logging identifiers.
2. Export the Keycloak realm and confirm stable subject IDs and memberships.
3. Copy backups to a separate approved retention location; a bucket inside the
   disposable project is not sufficient for project deletion recovery.
4. Preserve Terraform state and inspect all resources, retained PVs, and disks.
5. In a reviewed Terraform change, set cluster deletion protection false and
   bastion instance deletion protection false; save and inspect that plan.
6. Destroy only after explicit confirmation of the exact disposable project.
   Verify retained disks and the Artifact Registry repository are handled
   intentionally; delete them only after backup restore verification and a
   second review. Never delete the source workstation Podman volumes as part of
   this lab's cleanup.

## Approval boundaries

This package is preparation only. Future human approval is required for the
project, API enablement, IAM bindings, VPC/subnet/firewall/cluster/node/bastion
creation, Artifact Registry repository and image publication, Kubernetes
deployment, PostgreSQL restore, Keycloak realm import, backup bucket/retention,
and every deletion. It must not be applied to the existing test cluster.

## Official references

- [GKE Dataplane V2 and built-in NetworkPolicy enforcement](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/dataplane-v2)
- [GKE network isolation and private control-plane endpoints](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation)
- [GKE private-node networking](https://docs.cloud.google.com/kubernetes-engine/docs/best-practices/networking)
- [GKE Terraform cluster resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster)
- [GKE cluster and zonal pricing](https://cloud.google.com/kubernetes-engine/pricing)
- [E2 VM pricing](https://cloud.google.com/products/compute/pricing/general-purpose)
- [Persistent Disk pricing](https://cloud.google.com/compute/disks-image-pricing)
- [Artifact Registry pricing](https://cloud.google.com/artifact-registry/pricing)
- [Cloud Storage pricing](https://cloud.google.com/storage/pricing)
- [Cloud NAT pricing](https://cloud.google.com/vpc/network-pricing)
