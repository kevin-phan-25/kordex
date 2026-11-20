# Private GKE lab management plane (preparation only)

This package prepares a single-cluster, inventory lab using the existing GKE
cluster. It is not production HA, and nothing in this package has been applied.
It contains no Kubernetes Secret data, and the Kustomize overlay intentionally
fails validation until the API image digest and reserved Keycloak Service IP
are supplied. It excludes the operator, scheduler, dashboard, CRDs, and agent.

## Current findings

- Context: `gke_kordex-fleet-platform_us-east1-b_kordex-gke-test`.
- Three Ready `amd64` `e2-medium` nodes are in two pools. Each has about 940m
  allocatable CPU and 2.8 GiB allocatable memory.
- Current requested CPU allocations are 398m, 410m, and 196m. Requested-memory
  allocations are approximately 654 MiB, 649 MiB, and 420 MiB. Current measured
  use at the latest read-only check was 86m/1585Mi, 77m/1017Mi, and 71m/1100Mi
  respectively.
- Aggregate unallocated requests are about 1.8 CPU and 6.5 GiB. Existing limits
  are heavily overcommitted (CPU limits are 425–749% of allocatable), so requests
  show schedulability, not a guarantee against memory pressure.
- Both pools use 30 GiB `pd-standard` boot disks. Autoscaling is not enabled;
  GKE auto-repair and auto-upgrade are enabled. No node-pool changes are part of
  this plan.
- There are no existing PVCs or PVs. `standard-rwo` uses the GCE PD CSI driver,
  waits for first consumer, and has `Delete` reclaim policy. The prepared
  PostgreSQL StatefulSet retains its claim on StatefulSet deletion/scale-down;
  after binding, the PV reclaim policy must also be changed to `Retain` before
  restoring data. Never delete the claim as routine cleanup.
- PostgreSQL holds about 9.7 MiB locally. The local PostgreSQL and Keycloak
  Podman volumes remain the rollback source and are not changed by this plan.
- The workstation has no private route into the GKE VPC. The private endpoint
  will be a ClusterIP reachable by the agent from inside GKE. Workstation
  dashboard access uses `kubectl port-forward` through the existing GKE API
  connection. No VPC, firewall, VPN, DNS, Ingress, or public-IP resource is
  required.

## Prepared resources and images

`deployments/kustomize/hub/overlays/gke-private-lab` renders only:

- PostgreSQL 17 StatefulSet and private headless/client Services, with a 20 GiB
  `standard-rwo` claim, TLS enabled, health probes, and non-secret Secret
  references. The local PostgreSQL image is pinned to
  `docker.io/library/postgres@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32`.
- Keycloak 26.8.2 Deployment and private HTTPS ClusterIP Service, with the
  checked-in image digest, PostgreSQL storage, the existing realm imported from
  a Secret, and TLS.
- The existing Kordex API Deployment, one replica, with its HTTP listener on Pod
  loopback behind a pinned, unprivileged Nginx TLS sidecar. Only the private
  Service port 8443 is exposed. The proxy image is pinned to
  `docker.io/nginxinc/nginx-unprivileged@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6`.
  Kubelet HTTPS probes check the proxy health paths; normal clients must validate
  the CA and hostname.
- A Kordex API image reference at
  `us-east1-docker.pkg.dev/kordex-fleet-platform/kordex-artifacts/control-plane`
  with an unresolved digest placeholder. No API or agent image has been pushed.

Required Secret names/keys are referenced, not created here:

- `kordex-postgres-credentials`: `postgresSuperuserPassword`,
  `kordexRuntimePassword`, `kordexMigrationPassword`, `keycloakDbPassword`.
- `kordex-hub-credentials`: existing hub keys including `databaseURL`,
  `migrationDatabaseURL`, `maintenanceSigningKey`, and `auditSigningKey`.
- `kordex-postgres-tls`, `kordex-keycloak-tls`, `kordex-api-tls`, and
  `kordex-management-ca`.
- `kordex-keycloak-bootstrap` and `kordex-keycloak-realm-import`.

Values must be generated/staged outside Git after deployment approval. The API
uses `sslmode=verify-full` and the mounted CA for PostgreSQL and OIDC discovery.
The API remains OIDC-only (`KORDEX_LOCAL_DEVELOPMENT=false`); no bootstrap
listener or administrative bootstrap token is deployed.

## Issuer and TLS name resolution

The issuer stays exactly:

`https://keycloak.localhost:8443/realms/kordex`

Keycloak's `KC_HOSTNAME` stays `https://keycloak.localhost:8443`. A browser on
the workstation reaches the private Keycloak Service through port-forward and
uses the local CA-trusted certificate for `keycloak.localhost`. The API Pod
uses a `hostAliases` entry for `keycloak.localhost` that points to the same
static Keycloak ClusterIP; TLS SNI and certificate validation still use the
hostname `keycloak.localhost`. Kubernetes does not resolve `*.localhost` to a
Service automatically.

The ClusterIP is deliberately a placeholder in both the Service and API Pod.
Before any apply, select an unused IP from the live GKE Service CIDR
`34.118.224.0/20`, set it in both places, and run the strict validator. The
validator checks the current context, service CIDR, and Service allocation
read-only. It does not reserve an IP. Re-run immediately before apply.

PostgreSQL's leaf SAN is
`kordex-postgres.kordex-management.svc.cluster.local`. The API leaf SAN includes
that API Service DNS name and `127.0.0.1`; the latter is used only for local
port-forward. The API calls Keycloak through its canonical issuer name and the
Keycloak leaf certificate. `scripts/gke-private-lab-generate-tls.sh` creates
these leaf certificates from the existing local CA only when explicitly
invoked; its private keys stay outside Git.

## Local dashboard access after an approved deployment

Run these in separate terminals (not run in this preparation task):

```bash
kubectl -n kordex-management port-forward svc/kordex-api 8081:8443
kubectl -n kordex-management port-forward svc/kordex-keycloak 8443:8443
```

The workstation dashboard configuration remains:

```text
KORDEX_DASHBOARD_URL=http://127.0.0.1:3000
KORDEX_API_URL=https://127.0.0.1:8081
KORDEX_OIDC_ISSUER=https://keycloak.localhost:8443/realms/kordex
KORDEX_OIDC_CLIENT_ID=kordex-dashboard
```

Trust the local CA in the workstation and Node process before starting Next.js.
The API certificate must include the IP SAN `127.0.0.1`; Keycloak's exact
callback remains `http://127.0.0.1:3000/api/auth/callback`. No switch to
`localhost` is made for dashboard login.

## Backup, realm export, restore, and rollback

These procedures have not been run. They require separate approval to migrate
data. Keep the current Podman PostgreSQL and Keycloak volumes untouched.

1. Use a dedicated encrypted backup directory outside the repository and an
   approved `age` recipient whose identity is stored separately. Stop local API
   writers before the final PostgreSQL dump. The backup script requires the
   exact confirmation `BACK UP EXISTING KORDEX DATABASE` and
   `KORDEX_SOURCE_WRITES_QUIESCED=YES`; it never stops services itself.
2. Back up PostgreSQL with the custom-format archive helper. It validates the
   archive, encrypts it, and writes a SHA-256 manifest. The local database was
   schema version 14 when last inspected. Do not run migrations against it.
3. Stop Keycloak only during an approved export window. The Keycloak export
   helper checks that its container is stopped, exports a copy of the existing
   H2 volume into a temporary Podman volume, exports the `kordex` realm, encrypts
   the realm files, writes a checksum, and records a hash-only fingerprint of
   the realm user IDs. It does not edit the source volume. If the export exceeds
   900 kB, the helper refuses the Kubernetes Secret path; use a separately
   approved protected import volume instead.
4. Deploy the PostgreSQL StatefulSet only after the required credentials and
   TLS Secret are prepared. Verify the PVC is bound, then set its PV reclaim
   policy to `Retain` and verify it. Keep a second encrypted backup outside the
   cluster.
5. Restore the PostgreSQL dump only to a new, empty `kordex` database. The
   restore helper requires the exact confirmation
   `RESTORE KORDEX BACKUP TO EMPTY PRIVATE LAB DATABASE`, checks the GKE
   context, verifies the checksum and age decryption, refuses a non-empty
   database, restores as `kordex_migrator`, then applies the existing runtime
   grants SQL. It does not run application schema migrations.
6. Only after the database restore is verified, create the realm-import Secret
   from the decrypted JSON export files and start Keycloak with the existing
   pinned image. Keycloak stores realm state in its PostgreSQL database, not
   H2. The import is not executed by this package.
7. Compare the hash-only realm subject-ID fingerprint before and after import.
   Then check that every `memberships.subject` in the restored Kordex database
   exists as a user ID in the imported realm, without printing either set.
   Verify login, callback, session, and the existing authorized/unauthorized
   organization behavior before starting the API or agent.
8. Start the API only after database, CA, signing-key, and OIDC checks pass. Do
   not run an application migration job unless the target schema check proves
   one is required and that migration is separately approved.

Rollback is to stop only the new lab Deployments, leave the new PVC and backups
intact for diagnosis, and point the workstation dashboard back to its original
Podman API URL. Restart the original local services if needed. Never delete or
recreate the original Podman volumes as part of rollback.

## Agent publishing and deployment remain separate

The approved Docker repository now exists at:

`us-east1-docker.pkg.dev/kordex-fleet-platform/kordex-artifacts`

The agent publisher command, **not run**, is:

```bash
scripts/publish-gke-inventory-agent.sh \
  'us-east1-docker.pkg.dev/kordex-fleet-platform/kordex-artifacts/agent'
```

After image publication, use its immutable digest in the existing
`gke-inventory` overlay. The control-plane image also needs a separately built
and published digest to replace the placeholder in this private overlay. The
agent overlay remains inventory-only; this management-plane overlay contains
no agent or operator resources.

## Read-only capacity and cost estimate

Steady-state requests in this lab package are approximately 475m CPU and 928
MiB memory: API 100m/128Mi, TLS proxy 25m/32Mi, PostgreSQL 100m/256Mi, and
Keycloak 250m/512Mi. The agent adds 50m/64Mi. Aggregate currently unallocated
requests are about 1.8 CPU and 6.5 GiB, so the requests can reasonably fit on
the existing nodes. Actual use already leaves about 4.6 GiB free by `kubectl
top`; the proposed limits permit more than that if all components peak together.
There is no autoscaling, so monitor memory pressure and do not add a node without
approval.

Using the current published us-east1 rates, a 20 GiB standard PD is about $0.80
per month after any account free quota, and a fully stored 20 GiB standard
snapshot is about $1.00/month. Existing 30 GiB boot disks may already consume
the account's 30 GiB-month standard-disk allowance. [Disk pricing](https://cloud.google.com/compute/disks-image-pricing)
lists the rates and free quota. If one more e2-medium becomes necessary, its
listed on-demand compute rate is about $24.46/month, plus its boot disk; none is
requested here. [E2 pricing](https://cloud.google.com/products/compute/pricing/general-purpose?hl=en)
Artifact Registry storage has 0.5 GiB-month free, then charges by stored bytes.
[Artifact Registry pricing](https://cloud.google.com/artifact-registry/pricing)
No external load balancer, public IP, VPN, Cloud Run service, or new GKE cluster
is part of this design.

## Validation commands (read-only)

```bash
kubectl kustomize deployments/kustomize/hub/overlays/gke-private-lab
python3 scripts/test_gke_private_management_overlay.py
python3 scripts/validate-gke-private-lab.py --template
```

The template check passes with placeholders. The strict validator must fail
until image digests and the reserved Keycloak Service IP are supplied; it also
checks the target context/IP allocation before any future apply. Do not apply
this overlay in this preparation phase.
