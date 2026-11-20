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
- There are no existing PVCs or PVs. The live `standard-rwo` StorageClass uses
  the GCE PD CSI driver with `type=pd-balanced`, waits for first consumer, and
  has `Delete` reclaim policy. Do not restore to a newly bound PVC until the
  corresponding PV is read and its reclaim policy is verified as `Retain`.
  The prepared
  PostgreSQL StatefulSet retains its claim on StatefulSet deletion/scale-down;
  this does not override the PV reclaim policy. Never delete the claim, PV, or
  source backup as routine cleanup. The restore helper now refuses missing,
  unreadable, mismatched, or non-`Retain` PVs and never changes the policy.
- The current GKE cluster does not expose Dataplane V2 or the Calico network
  policy add-on, and no `anetd`/Calico enforcer was found. The overlay contains
  default-deny and narrowly scoped policies, but they are **not effective** on
  the current cluster until an enforcing dataplane is independently enabled
  and confirmed. The strict validator now refuses live validation when it
  cannot confirm enforcement. This package does not enable or change GKE
  networking.
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
- Keycloak 26.8.2 Deployment held at zero replicas until the PostgreSQL restore
  is verified, plus a private HTTPS ClusterIP Service. It uses PostgreSQL, a
  TLS trust file, and the existing realm import Secret; its image digest is
  pinned.
- The existing Kordex API Deployment is rendered at **zero replicas** until
  PostgreSQL restore verification succeeds. After verification, it can be
  explicitly scaled to one replica. Its HTTP listener is on Pod loopback behind
  a pinned, unprivileged Nginx TLS sidecar. Only the private Service port 8443
  is exposed. The proxy image is pinned to
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

### Protected Secret provisioning (not run)

The provisioner accepts a mode-`0700` input directory owned by the invoking
user, outside the repository. Passwords, DSNs, signing keys, TLS private keys,
and realm JSON files must be regular, non-symlink files owned by that user and
deny group/other access. It refuses to overwrite any existing Secret. `--from-file`
passes paths rather than values in process arguments; generated Secret YAML is
piped directly to `kubectl create` and is not written to disk or printed. If a
multi-Secret run stops part way through, inspect key presence and review the
partial state; the helper intentionally does not delete or replace Secrets.

| Secret | Required data keys | Protected input filenames |
| --- | --- | --- |
| `kordex-postgres-credentials` | `postgresSuperuserPassword`, `kordexRuntimePassword`, `kordexMigrationPassword`, `keycloakDbPassword` | Same names |
| `kordex-hub-credentials` | `databaseURL`, `migrationDatabaseURL`, `maintenanceSigningKey`, `auditSigningKey` | Same names; reuse existing Kordex signing keys |
| `kordex-postgres-tls` | `tls.crt`, `tls.key` | `postgres.crt`, `postgres.key` |
| `kordex-keycloak-tls` | `tls.crt`, `tls.key` | `keycloak.crt`, `keycloak.key` |
| `kordex-api-tls` | `tls.crt`, `tls.key` | `api.crt`, `api.key` |
| `kordex-management-ca` | `ca.crt` | `ca.crt` public CA certificate |
| `kordex-keycloak-bootstrap` | `username`, `password` | `keycloakBootstrapUsername`, `keycloakBootstrapPassword` |
| `kordex-keycloak-realm-import` | one or more `.json` keys | Existing `kordex` realm JSON export files; total at most 900,000 bytes |

Generate database URL files from protected one-line password files without
placing password values in arguments or terminal output:

```bash
python3 scripts/gke-private-lab-prepare-db-urls.py \
  --runtime-password-file "$KORDEX_PRIVATE_LAB_SECRET_DIR/kordexRuntimePassword" \
  --migration-password-file "$KORDEX_PRIVATE_LAB_SECRET_DIR/kordexMigrationPassword" \
  --output-dir "$KORDEX_PRIVATE_LAB_SECRET_DIR"
```

It writes mode-`0600` `databaseURL` and `migrationDatabaseURL` files using
`sslmode=verify-full`, the PostgreSQL Service DNS name, and the mounted CA path.
For a new lab-only credential set, create an outside-Git directory with mode
`0700`, then run the explicit generator; it writes independent random
PostgreSQL role and Keycloak bootstrap credentials as mode-`0600` files and
never displays them. Do not use it to replace passwords for an existing
database or Keycloak realm:

```bash
install -d -m 0700 "$HOME/.local/share/kordex/private-gke-lab/secrets"
KORDEX_CREDENTIAL_GENERATE_CONFIRM='GENERATE PRIVATE GKE LAB CREDENTIAL FILES' \
  python3 scripts/gke-private-lab-generate-credentials.py \
  "$HOME/.local/share/kordex/private-gke-lab/secrets"
```

Stage TLS files from the protected certificate output directory using
`install -m 0600` for each `.key` and `install -m 0644` for `.crt`. Stage the
existing maintenance/audit signing keys without regenerating them. Decrypt the
Keycloak realm export directly into this mode-`0700` directory; the file names
must end in `.json`. Then generate the two DSNs above. The helpers refuse
existing credential/DSN outputs so reruns cannot silently rotate them.
Before generating TLS leaves, the certificate helper verifies the existing CA
private key is a non-symlink, current-user-owned file with no group/other
permissions, checks CA constraints and certificate/key match, stores the serial
file only in the protected output directory, and validates leaf names. Private
keys and temporary files are mode `0600`; all generated material stays outside
Git.

After a separately approved deployment, use the following commands to create
the Secrets and check names/keys. Neither command prints Secret values:

```bash
export KORDEX_EXPECTED_KUBE_CONTEXT=gke_kordex-fleet-platform_us-east1-b_kordex-gke-test
export KORDEX_PRIVATE_LAB_SECRET_DIR="$HOME/.local/share/kordex/private-gke-lab/secrets"
KORDEX_SECRET_PROVISION_CONFIRM='CREATE PRIVATE GKE LAB SECRETS' scripts/gke-private-lab-provision-secrets.sh
scripts/gke-private-lab-verify-secrets.sh
```

The provisioner creates only the listed names in `kordex-management`; it does
not create the namespace or apply workloads. The verifier reports key names and
presence only.

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

Keycloak 26.8.2 uses the supported `KC_DB_TLS_MODE=verify-server` setting and
`KC_DB_TLS_TRUST_STORE_FILE=/run/postgres-ca/ca.crt`. For PostgreSQL, the trust
file is PEM; the PostgreSQL JDBC hostname is
`kordex-postgres.kordex-management.svc.cluster.local`, which must exactly match
the server certificate SAN. The CA and hostname are checked by the local TLS
test helper. A live JDBC connection test with a wrong CA/hostname is still
required after deployment; this package has not connected Keycloak to the
prepared PostgreSQL service. See Keycloak's [database TLS configuration](https://www.keycloak.org/server/db)
for the pinned-version unified TLS settings.

## Local dashboard access after an approved deployment

Run these in separate terminals (not run in this preparation task):

```bash
kubectl --context=gke_kordex-fleet-platform_us-east1-b_kordex-gke-test -n kordex-management port-forward svc/kordex-api 8081:8443
kubectl --context=gke_kordex-fleet-platform_us-east1-b_kordex-gke-test -n kordex-management port-forward svc/kordex-keycloak 8443:8443
```

The NetworkPolicies allow only same-namespace API↔PostgreSQL, API↔Keycloak,
DNS to kube-system CoreDNS Pods, and ingress to API TLS port 8443 from the
inventory-agent namespace/selector. API and TLS proxy share a Pod network
namespace, so their loopback traffic is not a separate network-policy flow.
Workstation port-forward traffic travels through the Kubernetes API/kubelet
path; no workstation CIDR or public ingress is allowed by these policies. Its
behavior with an enforcing dataplane is not verified. Confirm API and Keycloak
port-forward plus kubelet health probes before relying on the policy set.
NetworkPolicy objects alone do not isolate traffic unless GKE enforcement is
active. The current cluster has no confirmed enforcer, and this package does
not enable one. GKE documents that enabling policy enforcement on an existing
Standard cluster can disrupt Pods while node configuration is changed.

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
   TLS Secret are prepared. The Kustomize package starts PostgreSQL only; the
   Keycloak and Kordex API Deployments are set to zero replicas. Verify the PVC
   is Bound, read the PV name from that
   claim, and set/verify `spec.persistentVolumeReclaimPolicy: Retain` through an
   approved operator procedure before restore. The restore helper checks the
   expected claim reference and fails closed if the PV is absent/unreadable or
   not `Retain`; it never patches or deletes PVCs/PVs/backups/source data. Keep
   a second encrypted backup outside the cluster.
5. Restore the PostgreSQL dump only to a new, empty `kordex` database. The
   restore helper requires the exact confirmation
   `RESTORE KORDEX BACKUP TO EMPTY PRIVATE LAB DATABASE`, checks the GKE
   context from `KORDEX_EXPECTED_KUBE_CONTEXT`, and accepts
   `KORDEX_ENCRYPTED_BACKUP` plus its `KORDEX_BACKUP_SHA256` manifest only when
   they resolve to regular files in the same directory and the manifest's
   single lowercase SHA-256 line names that exact archive basename. It hashes
   the supplied archive bytes directly before decrypting, refuses a non-empty
   database or a PV not confirmed `Retain`, restores as `kordex_migrator`, then
   applies the existing runtime grants SQL. It verifies the target PostgreSQL
   major, exact complete schema-migration version/count, and the expected
   organization/fleet/site/cluster association and UID. It compares membership
   subjects against the protected realm export using counts only. It does not
   delete source data, change reclaim policy, start the API, or run application
   schema migrations. A failed restore can leave partial target data; inspect
   it and do not retry blindly.
6. The restore helper compares every database membership subject against the
   protected realm export, without printing identifiers. After it succeeds,
   start Keycloak so its pinned image imports the existing realm into its
   PostgreSQL database (the `kordex-keycloak-realm-import` Secret must already
   be provisioned):

   ```bash
   kubectl --context=gke_kordex-fleet-platform_us-east1-b_kordex-gke-test \
     -n kordex-management scale deployment/kordex-keycloak --replicas=1
   kubectl --context=gke_kordex-fleet-platform_us-east1-b_kordex-gke-test \
     -n kordex-management rollout status deployment/kordex-keycloak --timeout=10m
   ```

   Compare the hash-only subject-ID fingerprint before and after import. Verify
   discovery and TLS before starting the API.
7. Start the API only after the restore script has completed all schema and
   organization/fleet/site/cluster/membership checks and Keycloak discovery,
   CA, signing-key, and OIDC configuration are verified. Do not run an
   application migration job unless the target schema check proves one is
   required and that migration is separately approved. Then scale the API:

   ```bash
   kubectl --context=gke_kordex-fleet-platform_us-east1-b_kordex-gke-test \
     -n kordex-management scale deployment/kordex-api --replicas=1
   ```

   The restore helper refuses to run if either Deployment is nonzero or any
   API/Keycloak Pod exists. It never scales or starts either workload itself.
   After API startup, verify login/callback/session and the existing
   authorized/unauthorized organization behavior before any agent deployment.

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

The live cluster has three `e2-medium` nodes, each with about 940m CPU and
2.8GiB allocatable memory. The last node-level request sample was 398m/654Mi,
410m/649Mi, and 196m/420Mi, leaving request headroom of roughly 542m/2,146Mi,
530m/2,150Mi, and 744m/2,380Mi respectively. Summed current request headroom is
about 1.8 CPU and 6.5GiB. The management-plane requests are 475m CPU/928MiB
memory (API plus TLS proxy 125m/160Mi, PostgreSQL 100m/256Mi, Keycloak
250m/512Mi). The agent adds 50m/64Mi. The Keycloak init container is not
concurrent with its main container for scheduler request accounting.

Requests fit arithmetically on the existing three nodes, including one-node
loss: about 1.53 CPU/2.6GiB total requests versus about 1.88 CPU/5.46GiB
allocatable across two surviving nodes. This is not a reliability guarantee.
The last `kubectl top` sample showed approximately 1.6GiB, 1.0GiB, and 1.1GiB
used on the three nodes (about 3.6GiB total, with about 4.6GiB free across all
nodes). Current workload memory limits already exceed allocatable memory per
node (roughly 162%–203% in the sample). Current per-node workload limits were
about 7,043m CPU/4,932Mi memory, 6,000m/4,542Mi, and 4,000m/5,664Mi against
940m CPU and about 2,800Mi allocatable. CPU limits are intentionally
overcommitted; memory limits are the larger node-loss/OOM risk. The new package
allows up to about 3,200MiB across API, proxy, PostgreSQL, and Keycloak
(512+128+1,024+1,536MiB).
If workloads reschedule after losing a node and approach those limits, the two
remaining nodes could exceed their combined memory. OOM kills/evictions are a
credible risk. No HPA or node autoscaling is configured.

Each management component is a single replica. A node failure interrupts the
component until its Pod restarts; PostgreSQL may also need volume detach/attach.
The cluster is zonal in `us-east1-b`, so it has no zone-level failure
protection. For an approved future deployment, soft hostname topology spread
or anti-affinity can separate the three Pods across nodes; it cannot create
zone resilience here. A `minAvailable: 1` PDB for each single replica blocks
voluntary disruption but does not protect against node failure and can block
drain/maintenance. This is a functional test environment, not HA/production.
Do not add replicas or resize nodes without separate approval.

The 20Gi claim uses `standard-rwo`, which the live StorageClass maps to
`pd-balanced` (not `pd-standard`). The previously quoted dollar estimates used
the wrong disk class and are withdrawn. Disk and snapshot costs are **not
verified estimates**: confirm current regional `pd-balanced` rates, snapshot
incremental storage, and account discounts in the [Compute Engine disk pricing](https://cloud.google.com/compute/disks-image-pricing)
or Google Cloud Pricing Calculator before deployment. This report does not
query billing. No additional node or external network resource is included.

## Validation commands (read-only)

```bash
kubectl kustomize deployments/kustomize/hub/overlays/gke-private-lab
python3 scripts/test_gke_private_management_overlay.py
python3 scripts/test_gke_private_lab_validator.py
python3 scripts/test_gke_private_lab_db_urls.py
python3 scripts/test_gke_private_lab_credentials.py
python3 scripts/test_gke_private_lab_secret_verifier.py
bash scripts/test_gke_private_lab_tls.sh
python3 scripts/test_gke_private_lab_restore_safety.py
python3 scripts/test_gke_private_membership_subjects.py
python3 scripts/validate-gke-private-lab.py --template
```

The template check passes with placeholders. The strict validator must fail
until image digests, a reserved Keycloak Service IP, and live NetworkPolicy
enforcement are confirmed. It checks the target context, Service CIDR/IP
allocation, NetworkPolicy dataplane, and ready enforcer before a future apply.
Do not apply this overlay in this preparation phase.
