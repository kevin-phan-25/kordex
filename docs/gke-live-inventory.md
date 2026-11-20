# GKE live inventory enrollment

This runbook enrolls a GKE cluster into an existing Kordex organization and
deploys the read-only inventory agent. It does not enable maintenance, upgrades,
drains, or reboots.

## Current qualification state

The agent already uses the in-cluster Kubernetes API, a short-lived enrollment
token, a persisted Ed25519 identity, signed reports, and bounded retry. The API
provides organization-scoped cluster registration, enrollment, inventory, and
dashboard endpoints. The GKE inventory-only Kustomize overlay keeps maintenance
disabled and grants read access to inventory metadata, patch-only access to the
named identity Secret state key, and access to its own Lease. The identity data
is read from a read-only kubelet projection, not through the Kubernetes API.

The live deployment is currently blocked: the local API is published only on
`127.0.0.1:8081` (OIDC) and `127.0.0.1:8080` (local bootstrap). A GKE Pod cannot
route to the workstation loopback address. Read-only inspection found no
existing VPN, private DNS zone, or route between the workstation LAN and the
GKE VPC. No public endpoint, tunnel, firewall rule, or VPC change is configured
or authorized by this runbook. Do not deploy the agent until an approved private
HTTPS route exists. Use the current authenticated HTTPS API only; never expose
the bootstrap listener to GKE.

The repository includes an agent-only Kustomize overlay at
`deployments/kustomize/overlays/gke-inventory`. It does not include the operator,
CRDs, or maintenance RBAC. It requires an existing `kordex-system` namespace,
an immutable image digest, and the approved endpoint/cluster ID to be filled in
before deployment. The agent reads its identity through a read-only projected
Secret volume and uses compare-and-swap patches for the named `state.json` key;
it has no Kubernetes API Secret read permission. The enrollment Secret is also
mounted by kubelet and is not read through the Kubernetes API. The Role grants
no access to other Secrets.

Last checked 2026-11-19: the local database is at schema version 14. It contains
two GKE cluster records. The record whose `cluster_uid` matches the live
`kube-system` UID is `103f4d61-4751-4613-8e7c-ed58f0561d3a`; reuse it and do not
register a third copy. Its display name is
`kordex-gke-test-current-20261118`, and it contains two stored nodes. Its linked
organization/fleet/site are `Kordex GCP Test` /
`gcp-test-fleet` / `gcp-test-site`. The site's recorded region is
`us-central1`, while this GKE cluster is in `us-east1-b`. Site region is an
organization-maintained descriptive field; the schema and registration path do
not require it to equal the GKE location, and the cluster is selected by its
explicit site ID. The existing organization/fleet/site association is therefore
valid in the data model, but may be geographically inaccurate if this site is
intended to describe the cluster's physical/cloud region. Do not alter the site
or cluster association without an operator decision. The other cluster record has a different UID
and is historical. Both records currently have empty provider metadata. The
identity associated with the live-UID record is revoked, and the database has
no unexpired enrollment token, so a new enrollment is required. Read-only
database checks found two cluster records, four stored nodes, one existing
administrator membership, and no active agent identity. Read-only Artifact
Registry inspection found no repository in the configured GCP project, and no
agent image has been published.

## Registration

## Build and publish the inventory agent

The publisher requires an explicitly selected existing Artifact Registry Docker
repository in project `kordex-fleet-platform`. It does not create repositories.
It builds the pinned `agent/Dockerfile` for `linux/amd64`, tags the image with
the Git revision and source-tree hash, authenticates using a short-lived
`gcloud` access token in a private temporary auth file, and prints the registry
manifest digest. Use the resulting `repository@sha256:...` reference in the
Kustomize overlay; do not deploy the mutable tag.

```bash
scripts/publish-gke-inventory-agent.sh \
  'us-east1-docker.pkg.dev/kordex-fleet-platform/<existing-repository>/agent'
```

The command fails closed if that repository is missing or is not a Docker
repository. The currently inspected project has no Artifact Registry
repository, so publishing remains pending until an existing approved
repository is identified or repository creation is explicitly approved.

Use an existing organization, fleet, and site. The caller must have the
existing administrator authorization accepted by the chosen control-plane API.
Do not create an organization or put credentials in this file or in shell
history. GKE project and location metadata are identifiers, not credentials.

```bash
export KORDEX_REGISTRATION_API_URL='<authenticated-admin-api-url>'
export KORDEX_REGISTRATION_TOKEN='<supply through a protected shell environment>'
export KORDEX_ORG_ID='<existing organization UUID>'
export KORDEX_FLEET_ID='<existing fleet UUID in that organization>'
export KORDEX_SITE_ID='<existing site UUID in that organization>'
export KORDEX_CLUSTER_NAME='kordex-gke-test'
export KORDEX_GCP_PROJECT='kordex-fleet-platform'
export KORDEX_GKE_LOCATION='us-east1-b'
set +x

export KORDEX_CLUSTER_UID=$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}')
cluster_list=$(curl -fsS \
  "$KORDEX_REGISTRATION_API_URL/v1/organizations/$KORDEX_ORG_ID/clusters" \
  -H "Authorization: Bearer $KORDEX_REGISTRATION_TOKEN")
match_count=$(jq --arg uid "$KORDEX_CLUSTER_UID" '[.items[] | select(.clusterUid == $uid)] | length' <<<"$cluster_list")
if [ "$match_count" = 1 ]; then
  existing_cluster=$(jq -ec --arg uid "$KORDEX_CLUSTER_UID" '.items[] | select(.clusterUid == $uid)' <<<"$cluster_list")
  export KORDEX_CLUSTER_ID=$(jq -er '.id' <<<"$existing_cluster")
  export KORDEX_CLUSTER_NAME=$(jq -er '.name' <<<"$existing_cluster")
elif [ "$match_count" = 0 ]; then
  :
else
  echo "multiple cluster records match this Kubernetes UID; stop and resolve registration" >&2
  exit 1
fi
cluster_json=$(curl -fsS -X POST \
  "$KORDEX_REGISTRATION_API_URL/v1/organizations/$KORDEX_ORG_ID/clusters" \
  -H "Authorization: Bearer $KORDEX_REGISTRATION_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --arg name "$KORDEX_CLUSTER_NAME" --arg fleet "$KORDEX_FLEET_ID" --arg site "$KORDEX_SITE_ID" --arg project "$KORDEX_GCP_PROJECT" --arg location "$KORDEX_GKE_LOCATION" '{name:$name,fleetId:$fleet,siteId:$site,provider:"gke",providerMetadata:{gcpProjectId:$project,location:$location}}')")
registered_id=$(jq -er '.id' <<<"$cluster_json")
if [ -n "${KORDEX_CLUSTER_ID:-}" ] && [ "$registered_id" != "$KORDEX_CLUSTER_ID" ]; then
  echo "registration returned a different cluster ID; stop and inspect the existing association" >&2
  exit 1
fi
export KORDEX_CLUSTER_ID="$registered_id"
unset cluster_json existing_cluster registered_id
unset cluster_list
```

Registration is idempotent by organization and cluster name. The procedure
first reuses a single record already bound to the live Kubernetes UID, avoiding
a duplicate when the display name differs. Repeating the registration request
with matching fleet/site/provider values also fills provider metadata only on
an identity-bound legacy record where the metadata is still empty. A conflicting
name, association, or multiple UID matches fail closed. Provider metadata
contains no kubeconfig or cloud credential.

## Issue and deliver the one-time enrollment token

Enrollment tokens are single-use and expire after ten minutes. Keep the token
in a mode-0600 temporary file and do not print it. The agent stores its
long-lived signing identity in its pre-created Kubernetes Secret and rotates
that key using the existing agent protocol.

```bash
set -euo pipefail
set +x
umask 077
token_file=$(mktemp)
chmod 0600 "$token_file"
trap 'rm -f -- "$token_file"' EXIT HUP INT TERM
curl -fsS -X POST \
  "$KORDEX_REGISTRATION_API_URL/v1/organizations/$KORDEX_ORG_ID/clusters/$KORDEX_CLUSTER_ID/enrollment-tokens" \
  -H "Authorization: Bearer $KORDEX_REGISTRATION_TOKEN" \
  | jq -er '.token' >"$token_file"
```

The enrollment Secret and agent resources below are cluster mutations. Before
applying them, verify the context and project, confirm the private API route
from the Pod network, fill in the image digest and registration values, and
review the rendered resources. The inventory overlay grants no cluster-admin,
does not include the operator, and keeps maintenance disabled.

```bash
kubectl config current-context
kubectl get nodes -o wide
kubectl get namespace kordex-system

# Point to the public CA certificate (not a private key) for the approved
# management endpoint. The path must be readable by the validator process.
export KORDEX_MANAGEMENT_CA_FILE='<path-to-approved-management-ca.pem>'

# Edit these two non-secret files only after the approved route, cluster record,
# and immutable image digest are known.
$EDITOR deployments/kustomize/overlays/gke-inventory/agent-settings.patch.yaml
$EDITOR deployments/kustomize/overlays/gke-inventory/kustomization.yaml

kubectl kustomize deployments/kustomize/overlays/gke-inventory
python3 scripts/validate-gke-inventory-overlay.py
```

The validation command must pass before applying. It rejects unresolved
placeholders, a non-digest image reference, invalid cluster UUID, loopback or
non-TLS control-plane URLs, bootstrap port 8080, rendered enrollment
credentials, public DNS answers, and TLS chains or hostnames that do not
validate with `KORDEX_MANAGEMENT_CA_FILE`. The URL must be an HTTPS origin
without a path. This check runs from the workstation: it verifies that the
hostname currently resolves only to RFC1918/ULA addresses and that the
certificate chains to the supplied CA with the hostname in its SAN. It does
not prove that GKE Pods have a route to that private endpoint; verify that
separately from an approved path before applying. It must contain exactly the Kordex agent, its
service account/RBAC, the settings ConfigMap, identity Secret, and Lease. It
must not contain operator Deployments, CRDs, maintenance-policy access, or
node-maintenance access. Confirm the image reference is the approved immutable
digest and the endpoint hostname matches the mounted CA certificate. Only then
apply the overlay:

```bash
kubectl -n kordex-system create secret generic kordex-enrollment \
  --from-file=token="$token_file" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kordex-system create secret generic kordex-management-ca \
  --from-file=ca.crt="$KORDEX_MANAGEMENT_CA_FILE" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -k deployments/kustomize/overlays/gke-inventory
kubectl -n kordex-system rollout status deployment/kordex-agent --timeout=180s
```

`kordex-management-ca` contains only the CA certificate from
`KORDEX_MANAGEMENT_CA_FILE`. Never disable TLS
verification. Do not place the enrollment token in the ConfigMap or image. The
after enrollment is confirmed through the authenticated API, replace the token
in the retained `kordex-enrollment` Secret with an empty value; keep the Secret
object so the Pod can restart. The shell trap removes the temporary token file
on shell exit. The agent reports every 30 seconds by default; API inventory and
agent connectivity are considered fresh for 90 seconds.

Only after confirming enrollment, run this to remove the spent token while
retaining the mounted Secret and `token` key:

```bash
kubectl -n kordex-system create secret generic kordex-enrollment \
  --from-literal=token= --dry-run=client -o yaml | kubectl apply -f -
```

## Verify inventory and idempotency

The relevant API routes are:

- `GET /v1/organizations/{organizationID}/dashboard/clusters`
- `GET /v1/organizations/{organizationID}/dashboard/summary`
- `GET /v1/organizations/{organizationID}/nodes`
- `GET /v1/organizations/{organizationID}/clusters/{clusterID}/nodes`

All require the existing organization authorization. The authenticated
dashboard proxies these endpoints server-side; it never receives the agent
identity or enrollment token. Dashboard sign-in must be functional and the
current subject must already have membership in the selected organization.
The fleet cluster table links to `/fleet/clusters/{clusterID}`, which displays
registration metadata, agent heartbeat, and the cluster's persisted node
records. This page is implemented but has not been verified against live GKE
inventory because no agent report or authenticated browser session exists yet.

Reports are transactional and upsert on `(cluster_id, node_uid)`. Nodes absent
from a newer full report are retained with `present=false` and their last-seen
time; they are not returned as current nodes to maintenance APIs and appear as
absent/stale in dashboard inventory. Repeated reports update records without
creating duplicates.

Database evidence can be checked read-only after deployment:

```sql
SELECT id, name, provider, provider_metadata, cluster_uid, kubernetes_version,
       created_at, observed_at, last_heartbeat_at
FROM clusters WHERE id = '<cluster UUID>';

SELECT uid, name, present, first_seen_at, last_seen_at,
       inventory->>'osImage' AS os_image,
       inventory->>'osId' AS os_id,
       inventory->>'osVersion' AS os_version
FROM nodes WHERE cluster_id = '<cluster UUID>' ORDER BY name, uid;
```

For the current three-node GKE test cluster, expect two `cos` OS identities and
one `ubuntu` identity with version `24.04.5`. This is inventory evidence only;
the GKE-managed Ubuntu node is not a self-managed host-upgrade qualification
target.

## RBAC, data, and cleanup

The agent's cluster role lists Nodes, CSI node records, StorageClasses,
admission configuration, and API discovery; a namespaced role reads
`kube-system` DaemonSet names for CNI hints. It reads its own identity through
a read-only kubelet Secret projection and can patch only the named identity
Secret, but has no Kubernetes API Secret read permission. It does not grant
workload mutation. Inventory
contains node labels, taints, conditions, addresses, capacities, allocatable
resources, provider IDs, and OS/runtime metadata; it does not collect workload
environment variables, application Secrets, or Secret objects.

To remove only the agent release after an approved test, run `helm uninstall
kordex-agent -n kordex-system`. Review and remove the agent enrollment Secret
separately if it remains. The identity Secret is deliberately retained by the
chart; revoke the agent through the organization-scoped revoke API before
removing retained identity data. Do not delete the namespace if it contains
other Kordex resources.

## Troubleshooting

- **Agent cannot connect:** verify the configured HTTPS DNS name and route from
  the Pod network; the workstation's `127.0.0.1` is never a valid GKE target.
- **TLS failure:** mount the approved private CA or use a certificate chaining
  to a CA trusted by the container. Do not disable verification.
- **Enrollment rejected:** verify cluster ID, actual `kube-system` UID, token
  age (ten-minute expiry), and that it has not already been consumed. Issue a
  new token only when an administrator has confirmed no active identity exists.
- **Nodes missing:** inspect agent readiness, its sanitized cycle outcome, and
  the read-only RBAC rules. A denied Kubernetes list must fail the inventory
  cycle rather than report a partial node set.
- **Inventory stale:** compare cluster `observed_at`, agent heartbeat, and node
  `last_seen_at`; stale records are retained and not treated as current.
- **Dashboard denied:** complete the independent OIDC login and ensure the
  actual Keycloak subject has membership in the selected existing
  organization. Authentication alone grants no organization access.
