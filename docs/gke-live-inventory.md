# GKE live inventory enrollment

This runbook enrolls a GKE cluster into an existing Kordex organization and
deploys the read-only inventory agent. It does not enable maintenance, upgrades,
drains, or reboots.

## Current qualification state

The agent already uses the in-cluster Kubernetes API, a short-lived enrollment
token, a persisted Ed25519 identity, signed reports, and bounded retry. The API
already provides organization-scoped cluster registration, enrollment,
inventory, and dashboard endpoints. The Helm chart defaults maintenance off and
grants the agent read access to node and cluster capability metadata.

The live deployment is currently blocked: the local API is published only on
`127.0.0.1:8081` (OIDC) and `127.0.0.1:8080` (local bootstrap). A GKE Pod cannot
route to the workstation loopback address. The agent requires an HTTPS URL that
resolves and is reachable from the GKE Pod network. No public endpoint, tunnel,
firewall rule, or VPC change is configured or authorized by this runbook. Do not
deploy the agent until an approved private HTTPS route exists.

## Registration

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

cluster_json=$(curl -fsS -X POST \
  "$KORDEX_REGISTRATION_API_URL/v1/organizations/$KORDEX_ORG_ID/clusters" \
  -H "Authorization: Bearer $KORDEX_REGISTRATION_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --arg name "$KORDEX_CLUSTER_NAME" --arg fleet "$KORDEX_FLEET_ID" --arg site "$KORDEX_SITE_ID" --arg project "$KORDEX_GCP_PROJECT" --arg location "$KORDEX_GKE_LOCATION" '{name:$name,fleetId:$fleet,siteId:$site,provider:"gke",providerMetadata:{gcpProjectId:$project,location:$location}}')")
export KORDEX_CLUSTER_ID=$(jq -er '.id' <<<"$cluster_json")
unset cluster_json
```

Registration is idempotent by organization and cluster name. Repeating the same
identity reuses the same record. A different fleet, site, provider, project, or
location for that name is rejected. The first inventory report binds the
record to the actual `kube-system` namespace UID; the Kubernetes version,
registration time, and latest successful inventory time are recorded
separately. Provider metadata contains no kubeconfig or cloud credential.

## Issue and deliver the one-time enrollment token

Enrollment tokens are single-use and expire after ten minutes. Keep the token
in a mode-0600 temporary file and do not print it. The agent stores its
long-lived signing identity in its pre-created Kubernetes Secret and rotates
that key using the existing agent protocol.

```bash
umask 077
token_file=$(mktemp)
token_response=$(curl -fsS -X POST \
  "$KORDEX_REGISTRATION_API_URL/v1/organizations/$KORDEX_ORG_ID/clusters/$KORDEX_CLUSTER_ID/enrollment-tokens" \
  -H "Authorization: Bearer $KORDEX_REGISTRATION_TOKEN")
jq -er '.token' <<<"$token_response" >"$token_file"
unset token_response
```

The Secret and Helm release below are cluster mutations. Before applying them,
verify the context, confirm the private API route from a Pod network, and review
the rendered resources with `helm template`. The chart grants no cluster-admin
and has `maintenance.enabled=false`.

```bash
kubectl config current-context
kubectl get nodes -o wide
kubectl create namespace kordex-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kordex-system create secret generic kordex-agent-enrollment \
  --from-file=token="$token_file" --dry-run=client -o yaml | kubectl apply -f -
rm -f "$token_file"

helm template kordex-agent deployments/helm/kordex-agent \
  --namespace kordex-system \
  --set-string controlPlaneURL="$KORDEX_CONTROL_PLANE_URL" \
  --set-string clusterID="$KORDEX_CLUSTER_ID" \
  --set-string enrollmentSecretName=kordex-agent-enrollment \
  --set image.requireDigest=true \
  --set-string image.digest="$KORDEX_AGENT_IMAGE_DIGEST" \
  --set maintenance.enabled=false
```

Only after reviewing that output and confirming Pod-to-API connectivity, install
the chart with the same values. Use a versioned image or digest available to the
cluster; do not use `latest`.

```bash
helm upgrade --install kordex-agent deployments/helm/kordex-agent \
  --namespace kordex-system \
  --set-string controlPlaneURL="$KORDEX_CONTROL_PLANE_URL" \
  --set-string clusterID="$KORDEX_CLUSTER_ID" \
  --set-string enrollmentSecretName=kordex-agent-enrollment \
  --set image.requireDigest=true \
  --set-string image.digest="$KORDEX_AGENT_IMAGE_DIGEST" \
  --set maintenance.enabled=false
```

Set `KORDEX_AGENT_IMAGE_DIGEST` to the immutable SHA-256 digest of the agent
image built from the source being qualified. A version tag alone may refer to an
older binary that does not contain these inventory fields. Do not install until
that image is published to a registry reachable over the approved private
network path.

For a private API CA, create a separate namespace Secret containing only
`ca.crt` and pass `--set-string caSecretName=<secret-name>`. Never disable TLS
verification. The agent reports every 30 seconds by default; API inventory and
agent connectivity are considered fresh for 90 seconds.

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

The Helm chart's cluster role lists Nodes, CSI node records, StorageClasses,
admission configuration, and API discovery; a namespaced role reads
`kube-system` DaemonSet names for CNI hints. It does not read Secrets except the
agent's own identity Secret. It does not grant workload mutation. Inventory
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
