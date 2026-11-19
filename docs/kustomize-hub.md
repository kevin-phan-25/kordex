# Self-hosted Kordex management plane

This Kustomize path installs the stateless Kordex API, scheduler, and dashboard
inside a site-managed Kubernetes cluster. It is provider-neutral and has no
runtime dependency on Google, AWS, Azure, or a public container registry. The
site supplies PostgreSQL, an OIDC provider, HTTPS ingress/TLS, DNS, and secret
management. The cluster agents connect outbound to the hub.

## Required site configuration

Copy this tree into a deployment-specific configuration repository or work
directory. Do not commit secret values.

1. Mirror and digest-pin the release images using the signed bundle procedure
   in `air-gapped-deployment.md`; configure the copied `self-hosted` and
   `self-hosted-migration` overlays with the offline helper.
2. Configure the hub OIDC issuer, client ID, audience, and dashboard URL. The
   offline helper can write them consistently into both the hub and migration
   settings copies when `KORDEX_HUB_OIDC_ISSUER`,
   `KORDEX_HUB_OIDC_CLIENT_ID`, and `KORDEX_HUB_DASHBOARD_URL` are set; set
   `KORDEX_HUB_OIDC_AUDIENCE` for an API-specific audience in access-token
   mode. ID-token mode requires the audience to match the client ID. If using a
   manually maintained tree, edit both `hub/base/settings.yaml` and
   `hub/overlays/self-hosted-migration/settings.yaml` identically. The issuer
   and its
   discovery/JWKS endpoints must be reachable from the API and dashboard over
   the site's trusted network. Set the dashboard URL to its external HTTPS
   origin. The offline helper sets `apiURL` from its positional hub HTTPS
   origin. If maintaining manifests manually, set `apiURL` in both settings
   copies to the HTTPS origin reachable by enrolled agents; it may be routed
   through a private Ingress or Gateway.
   The default token mode is `id_token`, where the API audience must equal the
   dashboard client ID. For RFC 9068 JWT access tokens, set
   `KORDEX_HUB_OIDC_TOKEN_MODE=access_token`, use a distinct API audience,
   `KORDEX_HUB_OIDC_ACCESS_CLIENT_ID` equal to the dashboard client ID, and
   `KORDEX_HUB_OIDC_ACCESS_REQUIRED_SCOPES`. The helper writes matching API and
   dashboard settings to both ConfigMaps. The provider must issue `typ=at+jwt`
   with the requested scopes; otherwise login/API requests fail closed.
3. Create `kordex-hub-credentials` in `kordex-management` through the site's
   secret manager. It must contain `databaseURL`, `migrationDatabaseURL`,
   `maintenanceSigningKey`, and a dedicated Ed25519 `auditSigningKey` for the
   API's signed audit download. Generate that key separately from the
   maintenance signing key and distribute its public trust bundle independently.
   The runtime database role must not have schema
   migration privileges; the migration role should have only the privileges
   required by the versioned migrations. The signing key must match the
   separately distributed public trust keys configured in each cluster.
4. Create `kordex-dashboard-identity` in `kordex-management` with key
   `session-secret`, containing at least 32 cryptographically random bytes.
   Keep it stable across dashboard restarts and replicas.
5. If the private registry requires authentication, create the configured
   image pull Secret (`kordex-registry` by default) in `kordex-management`.
   Configure trust for the private registry CA on every Kubernetes node.
   If the registry is unauthenticated, remove the `imagePullSecrets` entries
   from the three hub Deployments and migration Job in the deployment copy.
6. Provision a site-managed Ingress or Gateway with trusted HTTPS certificates
   for the dashboard and the API endpoint reachable by enrolled agents. Route
   browser requests to the dashboard and agent HTTPS requests to the API host.
   Both Services remain ClusterIP; only the selected Ingress/Gateway exposes
   the configured hosts. Keep that path private where the agent network allows.

For internal OIDC or PostgreSQL endpoints signed by a private CA, create
`kordex-management-ca` in `kordex-management` with the trusted PEM bundle under
key `ca.crt`. The bundle can contain the internal roots required by both
services. Since the Go `SSL_CERT_FILE` setting replaces Go's default root
bundle, include every public or internal root that the API, scheduler, and
migration process need to trust. Node's `NODE_EXTRA_CA_CERTS` adds the same
bundle to Node's default roots. Use `sslmode=verify-full` and
`sslrootcert=/var/run/kordex/ca/ca.crt` in the database URL when PostgreSQL
uses that CA. Render `hub/overlays/self-hosted-private-ca` and
`hub/overlays/self-hosted-migration-private-ca` instead of the default
overlays; they mount the CA read-only and configure Go and Node.js certificate
trust. The Secret contains public trust anchors, not a private key, and must
still be provisioned outside the release bundle.

The manifests intentionally contain no Kubernetes Secret payloads. Do not
replace this with committed base64 data. Use the organization's secret
operator, external secret integration, or a controlled pre-install process.

## Install and upgrade

Run the following commands from the root of the configured Kustomize tree. For
an offline helper output, this is the output directory; the hub manifests live
under its `hub/` subdirectory. First create the namespace and provision the
Secrets listed above. Then apply the migration Job and wait for it to complete
before starting API replicas. This avoids serving requests against an old
schema:

```sh
kubectl apply -f ./hub/overlays/self-hosted-migration/namespace.yaml
kubectl apply -k ./hub/overlays/self-hosted-migration
kubectl wait -n kordex-management --for=condition=complete job/kordex-migrate --timeout=10m
kubectl apply -k ./hub/overlays/self-hosted
kubectl rollout status -n kordex-management deployment/kordex-api --timeout=5m
kubectl rollout status -n kordex-management deployment/kordex-scheduler --timeout=5m
kubectl rollout status -n kordex-management deployment/kordex-dashboard --timeout=5m
```

The API, scheduler, and dashboard each run two replicas, with a
`minAvailable: 1` PodDisruptionBudget and preferred anti-affinity across node
hostnames. Keep at least two schedulable nodes if voluntary node maintenance
must preserve one replica of each component. The budgets constrain voluntary
evictions; they do not provide database failover, application-level health, or
a measured availability target.

The scheduler exposes `/healthz` and `/readyz` on pod port 8081. Readiness
requires a successful database-backed tick within 15 seconds; liveness only
reports that the process is serving probes. Startup, readiness, and liveness
probes are configured for the API, scheduler, and dashboard Deployments.

The default hub overlay does not create Ingress resources. For opt-in HTTPS
routing, edit `overlays/self-hosted-ingress/ingress-settings.yaml` with the
API host, dashboard host, installed IngressClass, and names of pre-created API
and dashboard TLS Secrets in `kordex-management`, then apply:

```sh
kubectl apply -k ./hub/overlays/self-hosted-ingress
```

The overlay routes each host to its matching API or dashboard Service and does
not create the IngressClass, TLS Secrets, certificates, or controller.
Configure HTTP redirect behavior on the selected controller. After securely
transferring the certificates and private keys to the deployment
administrator's workstation, create the referenced Secrets with:

```sh
kubectl -n kordex-management create secret tls kordex-api-tls \
  --cert=/secure/path/api-fullchain.pem \
  --key=/secure/path/api-private-key.pem
kubectl -n kordex-management create secret tls kordex-dashboard-tls \
  --cert=/secure/path/dashboard-fullchain.pem \
  --key=/secure/path/dashboard-private-key.pem
```

Keep the key out of source control and shell history, and set the actual
hostnames in the ingress settings; the overlay routes those names and sets the
dashboard's `apiURL` and `dashboardURL` to the matching HTTPS origins.

The `self-hosted-ingress` overlay includes ingress-only NetworkPolicies that
allow the API and dashboard ports from pods labeled
`app.kubernetes.io/component=controller` in the `ingress-nginx` namespace.
Edit `overlays/self-hosted-ingress/network-policy.yaml` to match the actual
Ingress controller namespace and pod labels before applying it. These ingress
policies do not restrict egress.

For an in-cluster PostgreSQL and OIDC deployment, the opt-in
`self-hosted-restricted-egress` overlay combines the ingress overlay with
component-scoped egress policies for the API, scheduler, migration Job, and
dashboard. Its peer selectors require both the PostgreSQL and OIDC namespaces
and pods to carry `kordex.io/egress-role=postgres` or
`kordex.io/egress-role=oidc`. The dashboard policy allows HTTPS to the sample
ingress-nginx controller because its configured API URL uses that HTTPS
ingress, when traffic routes to those pods inside the cluster. If the public API
hostname resolves to an external load balancer, add its exact CNI-visible
destination CIDR or use a private DNS route. Adapt selectors and allowed ports
to the actual services. External
database/identity endpoints require narrowly reviewed destination CIDRs or an
egress gateway; NodeLocal DNS requires a cluster-specific rule. The overlay
does not restrict the agent or operator.

NetworkPolicies are additive. Remove or narrow any other policy that grants
broader egress, and verify the selected CNI enforces these rules. For the
restricted overlay, apply the egress policies before the separate migration
Job so that the Job starts with its intended egress boundary, then apply the
restricted overlay after the migration completes.

The restricted-overlay installation sequence is:

```sh
kubectl apply -f ./hub/overlays/self-hosted-migration/namespace.yaml
# Provision required Secrets and the documented peer labels first.
kubectl apply -f ./hub/overlays/self-hosted-restricted-egress/network-policy-egress.yaml
kubectl apply -k ./hub/overlays/self-hosted-migration
kubectl wait -n kordex-management --for=condition=complete job/kordex-migrate --timeout=10m
kubectl apply -k ./hub/overlays/self-hosted-restricted-egress
kubectl rollout status -n kordex-management deployment/kordex-api --timeout=5m
kubectl rollout status -n kordex-management deployment/kordex-scheduler --timeout=5m
kubectl rollout status -n kordex-management deployment/kordex-dashboard --timeout=5m
```

Use the restricted overlay instead of applying `self-hosted` or
`self-hosted-ingress` as the workload install; it includes both HTTPS ingress
and egress policies. The default `self-hosted` overlay includes neither ingress
nor egress NetworkPolicies.

Before each release upgrade, back up PostgreSQL and review the release
migration notes. Kubernetes Jobs are immutable: delete the completed migration
Job, apply the updated migration overlay, wait for it to complete, then apply
the updated workload overlay. Do not delete or recreate the database as part
of this process.

Render and inspect both overlays before applying them in a production site:

```sh
kubectl kustomize ./hub/overlays/self-hosted-migration > /tmp/kordex-migrate.yaml
kubectl kustomize ./hub/overlays/self-hosted > /tmp/kordex-hub.yaml
kubectl kustomize ./hub/overlays/self-hosted-restricted-egress > /tmp/kordex-hub-restricted.yaml
kubectl diff -f /tmp/kordex-migrate.yaml
kubectl diff -f /tmp/kordex-hub.yaml
kubectl diff -f /tmp/kordex-hub-restricted.yaml
```

For an offline release, run the configuration helper from the verified bundle
as described in `air-gapped-deployment.md`. It verifies the signed bundle
and image lock, rewrites hub images to private registry digests, and configures
the registry pull Secret name. It does not create database, OIDC, TLS, or
identity credentials. Keep the hub's image digests aligned with the same
release bundle used for spoke agents and operators.

## Operational boundaries

* PostgreSQL HA, backup, restore, TLS, and network policy are site-managed.
* OIDC must be available inside the restricted network; the platform does not
  require a public identity service but does require the configured issuer.
* Agents require outbound TLS to the configured hub. The hub does not connect
  inbound to Kubernetes API servers.
* Air-gapped host upgrades need internally mirrored, approved OS package
  repositories reachable by the managed hosts. Cloud provider adapters remain
  optional and disabled unless explicitly configured.
* The host-upgrade and provider-native execution gates remain disabled by
  default. Installation and image mirroring do not qualify upgrade safety.
