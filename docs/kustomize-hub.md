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
   `KORDEX_HUB_OIDC_AUDIENCE` when it differs from the client ID. If using a
   manually maintained tree, edit both `hub/base/settings.yaml` and
   `hub/overlays/self-hosted-migration/settings.yaml` identically. The issuer
   and its
   discovery/JWKS endpoints must be reachable from the API and dashboard over
   the site's trusted network. Set the dashboard URL to its external HTTPS
   origin and retain the internal API service URL unless the topology requires
   a reviewed alternative.
3. Create `kordex-hub-credentials` in `kordex-management` through the site's
   secret manager. It must contain `databaseURL`, `migrationDatabaseURL`, and
   `maintenanceSigningKey`. The runtime database role must not have schema
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
6. Provision a site-managed Ingress or Gateway with a trusted HTTPS certificate
   for the dashboard. Route browser traffic to the dashboard only; dashboard
   server routes call the internal API using `KORDEX_API_URL`. Keep the API
   Service private unless a separate, reviewed deployment design requires
   direct API access. Both Services are ClusterIP and are not exposed directly
   by these manifests.

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

Before each release upgrade, back up PostgreSQL and review the release
migration notes. Kubernetes Jobs are immutable: delete the completed migration
Job, apply the updated migration overlay, wait for it to complete, then apply
the updated workload overlay. Do not delete or recreate the database as part
of this process.

Render and inspect both overlays before applying them in a production site:

```sh
kubectl kustomize ./hub/overlays/self-hosted-migration > /tmp/kordex-migrate.yaml
kubectl kustomize ./hub/overlays/self-hosted > /tmp/kordex-hub.yaml
kubectl diff -f /tmp/kordex-migrate.yaml
kubectl diff -f /tmp/kordex-hub.yaml
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
