# Agent Helm deployment

For the customer-owned end-to-end installation and recovery rehearsal, see
[`customer-deployment-rehearsal.md`](../../docs/customer-deployment-rehearsal.md).
That procedure is a plan and has not been completed by an independent team.

For offline installation, use the packaged charts and OCI image bundle
described in [`air-gapped-deployment.md`](../../docs/air-gapped-deployment.md).
Every chart accepts `imagePullSecrets`; image repositories and tags can be
overridden to point at a private registry. Charts do not require cloud APIs.
Set the optional `image.digest` to a registry manifest digest to render an
immutable `repository@sha256:...` reference; it takes precedence over `tag`.
For production installs, pass the chart's `values-production.yaml` as well as
the deployment values. That profile makes a digest mandatory and Helm rejects
tag-only or malformed image references. Supply the digest from the reviewed
release artifact for each chart; this profile does not verify OCI signatures,
provenance, or SBOMs. An optional standalone Kyverno policy is documented at
`deployments/policies/kyverno/README.md`; it requires a separately installed
Kyverno controller and is not installed by the charts.

Build/publish agent/Dockerfile to your registry first. Register a site, fleet and cluster through the management API, then issue a ten-minute enrollment token.

Create a separate enrollment Secret using your normal secret delivery system. For a local lab, put the token in a mode-0600 file and run:

```sh
kubectl create namespace kordex-system
kubectl -n kordex-system create secret generic kordex-enrollment --from-file=token=/path/to/token-file
helm upgrade --install kordex deployments/helm/kordex-agent \
  --namespace kordex-system \
  -f deployments/helm/kordex-agent/values-production.yaml \
  --set controlPlaneURL=https://your-management-host \
  --set clusterID=YOUR_REGISTERED_CLUSTER_UUID \
  --set enrollmentSecretName=kordex-enrollment \
  --set image.repository=YOUR_REGISTRY/kordex-agent \
  --set-string image.digest=sha256:REPLACE_WITH_REVIEWED_64_HEX_DIGEST
```

The URL must use HTTPS. For a private management CA, create a Secret with key ca.crt and set caSecretName. No token or private key belongs in values files or image layers.

The chart keeps the identity Secret on uninstall and leaves existing runtime data outside the rendered manifest on upgrade. The Helm deployer needs permission to read that Secret because the chart uses `lookup`; the agent itself has patch-only API access and reads identity through a read-only kubelet projection. Historical 0.2.0 Helm release storage may include copied identity data and remains sensitive. 0.3.0 does not render existing private identity data. Never replace the identity Secret or change a release name casually. Explicit identity loss/expiry recovery requires administrator revocation and new enrollment. The spent enrollment Secret can be replaced with an empty token after successful enrollment; keep the named Secret present for the pod volume.

This agent chart never grants node patch or eviction. To enable signed command delivery, install the separate kordex-operator chart and public trust ConfigMap in the same namespace, then set maintenance.enabled=true. That opt-in adds only CRD inbox and named connection-Lease permissions. No host mounts or privileged containers are installed. Pod security is nonroot with a read-only root filesystem, dropped capabilities and a default seccomp profile. The agent and operator charts each have a default-off `networkPolicy.egress.enabled` policy. When enabled, `networkPolicy.egress.rules` must enumerate every required destination peer and numeric TCP/UDP port; empty rules, all-address CIDRs, empty selectors, and invalid ports are rejected. Include DNS, the cluster API endpoint, the agent's hub endpoint, and for the operator any configured etcd, Rook metrics, or cloud provider endpoints. The operator's ephemeral Ansible Job retains its separate target-IP-and-port-22 policy. NetworkPolicy depends on the API endpoint/DNS/CNI topology and must be validated against the deployment's complete additive policy set.

Operator installation and safety prerequisites are documented in [maintenance operator](../../docs/maintenance-operator.md). Pass clusterID and hubPublicKeysConfigMap to deployments/helm/kordex-operator. Review/apply generated CRD upgrades explicitly; do not clear retained ledger records or runtime Lease fields during upgrades.

## Self-hosted hub and campaign worker

`kordex-control-plane` packages separate API/scheduler Deployments and a migration hook. Supply `credentialsSecretName` with `databaseURL`, `migrationDatabaseURL`, and `maintenanceSigningKey`; the API/scheduler use the runtime URL and the migration hook uses the migration URL. Signed browser audit downloads are disabled by default. Set `auditExport.enabled=true` and add the dedicated Ed25519 seed under `auditExport.secretKey` (default `auditSigningKey`) in the same Secret to enable them; only the API mounts this key. Keep its public trust bundle independent. Use separate least-privilege database roles and verified TLS. The API rate limiter defaults to 20 RPS and burst 600 per authenticated subject per replica. API and scheduler metrics are loopback-only unless `metrics.enabled=true`; that option creates private ClusterIP Services and additive NetworkPolicies. Set `metrics.namespaceSelector` to the trusted scraper namespace labels and validate policy behavior with your cluster CNI. API and scheduler traces export over OTLP/HTTP only when `telemetry.otlpEndpoint` is explicitly set; its default is empty. Keep the collector private and TLS-protected, and allow only its exact peer/port in restricted-egress rules. The chart rejects endpoint credentials, query strings, and fragments. Opt-in TLS Ingress templates are provided for the API and dashboard; the Ingress controller, TLS Secrets/certificates, DNS, redirect behavior, and initial organization bootstrap remain deployment responsibilities. See [campaign deployment](../../docs/campaigns.md), [Kustomize hub](../../docs/kustomize-hub.md), [Phase 6 hardening](../../docs/phase6-hardening.md), and [Phase 8 operational observability](../../docs/phase8-operational-observability.md). The chart does not provision cloud resources.

The API and scheduler in `kordex-control-plane`, and the dashboard in
`kordex-dashboard`, each default to two replicas, a `minAvailable: 1`
PodDisruptionBudget, and preferred anti-affinity across node hostnames. Keep at
least two schedulable nodes if voluntary node maintenance must preserve one
replica of each component. The budgets constrain voluntary evictions; they do
not provide database failover, application-level health checks, or a measured
availability target.

OIDC remains ID-token mode by default. For a provider-issued RFC 9068 JWT
access-token contract, set the control-plane chart's
`oidc.tokenMode=access_token`, API-specific `oidc.audience`, matching
`oidc.accessClientID`, and `oidc.accessRequiredScopes`. Set the dashboard chart's
`oidc.apiTokenMode=access_token` and matching `oidc.apiScopes`. The API audience
must differ from the dashboard client ID. The local render tests reject missing
scopes and identical audience/client IDs; the provider must issue a JWT with
`typ=at+jwt`, a single resource audience, `client_id`, `jti`, and the required
scope claims. Configure both charts consistently. This mode is not enabled by
default and has no real provider qualification.

The scheduler exposes `/healthz` and `/readyz` on pod port 8081. Readiness
requires a successful database-backed tick within 15 seconds; liveness only
reports that the process is serving probes. The chart configures startup,
readiness, and liveness probes for API, scheduler, and dashboard pods.

Both the control-plane and dashboard charts include an opt-in
`ingress.enabled=true` HTTPS Ingress. Set `ingress.host` and
`ingress.tls.secretName`; optionally set `ingress.className` and controller-
specific `ingress.annotations`. The referenced TLS Secret must already exist in
the release namespace. Use separate API and dashboard hosts, and set the
dashboard chart's `apiURL` and `dashboardURL` to those public HTTPS URLs. The
charts do not install an Ingress controller, create certificates, or configure
HTTP-to-HTTPS redirects; those behaviors depend on the selected controller.

Each chart has an opt-in ingress NetworkPolicy at
`networkPolicy.ingress.enabled=true`. Supply nonempty `apiFrom` (control-plane)
or `dashboardFrom` (dashboard) NetworkPolicyPeer rules; the chart rejects empty
selectors and universal CIDRs that would allow all sources. These policies
restrict inbound application ports only and do not replace the separately
configured metrics policies.

The control-plane chart can also restrict API, scheduler, and migration Job
egress with `networkPolicy.egress.enabled=true`; the dashboard chart has the
same setting for its server-side pod. Egress stays unrestricted by default.
When enabled, each chart requires explicit rules with nonempty `to` peers and
numeric TCP or UDP destination ports. The control-plane chart additionally requires
`commonTo` (shared rules such as DNS), `apiTo`, `schedulerTo`, and `migrationTo`.
The dashboard requires `commonTo` and `dashboardTo`. Rules can use namespace and
pod selectors or specific non-universal `ipBlock` CIDRs. They intentionally
cannot express an all-addresses CIDR or all-ports rule.

For example, put a shared DNS rule under `commonTo`, allow API-to-PostgreSQL and
API-to-OIDC HTTPS under `apiTo`, PostgreSQL under `schedulerTo` and
`migrationTo`, and the API plus OIDC HTTPS under the dashboard's `dashboardTo`.
Use actual pod/namespace labels or narrowly scoped destination CIDRs for the
site. Account for NodeLocal DNS, external database and identity endpoint ranges,
metrics scraping, and any configured telemetry/export destinations. Network
policies are additive: another policy selecting the same pod can widen the
effective egress. The CNI must enforce NetworkPolicy; review the complete policy
set and test denied and allowed flows before enabling this restriction.

The agent and operator charts expose the same explicit-peer mechanism for
their individual spoke Deployments. Include the management endpoint for the
agent; include the API, DNS, configured storage/provider endpoints, and any
explicitly configured OTLP collector for the operator. Agent and operator
OTLP export is disabled unless `telemetry.otlpEndpoint` is set on the
respective chart. Both schemas reject embedded endpoint credentials, query
strings, and fragments:

```yaml
networkPolicy:
  egress:
    enabled: true
    rules:
      - to:
          - ipBlock:
              cidr: 10.20.0.10/32 # replace with the actual API endpoint
        ports:
          - {protocol: TCP, port: 6443}
      - to:
          - namespaceSelector:
              matchLabels:
                kubernetes.io/metadata.name: kube-system
            podSelector:
              matchLabels:
                k8s-app: kube-dns
        ports:
          - {protocol: UDP, port: 53}
```

The agent also needs its configured hub URL on TCP 443. The operator needs
only the destinations for configured safety probes and provider APIs; host SSH
is opened for an individual target by the execution Job's narrower policy.
Replace all sample endpoint details with values for the cluster. Some CNIs
handle API-server traffic to host-networked endpoints differently, so verify
both allowed and denied connections before enabling these policies. The spoke
Kustomize overlays do not enable egress isolation; apply reviewed, site-specific
policies there with the same destination and port restrictions.

The Kustomize overlay
`hub/overlays/self-hosted-restricted-egress` combines the sample ingress
configuration with egress rules for in-cluster DNS, PostgreSQL, and OIDC pods.
It expects namespaces and pods to carry the documented
`kordex.io/egress-role=postgres|oidc` labels. Its dashboard rule allows HTTPS
to the sample ingress-nginx pods for in-cluster API routing. If the public API
hostname resolves to an external load balancer, add its exact destination CIDR
or use a private DNS route. Adapt the policy file for external dependencies
and the cluster's DNS layout before applying it. This overlay is a starting
configuration, not live CNI qualification.

For an ingress-nginx controller running as pods in the `ingress-nginx`
namespace, the source rule can be:

```yaml
networkPolicy:
  ingress:
    enabled: true
    apiFrom:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
        podSelector:
          matchLabels:
            app.kubernetes.io/component: controller
```

Use the same rule under `dashboardFrom` in the dashboard chart. Replace the
namespace and pod labels with the actual controller selectors; use a reviewed
`ipBlock` if the controller uses host networking and therefore has no pod
source identity.

The `kordex-operator` chart also keeps metrics on loopback by default. Set its `metrics.enabled=true` and the same trusted namespace selector to expose local recovery signals through a private Service. Operator maintenance spans export over OTLP/HTTP only when `telemetry.otlpEndpoint` is set; the value defaults empty and its schema rejects embedded credentials, query strings, and fragments. Allow only the collector's exact peer and port through any enabled operator egress policy.

For HTTPS Rook manager metrics, create a ConfigMap in the operator namespace
with the private CA bundle under `ca.crt`, then set
`rookMetrics.caConfigMap` to its name. The operator verifies the Service DNS
identity and fails closed if the CA is missing or invalid. Plain HTTP manager
metrics do not need this setting.
