# Agent Helm deployment

Build/publish agent/Dockerfile to your registry first. Register a site, fleet and cluster through the management API, then issue a ten-minute enrollment token.

Create a separate enrollment Secret using your normal secret delivery system. For a local lab, put the token in a mode-0600 file and run:

```sh
kubectl create namespace kordex-system
kubectl -n kordex-system create secret generic kordex-enrollment --from-file=token=/path/to/token-file
helm upgrade --install kordex deployments/helm/kordex-agent \
  --namespace kordex-system \
  --set controlPlaneURL=https://your-management-host \
  --set clusterID=YOUR_REGISTERED_CLUSTER_UUID \
  --set enrollmentSecretName=kordex-enrollment \
  --set image.repository=YOUR_REGISTRY/kordex-agent \
  --set image.tag=0.4.0
```

The URL must use HTTPS. For a private management CA, create a Secret with key ca.crt and set caSecretName. No token or private key belongs in values files or image layers.

The chart keeps the identity Secret on uninstall and leaves existing runtime data outside the rendered manifest on upgrade. Helm must have permission to read that Secret; Historical 0.2.0 Helm release storage may include copied identity data and remains sensitive. 0.3.0 does not render existing private identity data. Never replace the identity Secret or change a release name casually. Explicit identity loss/expiry recovery requires administrator revocation and new enrollment. The spent enrollment Secret can be replaced with an empty token after successful enrollment; keep the named Secret present for the pod volume.

This agent chart never grants node patch or eviction. To enable signed command delivery, install the separate kordex-operator chart and public trust ConfigMap in the same namespace, then set maintenance.enabled=true. That opt-in adds only CRD inbox and named connection-Lease permissions. No host mounts or privileged containers are installed. Pod security is nonroot with a read-only root filesystem, dropped capabilities and a default seccomp profile. NetworkPolicy depends on your API endpoint/DNS/CNI topology and must be supplied by the deployment owner.

Operator installation and safety prerequisites are documented in [maintenance operator](../../docs/maintenance-operator.md). Pass clusterID and hubPublicKeysConfigMap to deployments/helm/kordex-operator. Review/apply generated CRD upgrades explicitly; do not clear retained ledger records or runtime Lease fields during upgrades.

## Self-hosted hub and campaign worker

`kordex-control-plane` packages separate API/scheduler Deployments and a migration hook. Supply `credentialsSecretName` with `databaseURL`, `migrationDatabaseURL`, and `maintenanceSigningKey`; the API/scheduler use the runtime URL and the migration hook uses the migration URL. Use separate least-privilege database roles and verified TLS. The API rate limiter defaults to 20 RPS and burst 600 per authenticated subject per replica. Metrics are loopback-only unless `metrics.enabled=true`; that option creates a ClusterIP and an additive NetworkPolicy. Set `metrics.namespaceSelector` to the trusted scraper namespace labels and validate policy behavior with your cluster CNI. HTTPS ingress and initial organization bootstrap remain deployment responsibilities; see [campaign deployment](../../docs/campaigns.md) and [Phase 6 hardening](../../docs/phase6-hardening.md). The chart does not provision cloud resources.
