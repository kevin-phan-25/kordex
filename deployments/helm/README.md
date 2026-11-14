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
  --set image.tag=0.2.0
```

The URL must use HTTPS. For a private management CA, create a Secret with key ca.crt and set caSecretName. No token or private key belongs in values files or image layers.

The chart keeps the identity Secret on uninstall and preserves its data on upgrade using Helm lookup. Helm must have permission to read that Secret; Helm release storage and rendered output must be treated as sensitive. Never replace the identity Secret or change a release name casually. Explicit identity loss/expiry recovery requires administrator revocation and new enrollment. The spent enrollment Secret can be replaced with an empty token after successful enrollment; keep the named Secret present for the pod volume.

No operator, CRDs, maintenance permissions, host mounts or privileged container are installed by this chart. Pod security is nonroot with a read-only root filesystem, dropped capabilities and a default seccomp profile. NetworkPolicy depends on your API endpoint/DNS/CNI topology and must be supplied by the deployment owner.
