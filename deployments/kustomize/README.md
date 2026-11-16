# Kordex Kubernetes deployments with Kustomize

Kustomize is the maintained raw-manifest deployment path for the Kordex agent
and operator. The Helm charts remain supported as an alternative packaging
path, so workload settings must be kept aligned in both paths. Generated
maintenance CRDs are copied into this tree by `make generate`, alongside the
copies used by Helm.

## GKE validation prerequisites

The current GKE validation workflow runs the control plane, agent, and
operator from the developer workstation. This overlay installs the CRDs and
the namespaces and Leases needed by that workflow; it does not install an
in-cluster agent or operator.

From the repository root, with `kubectl` pointing at the intended test
cluster, run these commands one at a time:

```sh
kubectl apply -k deployments/kustomize/overlays/gke-validation
kubectl wait --for=condition=Established --timeout=120s crd/maintenancepolicies.operations.kordex.local crd/maintenancecampaigns.operations.kordex.local crd/nodemaintenances.operations.kordex.local
kubectl get namespaces kordex-system kordex-operations-ledger
kubectl get leases -n kordex-system
kubectl get leases -n kordex-operations-ledger
```

This setup is suitable for the supervised validation exercises documented in
the repository. It does not make the host-run binaries highly available.

## In-cluster operator overlay

`overlays/gke-operator` installs the operator and the shared base resources.
Before applying it:

1. Push the operator image to Artifact Registry and replace `PROJECT_ID` in
   `overlays/gke-operator/kustomization.yaml` with the GCP project ID.
2. Replace `REPLACE_WITH_REGISTERED_CLUSTER_UUID` in
   `overlays/gke-operator/operator-settings.patch.yaml` with the cluster UUID
   registered in the Kordex control plane.
3. Export the control plane's **public** maintenance verification keys as a
   JSON file named `keys.json` in this overlay directory. The file is ignored
   by Git. Never put a signing private key in this file or commit key material.
4. Apply the base first and wait for the CRDs to become Established, then
   render and apply the operator overlay:

   ```sh
   kubectl apply -k deployments/kustomize/overlays/gke-validation
   kubectl wait --for=condition=Established --timeout=120s crd/maintenancepolicies.operations.kordex.local crd/maintenancecampaigns.operations.kordex.local crd/nodemaintenances.operations.kordex.local
   kubectl apply -k deployments/kustomize/overlays/gke-operator
   kubectl rollout status -n kordex-system deployment/kordex-operator --timeout=180s
   ```

The operator talks to the Kubernetes API and watches the hub-connection Lease;
the operator overlay does not deploy a control plane or expose a Kubernetes
API server to the control plane.

## Full in-cluster agent and operator overlay

`overlays/gke-fleet` is the packaging foundation for both components. It is
not ready to apply until a reachable HTTPS control plane exists. The local
development API at `127.0.0.1` is not reachable from a GKE pod and must not be
used as the agent URL.

Before applying this overlay, push both images to Artifact Registry, replace
`PROJECT_ID` in its `kustomization.yaml`, set the registered cluster UUID and
externally reachable HTTPS URL in `agent-settings.patch.yaml`, set the UUID in
`operator-settings.patch.yaml`, export the same public `keys.json`, and create
the `kordex-enrollment` Secret in the `kordex-system` namespace using the
control plane's enrollment flow. Do not put enrollment tokens, private keys,
or cloud credentials in Kustomize files or Git.

The overlay is an install foundation; it does not provision the central
control plane, database, TLS endpoint, OIDC, or cloud infrastructure. Those
must be configured separately before enrolling a live cluster.

## Updating CRDs

Edit the API types under `api/operations`, then run `make generate`. That
updates the controller-gen CRDs in `operator/config/crd`, the Helm CRD copies,
and this Kustomize base. CI checks that all generated copies are current.
