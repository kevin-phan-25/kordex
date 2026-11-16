# GKE maintenance safety qualification

This procedure qualifies the current drain-and-verify workflow on a disposable
GKE Standard cluster. It does not update packages or kernels, reboot nodes, or
call GKE lifecycle APIs. `ValidateOnly` has no node side effects. Do not use
these steps on production nodes.

The GKE exception is opt-in in a local `MaintenancePolicy`. It recognizes only
the `kube-dns`, `konnectivity-agent`, and their autoscaler Deployments when
their live owner chain and GKE release images match. It also requires the
configured number of healthy replicas on distinct nodes away from the target.
Every workload being evicted still needs exactly one matching PDB with a
positive disruption allowance. Kordex does not synthesize or bypass PDBs.
The exact GKE `kube-proxy` mirror pod is retained and never evicted during this
drain-only workflow.

## Prepare the cluster

Keep the local control plane, GKE-connected agent, and operator running. Build
the updated binaries from the repository root, stop the old operator process,
and start the rebuilt operator with the same GKE kubeconfig, registered
cluster UUID, and public trust bundle.

Update the installed CRDs and wait for the policy schema to be served:

```sh
kubectl apply -k deployments/kustomize/overlays/gke-validation
kubectl wait --for=condition=Established --timeout=120s crd/maintenancepolicies.operations.kordex.local
```

Check for existing PDBs selecting the GKE add-ons before applying the sample.
The operator requires exactly one matching PDB for each evicted pod. The
sample selectors match the GKE pod labels observed in the validation cluster.
Do not apply it if another PDB already selects those pods; review and update
the existing PDB instead.

```sh
kubectl get pdb -n kube-system
kubectl apply -f operator/config/samples/gke-addon-pdbs.yaml
kubectl get pdb -n kube-system
```

With two healthy replicas per Deployment, each sample PDB should report one
allowed disruption. If that is not true, stop and investigate; do not weaken
the PDB.

Apply the opt-in policy and select one worker node for validation:

```sh
kubectl apply -f operator/config/samples/maintenancepolicy-gke.yaml
kubectl label node NODE_NAME operations.kordex.local/maintenance=stateless --overwrite
```

Replace `NODE_NAME` with a worker name from `kubectl get nodes -o wide`. Confirm
the add-on replicas are healthy and placed on distinct nodes before continuing.

## Submit `ValidateOnly`

Use the registered organization and cluster UUIDs, the node's current UID, and
the live policy UID and generation. The helper checks the hub Lease, connected
cluster state, policy opt-in, PDB allowance, existing active operations, and
node label before submitting a fixed `ValidateOnly` request. It never labels
the node, creates PDBs, prints the admin token, or submits `DrainAndVerify`.

After the old operation is terminal, load the local bootstrap token and run
the helper:

```sh
set -a
. deployments/local/.env
set +a
export ORG_ID=733ff86d-5dd0-4ad9-8476-0910f9eac046
export CLUSTER_ID=a67517b0-41fd-442f-a2d1-54e588be1b74
export NODE_NAME=gke-kordex-gke-test-default-pool-f93d8528-0kbz
scripts/gke-validateonly.sh
```

For other clusters, replace the organization, registered cluster, and node
values with their own IDs and node name. See the operation request contract in
[`maintenance-operator.md`](maintenance-operator.md). Do not change the helper
to submit `DrainAndVerify` as part of validation.

Inspect the returned operation and its local `NodeMaintenance` status. A
`Succeeded` result means the live safety checks passed; it does not prove a
drain, reboot, or host maintenance action. A `Blocked` result is a safety
outcome. Preserve its reason and do not bypass it.

After the request reaches a terminal phase, remove the worker opt-in label:

```sh
kubectl label node NODE_NAME operations.kordex.local/maintenance-
```

If this was only a validation exercise and no further drain drill is planned,
remove the sample PDBs after the operation is terminal:

```sh
kubectl delete -f operator/config/samples/gke-addon-pdbs.yaml
```

Keep the PDBs in place if you are continuing to a separately reviewed,
supervised `DrainAndVerify` drill. This release still does not execute host
updates or reboot nodes.
