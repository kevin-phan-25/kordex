# Kordex Kubernetes deployments with Kustomize

Kustomize is the maintained raw-manifest deployment path for the Kordex agent
and operator. The Helm charts remain supported as an alternative packaging
path, so workload settings must be kept aligned in both paths. Generated
maintenance CRDs are copied into this tree by `make generate`, alongside the
copies used by Helm.

The `hub/` tree is the self-hosted management-plane path. It deploys the API,
scheduler, dashboard, and a separately applied database migration Job. It does
not provision PostgreSQL, OIDC, ingress, certificates, or Secret contents;
those remain site-managed dependencies. The management plane uses internal
service endpoints and does not call cloud APIs at runtime. See
[`docs/air-gapped-deployment.md`](../../docs/air-gapped-deployment.md) for the
offline image-bundle procedure and migration-first install sequence. The hub
install guide is also packaged in offline bundles as
[`docs/kustomize-hub.md`](../../docs/kustomize-hub.md).

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

Host package/reboot execution is disabled by default. Do not enable it on the
GKE validation cluster: its nodes run Container-Optimized OS. For a disposable
Debian/Ubuntu or RHEL-family VM qualification lab only, patch `upgradeEnabled` to `"true"` and set
`upgradeSSHUser`, `upgradeSSHSecret`, and `upgradeKnownHosts` in
`components/operator/settings.yaml` (or an environment-specific settings
patch). Set `upgradeExecutionEnvironmentAllowlist` to comma-separated,
reviewed digest-pinned Kordex EE images; the operator rejects images outside
that list. For offline configuration, set `KORDEX_UPGRADE_IMAGE_PULL_SECRETS` to
comma-separated Secret names before running `scripts/configure-offline-kustomize.sh`;
the helper writes them to `upgradeImagePullSecrets` for Ansible Jobs and checks
that each is a unique DNS label; if unset, Jobs use the workload registry
Secret. Set `KORDEX_REGISTRY_PULL_SECRET` to choose the
Secret referenced by the agent and operator workloads (default:
`kordex-registry`). Create namespace-local registry Secrets in `kordex-system`
before installing or running an upgrade. Create the named SSH Secret with an
`id_ed25519` key and the
named ConfigMap with pinned `known_hosts` entries keyed by Kubernetes node name
before rolling out the operator. Obtain keys through trusted host provisioning
or console access; do not accept unverified key scans. The EE uses each node
name as `HostKeyAlias`, so changing a node IP alone cannot change the trusted
SSH key. The base Role permits the operator to read only the SSH Secret named
`kordex-upgrade-ssh`; if you configure another name, update the Role's
`resourceNames` entry in `components/operator/rbac.yaml` to match.
For the offline helper, optionally set `KORDEX_UPGRADE_SSH_USER`,
`KORDEX_UPGRADE_SSH_SECRET`, and `KORDEX_UPGRADE_KNOWN_HOSTS` together; it
writes these references into the operator settings and scopes the Role to the
chosen SSH Secret. This prepares the executor configuration but keeps
`upgradeEnabled: "false"` unchanged. Create the named Secret and ConfigMap
through the site's trusted secret-management process.
Provide only a dedicated host account with the privileges required by the
fixed Ansible playbook, and verify the Job namespace can reach the VM over SSH.
Keep the gate false until the documented VM failure/recovery drills pass.

For self-managed etcd evidence only, set `etcdEndpoints` in
`components/operator/settings.yaml` and create a Secret named
`kordex-etcd-client` in `kordex-system` with keys `ca.crt`, `tls.crt`, and
`tls.key`. The operator reads membership and status from every configured
member; it does not change etcd state. Label each Node that hosts an etcd
member with `operations.kordex.local/etcd-member-id=<hex-member-id>` only after
verifying the mapping against etcd membership. That label triggers projected
quorum checks even if the Kubernetes control-plane role label is absent.
Without endpoints and TLS material,
control-plane safety checks block. This evidence does not make static-pod
draining or control-plane upgrades supported; separate eligibility gates
continue to block those operations.

For Rook deployments whose manager metrics Service advertises HTTPS, create a
ConfigMap named `kordex-rook-metrics-ca` in `kordex-system` with the private
CA bundle at key `ca.crt`, then set `rookMetricsCAFile` in
`components/operator/settings.yaml` to `/var/run/kordex-rook-metrics/ca.crt`.
The operator verifies the Service DNS name against this CA. An absent or
invalid bundle causes storage evidence to fail closed; there is no insecure
TLS mode. Plain HTTP metrics Services do not need this setting.

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

## Self-managed and air-gapped overlay

This section describes the cluster-side agent/operator. For a self-hosted
central management plane, use the separate [hub Kustomize guide](hub/README.md)
and deploy its migration Job before its API, scheduler, and dashboard.

Use `overlays/self-managed` for on-premises, private data center, and restricted
network clusters. It has no cloud identity or provider API dependency. Its
image names point at a private registry placeholder; edit only the image
`newName` and `newTag` entries for your mirrored release. The source overlay
includes image-pull-secret patches expecting a namespace-local Secret named
`kordex-registry`; the offline helper can select another name with
`KORDEX_REGISTRY_PULL_SECRET`. Remove those two patch entries if the internal
registry is accessible without authentication. Maintenance command delivery is disabled
in this provider-neutral overlay by default. Set `maintenanceEnabled: "true"`
in `agent-settings.patch.yaml` only after reviewing the operator, local trust
keys, and scoped agent RBAC; upgrade execution remains independently disabled
by the operator settings.

For a management endpoint using a private CA, use
`overlays/self-managed-private-ca` and create `kordex-management-ca` in
`kordex-system` with the CA certificate stored as `ca.crt`. The variant mounts
that Secret read-only into the agent and sets `KORDEX_CA_FILE`; the default
self-managed overlay does not require or mount this Secret.

The portable release bundle, image archive verification, private-registry
push helper, and complete disconnected install procedure are documented in
[`air-gapped-deployment.md`](../../docs/air-gapped-deployment.md). That guide
includes both Helm and Kustomize paths. Keep host and provider-native upgrade
gates disabled until their respective qualification evidence is recorded.

## Updating CRDs

Edit the API types under `api/operations`, then run `make generate`. That
updates the controller-gen CRDs in `operator/config/crd`, the Helm CRD copies,
and this Kustomize base. CI checks that all generated copies are current.
