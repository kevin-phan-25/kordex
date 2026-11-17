# GKE node-pool upgrade adapter

Kordex has an opt-in provider-native executor for changing a GKE node pool's Kubernetes version. GKE owns node replacement and its drain implementation; Kordex performs local preflight, authorizes one pool update, tracks the GKE long-running operation, then verifies the pool, replacement nodes, and cluster workloads. The operation is not a host shell, SSH, or COS package update.

This path is implemented but not production-qualified. Use a disposable GKE cluster only. The current pilot cluster must not be targeted until it has been recreated as disposable and the failure drills below have been run.

## Identity and permissions

Run the operator inside GKE with Workload Identity. Give its Kubernetes ServiceAccount a dedicated Google service account and grant that identity only the GKE permissions needed to read node pools, update a node pool, and get/list GKE operations. The update endpoint requires `container.clusters.update`; operation listing requires `container.operations.list`. Do not attach a project editor/owner role or a service-account key. Google's [nodePools.update API](https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters.nodePools/update) requires an explicit node version and image type; Kordex reads and retains the existing image type and etag before updating. The [operations.list API](https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.operations/list) is used only to investigate a lost update response. Operation polling also requires the corresponding `container.operations.get` permission.

For Helm, set:

```yaml
providerUpgrade:
  gkeEnabled: true
  gcpServiceAccount: kordex-gke-upgrader@PROJECT_ID.iam.gserviceaccount.com
```

Then bind that Google service account to the `kordex-operator` Kubernetes ServiceAccount using GKE Workload Identity. The chart adds the `iam.gke.io/gcp-service-account` annotation only when the gate is enabled. For Kustomize, set `gkeUpgradeEnabled: "true"` in `deployments/kustomize/components/operator/settings.yaml`, annotate `kordex-system/kordex-operator` with the same GSA email, and create the corresponding Workload Identity IAM binding. The binary uses the GKE metadata server token endpoint; running it on a workstation with only `kubectl` credentials does not provide Google Cloud identity.

The Google service account must not be reused by the control plane or dashboard. Keep the gate false in environments where the operator should only inventory, validate, or drain.

## Policy and campaign requirements

The policy's `providerUpgrade` must name one exact GKE resource and one explicit, non-floating node version, for example:

```yaml
providerUpgrade:
  schemaVersion: 2
  provider: gke
  resource: projects/PROJECT_ID/locations/us-central1-a/clusters/CLUSTER_NAME/nodePools/POOL_NAME
  targetVersion: 1.36.4-gke.2377000
  maxSurge: 1
  maxUnavailable: 0
  timeout: 2h
```

Use the actual resource location and a version currently accepted by GKE. The first adapter supports only the `SURGE` strategy with `maxSurge: 1` and `maxUnavailable: 0`; both values are part of the signed policy digest. Before mutation, the operator reads the node-pool settings and blocks unless the existing settings exactly match. Kordex does not silently change persistent node-pool configuration as a side effect of an upgrade. GKE applies these limits per zone, so a regional pool may create one surge node in each zone at once. GKE documents these fields as controlling parallelism and simultaneous unavailability; configured PodDisruptionBudgets continue to limit eviction. The operation is still treated as a single cluster-level provider action and requires a dedicated campaign stage/canary. See [GKE UpgradeSettings](https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/UpgradeSettings).

The policy node selector must include every node in the pool. Every pool node must have fresh matching `ProviderID`, topology and `cloud.google.com/gke-nodepool` inventory, pass local node/workload/storage/quorum checks, and be schedulable before the operation starts. Safety remains local and fails closed. The operator publishes its opt-in gate through a 45-second Lease, relayed by the signed agent inventory report. Campaign preview and start block when that capability is absent, stale, or disabled. The local operator still independently rejects the permit if its GKE gate is disabled or the provider client cannot be configured.

Campaign scheduling deduplicates targets to one signed operation per pool. Use staged campaign canaries to qualify one pool at a time before expanding. A pool upgrade can replace every node in that pool, so do not model individual nodes from the same pool as independent canaries.

## Repeatable disposable-cluster success drill

`tests/integration/gke_upgrade_smoke.py` performs a read-only preflight by default. It compares the current `kubectl` context and live pool nodes with the registered cluster UID and fresh hub inventory; verifies the local operator capability, exact policy digest, GKE pool status/settings, and an explicit higher patch target; and checks all pool nodes are healthy and schedulable. It does not create infrastructure. After a successful operation it polls post-upgrade evidence for up to 30 minutes by default (`--verification-timeout-seconds`): GKE's target version, full replacement node membership and kubelet versions, and Deployment/StatefulSet/DaemonSet readiness must all be confirmed. The returned pool node count must match the pre-upgrade count; the operator also waits rather than succeeding if membership has not fully returned. The evidence JSON omits the signed command, authorization, and signature.

Set `KORDEX_API`, `KORDEX_ADMIN_TOKEN`, `KORDEX_ORG_ID`, `KORDEX_CLUSTER_ID`, `KORDEX_GKE_PROJECT`, `KORDEX_GKE_LOCATION`, `KORDEX_GKE_CLUSTER`, `KORDEX_GKE_NODE_POOL`, `KORDEX_GKE_POLICY`, `KORDEX_GKE_TARGET_VERSION`, `KORDEX_GKE_PLAN_DIGEST`, and `KORDEX_GKE_EXPECTED_CONTEXT`. `KORDEX_GKE_EXPECTED_CONTEXT` must be the exact output of `kubectl config current-context`. The script also requires `gcloud` and `kubectl` on `PATH` (or explicit `GCLOUD`/`KUBECTL` paths).

Start with the read-only check and preserve its evidence:

```bash
python3 tests/integration/gke_upgrade_smoke.py --evidence /tmp/kordex-gke-preflight.json
```

To submit the provider operation, explicitly set the exact canonical resource as the disposable-target confirmation, then run:

```bash
export KORDEX_GKE_DISPOSABLE_CONFIRM="projects/$KORDEX_GKE_PROJECT/locations/$KORDEX_GKE_LOCATION/clusters/$KORDEX_GKE_CLUSTER/nodePools/$KORDEX_GKE_NODE_POOL"
python3 tests/integration/gke_upgrade_smoke.py --execute --timeout-seconds 14400 --evidence /tmp/kordex-gke-upgrade.json
```

Execution creates one `UpgradeNodePool` operation through the authenticated Kordex API and waits for its terminal phase. A timeout does not cancel an accepted GKE operation; inspect the operation and cluster before deciding what to do next. Do not reuse this command against a shared pilot or production pool. Local guardrail tests run with `python3 -m unittest discover -s tests/integration -p 'test_gke_upgrade_smoke.py'`.

## Recovery behavior and known limit

The operator persists pool resource, signed plan digest, initial version, target version, submission time, operation name and checkpoint sequence. It does not bind completion to the original Kubernetes Node UID because GKE is expected to replace nodes.

The GKE update endpoint does not accept a Kordex operation ID or documented idempotency key. If the HTTP response is lost, the operator considers only `UPGRADE_NODES` operations whose canonical target path exactly matches the node pool and whose provider start time is between five seconds before the durable intent timestamp and two minutes after it. A single match is adopted; multiple matches or no match after the investigation interval produce `RecoveryRequired`. The operator never issues a second update to resolve an ambiguous submission. This time-window correlation is weaker than a provider-issued idempotency key, so it remains a production qualification blocker. A human must inspect the pool and GKE operation history before resolving `RecoveryRequired`.

Hub cancellation before submission prevents the mutation. After GKE accepts the update, cancellation is a withdrawal of further authorization: the operator continues read-only observation and verification because abandoning an in-flight cloud operation would leave the outcome unknown. It records cancellation and reports it only after the pool and workloads have been verified.

## Qualification checklist

On a disposable cluster and a dedicated node pool, capture evidence for:

1. Successful explicit patch upgrade, replacement-node readiness, workload recovery, and final campaign status.
2. PDB blockage and degraded workload/storage/quorum evidence before submission; confirm no GKE operation was created.
3. Operator restart before submission, after the request leaves the process, while the operation is running, and during replacement-node verification.
4. Hub disconnection before submission and after GKE accepts the operation.
5. Signed cancellation before and after submission.
6. Cloud permission denial, stale etag, unsupported version, GKE operation failure and timeout.
7. Duplicate/stale permit, changed policy generation, wrong pool resource, wrong project/location/cluster, and replacement Node UID.
8. Audit record, operation evidence, retained reservation and an explicit human recovery procedure for each ambiguous outcome.

Until those drills pass, keep the feature disabled for production and do not describe it as production-ready.
