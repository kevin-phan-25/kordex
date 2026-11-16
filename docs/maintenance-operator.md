# Local maintenance safety and execution — release 0.4.0

## Implemented scope

Phase 3 adds a real controller-runtime operator, three CRDs, manual operation APIs, durable agent delivery, sequenced audit status and an eviction-only execution adapter. It is a constrained maintenance foundation. Operating-system changes, kernel changes, reboots, Ceph/Rook and etcd actions remain disabled because their independent verification/execution integrations are not implemented.

ValidateOnly runs the same live safety gates without disruptive side effects. DrainAndVerify is a stateless worker maintenance drill: cordon, evict through the Kubernetes eviction API, verify availability and workload recovery, and uncordon. It deliberately performs no host maintenance between drain and verification. Provider values such as gke are still inventory metadata; provider-managed lifecycle APIs are not invoked.

Only opted-in workers (`operations.kordex.local/maintenance=stateless`) are eligible. The initial implementation requires two available worker nodes, healthy cluster deployments and pods, fresh kubelet Leases, stable node readiness without pressure, and a healthy API-server readyz response. Other cordoned nodes block new disruption. Policy selectors, policy UID and generation must match the signed authorization. Changes invalidate old authorization; they do not silently weaken safety.

Every evictable target pod must belong to a healthy Deployment through a valid ReplicaSet/controller UID chain and match exactly one current PDB with a positive disruption allowance. Unmanaged pods, mirror pods, unsupported controllers and critical or management workloads block the drill. Valid DaemonSet pods remain running; completed pods are ignored. EmptyDir, hostPath, ephemeral/CSI and PVC-backed target workloads block the built-in storage gate except for the explicitly enabled GKE add-on path below. A local PV placed on the target node, unknown local-PV placement, recognized storage daemon, or labeled storage node requires a storage adapter. Unrelated remote PVs elsewhere in the cluster do not block by themselves. Control-plane nodes always require a quorum adapter and are blocked in this release. These restrictions cannot be bypassed with a force flag.

GKE system add-ons remain blocked by default. A policy may explicitly set `allowGKESystemWorkloads: true` to enable the narrow GKE evaluator for the `kube-dns`, `konnectivity-agent`, and their autoscaler Deployments. The evaluator verifies GKE node identity, the exact kube-system Deployment/ReplicaSet ownership chain, GKE release image registries, healthy current Deployment replicas, and the configured number of ready replicas on distinct nodes other than the target (`gkeSystemWorkloadMinAvailable`, default 1). A matching PDB is still required for every eviction; Kordex never substitutes replica observations for PDB enforcement. The sample PDB manifest adds `minAvailable: 1` for the two observed two-replica GKE Deployments. Existing PDBs remain authoritative, including a zero disruption allowance. Unknown workloads, a single-replica autoscaler on the target, or insufficient peer replicas block. The target node's exact GKE `kube-proxy` static mirror pod is retained and excluded from eviction only after its mirror annotations, Node owner UID, priority, image registry, and host-path names are verified. This exception supports the current drain-and-verify workflow only; it does not authorize reboot or host maintenance. See `operator/config/samples/maintenancepolicy-gke.yaml` and `operator/config/samples/gke-addon-pdbs.yaml`.

## Authorization and delivery

The control plane signs a fifteen-minute permit containing protocol version, organization/cluster UUIDs, immutable kube-system UID, operation UUID, node name/UID, action, policy name/UID/generation, key ID and UTC validity interval. Administrative requests require existing organization authorization and fresh authenticated inventory for the exact target. Operation UUIDs must be canonical lowercase. Same UUID/same request returns the existing operation; changed payload returns 409. One active manual operation per cluster is enforced by a PostgreSQL unique index.

The signing key is an optional runtime secret. Without it, operation creation returns 503 and cannot initiate maintenance. Generate a new key without exposing it in an image or command argument:

```sh
go run ./api/cmd/kordex-keygen -private-file /secure/path/maintenance.seed -public-file /secure/path/keys.json
```

Both paths must be new. The private seed is written as unpadded base64 with mode 0600. Configure KORDEX_MAINTENANCE_SIGNING_KEY_FILE only on the management service. Mount the public keys.json as a ConfigMap into the operator. Never deliver the private signing key to a managed cluster. To rotate signing keys, provision a trust bundle containing the old and new public keys before changing the hub key; retain old trust while operations are outstanding. Recovery of already-disrupted nodes does not require a still-valid permit.

The opt-in agent polls POST /v1/agent/operations/sync using its existing signed HTTPS identity. It creates an immutable NodeMaintenance before renewing a dedicated hub-connection Lease. The CRD itself is the durable inbox; neither a pod-local memory queue nor an acknowledgement is treated as completion. Duplicate delivery compares the exact envelope. Conflicting reuse is rejected.

The connection Lease is valid for 45 seconds and is renewed with the hub's response timestamp, not the time a delayed response arrives. Every disruptive boundary requires a current permit and a fresh matching cluster Lease. Reconciles have a twenty-second deadline; the operator rechecks cancellation, immutable identity, policy generation, node health, reservation and authorization freshness after preflight reads and immediately before cordon/eviction. Kubernetes cannot atomically snapshot health across all objects; the eviction API remains the authoritative transactional PDB guard. Instant detection of a network partition is impossible: 45 seconds is the explicit maximum evidence-age assumption, and clocks must stay within five seconds. A connection failure never renews permission. Inventory/maintenance polling is fifteen seconds with jitter while enabled.

## Durable state and concurrency

Local phases are Pending, Validating, SafetyChecking, Blocked, Cordoning, Draining, VerifyingNode, VerifyingWorkloads, Uncordoning, RecoveryRequired, Succeeded, Failed and Cancelled. Status records observed generation, target identity, original schedulability/boot ID, eviction intents, phase event sequence/timestamps, conditions, recovery-stability checkpoints and the original failure reason. Status writes use resource-version concurrency control. The event history is bounded; approaching its limit stops new disruption and requires recovery rather than discarding history.

A fixed Lease in the dedicated kordex-operations-ledger namespace is the cluster-wide single-operation reservation. It does not expire or get stolen when a process stops. Only the owning operation releases it after verified restoration. Multiple operator replicas use leader election; independent installations share the same slot. Phase 4 adds organization/fleet/site reservations at the hub; this local reservation remains an independent cluster safety boundary. See campaigns.md for shared manual and campaign admission.

An immutable ConfigMap receipt in that same ledger namespace records operation UUID, accepted CR UID and command digest before validation/cancellation proceeds. Receipts have no owner reference and survive request deletion. Recreating a completed or rejected request under a new Kubernetes UID cannot execute it again. Do not garbage-collect receipts or clear the slot to make a blocked operation run; ledger backup/retention and explicit incident recovery are production-hardening work.

The agent attaches a recovery finalizer when it first creates the inbox object. Terminal objects retain that finalizer until the hub has durably acknowledged their event sequence. This prevents deletion from losing an unreported completion/cancellation and causing redelivery. Central status/audit updates are transactional, append only new event sequences, reject changed historical prefixes and reject reopening terminal operations. Agent acknowledgements persist on CR metadata, so restarts do not duplicate audit transitions.

## Side effects and restart behavior

Before cordon, the controller stores the original node state. A JSON patch atomically tests node UID and resource version, writes an operation-owned annotation and cordons. Existing external cordons are never adopted. After an ambiguous response, reconciliation observes ownership before proceeding. Each eviction intent, including pod UID and deployment identity/replica baseline, is persisted first. Evictions carry a UID precondition and use policy/v1 eviction, never pod DELETE. PDB denial stops the operation; no bypass/fallback exists.

Before the next eviction, the operator checks current health and prior workload recovery. New unhealthy or stale evidence blocks progress. Replaced nodes, changed policies and unexpected boot IDs invalidate execution. Package/reboot interfaces are not mocked as success; those actions are rejected at the API/permit boundary.

After drain, recovery verifies live node/cluster/storage/quorum evidence and Deployment recovery. Workloads must remain healthy for the captured policy recovery period (at least ten seconds). Uncordon is its own persisted phase. Only the original UID and an operation-owned cordon may be restored; an external later cordon or replacement node is never adopted. A successful drain response is not completion.

Disconnection stops new disruptive steps. Permit expiry, policy changes or accepted request deletion initiate local recovery when a cordon may exist. Recovery can verify and restore an owned cordon offline, but cannot start another eviction. Failed recovery retains the reservation, finalizer and evidence. A missing/replaced node or unexpected reboot requires investigation; capacity is not released on a timer. Once all recovery checks pass, the outcome remains Failed or Cancelled when appropriate, with the original failure reason.

Deleting an accepted NodeMaintenance requests cancellation, not forced undo. It waits for safe recovery and hub acknowledgement. There is no remote cancellation/campaign API in this phase. Operators without access to the hub retain unacknowledged terminal records locally until connectivity returns. Forced finalizer removal or receipt/slot deletion defeats these guarantees and is outside automated recovery.

## Installation and upgrades

1. Register the cluster and install the inventory agent using the existing enrollment flow.
2. Generate the hub signing key and configure the management service; distribute only the public trust bundle.
3. Install operator CRDs/chart in the agent's namespace, supplying clusterID and hubPublicKeysConfigMap (keys.json).
4. Create a MaintenancePolicy and label only eligible stateless workers.
5. Upgrade the agent with maintenance.enabled=true. This adds narrowly scoped inbox/connection-Lease permissions; it grants no node mutation or pod-eviction permission to the agent.
6. Submit an organization-scoped POST /v1/organizations/{org}/clusters/{cluster}/operations with operationId, nodeName, nodeUid, action and policy reference. Inspect the corresponding GET list and NodeMaintenance status.

Helm installs CRDs on initial installation but does not safely upgrade stored CRD schemas automatically. Apply reviewed generated CRD updates explicitly before application upgrades. Helm does not manage runtime Lease spec fields. An existing identity Secret is retained without rendering its private data into a new release manifest. Historical 0.2.0 Helm release records may contain copied identity data and remain sensitive. Upgrade inventory-only 0.2.0 deployments before enabling maintenance; do not rename the release or replace its identity Secret casually.

The operator has node patch, read-only health/inventory, pod eviction, local CR/status/finalizer, leader-election and dedicated-ledger permissions. It has no pod delete, Secret read, host mount, privileged container or arbitrary shell permissions. The real-cluster smoke exercises these roles through service-account impersonation. Containers are nonroot/read-only with dropped capabilities. Environment-specific NetworkPolicy, production TLS, database-role separation, encrypted backups and recovery drills remain deployment responsibilities.

## Verification and limits

See maintenance-verification.md for actual test results. Envtest validates real API admission/status semantics; kind validates real PDBs, eviction, chart RBAC, restart recovery and replay receipts. Kind cannot validate host kernel changes or physical reboots. No production fleet-scale or storage/quorum safety claim is made by this release.
