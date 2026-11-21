# Local maintenance safety and execution

## Implemented scope

The operator provides ValidateOnly and DrainAndVerify by default, plus two separately gated upgrade paths: fixed Debian/Ubuntu and RHEL-family Ansible EE package/reboot executors and a GKE-native node-pool Kubernetes version adapter. Both upgrade gates default off and remain unqualified; use only disposable VMs or a disposable GKE cluster. The local controller-runtime operator and its three CRDs remain the authority for per-cluster validation, status, safety veto and recovery. The GKE path delegates node replacement to GKE and never runs host package commands on Container-Optimized OS.

ValidateOnly runs the same live safety gates without disruptive side effects. DrainAndVerify is a stateless worker maintenance drill: cordon, evict through the Kubernetes eviction API, verify availability and workload recovery, and uncordon. It deliberately performs no host maintenance between drain and verification. GKE node-pool version upgrades are a separate opt-in action and use the provider executor documented in [GKE node-pool upgrades](gke-node-pool-upgrades.md); they do not run host commands on Container-Optimized OS.

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

The customer owns this signing key and its custody policy. Preserve the public
bundle produced during the original key provisioning in an independently
controlled backup. There is no public API endpoint for retrieving operator
trust. If that public bundle is lost but the original private seed remains
available through the approved secret store, an authorized custodian can derive
the matching public-only bundle without replacing the key:

```sh
go run ./api/cmd/kordex-trust-export \
  -private-file /secure/read-only-source/maintenance.seed \
  -public-file /secure/deployment-config/keys.json
```

The exporter accepts only a regular, non-symlink existing key file with
restricted permissions, refuses to overwrite output, and writes only the
matching public bundle. Run it in a controlled environment with access to the
existing key; do not copy the private seed into the repository, deployment
bundle, or managed cluster. Independently compare the resulting key ID with the
customer's key-provisioning record before distributing it. If the existing key
is unavailable, stop and recover it through the customer's approved backup or
secret-store process; do not run `kordex-keygen` as a substitute.

The opt-in agent polls POST /v1/agent/operations/sync using its existing signed HTTPS identity. It creates an immutable NodeMaintenance before renewing a dedicated hub-connection Lease. The CRD itself is the durable inbox; neither a pod-local memory queue nor an acknowledgement is treated as completion. Duplicate delivery compares the exact envelope. Conflicting reuse is rejected.

The connection Lease is valid for 45 seconds and is renewed with the hub's response timestamp, not the time a delayed response arrives. Every disruptive boundary requires a current permit and a fresh matching cluster Lease. Reconciles have a twenty-second deadline; the operator rechecks cancellation, immutable identity, policy generation, node health, reservation and authorization freshness after preflight reads and immediately before cordon/eviction. Kubernetes cannot atomically snapshot health across all objects; the eviction API remains the authoritative transactional PDB guard. Instant detection of a network partition is impossible: 45 seconds is the explicit maximum evidence-age assumption, and clocks must stay within five seconds. A connection failure never renews permission. Inventory/maintenance polling is fifteen seconds with jitter while enabled.

## Durable state and concurrency

Local phases include Pending, Validating, SafetyChecking, Blocked, Cordoning, Draining, Executing, Rebooting, VerifyingNode, VerifyingWorkloads, Uncordoning, RecoveryRequired, Succeeded, Failed and Cancelled. Upgrade checkpoints separately retain the signed plan digest, host or provider identity, deterministic execution reference, receipts, phase sequence and timestamps. Status writes use resource-version concurrency control. The event history is bounded; approaching its limit stops new disruption and requires recovery rather than discarding history.

The operator and hub validate phase changes against the same transition graph.
Reports cannot start at a mutation or success phase, skip recovery steps, or
move directly from package execution to Cancelled. A blocked operation resumes
from its recorded prior phase. Missing recovery ownership metadata stays in
`RecoveryRequired`; the operator does not publish terminal failure or release
the reservation. If a terminal operation still has its node cordon-owner
annotation, the operator verifies the original node UID and re-enters recovery
with reason `TerminalRecoveryIncomplete`. At the phase-event safety threshold,
the visible reason stabilizes at `AuditCapacityReached`; structured checkpoints
continue to persist without growing the event list. These controls have local
test coverage, not live cluster restart qualification.

Each durable phase event must also have a timestamp no earlier than its prior
event. The shared report validator rejects backwards timestamps while allowing
equal values for coarse clock resolution; the operator clamps an event after a
backwards wall-clock step to the preceding event time. This preserves sequence
and timestamp ordering but does not establish clock accuracy.
On ingestion, the hub applies the protocol's two-minute clock-skew allowance
against PostgreSQL `clock_timestamp()` to phase events and host/provider
checkpoint timestamps; out-of-bound future evidence is rejected. Operators
still need synchronized clocks for useful incident chronology.
The hub also validates every phase transition and terminal success path against
the signed operation action when it ingests a report. Drain and host-upgrade
success require recovery and uncordon; provider-upgrade success requires
verified workload recovery and a terminal provider checkpoint. This is
additional audit consistency validation and cannot establish that the reported
cluster-local work occurred.

A fixed Lease in the dedicated kordex-operations-ledger namespace is the cluster-wide single-operation reservation. It does not expire or get stolen when a process stops. Only the owning operation releases it after verified restoration. Multiple operator replicas use leader election; independent installations share the same slot. Phase 4 adds organization/fleet/site reservations at the hub; this local reservation remains an independent cluster safety boundary. See campaigns.md for shared manual and campaign admission.

When an operation is blocked with `ClusterConcurrencyLimit`, compare the Lease
holder UID with the live operation records:

```sh
kubectl -n kordex-operations-ledger get lease kordex-maintenance-cluster-slot \
  -o jsonpath='{.spec.holderIdentity}{"\n"}'
kubectl get nodemaintenances.operations.kordex.local -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid,PHASE:.status.phase,REASON:.status.reason'
```

If no record has the holder UID, admission reports
`OrphanedClusterReservation`. This is a diagnosis only: do not patch or delete
the Lease to clear the block. Check retained operation receipts and execution
evidence, establish whether any host/provider action has an ambiguous outcome,
and follow the organization's incident response with independent review. This
repository does not automate orphaned-Lease release or qualify a manual release
procedure. A recovery operation that loses its Lease reports
`ReservationLost` and keeps its node cordon. The controller does not reacquire
a transferred reservation or uncordon without current ownership.

An immutable ConfigMap receipt in that same ledger namespace records operation UUID, accepted CR UID and command digest before validation/cancellation proceeds. Receipts have no owner reference and survive request deletion. Recreating a completed or rejected request under a new Kubernetes UID cannot execute it again. Do not garbage-collect receipts or clear the slot to make a blocked operation run; ledger backup/retention and explicit incident recovery are production-hardening work.

The agent attaches a recovery finalizer when it first creates the inbox object. Terminal objects retain that finalizer until the hub has durably acknowledged their event sequence. This prevents deletion from losing an unreported completion/cancellation and causing redelivery. Central status/audit updates are transactional, append only new event sequences, reject changed historical prefixes and reject reopening terminal operations. Agent acknowledgements persist on CR metadata, so restarts do not duplicate audit transitions.

## Side effects and restart behavior

Before cordon, the controller stores the original node state. A JSON patch atomically tests node UID and resource version, writes an operation-owned annotation and cordons. Existing external cordons are never adopted. After an ambiguous response, reconciliation observes ownership before proceeding. Each eviction intent, including pod UID and deployment identity/replica baseline, is persisted first. Evictions carry a UID precondition and use policy/v1 eviction, never pod DELETE. PDB denial stops the operation; no bypass/fallback exists.

Before the next eviction, the operator checks current health and prior workload recovery. New unhealthy or stale evidence blocks progress. Replaced nodes, changed policies and unexpected boot IDs invalidate execution. Debian/Ubuntu or RHEL-family package/reboot execution requires the host-upgrade gate, exact policy pins, an allowlisted EE digest and a verified receipt. GKE pool upgrades require the GKE gate, Workload Identity, an exact provider plan and verified replacement-node/workload evidence. Both paths retain reservations on ambiguous outcomes and are documented as unqualified in [production-upgrade-requirements.md](production-upgrade-requirements.md).

After drain, recovery verifies live node/cluster/storage/quorum evidence and Deployment recovery. Workloads must remain healthy for the captured policy recovery period (at least ten seconds). Uncordon is its own persisted phase. Only the original UID and an operation-owned cordon may be restored; an external later cordon or replacement node is never adopted. A successful drain response is not completion.

Disconnection stops new disruptive steps. Permit expiry, policy changes or accepted request deletion initiate local recovery when a cordon may exist. Recovery can verify and restore an owned cordon offline, but cannot start another eviction. Failed recovery retains the reservation, finalizer and evidence. A missing/replaced node or unexpected reboot requires investigation; capacity is not released on a timer. Once all recovery checks pass, the outcome remains Failed or Cancelled when appropriate, with the original failure reason.

Deleting an accepted NodeMaintenance requests cancellation, not forced undo. It waits for safe recovery and hub acknowledgement. Campaign cancellation is signed; after a package action or provider operation has started, Kordex records withdrawal and continues observing enough evidence to reach a safe outcome. Operators without access to the hub retain unacknowledged terminal records locally until connectivity returns. Forced finalizer removal or receipt/slot deletion defeats these guarantees and is outside automated recovery.

## Installation and upgrades

1. Register the cluster and install the inventory agent using the existing enrollment flow.
2. Generate the hub signing key and configure the management service; distribute only the public trust bundle.
3. Install operator CRDs/chart in the agent's namespace, supplying clusterID and hubPublicKeysConfigMap (keys.json).
4. Create a MaintenancePolicy and label only eligible stateless workers.
5. Upgrade the agent with maintenance.enabled=true. This adds narrowly scoped inbox/connection-Lease permissions; it grants no node mutation or pod-eviction permission to the agent.
6. Submit an organization-scoped POST /v1/organizations/{org}/clusters/{cluster}/operations with operationId, nodeName, nodeUid, action and policy reference. Inspect the corresponding GET list and NodeMaintenance status.

Every MaintenancePolicy must explicitly set `spec.allowedActions`. Empty or invalid lists deny every operation, and configuring an upgrade plan does not by itself permit that upgrade. Keep the list limited to the actions needed by the policy. For an existing installation, quiesce all operation issuance (campaign dispatch and manual operation submission), apply the reviewed CRD schema, populate each policy's intended action list and matching upgrade plans, then upgrade the operator, agent, and hub while issuance remains quiesced. Resume only after the hub has received a fresh catalog with the new field. This ordering keeps an older hub from bypassing the new local check during migration. The host-upgrade gate remains independently default off.

Helm installs CRDs on initial installation but does not safely upgrade stored CRD schemas automatically. Apply reviewed generated CRD updates explicitly before application upgrades. Helm does not manage runtime Lease spec fields. An existing identity Secret is retained without rendering its private data into a new release manifest. Historical 0.2.0 Helm release records may contain copied identity data and remain sensitive. Upgrade inventory-only 0.2.0 deployments before enabling maintenance; do not rename the release or replace its identity Secret casually.

The operator has node patch, read-only health/inventory, pod eviction, local CR/status/finalizer, leader-election and dedicated-ledger permissions. It has no pod delete, Secret read, host mount, privileged container or arbitrary shell permissions. The real-cluster smoke exercises these roles through service-account impersonation. Containers are nonroot/read-only with dropped capabilities. Environment-specific NetworkPolicy, production TLS, database-role separation, encrypted backups and recovery drills remain deployment responsibilities.

## Verification and limits

See maintenance-verification.md and campaign-verification.md for recorded tests. Envtest validates API admission/status semantics; kind validates Kubernetes-side PDBs, eviction, chart RBAC, restart recovery and receipts. Neither kind nor the current unit tests qualify real Debian/RHEL package/kernel/reboot execution, GKE provider replacement, storage compatibility, or fleet-scale operation. Read-only Rook/Ceph and optional etcd evidence adapters exist; storage flag mutation and control-plane maintenance remain unsupported. No production qualification claim is made.
