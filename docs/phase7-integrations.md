# Phase 7 integrations: initial implementation

Phase 7 is the final numbered roadmap phase, but it is not the final product milestone. It begins integrations; production readiness still requires Phase 6 operational gates, real cluster and VM lifecycle drills, compatibility validation across providers, security review, performance evidence, and ongoing support work. The roadmap has no finite end to integration coverage.

This phase lays provider-neutral contracts, safety-evidence evaluators for Ceph/Rook and etcd, an opt-in GCP resource foundation, and a read-only Rook/Ceph status adapter wired into the local operator. It does not perform storage/provider mutations. A later Phase 9 slice adds a separately gated GKE node-pool version executor; see [GKE node-pool upgrades](gke-node-pool-upgrades.md). This is limited Rook evidence support, not general Ceph/Rook maintenance support.

## Integration contracts

`integrations/safety` represents each result as Pass, Block, or Unknown and carries observation time and validity. Unknown or expired evidence cannot grant safety. `integrations/lifecycle` defines narrow contracts for storage, quorum, node lifecycle, and package managers. Storage maintenance returns an operation ownership token so future implementations can avoid clearing flags set by another actor. The operator continues to require all existing signed authorization and Kubernetes safety gates.

### Ceph and Rook evidence

The operator reads `CephCluster` status, OSD Pods, and the cluster-local Rook manager metrics Service using read-only access. It requires fresh, observed-generation `HEALTH_OK` status and metrics for health, every OSD's `up` and `in` state, noout flags, PG backfill/recovery, and selected degraded PG states. Metric identities must match Rook's configured OSD count and `ceph-osd-id` pod identities; all OSD pods must be Running/Ready, and the target must not host an OSD. A non-OSD worker may pass this Ceph gate when all evidence is present and healthy and the existing local workload/storage checks also pass. Missing CRDs/services/metrics, stale status, unknown counts, mismatched identities, nonzero recovery/degradation, active noout flags, or unready OSD pods block. HTTP metrics remain supported; HTTPS requires a private CA bundle mounted into the operator and configured through `KORDEX_ROOK_METRICS_CA_FILE`, with certificate verification always enabled. The pre-cordon PDB gate now recognizes only Rook's canonical `rook-ceph-osd` budget when `managePodBudgets` is enabled and observed; it defers that one decision so Rook can observe the cordon. The eviction-time PDB gate remains strict, and any overlapping PDB still blocks. This does not enable OSD-host maintenance: target nodes hosting OSDs remain blocked until Rook's post-cordon PDB, noout ownership, timeout, OSD rescheduling, and storage recovery lifecycle are implemented and qualified together. Kordex never changes Ceph flags. Rook documents the manager metrics endpoint and `CephCluster.status`; Ceph defines the distinction between OSD `up` and `in`. See [Rook managed disruption budgets](https://github.com/rook/rook/blob/master/design/ceph/ceph-managed-disruptionbudgets.md), [Rook metrics monitoring](https://www.rook.io/docs/rook/latest-release/Storage-Configuration/Monitoring/ceph-monitoring/), [Rook CephCluster status](https://rook.io/docs/rook/latest/CRDs/specification/), [Ceph OSD metrics and health](https://docs.ceph.com/en/latest/mgr/prometheus/), and [Ceph OSD state](https://docs.ceph.com/en/latest/rados/operations/monitoring-osd-pg/). Required metric-family compatibility, topology variations, and real cluster behavior remain unqualified.

### etcd quorum evidence

The operator now has an optional live read-only etcd adapter for self-managed clusters. Configure HTTPS endpoints and a client TLS Secret containing `ca.crt`, `tls.crt`, and `tls.key`; label a node that hosts an etcd member with `operations.kordex.local/etcd-member-id` containing its hexadecimal member ID. The operator validates unique membership, cluster identity, endpoint-to-member identity, and successful status from every configured member under a short deadline before any maintenance operation. A standard Kubernetes control-plane role label or an explicit etcd member ID label triggers projected quorum checks: the mapped member is removed from the healthy voter count and the original majority must remain, even if the standard role label is absent. Missing endpoints, member identity for a control-plane target, TLS, or status block. It never edits membership or executes etcd commands. Without configuration, control-plane nodes remain blocked by `WorkerOnlyQuorum`.

This is a live quorum gate, not control-plane maintenance support. The current policy still requires explicit stateless-node opt-in and the drain workflow blocks static/mirror pods; managed control planes and real stacked-etcd maintenance remain unsupported. Kubeadm topology, learners, TLS rotation, alarms, snapshots, recovery, and actual control-plane upgrade drills need explicit qualification before enabling such operations.

### OS/package and node lifecycle

The upgrade slice includes a local Kubernetes Job adapter and fixed Debian/Ubuntu and RHEL-family Ansible EE catalog artifacts wired to `NodeMaintenance` behind `KORDEX_ENABLE_HOST_UPGRADES` (off by default). It runs read-only identity preflight, the normal local safety/drain path, exact package apply, optional separate reboot, and receipt plus Kubernetes/workload recovery checks. A GKE native node-pool version executor is separately gated by `KORDEX_ENABLE_GKE_UPGRADES` and uses a pool-scoped durable checkpoint because GKE replaces nodes; it is not production-qualified and has a documented ambiguous-operation correlation limitation. See [GKE node-pool upgrades](gke-node-pool-upgrades.md). Ceph OSD maintenance, EKS/AKS upgrades, and etcd compatibility qualification remain future work. Arbitrary playbook text, shell commands, inventory, tags, and extra-vars from callers remain out of scope.

## GCP foundation

`infrastructure/terraform/gcp` optionally creates an Artifact Registry Docker repository and Secret Manager secret containers in an existing dedicated GCP project. It defaults API enablement off and does not create projects, IAM grants, credentials, secret values, Cloud Run, Cloud SQL, Pub/Sub, networking, or billing. It has no remote state backend; one must be provisioned and reviewed before team use. See its README before planning or applying.

Cloud Run is deferred. The current control-plane process bundles API and metrics listeners, while migrations and campaign scheduling are separate processes. A stateless Cloud Run deployment needs a deliberate split, private Cloud SQL connection design, Cloud Run ingress/IAM policy, health/scale behavior, migration orchestration, and organization-specific project approval. This slice does not create cloud resources.

## Observability

Added starter Prometheus scrape annotations, Prometheus Operator alert rules for API 5xx share and p99 latency, and an importable Grafana overview for request rate/errors/latency. These use the Phase 6 private endpoint and are examples, not a packaged monitoring stack or approved SLOs. Scheduler queue age, blocked-operation reason, reservation, and recovery-duration signals were added as a Phase 8 follow-on; storage-health metrics remain future work. Metric labels must not include cluster, node, operation, user, or arbitrary error strings. See [Phase 8 operational observability](phase8-operational-observability.md) and [monitoring setup](../deployments/monitoring/README.md).

## Next integration sequence

1. Qualify the Rook metric family contract against supported Rook/Ceph releases, including real TLS-enabled endpoints, certificate rotation, and large metrics payloads. Unit tests cover private-CA verification and reject insecure TLS overrides, but do not establish compatibility with deployed Rook releases.
2. Qualify the live etcd membership and quorum adapter against supported self-managed topologies and TLS configurations.
3. Add failure-injection and real-cluster tests for Rook status freshness, generation lag, missing/mismatched OSDs, network/API failure, and recovery while storage degrades.
4. Implement operation-owned storage maintenance lifecycle and recovery observation, then exercise on disposable clusters.
5. Run and document package/reboot/recovery qualification on disposable Ubuntu GCE VMs using the opt-in Ansible EE path.
6. Provision the dedicated GCP project and Terraform remote state, then add registry workload identity and Secret Manager access without secret payloads in state.
7. Validate Prometheus/Grafana examples against the selected stack and define scheduler/recovery metrics from operational SLO requirements.
8. Evaluate Cloud Run only after the self-hosted deployment path and database connectivity have passed documented operational gates.

See [verification record](phase7-verification.md) for the checks run and evidence that remains outstanding.
