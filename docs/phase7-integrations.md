# Phase 7 integrations: initial implementation

Phase 7 is the final numbered roadmap phase, but it is not the final product milestone. It begins integrations; production readiness still requires Phase 6 operational gates, real cluster and VM lifecycle drills, compatibility validation across providers, security review, performance evidence, and ongoing support work. The roadmap has no finite end to integration coverage.

This initial slice lays provider-neutral contracts, pure safety-evidence evaluators for Ceph/Rook and etcd, and an opt-in GCP resource foundation. It deliberately does not wire these evaluators into maintenance execution or perform provider mutations. They are not claims of Ceph, Rook, or etcd support.

## Integration contracts

`integrations/safety` represents each result as Pass, Block, or Unknown and carries observation time and validity. Unknown or expired evidence cannot grant safety. `integrations/lifecycle` defines narrow contracts for storage, quorum, node lifecycle, and package managers. Storage maintenance returns an operation ownership token so future implementations can avoid clearing flags set by another actor. The operator continues to require all existing signed authorization and Kubernetes safety gates.

### Ceph and Rook evidence

The pure evaluator requires fresh `HEALTH_OK`, every expected OSD up and in, no recovery/backfill, and operation ownership for `noout`. It consumes a normalized evidence snapshot; no Ceph CLI, Ceph mgr API, Rook CR, or secret is accessed. Rook compatibility, topology awareness, pool redundancy, device class and failure-domain rules, maintenance flag lifecycle, recovery verification, and real outage drills remain unimplemented.

### etcd quorum evidence

The pure evaluator excludes the target member and verifies the remaining healthy set can still meet majority quorum. It rejects stale, absent, or contradictory membership. It does not connect to etcd, infer Kubernetes control-plane topology, or remove/re-add members. Kubeadm, managed control planes, stacked/separate etcd, learner behavior, TLS, alarms, snapshots, and recovery need explicit provider adapters and real drills.

### OS/package and node lifecycle

Interfaces define plan/apply/verify and preflight/execute/observe operations, but no package manager, reboot backend, Ansible runner, SSH client, or privileged host executor is implemented. Arbitrary shell commands are explicitly out of scope. A future executor needs a signed allowlisted action catalog, host identity binding, durable local journaling, interruption recovery, package rollback/recovery rules, and VM-backed tests before being enabled.

## GCP foundation

`infrastructure/terraform/gcp` optionally creates an Artifact Registry Docker repository and Secret Manager secret containers in an existing dedicated GCP project. It defaults API enablement off and does not create projects, IAM grants, credentials, secret values, Cloud Run, Cloud SQL, Pub/Sub, networking, or billing. It has no remote state backend; one must be provisioned and reviewed before team use. See its README before planning or applying.

Cloud Run is deferred. The current control-plane process bundles API and metrics listeners, while migrations and campaign scheduling are separate processes. A stateless Cloud Run deployment needs a deliberate split, private Cloud SQL connection design, Cloud Run ingress/IAM policy, health/scale behavior, migration orchestration, and organization-specific project approval. This slice does not create cloud resources.

## Observability

Added starter Prometheus scrape annotations, Prometheus Operator alert rules for API 5xx share and p99 latency, and an importable Grafana overview for request rate/errors/latency. These use the Phase 6 private endpoint and are examples, not a packaged monitoring stack or approved SLOs. See [monitoring setup](../deployments/monitoring/README.md). Scheduler queue age, blocked-reason, storage-health, and node-recovery metrics are still missing. Metric labels must not include cluster, node, operation, user, or arbitrary error strings.

## Next integration sequence

1. Add read-only Ceph/Rook and etcd clients with short-lived in-cluster credentials and bounded, cancellable requests.
2. Validate normalized evidence against supported Ceph/Rook/etcd versions and cluster topologies.
3. Wire preflight only, retaining fail-closed behavior, then run failure-injection tests.
4. Implement operation-owned storage maintenance lifecycle and recovery observation, then exercise on disposable clusters.
5. Design a least-privilege host execution boundary and test package/kernel/reboot/recovery on disposable GCE VMs.
6. Provision the dedicated GCP project and Terraform remote state, then add registry workload identity and Secret Manager access without secret payloads in state.
7. Validate Prometheus/Grafana examples against the selected stack and define scheduler/recovery metrics from operational SLO requirements.
8. Evaluate Cloud Run only after the self-hosted deployment path and database connectivity have passed documented operational gates.

See [verification record](phase7-verification.md) for the checks run and evidence that remains outstanding.
