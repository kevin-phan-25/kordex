# Integration tests

Go database tests live in control-plane/internal/store and exercise immutable migration history, tenant constraints, transactional audit, enrollment contention, nonce replay, key rotation/expiry/revocation, stale inventory and authorization. Set KORDEX_TEST_DATABASE_URL to a disposable PostgreSQL database; tests create persistent test rows.

smoke.py starts the compiled management API, creates organization/site records and verifies graceful restart persistence. Set KORDEX_BINARY and KORDEX_TEST_DATABASE_URL.

registration_smoke.py starts both compiled binaries against a real disposable Kubernetes cluster. Set KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_TEST_DATABASE_URL and KUBECONFIG. It enrolls, reads actual node inventory, restarts without an enrollment token and revokes the identity. Agent local file mode is used; this does not validate an installed Helm pod or production OIDC ingress.

Unit tests exercise signed-request tampering, freshness, UUID rejection, OIDC signature/issuer/audience/expiry, tenant authorization, HEAD read semantics, redirect refusal, Secret compare-and-swap and recovery after lost enrollment/rotation responses. Contract and guardrail tests do not execute host maintenance. The repository also includes disposable-cluster maintenance smoke tests and a guarded self-managed host-upgrade qualification runner; actual package/reboot execution requires explicit disposable-target confirmation, and no real-VM qualification is implied by the unit tests. Campaign concurrency and scale simulation still require their dedicated integration/scale environments.

maintenance_smoke.py uses a fresh disposable PostgreSQL database and a Kubernetes cluster with at least two ready workers. It starts the control plane, agent and operator, applies the chart RBAC, runs processes with service-account impersonation, proves a zero-disruption PDB blocks before cordon, then verifies eviction, operator restart, recovered workloads, uncordon, idempotent API retry and receipt replay rejection. It uses real CRD-backed identity/inbox state. Required binaries: KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_OPERATOR_BINARY, KORDEX_KEYGEN_BINARY, KUBECTL and HELM; also KORDEX_TEST_DATABASE_URL and KUBECONFIG. It must not run against a shared/production cluster.

Each real-cluster smoke needs its own database: a physical Kubernetes cluster UID cannot be enrolled into multiple registrations within one management database. Envtest assets and CI enforcement are configured separately. Package/kernel/reboot validation requires real VMs and is not performed.

`gke_upgrade_smoke.py` defaults to read-only preflight. Its `--execute` mode submits one signed `UpgradeNodePool` operation and is explicitly guarded by `KORDEX_GKE_DISPOSABLE_CONFIRM` matching the full canonical pool resource. See [the GKE qualification procedure](../../docs/gke-node-pool-upgrades.md). It does not create a cluster or node pool. The local Python guardrail tests require only the standard library and run with `python3 -m unittest discover -s tests/integration -p 'test_gke_upgrade_smoke.py'`.


`self_managed_upgrade_smoke.py` defaults to read-only preflight. Its `--execute` mode submits one signed `UpgradePackages` operation and requires `KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM` to match the exact cluster/node/UID target. It supports clean-upgrade, signed cancellation, and an operator Deployment restart during execution; cases requiring external host/network fault injection are recorded separately with `record_host_upgrade_fault.py`. Run completed evidence through `scripts/verify-host-upgrade-qualification.py` using the reviewed `host_upgrade_failure_matrix.json`. Evidence must be collected independently for Debian and RHEL-family hosts. See [production upgrade requirements](../../docs/production-upgrade-requirements.md) and [air-gapped deployment](../../docs/air-gapped-deployment.md).

`--cancel-on-phase` accepts `Draining`, `Executing`, `Rebooting`, and
`VerifyingWorkloads`. The first and last produce supplemental cases
`cancel-before-apply` and `cancel-during-recovery`; they do not replace cases in
the pinned matrix. A missed trigger or success after a cancellation request
fails the drill. Cancellation intent and the observed phase are persisted
before the API request, so a lost response remains explicitly unknown. Use
read-only observation to inspect that same operation. Retain independent host
journal/workload evidence; the runner does not itself prove absence of host
mutation or replace review of recovery postconditions.


Host execution requires a new `--evidence` path. The runner persists its chosen
operation ID before submission and checkpoints redacted observations while
polling. Existing evidence files are never overwritten by a new invocation.
After observer interruption or a lost submission response, use the saved record:

```sh
python3 tests/integration/self_managed_upgrade_smoke.py \
  --observe-evidence ./qualification/clean-upgrade-debian.json \
  --evidence ./qualification/clean-upgrade-observation.json
```

Observation uses only management API GETs and Kubernetes reads, checks the
saved management/organization/cluster/context and operation request identities,
and does not require fresh executor capability or a schedulable target. It
never submits, cancels, restarts, or resumes a host action. It verifies receipts
for observed success and fencing/reservation for `RecoveryRequired`. Its report
is supplemental and is deliberately rejected as a qualification case record.
If the operation is missing or times out, the outcome remains unknown; inspect
it rather than invoking `--execute` again. Older records without the saved
origin/organization/identity fields require manual inspection.
