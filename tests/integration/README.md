# Integration tests

Go database tests live in control-plane/internal/store and exercise immutable migration history, tenant constraints, transactional audit, enrollment contention, nonce replay, key rotation/expiry/revocation, stale inventory and authorization. Set KORDEX_TEST_DATABASE_URL to a disposable PostgreSQL database; tests create persistent test rows.

smoke.py starts the compiled management API, creates organization/site records and verifies graceful restart persistence. Set KORDEX_BINARY and KORDEX_TEST_DATABASE_URL.

registration_smoke.py starts both compiled binaries against a real disposable Kubernetes cluster. Set KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_TEST_DATABASE_URL and KUBECONFIG. It enrolls, reads actual node inventory, restarts without an enrollment token and revokes the identity. Agent local file mode is used; this does not validate an installed Helm pod or production OIDC ingress.

Unit tests exercise signed-request tampering, freshness, UUID rejection, OIDC signature/issuer/audience/expiry, tenant authorization, HEAD read semantics, redirect refusal, Secret compare-and-swap and recovery after lost enrollment/rotation responses. No tests execute node maintenance. Envtest, campaign concurrency, real host package/reboot tests and scale simulation are future work.

maintenance_smoke.py uses a fresh disposable PostgreSQL database and a Kubernetes cluster with at least two ready workers. It starts the control plane, agent and operator, applies the chart RBAC, runs processes with service-account impersonation, proves a zero-disruption PDB blocks before cordon, then verifies eviction, operator restart, recovered workloads, uncordon, idempotent API retry and receipt replay rejection. It uses real CRD-backed identity/inbox state. Required binaries: KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_OPERATOR_BINARY, KORDEX_KEYGEN_BINARY, KUBECTL and HELM; also KORDEX_TEST_DATABASE_URL and KUBECONFIG. It must not run against a shared/production cluster.

Each real-cluster smoke needs its own database: a physical Kubernetes cluster UID cannot be enrolled into multiple registrations within one management database. Envtest assets and CI enforcement are configured separately. Package/kernel/reboot validation requires real VMs and is not performed.

`gke_upgrade_smoke.py` defaults to read-only preflight. Its `--execute` mode submits one signed `UpgradeNodePool` operation and is explicitly guarded by `KORDEX_GKE_DISPOSABLE_CONFIRM` matching the full canonical pool resource. See [the GKE qualification procedure](../../docs/gke-node-pool-upgrades.md). It does not create a cluster or node pool. The local Python guardrail tests require only the standard library and run with `python3 -m unittest discover -s tests/integration -p 'test_gke_upgrade_smoke.py'`.
