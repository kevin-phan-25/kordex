# Integration tests

Go database tests live in control-plane/internal/store and exercise immutable migration history, tenant constraints, transactional audit, enrollment contention, nonce replay, key rotation/expiry/revocation, stale inventory and authorization. Set KORDEX_TEST_DATABASE_URL to a disposable PostgreSQL database; tests create persistent test rows.

smoke.py starts the compiled management API, creates organization/site records and verifies graceful restart persistence. Set KORDEX_BINARY and KORDEX_TEST_DATABASE_URL.

registration_smoke.py starts both compiled binaries against a real disposable Kubernetes cluster. Set KORDEX_BINARY, KORDEX_AGENT_BINARY, KORDEX_TEST_DATABASE_URL and KUBECONFIG. It enrolls, reads actual node inventory, restarts without an enrollment token and revokes the identity. Agent local file mode is used; this does not validate an installed Helm pod or production OIDC ingress.

Unit tests exercise signed-request tampering, freshness, UUID rejection, OIDC signature/issuer/audience/expiry, tenant authorization, HEAD read semantics, redirect refusal, Secret compare-and-swap and recovery after lost enrollment/rotation responses. No tests execute node maintenance. Envtest, campaign concurrency, real host package/reboot tests and scale simulation are future work.
