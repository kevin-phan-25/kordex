# Security model

## Implemented controls (0.2.0)

The service verifies OIDC issuer, audience, signature, allowed algorithms and token expiry. Organization membership and viewer/administrator roles are read from PostgreSQL on every request. Non-loopback production mode requires OIDC and disables bootstrap authentication. Loopback/explicit isolated local mode accepts a generated global bootstrap token for initial provisioning. No dashboard or browser session layer exists yet.

Agents use per-cluster Ed25519 identity over verified HTTPS, single-use enrollment tokens, persisted replay nonces, 24-hour key expiry, restart-safe rotation and transactional revocation fencing. See agent-protocol.md for exact assumptions, including one configured trusted OIDC issuer and membership migration on issuer changes. No agent or Kubernetes credentials are exposed through inventory endpoints.

The API itself serves HTTP behind a trusted TLS terminator. Database TLS requires verify-full outside local mode. Signed agent requests must arrive through HTTPS ingress; clients reject insecure origins outside explicit loopback tests and never forward identity across redirects. Local Compose binds exposed ports to loopback and requires generated secrets.

Requests have bounded bodies, strict JSON fields, UUID validation, bounded pagination and deadlines. SQL is parameterized. Metadata mutations and identity lifecycle events share transactions with audit writes. Request IDs and safe SQLSTATE/category diagnostics are logged, without raw credentials, SQL errors or bodies. Audit actor attribution distinguishes OIDC from bootstrap administration. Audit covers successful metadata changes and identity lifecycle events; full denied-access audit/export remains pending.

The agent Helm chart has separate resource-limited RBAC, no host mounts or maintenance privileges, nonroot/read-only containers and retained identity storage. Enable Kubernetes Secret encryption at rest and protect Helm release storage, which may include the retained identity Secret. Configure environment-specific NetworkPolicy separately.

Database application-role separation and tamper-resistant audit export are not implemented. Development uses the PostgreSQL initialization role. Production needs separate migration/runtime roles, audit UPDATE/DELETE restrictions, backups, monitored access, encryption and restoration drills. A database administrator can modify current audit records.

## Required production model

Use OIDC issuer/JWKS validation with issuer, audience, expiration and algorithm restrictions, key rotation, bounded cache freshness and explicit failure behavior. Map immutable subject IDs into organization memberships and roles: viewer, operator, approver and administrator. Define approval separation of duties. Authorization must apply to every resource and query; caller-supplied organization IDs never confer membership. Test cross-tenant reads/writes and aggregate endpoints. Add PostgreSQL row-level security as defense in depth once verified transaction-scoped identity propagation is designed.

Agents enroll with short-lived one-time enrollment tokens bound to an organization and cluster. Rotatable signed HTTPS identity is implemented; mTLS is an optional future deployment model. Verify expiry, revocation and immutable cluster identity server-side. Never bake secrets into images. Disconnected/expired/revoked identities cannot begin disruptive work. TLS root rollover and production identity recovery drills remain deployment gates. Agent key rotation and server-side revocation are implemented.

Dashboard obtains only management API credentials. It never receives kubeconfigs, node credentials or agent keys. Use secure session cookies, CSRF defenses, restrictive CORS and content policy when UI is built. Secrets come from mounted secret files or Secret Manager using workload identity; environment secrets in local Compose are development convenience only.

Operator and agent service accounts get separate least-privilege RBAC. No wildcard cluster-admin role. Node patches, pod evictions, node reads, specific CRDs/status updates and leader election permissions must be justified individually. Host package/reboot execution requires a reviewed privilege boundary, action allowlist, identity verification and immutable operation ledger. No arbitrary remote shell command API.

CI must scan Go vulnerabilities, containers and dependencies; future workflows need image digest pinning, SBOMs, signing, provenance, secret scanning and least-privilege cloud deployment identities. Air-gapped installation needs signed offline artifacts and documented trust rotation. No GCP resources or credentials are created in Phase 1.
