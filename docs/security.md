# Security model

## Foundation controls and limits

The foundation API is an isolated bootstrap administration surface. One environment-supplied bearer secret (minimum 32 characters; generate cryptographically) grants global organization/site administration. Comparison uses constant-time hashes. This is not OIDC, per-user RBAC, workload identity, or tenant authorization. The audit actor is explicitly `bootstrap-admin`; it is not proof of individual attribution. No browser frontend or public deployment is authorized by this design.

Default binding is loopback. Non-loopback binding is refused unless `KORDEX_LOCAL_DEVELOPMENT=true`; this opt-in is for isolated local networks only. Database TLS requires `verify-full` outside that opt-in. The HTTP server has no built-in TLS; any future network deployment requires a trusted TLS terminator and completed production authentication. Local Compose binds exposed ports to loopback and requires generated secrets. Never set the local opt-in in production.

API requests have bounded bodies, strict JSON fields, validated resource IDs, bounded pagination and query deadlines. SQL uses parameters. Mutation and audit persistence share a transaction. Readiness checks database/schema availability; liveness does not depend on PostgreSQL. Logs do not record tokens, DSNs, SQL errors or request payloads. Audit records currently capture successful creates only, not failed authentication, reads, policy changes or export.

Database application-role privilege separation and external tamper-resistant audit export are not implemented. Local development uses the PostgreSQL initialization user. Production requires a migration DDL role and a separate runtime role with only necessary DML, no audit UPDATE/DELETE, plus TLS, backups, encryption and monitored access. A compromised database administrator can alter current audit records.

## Required production model

Use OIDC issuer/JWKS validation with issuer, audience, expiration and algorithm restrictions, key rotation, bounded cache freshness and explicit failure behavior. Map immutable subject IDs into organization memberships and roles: viewer, operator, approver and administrator. Define approval separation of duties. Authorization must apply to every resource and query; caller-supplied organization IDs never confer membership. Test cross-tenant reads/writes and aggregate endpoints. Add PostgreSQL row-level security as defense in depth once verified transaction-scoped identity propagation is designed.

Agents enroll with short-lived one-time enrollment tokens bound to an organization and cluster. Exchange for rotatable mTLS identities; verify chain, expiry, revocation and immutable cluster identity server-side. Never bake secrets into images. Disconnected/expired/revoked identities cannot begin disruptive work. Certificate rotation, root rollover, revocation distribution and offline grace policy are Phase 2 design gates.

Dashboard obtains only management API credentials. It never receives kubeconfigs, node credentials or agent keys. Use secure session cookies, CSRF defenses, restrictive CORS and content policy when UI is built. Secrets come from mounted secret files or Secret Manager using workload identity; environment secrets in local Compose are development convenience only.

Operator and agent service accounts get separate least-privilege RBAC. No wildcard cluster-admin role. Node patches, pod evictions, node reads, specific CRDs/status updates and leader election permissions must be justified individually. Host package/reboot execution requires a reviewed privilege boundary, action allowlist, identity verification and immutable operation ledger. No arbitrary remote shell command API.

CI must scan Go vulnerabilities, containers and dependencies; future workflows need image digest pinning, SBOMs, signing, provenance, secret scanning and least-privilege cloud deployment identities. Air-gapped installation needs signed offline artifacts and documented trust rotation. No GCP resources or credentials are created in Phase 1.
