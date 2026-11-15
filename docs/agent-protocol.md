# Cluster registration and inventory protocol (0.2.0)

The identity/inventory protocol remains in use in release 0.4.0. The agent now optionally delivers signed maintenance permits to the local operator; it still cannot patch nodes, evict pods, update packages or reboot. See maintenance-operator.md. Provider (`self-managed`, `gke`, `eks`, `aks`) is inventory metadata, not an implemented cloud-provider integration. A cluster belongs to one organization, one fleet and one site. Fleet and site foreign keys include organization ID to prevent cross-tenant associations.

## Human identity and authorization

Configure KORDEX_OIDC_ISSUER (HTTPS discovery issuer) and KORDEX_OIDC_AUDIENCE. Bearer OIDC ID tokens must pass issuer, audience, signature, expiry and allowed-algorithm verification. Subject membership is read from PostgreSQL on every request: viewer permits reads, administrator permits organization-scoped mutations. Organization listing is filtered by membership. There is one configured trusted issuer; changing issuer requires an explicit membership migration to prevent subject collision. OIDC audit actors use an `oidc:` prefix.

A generated bootstrap bearer token is accepted only when the service binds loopback or explicitly runs in local-development mode. Production non-loopback binding requires OIDC and disables bootstrap authentication, even if its environment variable exists. PORT is supported for Cloud Run. The service expects TLS termination at a trusted ingress; it does not serve TLS itself. Do not publish an HTTP ingress. Trust neither caller-supplied organization IDs nor forwarded identity headers.

Provision organizations and first administrator memberships through the isolated bootstrap API before exposing the service. Supported membership call: PUT /v1/organizations/{organizationID}/memberships with `subject` (OIDC sub) and `role` (viewer or administrator). Production platform-wide organization provisioning and issuer migration remain an operational bootstrap task. This release does not implement interactive login, browser sessions, approval roles or a dashboard.

## Enrollment

1. An organization administrator creates a site, fleet and cluster registration.
2. POST /v1/organizations/{organizationID}/clusters/{clusterID}/enrollment-tokens issues a cryptographically random 256-bit token valid for ten minutes. Store only its SHA-256 hash. Issuing another token invalidates outstanding tokens. An existing identity must first be explicitly revoked, including after identity expiry.
3. Provision the token into a separate Kubernetes Secret, outside Helm values. Agents generate an Ed25519 keypair and persist it to their identity Secret before sending enrollment.
4. POST /v1/agent/enroll submits clusterId, immutable kube-system namespace UID, token, public key and key possession proof.
5. PostgreSQL atomically consumes the token, binds the immutable cluster UID, installs the public key and records audit. Replay is rejected. Cluster UID replacement requires a new cluster registration.
6. If the enrollment response is lost, the agent probes its persisted key against the identity endpoint. A consumed token cannot create another identity.

Ed25519 application signatures over HTTPS are the workload identity model for this release. TLS authenticates the hub and protects enrollment secrecy. Signatures authenticate the agent across TLS-terminating proxies, including a future Cloud Run ingress. This is not an mTLS implementation and does not depend on trusting a proxy-supplied certificate header.

## Signed requests

All agent endpoints except enrollment require:

- X-Kordex-Version: `1`
- X-Kordex-Cluster: registered cluster UUID
- X-Kordex-Key: lowercase hexadecimal SHA-256 of the raw public key
- X-Kordex-Time: Unix seconds
- X-Kordex-Nonce: 24 random bytes encoded as 48 hexadecimal characters
- X-Kordex-Signature: unpadded standard base64 Ed25519 signature

Canonical signed message, with newline separators and no final newline:

```text
kordex.agent.v1
METHOD
ESCAPED_PATH
CLUSTER_ID
KEY_ID
UNIX_SECONDS
NONCE
HEX_SHA256_EXACT_BODY
```

Query strings are rejected. Allowed clock skew is two minutes in either direction. Each accepted authenticated request reserves its nonce transactionally; nonce retention is five minutes, exceeding the complete signature-validity window. The cluster row lock serializes inventory, identity rotation and revocation. Every write rechecks active key and expiry inside its transaction; earlier signature verification alone never authorizes a later write. Consumers must synchronize clocks. Redirects are never followed by the agent.

## Rotation and recovery

Keys expire after 24 hours and rotate when less than twelve hours remain. Before rotation the agent persists a pending private key. Rotation requires a request signed by the old key plus possession proof from the new key. The database updates the key and audit entry atomically. After a lost response or restart, the agent tries its pending key first and promotes it if the server recognizes it. A rejected pending key falls back to the current key. A transport error never triggers destructive identity reset.

Administrator revocation immediately fences later requests, invalidates pending enrollment tokens and updates inventory connectivity. Re-enrollment requires explicit administrator action. An agent offline beyond key expiry requires revocation and fresh enrollment; expiry is not silently bypassed. Protect the identity Secret with Kubernetes encryption at rest, namespace access restrictions and backups. Loss of both identity state and management enrollment acknowledgement requires administrator recovery.

## Inventory and freshness

GET /v1/agent/identity is an authenticated heartbeat. POST /v1/agent/report replaces a full current node snapshot atomically. The agent persists a monotonically increasing int64 report version before sending. Older/equal versions, decreasing observation timestamps, duplicate node identities and observations outside the clock-skew bound are rejected. Snapshot persistence and node replacement share a transaction. An ambiguous report response is safe: the next cycle sends a higher version and a new nonce.

Limits: 4 MiB per report, 5,000 nodes per cluster, bounded field lengths, paged Kubernetes list calls, 500 records per management list page. Only selected operational fields are collected, not kubeconfigs, workload secrets or arbitrary labels. Current snapshots replace missing nodes; historical node inventory is not retained. Metadata changes and identity events are audited; every heartbeat is not written as an audit event.

Connected means a heartbeat within 90 seconds and an unexpired, non-revoked identity. Inventory has a separate observedAt timestamp. A connected agent with stale inventory is not evidence of cluster readiness. Node Ready reflects observed Kubernetes status only and must never authorize maintenance by itself.

The agent uses bounded exponential retry with jitter and context cancellation. In Kubernetes, a pre-created Lease selects one agent leader and the identity Secret uses resource-version compare-and-swap. Local file mode is single-process only and requires an explicit development setting. The opt-in NodeMaintenance CRD inbox and terminal acknowledgements now provide durable maintenance delivery; all execution/safety authority stays in the operator.

## Schema evolution

The migration runner now validates a contiguous checksum-verified history and applies all pending embedded migrations under one advisory-locked transaction. Migrations 1–3 are immutable. This binary requires its complete known schema and rejects unknown future versions. Rolling upgrades need an explicit expand/contract compatibility policy in the next schema release; do not assume old foundation binaries accept migration 2.

## Campaign inventory and withdrawal

Inventory now includes the complete bounded node label set. Old agents without labels cannot satisfy nonempty selectors. Maintenance permits may include campaign ID, stage, plan generation, snapshot digest and attempt. Sync returns controls bound to a specific operation and command digest. The agent persists the cancellation annotation; the operator verifies the hub signature and performs recovery. See campaigns.md for upgrade ordering and cancellation semantics.
