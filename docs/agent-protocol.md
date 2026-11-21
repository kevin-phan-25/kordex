# Cluster registration and inventory protocol (0.2.0)

The identity/inventory protocol remains in use. The agent optionally delivers signed maintenance permits to the local operator and reports operation checkpoints; Kubernetes or cloud mutations are performed only by the local operator. The operator has a separately gated GKE node-pool version action; see [GKE node-pool upgrades](gke-node-pool-upgrades.md). The agent itself cannot patch nodes, evict pods, update packages or reboot. A cluster belongs to one organization, one fleet and one site. Fleet and site foreign keys include organization ID to prevent cross-tenant associations.

## Human identity and authorization

Configure KORDEX_OIDC_ISSUER (HTTPS discovery issuer) and KORDEX_OIDC_AUDIENCE. The default bearer contract validates OIDC ID tokens against issuer, audience, signature, expiry and allowed algorithms. An explicit RFC 9068 access-token mode is available with a separate API audience, OAuth client ID, and required scopes; the API rejects ID tokens in that mode. The dashboard can request access-token scopes and forward that access token while retaining the ID token only for display claims. Subject membership is read from PostgreSQL on every request: viewer permits reads, administrator permits organization-scoped mutations. Organization listing is filtered by membership. There is one configured trusted issuer; changing issuer requires an explicit membership migration to prevent subject collision. OIDC audit actors use an `oidc:` prefix. Machine agents continue to use enrolled Ed25519 signatures, separate from human OIDC credentials.

A generated bootstrap bearer token is accepted only when the service binds loopback or explicitly runs in local-development mode. Production non-loopback binding requires OIDC and disables bootstrap authentication, even if its environment variable exists. PORT is supported for Cloud Run. The service expects TLS termination at a trusted ingress; it does not serve TLS itself. Do not publish an HTTP ingress. Trust neither caller-supplied organization IDs nor forwarded identity headers.

Provision organizations and first administrator memberships through the isolated bootstrap API before exposing the service. Supported membership call: PUT /v1/organizations/{organizationID}/memberships with `subject` (OIDC sub) and `role` (viewer or administrator). Production platform-wide organization provisioning and issuer migration remain an operational bootstrap task. This agent protocol document covers cluster identity and human API authentication; interactive login, browser sessions, and dashboard behavior are documented separately in [dashboard operations](../dashboard/README.md).

## Enrollment

1. An organization administrator creates a site, fleet and cluster registration.
2. POST /v1/organizations/{organizationID}/clusters/{clusterID}/enrollment-tokens issues a cryptographically random 256-bit token valid for ten minutes. Store only its SHA-256 hash. Issuing another token invalidates outstanding tokens. An existing identity must first be explicitly revoked, including after identity expiry.
3. Provision the token into a separate Kubernetes Secret, outside Helm values. Agents generate an Ed25519 keypair and persist it to their identity Secret before sending enrollment.
4. POST /v1/agent/enroll submits clusterId, immutable kube-system namespace UID, token, public key and key possession proof.
5. PostgreSQL atomically consumes the token, binds the immutable cluster UID, installs the public key and records audit. Replay is rejected. Cluster UID replacement requires a new cluster registration.
6. If the enrollment response is lost, the agent probes its persisted key against the identity endpoint. A consumed token cannot create another identity.

Ed25519 application signatures over HTTPS remain the workload identity and authorization model. The agent also has an opt-in mTLS transport mode for a customer-operated endpoint: it verifies an explicitly configured server CA and DNS name and presents a separately provisioned client certificate. mTLS does not replace signatures or authorize a cluster, and the API does not trust proxy-supplied certificate headers. Client transport support is implemented locally; no customer relay, PKI lifecycle, or live mTLS route has been qualified.

When maintenance is enabled, the agent includes the local operator's short-lived capability Lease in the signed policy catalog report. The Lease renews every 15 seconds with a 45-second lifetime. Its `nodeMaintenance` bit reflects the operator's effective drain/recovery RBAC probe; `hostUpgrades` and `gkeNodePoolUpgrade` report their separate executor gates. Missing or stale capability evidence blocks applicable campaign admission, and a false `nodeMaintenance` bit blocks drain and host-package campaigns. These are advisory admission signals and never grant local execution authority. The operator independently checks authorization, policy, executor configuration, and live safety evidence when reconciling each signed operation.

Each reported maintenance policy includes `allowedActions`, the explicit local authorization ceiling: `ValidateOnly`, `DrainAndVerify`, `UpgradePackages`, and/or `UpgradeNodePool`. Empty, duplicate, or unknown values authorize nothing. A plan does not implicitly authorize its matching upgrade action. The management plane checks the same list during campaign planning and immediately before issuing an operation; the operator checks the live CRD policy again before acting. Missing allowlists from older agents remain readable for wire compatibility but cannot authorize operations. Upgrade actions must be paired with their matching local host or provider plan.

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

Limits: 4 MiB per report, 5,000 nodes per cluster, bounded field lengths, paged Kubernetes list calls, 500 records per management list page. Only selected operational fields are collected, not kubeconfigs, workload secrets or arbitrary labels. Cluster capability evidence is separately bounded: admission inventory contains only counts of supported webhook/policy objects (or `unserved`), never object names, URLs, CA bundles or policy bodies. Permission or discovery failures report `Unknown`; these counts do not prove effective policy enforcement. Current snapshots replace missing nodes; historical node inventory is not retained. Metadata changes and identity events are audited; every heartbeat is not written as an audit event.

Connected means a heartbeat within 90 seconds and an unexpired, non-revoked identity. Inventory has a separate observedAt timestamp. A connected agent with stale inventory is not evidence of cluster readiness. Node Ready reflects observed Kubernetes status only and must never authorize maintenance by itself.

The agent uses bounded exponential retry with jitter and context cancellation. In Kubernetes, a pre-created Lease selects one agent leader and the identity Secret uses resource-version compare-and-swap. Local file mode is single-process only and requires an explicit development setting. Its state file must be a regular file inaccessible to group/other users, and its containing directory must not be group/other-writable; symlinked state files/directories are rejected. Stored cluster ID, Kubernetes UID, current key, pending rotation key, and inventory version must form a consistent initialized state; partial state is rejected rather than treated as a new identity. Both stored Ed25519 private keys must encode a public key consistent with their seed, and the pending key must differ from the current key. The opt-in NodeMaintenance CRD inbox and terminal acknowledgements now provide durable maintenance delivery; all execution/safety authority stays in the operator.

## Agent health diagnostics

The agent listens on container port 8081 without creating a Kubernetes Service.
`GET /healthz` is process liveness and remains successful during management
plane outages so Kubernetes does not turn a network interruption into a restart
storm. `GET /readyz` reports the leader state, last successful and failed sync
times, and consecutive cycle failures. Readiness requires leadership and a
successful complete sync within three configured sync intervals; it is false
before first sync, after losing leadership, or after inventory/management
evidence becomes stale. Raw error strings, node names, tokens, and credentials
are never returned. Helm and Kustomize deployments configure startup, liveness,
and readiness probes. Readiness describes agent reporting health only; it is
not node or maintenance authorization evidence.

Upgrade operation reports carry the local or provider checkpoint and its receipt summaries into central campaign history. Every changed checkpoint is appended to the organization hash-chained audit log. The control plane binds checkpoints to the signed operation action and plan digest, rejects checkpoint removal/type changes, and verifies forward-reachable phase movement, stable target identity, monotonic sequence, and immutable previously reported receipt/node identity evidence. Since agent reports are periodic, a report may skip intermediate checkpoint snapshots; accepted phase jumps must remain reachable and any reported boot-ID change must include new reboot or recovery inspection evidence. This central validation complements, but does not replace, the operator's stricter one-transition-at-a-time local checkpoint validation.

## Schema evolution

The migration runner now validates a contiguous checksum-verified history and applies all pending embedded migrations under one advisory-locked transaction. Migrations 1–3 are immutable. This binary requires its complete known schema and rejects unknown future versions. Rolling upgrades need an explicit expand/contract compatibility policy in the next schema release; do not assume old foundation binaries accept migration 2.

## Campaign inventory and withdrawal

Inventory now includes the complete bounded node label set. Old agents without labels cannot satisfy nonempty selectors. Maintenance permits may include campaign ID, stage, plan generation, snapshot digest and attempt. Sync returns controls bound to a specific operation and command digest. The agent persists the cancellation annotation; the operator verifies the hub signature and performs recovery. See campaigns.md for upgrade ordering and cancellation semantics.
