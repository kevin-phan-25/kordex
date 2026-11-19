# Kordex Dashboard

The dashboard is the server-rendered Next.js operator interface for fleet visibility and the Phase 4 campaign API. It does not hold Kubernetes credentials and does not connect to cluster APIs. Mutating requests are proxied from same-origin server routes using the current user's configured short-lived OIDC bearer token (ID token by default, or an explicitly configured API access token); the control plane remains the authorization authority.

## Local development

Use Node.js 22.14 or newer. Configure an OIDC issuer that accepts the callback URL, and an isolated management plane with OIDC verification enabled. The callback is `${KORDEX_DASHBOARD_URL}/api/auth/callback`.

```sh
cp .env.example .env.local
openssl rand -hex 32
npm ci
npm run dev
```

Set `KORDEX_DASHBOARD_URL=http://127.0.0.1:3000` for loopback development; the app uses a separate non-secure cookie name only on loopback while `NODE_ENV` is not production. All other hosts and production deployments require HTTPS. Set the generated random value as `KORDEX_SESSION_SECRET`; it must contain at least 32 bytes. Never use the local cookie setting outside an isolated loopback environment.

## Runtime configuration

| Variable | Purpose |
| --- | --- |
| `KORDEX_DASHBOARD_URL` | Public HTTPS origin and exact OIDC redirect URI base |
| `KORDEX_API_URL` | Control plane HTTPS origin |
| `KORDEX_OIDC_ISSUER` | OIDC discovery issuer |
| `KORDEX_OIDC_CLIENT_ID` | Public OIDC client ID; PKCE is enabled |
| `KORDEX_OIDC_API_TOKEN_MODE` | `id_token` by default; set `access_token` when the API accepts RFC 9068 JWT access tokens |
| `KORDEX_OIDC_API_SCOPES` | Required API scopes to request in access-token mode |
| `KORDEX_SESSION_SECRET` | Random key material used to derive the AES-256-GCM session-cookie key |
| `KORDEX_PRODUCT_NAME` | Configurable product label |

OIDC bearer tokens are stored only inside an authenticated encrypted, HTTP-only, secure, same-site cookie. Tokens are never exposed to React client state or browser local storage. The cookie key must be shared across replicas. Organization memberships and roles are checked by the management API on every request. The sidebar lists the signed-in user's authorized organizations; switching revalidates membership with the management API before replacing the encrypted session's active organization and role. The control plane remains the authorization authority.

Under the backward-compatible ID-token mode, the management API audience must
equal `KORDEX_OIDC_CLIENT_ID`. Multi-audience tokens require matching `azp`;
any present authorized party must match. For access-token mode, configure the
API's resource audience and required scopes, then set the dashboard mode and
matching requested scopes. The dashboard stores the API bearer token only
inside its encrypted server-side session cookie and uses the ID token for
profile claims. OIDC listeners do not accept bootstrap tokens or
local-development mode. See
[security configuration and migration](../docs/KORDEX-SECURITY-MODEL.md).

The read-only Driver compatibility page shows the shared API catalog. Unsupported
entries are extension targets, not installed executors. Fleet rows show advisory
Kubernetes distribution/role/pool hints; unknown evidence is not shown as safe.
Roll out the updated hub before agents that send `node.lifecycle`.

For Kubernetes self-hosting, use `deployments/helm/kordex-dashboard`. Create the referenced secret outside Helm values and inject it using a secret manager or an existing Secret. Terminate TLS at a trusted ingress or load balancer and set `dashboardURL` to that public HTTPS origin. The container has no Kubernetes service-account token, runs as non-root, and uses a read-only root filesystem.

## Current scope

Implemented views: overview and freshness, fleet/site/cluster/node inventory with filters, campaign planning and start review, campaign stages/targets/approvals/controls, signed operation history, searchable audit records, bounded audit snapshot export, and an organization concurrency limits editor for administrators. The editor uses revision-checked writes and a separate review/confirmation step; the API remains the authorization and audit authority, while cluster and node concurrency remain fixed at one. Export captures the latest organization event ID as a high-water mark, pages in ascending order through that ID, refuses incomplete or cross-organization results, and downloads one JSON bundle containing NDJSON records and their SHA-256 digest. Each response page is capped at 16 MiB; the full export is capped at 100,000 events and 64 MiB of NDJSON. Use `scripts/export-audit.sh` for larger exports. Verify a downloaded bundle with `kordex-audit-verify -bundle -input export.json -through-id EXTERNALLY_RETAINED_EVENT_ID`; the independent event ID detects a missing tail. Without it, the verifier can only check the bundle's own checkpoint. The digest detects accidental changes but is not a signature or independent immutable checkpoint. Campaign planning discovers each cluster's recently reported local policy catalog and binds the selected policy name, UID, and generation into the plan; missing or stale upgrade policy discovery blocks upgrade planning. The planner loads paginated cluster/site/fleet inventories, can quick-select every currently registered cluster in one or more sites or fleets, expands those choices to explicit cluster IDs, displays the included cluster list, and binds policies per cluster before preview. Campaign creation is limited to 500 clusters by the current policy-binding contract; the UI rejects larger selections instead of silently truncating them.

Campaign drafts expose organization, fleet, site, zone, cluster, node, and site-unavailability concurrency ceilings. The preview, campaign detail, and final start confirmation show the campaign's persisted limits; server admission remains authoritative and organization-wide limits may be stricter.

Campaign detail and operation-history pages refresh every 10 seconds while work is pending, active, retrying, or the campaign is running. Refresh pauses when the browser tab is hidden. Operation history exposes the current block/recovery reason, the latest checkpoint and receipt summaries, and the eight most recent phase transitions so operators can inspect progress without opening cluster credentials or kubectl.

The dashboard supports validation, stateless worker drain/recovery, Debian Ansible package campaigns, and a separately gated GKE node-pool Kubernetes version campaign. The upgrade executors are not production qualified; GKE campaigns require fresh provider plans plus local operator Workload Identity configuration, which the hub cannot yet attest. The dashboard does not enable GKE COS package/kernel updates, storage maintenance, provisioning, notifications, or broad campaign selector authoring. Inventory tables page at a maximum of 200 nodes per request; summary totals are computed in PostgreSQL. Counts from a page must not be interpreted as fleet totals.

## Build

```sh
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```
