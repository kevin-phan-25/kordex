# Kordex Dashboard

The dashboard is the server-rendered Next.js operator interface for fleet visibility and the Phase 4 campaign API. It does not hold Kubernetes credentials and does not connect to cluster APIs. Mutating requests are proxied from same-origin server routes using the current user's short-lived OIDC ID token; the control plane remains the authorization authority.

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
| `KORDEX_SESSION_SECRET` | Random key material used to derive the AES-256-GCM session-cookie key |
| `KORDEX_PRODUCT_NAME` | Configurable product label |

OIDC ID tokens are stored only inside an authenticated encrypted, HTTP-only, secure, same-site cookie. API tokens are never exposed to React client state or browser local storage. The cookie key must be shared across replicas. Organization memberships and roles are checked by the management API on every request. The initial UI selects the first authorized organization; switching among multiple organizations is not implemented yet.

For Kubernetes self-hosting, use `deployments/helm/kordex-dashboard`. Create the referenced secret outside Helm values and inject it using a secret manager or an existing Secret. Terminate TLS at a trusted ingress or load balancer and set `dashboardURL` to that public HTTPS origin. The container has no Kubernetes service-account token, runs as non-root, and uses a read-only root filesystem.

## Current scope

Implemented views: overview and freshness, fleet/site/cluster/node inventory with filters, campaign planning and start review, campaign stages/targets/approvals/controls, signed operation history, and searchable audit records. The campaign planner requires an operator to copy each cluster's exact local policy name, UID, and generation because policy discovery is not in the current management API.

Only validation and stateless worker drain/recovery operations are supported by the backend. The dashboard does not enable OS or kernel updates, reboot execution, storage maintenance, provisioning, notifications, or broad campaign selector creation. Inventory tables page at a maximum of 200 nodes per request; summary totals are computed in PostgreSQL. Counts from a page must not be interpreted as fleet totals.

## Build

```sh
npm ci
npm run typecheck
npm run lint
npm run build
```
