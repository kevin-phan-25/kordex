# Local Keycloak OIDC

This opt-in local stack adds a persistent Keycloak realm and an OIDC-only API
endpoint while retaining the existing bootstrap API on port 8080. It does not
create a Kordex organization, Keycloak test user, or organization membership.
Do not run `podman-compose down -v`; the PostgreSQL and Keycloak named volumes
contain persistent local state.

## Issuer and network

The fixed issuer is
`https://keycloak.localhost:8443/realms/kordex`. The host resolver treats
`keycloak.localhost` as loopback for the browser and dashboard Node process.
The Compose network gives the same name as a DNS alias for the Keycloak
container, so the OIDC API reaches it directly over the private Podman bridge.
The published Keycloak port binds only to `127.0.0.1` and `::1`; Keycloak's
admin console is therefore local-only. The API remains at `127.0.0.1:8080` in
bootstrap mode; the separate OIDC API is at `127.0.0.1:8081`.

The dashboard callback registered in Keycloak is exactly
`http://127.0.0.1:3000/api/auth/callback`. The client web origin is exactly
`http://127.0.0.1:3000`. The issuer is HTTPS even though the dashboard callback
is HTTP on loopback.

## Keycloak realm and client

The official `quay.io/keycloak/keycloak:26.8.2` image is pinned by digest in
`deployments/local/compose.oidc.yaml`. The import file
`deployments/local/keycloak/kordex-realm.json` defines realm `kordex` and public
client `kordex-dashboard`:

- Authorization Code flow enabled; implicit and direct password grants disabled.
- PKCE challenge method fixed to S256.
- Exact callback and web origin listed above; local post-logout redirect is
  constrained to the dashboard loopback origin.
- Default OIDC scopes include `profile` and `email`; the dashboard requests
  `openid profile email`.
- User self-registration is disabled. No test user is imported.

The Keycloak bootstrap administrator password and TLS material are generated
outside the repository under `${XDG_DATA_HOME:-~/.local/share}/kordex/local-oidc`.
The password file is mode 0600. The persistent Keycloak data is in the dedicated
`kordex-local_keycloak-data` volume. Do not place the password in Git or paste it
into commands or logs.

Initialize the local files and certificates:

```sh
./scripts/local-oidc-init.sh
```

The script creates a local CA plus separate server certificates with these
SANs: `DNS:keycloak.localhost`, `IP:127.0.0.1`, `IP:::1` for Keycloak and
`DNS:postgres` for PostgreSQL. Container-readable key ownership is set through
the rootless Podman user namespace. The CA private key stays on the host and is
not mounted into a container.

Trust only the public CA certificate (`certs/ca.crt`) on the workstation.
For system trust on Fedora, the operator can run
`sudo trust anchor --store ~/.local/share/kordex/local-oidc/certs/ca.crt` and
remove it after the local stack is no longer needed. Alternatively, import that
CA as a website authority in the browser's certificate settings. Do not bypass
certificate errors. The dashboard process also needs
`NODE_EXTRA_CA_CERTS=.../certs/ca.crt`; the OIDC API receives the CA as
`SSL_CERT_FILE` and PostgreSQL's `sslrootcert`.

Start Keycloak and the OIDC API with:

```sh
./scripts/local-oidc-up.sh
```

This command intentionally recreates the existing PostgreSQL container to
enable TLS, but retains `kordex-local_postgres-data`. It causes a brief local
database outage. The existing bootstrap API is not recreated and remains on
port 8080. PostgreSQL accepts both the existing local `sslmode=disable`
connection and the OIDC API's `sslmode=verify-full` connection. The new OIDC API
does not receive `KORDEX_ADMIN_TOKEN` and does not enable bootstrap auth.
The ordinary `compose.yaml` plus `compose.campaigns.yaml` remain the separate
bootstrap configuration.

After the OIDC API is ready, restart the dashboard with the same issuer and the
local CA trust enabled (the session key is generated without printing it):

```sh
cd dashboard
KORDEX_DASHBOARD_URL=http://127.0.0.1:3000 \
KORDEX_API_URL=http://127.0.0.1:8081 \
KORDEX_OIDC_ISSUER=https://keycloak.localhost:8443/realms/kordex \
KORDEX_OIDC_CLIENT_ID=kordex-dashboard \
NODE_EXTRA_CA_CERTS="$HOME/.local/share/kordex/local-oidc/certs/ca.crt" \
KORDEX_SESSION_SECRET="$(openssl rand -hex 32)" \
npm run dev
```

The dashboard remains in ID-token mode; no API access-token scopes are needed.

## Local user provisioning

1. Open `https://keycloak.localhost:8443/admin` after trusting the local CA.
2. Sign in to the master realm with username `kordex-local-admin` and the
   password in the external `keycloak-admin-password` file.
3. Select realm `kordex`, create one enabled user, set the email/profile fields,
   and set a local password. Self-registration is disabled.
4. Have the user sign in through the Kordex dashboard. Keycloak's user UUID is
   the OIDC `sub`; confirm it against the authenticated identity before any
   Kordex membership grant.

Keycloak login authenticates identity only. The existing organization has no
memberships, so an authenticated user remains unauthorized until an operator
explicitly assigns a role. After obtaining the actual organization UUID and
subject, the operator can run:

```sh
python3 scripts/local-oidc-grant-membership.py
```

The helper reads the bootstrap token directly from the ignored local
`deployments/local/.env`, never prints it, and requires the exact confirmation
`GRANT ADMIN <organization-uuid>` before issuing
`PUT /v1/organizations/{org}/memberships` with role `administrator`. It does not
create organizations or enrollment tokens. The helper must be run while the
bootstrap API on port 8080 is still available.

## Verification

`local-oidc-up.sh` verifies the discovered issuer with the local CA and checks
the OIDC API readiness endpoint. Additional read-only checks:

```sh
curl --fail --silent --show-error \
  --cacert "$HOME/.local/share/kordex/local-oidc/certs/ca.crt" \
  https://keycloak.localhost:8443/realms/kordex/.well-known/openid-configuration \
  | jq -e '.issuer == "https://keycloak.localhost:8443/realms/kordex"'
curl --fail --silent --show-error http://127.0.0.1:8081/readyz
```

With a Keycloak user but no Kordex membership, the dashboard must not establish
a session. With an explicitly authorized membership, the dashboard should
redirect to Keycloak and then load organization-scoped API data. The dashboard's
logout clears its Kordex session and requests Kordex token revocation; it does
not currently terminate the Keycloak SSO session, so a later login may reuse
the IdP session.

The OIDC API uses `KORDEX_OIDC_ISSUER` and
`KORDEX_OIDC_AUDIENCE=kordex-dashboard`. Its PostgreSQL connection sets
`sslmode=verify-full` and verifies the `postgres` DNS SAN against the local CA.
The base bootstrap API continues to use the existing local-only
`KORDEX_LOCAL_DEVELOPMENT=true` configuration and its current database
connection. Do not set local-development mode on the OIDC API.
