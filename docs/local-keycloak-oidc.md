# Local Keycloak OIDC

This opt-in local stack uses Keycloak for dashboard authentication and a
separate OIDC-only API listener. The existing bootstrap API remains on port
8080 for local setup administration. The OIDC API is on port 8081. Setup never
creates an organization; it only creates/reuses the explicitly named Keycloak
user and grants the explicitly confirmed role in an existing organization.

Do not run `podman-compose down -v`. PostgreSQL and Keycloak use persistent
volumes.

## Prerequisites and endpoints

- Podman and `podman-compose`, Python 3, OpenSSL, curl, jq, and sudo for a
  system trust-store installation.
- Existing local `deployments/local/.env` with the bootstrap API configuration.
- Running Keycloak, PostgreSQL, OIDC API, and dashboard.
- Existing TLS materials under `${KORDEX_LOCAL_OIDC_DIR:-~/.local/share/kordex/local-oidc}`.

The fixed issuer is
`https://keycloak.localhost:8443/realms/kordex`. The same hostname resolves to
loopback for the browser and dashboard process and to Keycloak's Podman network
alias for the API container. Keycloak is published only on `127.0.0.1:8443`
and `[::1]:8443`. The dashboard callback is exactly
`http://127.0.0.1:3000/api/auth/callback`; the public client is
`kordex-dashboard`, authorization-code flow with S256 PKCE, and scopes
`openid profile email`. It has no client secret, password grant, or implicit
flow.

The OIDC API is configured with `KORDEX_OIDC_ISSUER`,
`KORDEX_OIDC_AUDIENCE=kordex-dashboard`, and PostgreSQL `sslmode=verify-full`
with the local CA. Its container does not enable
`KORDEX_LOCAL_DEVELOPMENT` or receive the bootstrap token. The dashboard uses
`KORDEX_API_URL=http://127.0.0.1:8081`, the same issuer and client ID,
`NODE_EXTRA_CA_CERTS` for server-side OIDC discovery, and
`KORDEX_SESSION_SECRET`. Keep ID-token mode. The dashboard encrypts its
HTTP-only session with A256GCM. On the local HTTP loopback URL the cookie is
`SameSite=Lax` and has `Secure=false` so the browser can return it to the HTTP
callback; production URLs must use HTTPS and get `Secure=true`.

## Local CA trust

The CA private key stays on the workstation. The public CA is
`certs/ca.crt`; the Keycloak leaf certificate includes `DNS:keycloak.localhost`
and is chained to that CA. The trust helper validates the CA, chain, hostname,
and validity before installing anything:

```sh
./scripts/local-oidc-trust-ca.sh
```

The helper supports Fedora/RHEL/Rocky/AlmaLinux through p11-kit and Debian/
Ubuntu through `update-ca-certificates`. A system-wide change requires typing
`INSTALL LOCAL OIDC CA SYSTEM-WIDE`; the helper then verifies the issuer over
the normal system TLS path without `--cacert` or verification bypasses.
Cancel at the prompt to make no trust-store change.

This helper does not modify browser settings. Chromium usually uses the system
trust store on Linux, but verify in the browser itself. Firefox may use its own
certificate database; if it rejects Keycloak after system trust succeeds,
manually import only `certs/ca.crt` as a website authority in Firefox's
certificate settings. Never ignore certificate errors. The dashboard Node
process separately needs `NODE_EXTRA_CA_CERTS` set before startup.

For system trust removal, remove only this CA using the distribution's matching
trust mechanism. On Debian/Ubuntu remove
`/usr/local/share/ca-certificates/kordex-local-oidc.crt` and run
`sudo update-ca-certificates`; on p11-kit systems remove the matching
`Kordex Local OIDC CA` anchor using `trust anchor --remove` with that CA file.

## Test-user and membership setup

The admin password is read from the external
`keycloak-admin-password` file created by `scripts/local-oidc-init.sh`; it is
never printed. If the file is absent, the provisioner prompts without echo.
The test user's password is also prompted without echo, only when creating a
new user. Existing usernames must have the requested email. If a matching
account is disabled or lacks profile names, the script requires the exact
`UPDATE USER <username>` confirmation to enable it or fill only missing names;
it never resets a password or overwrites existing profile names. A newly
created user gets the provided email, username-derived first name, and
`Kordex Local` family name.

The provisioner uses the Keycloak Admin REST API over validated HTTPS and
prints only the actual Keycloak user ID returned by the server. With this
realm's default public subject mapping, that ID is the OIDC `sub`; username and
email are never used as a substitute. Keycloak authenticates this identity but
does not grant Kordex permissions.

Run the guided setup after the services are already running:

```sh
./scripts/local-oidc-setup.sh
```

It checks discovery, JWKS, API/dashboard readiness, and PostgreSQL TLS; checks
or installs system CA trust; prompts for the explicit test username and email;
creates or reuses that Keycloak user; then prompts for the existing
organization UUID and role. The role defaults to `viewer`. Administrator
grants require the exact phrase `GRANT ADMIN <organization-uuid>`. The script
does not open a browser. It verifies the final membership through the local
read-only PostgreSQL path after the API write. It never creates an
organization.

The individual steps can also be run separately:

```sh
./scripts/local-oidc-trust-ca.sh
./scripts/local-oidc-provision-user.py --username test-user --email test-user@example.test
./scripts/local-oidc-grant-membership.py --organization <existing-org-uuid> --subject <printed-keycloak-user-id>
```

The grant helper defaults to `viewer`; pass `--role administrator` only when
that privilege is intended. It verifies the organization using the bootstrap
API before writing, requires the exact role-specific confirmation, avoids a
write when the membership already has the requested role, and reads the role
back from PostgreSQL after a change. It reads `KORDEX_ADMIN_TOKEN` internally
from the ignored local `.env`; it never prints or stores the token elsewhere.

## Interactive dashboard login and logout

After setup completes, open `http://127.0.0.1:3000` and choose **Sign in**.
Complete Keycloak login in the browser. The callback checks state, nonce, and
the PKCE verifier through `openid-client`, exchanges the code, and explicitly
enables its JWKS-backed signature (non-repudiation) check plus issuer,
audience, expiry, and nonce validation. The API independently validates the token signature against
Keycloak JWKS, issuer, audience, expiry, and subject before returning
organization membership. The dashboard only creates its encrypted session
after it receives an authorized organization and confirms that the API subject
matches the ID token subject.

Dashboard logout clears the Kordex session and requests API token revocation.
It does not end Keycloak's SSO session; a later login may reuse it. Close the
Keycloak session separately if a fresh identity-provider login is required.

## Troubleshooting

- **Certificate authority invalid / issuer unavailable:** run the trust helper;
  verify `keycloak.crt` chains to `ca.crt` and includes the hostname SAN. Ensure
  dashboard Node was started with `NODE_EXTRA_CA_CERTS` set. Do not disable
  verification.
- **Browser fails but curl works:** the browser may have its own trust store.
  Import only the local CA as a website authority in that browser.
- **Callback returns `signin_failed`:** verify the browser uses the exact
  `127.0.0.1` callback and dashboard URL, local cookies are enabled, system
  clocks are correct, and a new login was started. State, nonce, PKCE,
  authorization-code, and token errors intentionally fail closed.
- **Invalid token:** confirm the Keycloak issuer exactly matches both API and
  dashboard configuration, audience is `kordex-dashboard`, discovery/JWKS are
  reachable with certificate verification, and the account's clock/token has
  not expired.
- **Login reports no organization:** authentication succeeded but the subject
  has no Kordex membership. Grant a role only through the explicit helper.
- **HTTP 401:** the request was unauthenticated, the dashboard session expired,
  or the API rejected the token. Sign in again and inspect sanitized service
  logs; never copy tokens into logs or support messages.
- **HTTP 403:** the authenticated role lacks permission for that operation.
  Authentication does not imply administrator authorization.

This local flow is a development integration, not production qualification.
It does not change the existing bootstrap API, GKE, cloud resources, or the
production host-upgrade status.
