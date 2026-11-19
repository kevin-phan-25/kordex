# Kordex Fleet Platform security boundary

The existing [security model](security.md), signed
[maintenance protocol](agent-protocol.md), and
[recovery procedure](failure-recovery.md) remain authoritative. The console is
not the authorization boundary; API tenant membership and local signed permits
are independently enforced.
See the [threat model](threat-model.md) for attacker scenarios and residual
risks across these boundaries.

## Authentication and bootstrap contract

The backward-compatible default uses OIDC **ID tokens** as management bearer
credentials. Configure one reviewed issuer, set the API `KORDEX_OIDC_AUDIENCE`
to the dashboard `KORDEX_OIDC_CLIENT_ID`, and ensure the provider explicitly
permits this relying-party contract. The verifier checks signature, allowed
algorithm, issuer, audience, expiry, subject and authorized party.
Multi-audience tokens require `azp` to equal the configured audience; any
present `azp` must match. See
[OIDC ID token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

An opt-in RFC 9068 JWT access-token contract is also implemented for providers
that issue it. Set API `KORDEX_OIDC_TOKEN_MODE=access_token`, use an API-specific
`KORDEX_OIDC_AUDIENCE` distinct from the dashboard OAuth client ID, set
`KORDEX_OIDC_ACCESS_CLIENT_ID` to that dashboard client ID, and configure
`KORDEX_OIDC_ACCESS_REQUIRED_SCOPES`. Set dashboard
`KORDEX_OIDC_API_TOKEN_MODE=access_token` and request the same scopes with
`KORDEX_OIDC_API_SCOPES`. The API requires `typ=at+jwt`, a single exact resource
audience, issuer/signature/algorithm/expiry/issued-at/subject validation,
matching `client_id`, nonempty `jti`, and every configured scope. The dashboard
keeps the ID token for profile claims but sends only the access token to the
API; it also checks that both tokens identify the same subject. The API rejects
ID tokens in this mode. Agent machine identity remains separate, using the
agent's enrolled Ed25519 key rather than browser OIDC credentials.

Single-audience existing ID-token providers without `azp` remain compatible.
Both token modes are covered by local contract tests; no provider-backed login,
scope mapping, key rotation, or production identity-provider qualification is
claimed. Configure the provider's API resource audience and scopes before
switching both API and dashboard settings together. Existing ID-token sessions
will fail closed after the API switches modes; roll out both settings in a
planned window and have users sign in again. There is no fallback from one
token type to the other.

OIDC and bootstrap authentication are disjoint. OIDC listeners ignore the
global bootstrap credential even if constructor options request both modes.
An OIDC issuer combined with `KORDEX_LOCAL_DEVELOPMENT=true` fails startup.
Production deployments must use OIDC and verified database TLS. Isolated local
Compose bootstrap without OIDC remains available; its shared global token is
not a production organization role. Bootstrap organizations/memberships before
switching the service to OIDC; a token configured alongside OIDC cannot serve
as an administrative back door.

Every verified OIDC bearer token can be revoked for this API with
`POST /v1/session/revoke`. The API stores only the SHA-256 token digest, the
verified expiry, and request ID; it rejects that exact token on subsequent API
requests until expiry. Revocation rows are immutable while active, and the
database cleanup function can remove only expired rows. The dashboard logout
route invokes this endpoint before clearing its encrypted cookie; if the API is
unavailable, it still clears the local cookie and tells the user that remote
Kordex revocation was not confirmed. The registry is checked on every OIDC API
request, so a registry/database outage denies API access. This is Kordex API
revocation, not authorization-server revocation for other clients. Refresh
tokens and silent session refresh are not implemented; sessions end at the
verified API bearer expiry and require a new sign-in.

## Authorization, HTTP and discovery

Viewer, operator, approver and administrator permissions remain enforced at the
API. Unknown roles fail closed. Cross-tenant tests cover organization-scoped
read/mutation routes. Approval rejects creators, editors and starters even when
they hold an administrative or approver role. Discovery metadata confers no
execution privilege or qualification.

The dashboard proxy uses canonical segments, explicit method/route allowlists,
same-origin mutations, session-bound organization IDs, no redirect following,
and streaming byte limits (256 KiB for the proxy; 2 KiB for organization switch).
Missing or dishonest Content-Length cannot bypass the bound; malformed UTF-8
is rejected. The API still checks roles and payloads independently. Request
limits and timeouts also need enforcement at the deployment ingress.

No new host mount, privileged shell, provider credential, broad Kubernetes RBAC
or automatic reboot retry is introduced. Real host, kured contention, network
partition and disconnected installation evidence remains required.
