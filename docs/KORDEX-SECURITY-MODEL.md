# Kordex Fleet Platform security boundary

The existing [security model](security.md), signed
[maintenance protocol](agent-protocol.md), and
[recovery procedure](failure-recovery.md) remain authoritative. The console is
not the authorization boundary; API tenant membership and local signed permits
are independently enforced.

## Authentication and bootstrap contract

The current dashboard deliberately uses OIDC **ID tokens**, not access tokens,
as management bearer credentials. Configure one reviewed issuer, set the API
`KORDEX_OIDC_AUDIENCE` to the dashboard `KORDEX_OIDC_CLIENT_ID`, and ensure the
provider explicitly permits this relying-party contract. The verifier checks
signature, allowed algorithm, issuer, audience, expiry, subject and authorized
party. Multi-audience tokens require `azp` to equal the configured audience;
any present `azp` must match. See
[OIDC ID token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

Single-audience existing providers without `azp` remain compatible. Dedicated
API access tokens are preferred when supported, but require a separate explicit
issuer/resource audience/token-type/expiry/scope contract and migration tests.
That migration is pending; changing the callback to blindly forward an access
token is not supported. No provider-backed login/rotation qualification is
claimed by the local signed-token tests.

OIDC and bootstrap authentication are disjoint. OIDC listeners ignore the
global bootstrap credential even if constructor options request both modes.
An OIDC issuer combined with `KORDEX_LOCAL_DEVELOPMENT=true` fails startup.
Production deployments must use OIDC and verified database TLS. Isolated local
Compose bootstrap without OIDC remains available; its shared global token is
not a production organization role. Bootstrap organizations/memberships before
switching the service to OIDC; a token configured alongside OIDC cannot serve
as an administrative back door.

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
