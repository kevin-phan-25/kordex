# M3 local agent API gateway

This is a preparation component for the disposable self-managed Ubuntu M3 lab.
It does not configure Cloudflare, publish a tunnel, or enable host maintenance.
The Kordex API remains on workstation loopback; only the outbound agent path is
forwarded.

## Request path and allowed routes

```text
Ubuntu lab VM -- HTTPS + Cloudflare Access service token --> Cloudflare edge
  --> outbound Cloudflare Tunnel --> 127.0.0.1:18443 (TLS gateway)
  --> 127.0.0.1:8080 (Kordex API, HTTP loopback only)
```

The gateway has no configurable upstream. It only forwards these exact
method/path pairs:

| Method | Path | Kordex authentication |
|---|---|---|
| `POST` | `/v1/agent/enroll` | Single-use enrollment token and Ed25519 key possession proof |
| `GET` | `/v1/agent/identity` | Enrolled Ed25519 request signature |
| `POST` | `/v1/agent/report` | Enrolled Ed25519 request signature |
| `POST` | `/v1/agent/rotate` | Current-key signature and new-key proof |
| `POST` | `/v1/agent/operations/sync` | Enrolled Ed25519 request signature; agent maintenance delivery must remain disabled unless separately authorized |

Cloudflare Access service-token headers are checked by the gateway and removed
before forwarding. The existing Kordex enrollment/signature checks remain
required. Query strings, encoded/noncanonical paths, path traversal,
`Authorization`/`Proxy-Authorization` headers, cookies, incorrect methods,
duplicate Access headers, and all other routes are rejected. Health/readiness,
metrics, administrative APIs,
dashboard, PostgreSQL, and Keycloak are not forwarded. Responses do not expose
upstream addresses or cookies. The gateway does not log requests or headers.

The agent sends `CF-Access-Client-Id` and `CF-Access-Client-Secret` only when
`KORDEX_GATEWAY_AUTH_REQUIRED=true` and both values are configured. The
self-managed Kustomize overlay enables this requirement and reads the pair from
the `kordex-api-gateway` Secret (`client-id`, `client-secret`). Other agent
deployments remain backward compatible with gateway mode off and no Access
credentials. Missing self-managed credentials cause agent startup to fail
closed.

## Local gateway configuration

Build and run from the repository root. The service requires all credentials
and TLS files; no default credentials, plaintext mode, arbitrary upstream, or
non-loopback bind is available.

```sh
go run ./integrations/cmd/kordex-agent-gateway
```

Required environment variables:

| Variable | Purpose |
|---|---|
| `KORDEX_GATEWAY_CLIENT_ID` | Cloudflare Access service-token client ID |
| `KORDEX_GATEWAY_CLIENT_SECRET` | Cloudflare Access service-token secret |
| `KORDEX_GATEWAY_TLS_CERT_FILE` | Local gateway origin certificate |
| `KORDEX_GATEWAY_TLS_KEY_FILE` | Matching private key; file must be regular and owner-only |
| `KORDEX_GATEWAY_TLS_SERVER_NAME` | DNS SAN Cloudflare's connector must verify as `originServerName` |
| `KORDEX_GATEWAY_LISTEN_ADDRESS` | Optional numeric loopback address; defaults to `127.0.0.1:18443` |

Set secrets in the process environment through a local secret manager or a
protected, untracked shell environment. Do not pass them as command-line
arguments, write them to shell history, add them to Git, or enable request
logging. The origin certificate's DNS SAN and validity are checked at startup;
the gateway requires a matching key with no group/other permission bits. The
Cloudflare connector must validate that certificate using its configured CA
pool and server name. The agent independently verifies the public HTTPS
hostname using system trust or its existing `KORDEX_CA_FILE` support; TLS
verification is not disabled.

For a short-lived local origin certificate, create files outside the checkout
and keep its self-signed certificate available as the Cloudflare connector's
origin CA:

```sh
umask 077
mkdir -p "$HOME/.local/share/kordex/agent-gateway"
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout "$HOME/.local/share/kordex/agent-gateway/ca.key" \
  -out "$HOME/.local/share/kordex/agent-gateway/ca.crt" \
  -subj '/CN=Kordex local agent gateway CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -newkey rsa:3072 -nodes \
  -keyout "$HOME/.local/share/kordex/agent-gateway/origin.key" \
  -out "$HOME/.local/share/kordex/agent-gateway/origin.csr" \
  -subj '/CN=kordex-gateway.local'
printf '%s\n' 'subjectAltName=DNS:kordex-gateway.local' \
  'extendedKeyUsage=serverAuth' 'keyUsage=digitalSignature,keyEncipherment' \
  > "$HOME/.local/share/kordex/agent-gateway/origin.ext"
openssl x509 -req \
  -in "$HOME/.local/share/kordex/agent-gateway/origin.csr" \
  -CA "$HOME/.local/share/kordex/agent-gateway/ca.crt" \
  -CAkey "$HOME/.local/share/kordex/agent-gateway/ca.key" \
  -CAcreateserial -days 7 -sha256 \
  -extfile "$HOME/.local/share/kordex/agent-gateway/origin.ext" \
  -out "$HOME/.local/share/kordex/agent-gateway/origin.crt"
chmod 600 "$HOME/.local/share/kordex/agent-gateway/ca.key" \
  "$HOME/.local/share/kordex/agent-gateway/origin.key"
chmod 644 "$HOME/.local/share/kordex/agent-gateway/ca.crt" \
  "$HOME/.local/share/kordex/agent-gateway/origin.crt"
```

This command generates local key material only. `ca.crt` is the Cloudflare
connector's `caPool`; configure `originServerName` as `kordex-gateway.local`.
Do not put either private key in Cloudflare, Kubernetes, Terraform, or the
repository. The origin certificate is for the local connector-to-origin hop;
it is not the public certificate seen by the agent. Remove the short-lived
CA private key after the origin certificate has been signed and verified if
you do not need to issue another origin certificate.

## Cloudflare configuration still required

No Cloudflare account, domain, DNS record, Access application, service token,
tunnel, or policy is created by this repository change. Before use, the
operator must:

1. Have a Cloudflare account and a domain managed by Cloudflare; choose a
   dedicated hostname for the agent API.
2. Create a named Tunnel and install/run `cloudflared` on the workstation using
   its protected tunnel credentials. Configure that hostname to reach
   `https://127.0.0.1:18443`, set `originServerName` to
   `kordex-gateway.local`, and configure `caPool` to the local origin
   CA. The local config shape is:

   ```yaml
   tunnel: <TUNNEL_UUID>
   credentials-file: /secure/path/<TUNNEL_UUID>.json
   ingress:
     - hostname: <agent-api-hostname>
       service: https://127.0.0.1:18443
       originRequest:
         originServerName: kordex-gateway.local
         caPool: /secure/path/ca.crt
     - service: http_status:404
   ```

   Route that hostname to the named Tunnel using the Cloudflare dashboard or
   `cloudflared tunnel route dns`. Use a final catch-all route returning 404,
   not an alternate service.
3. Add a Cloudflare Access self-hosted application for the exact hostname and
   a **Service Auth** policy that permits only the dedicated service token.
   Do not add an `Everyone` or browser-user allow policy. The local proxy's
   exact path/method list remains the final route restriction. Enable strict
   service-token authentication where available, so service-token failures
   return 401/403 and only Service Auth policies can authorize the request;
   see [Cloudflare service-token guidance](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/).
4. Create one short-lived service token and keep its ID/secret in the approved
   local secret store. Configure the gateway process from that store. Deliver
   the same pair to the agent only through the dedicated `kordex-api-gateway`
   Kubernetes Secret in the disposable lab; create Secret key files with
   restrictive permissions and use `--from-file`, never `--from-literal`:

   ```sh
   kubectl --context "$KORDEX_EXPECTED_CONTEXT" -n kordex-system create secret generic kordex-api-gateway \
     --from-file=client-id=/secure/path/cloudflare-client-id \
     --from-file=client-secret=/secure/path/cloudflare-client-secret
   ```

   Do not run this until the disposable lab deployment is separately approved.
5. Set the self-managed agent's `controlPlaneURL` to the public HTTPS hostname
   and `gatewayAuthRequired: "true"`. Keep its `KORDEX_CA_FILE` behavior and
   standard public certificate verification intact.
6. Test denied paths and methods, missing/wrong service token, Kordex agent
   signature verification, and successful enrollment/reporting. Revoke the
   service token and stop the local gateway/tunnel after the qualification
   session.

The Cloudflare policy and tunnel have not been configured or tested here.
Account plan, domain ownership, service-token lifetime/policy availability,
and any subscription cost must be confirmed in the account before setup.

## Local verification boundary

Automated tests exercise the five routes, TLS hostname/CA validation,
service-token fixtures, rejection behavior, and an HTTPS local gateway to a
local API fixture. These tests do not prove that Cloudflare Access, DNS,
Tunnel, or the real service-token policy is configured correctly. A real
Cloudflare test must be recorded separately before M3 preflight.
