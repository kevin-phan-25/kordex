# Agent mTLS transport configuration

The Kordex agent can optionally use customer-issued mutual TLS to authenticate
its HTTPS connection to a customer-operated endpoint. This is a transport
boundary only. It does not replace the agent's Ed25519 request signatures,
single-use enrollment authorization, organization/cluster checks, or operator
maintenance-permit verification. The private relay and certificate-to-cluster
authorization policy are implemented as a separate component and are
documented in [private agent relay operations](private-agent-relay-operations.md).
The relay, customer PKI, and private network path have not been deployed or
qualified.

## Customer PKI responsibilities

The customer PKI owner must:

1. Issue a relay server certificate whose DNS Subject Alternative Name matches
   the exact hostname in `KORDEX_CONTROL_PLANE_URL` and
   `KORDEX_MTLS_SERVER_NAME`. The agent requires these names to match and
   rejects IP-literal identities in mTLS mode.
2. Issue each agent a distinct client certificate with `clientAuth` extended
   key usage and digital-signature key usage. Use the customer's documented
   identity/SAN profile; a relay must bind the verified certificate to the
   registered cluster independently of the certificate's display name.
3. Keep the client private key in customer PKI or secret management. Deliver
   it only through an approved secret-projection mechanism. Never put it in a
   ConfigMap, Helm values, command-line argument, image, Terraform state, or
   Git.
4. Provision the public CA bundle that validates the relay server through an
   independent trusted channel. In mTLS mode this configured bundle is the
   trust root set; the agent does not silently add system roots.
5. Define short lifetimes, renewal, revocation, incident response, and CA
   overlap. The agent loads the certificate and key at process start; rotation
   requires updating the mounted Secret and restarting the agent. Dynamic
   certificate reload is not implemented. The relay must enforce its own
   revocation/deny policy; the client cannot make a revoked server-side
   credential valid.

Do not send private keys, passwords, or certificate Secret values through
chat, ordinary email, documentation, or repository files.

## Agent behavior

Set `KORDEX_MTLS_ENABLED=true` to select mTLS. Startup then requires readable
client certificate, matching private key, server CA bundle, and expected DNS
name. The agent rejects invalid PEM, a mismatched keypair, empty/non-CA trust,
expired client certificates, missing `clientAuth` usage, a DNS name that does
not match the HTTPS URL hostname, and any non-HTTPS endpoint. TLS requires at
least TLS 1.2. Server chain, validity, and DNS SAN are verified by Go's normal
TLS verifier. Handshake or configuration failure stops the request; there is
no plaintext, legacy-client, Cloudflare, or system-root fallback. Redirects are
not followed.

The existing direct HTTPS configuration remains unchanged when
`KORDEX_MTLS_ENABLED=false` (the default). `KORDEX_CA_FILE` continues to add a
management CA to system roots in that legacy mode. When mTLS is enabled, use
the separate `KORDEX_MTLS_SERVER_CA_FILE`; Helm rejects simultaneous use of
the legacy `caSecretName` setting to avoid ambiguous trust configuration.

The agent still sends Kordex Ed25519 signatures on identity, rotation, report,
and operation-sync requests. Enrollment still uses its one-time token and
Ed25519 proof. A valid TLS client certificate does not create an identity or
grant organization, cluster, operation, or maintenance permissions. mTLS also
does not make forwarding headers trustworthy.

## Secret files and deployment

The process runs as UID/GID 65532 in the supplied charts. Mount client-key
files read-only with owner/group access limited to the agent (for example mode
`0440`, with the Pod `fsGroup` set to the agent group). The CA is public
material but should still be mounted read-only. Secret encryption at rest,
namespace RBAC, backup, rotation and access audit remain customer
responsibilities.

### Helm

Create these Secrets separately using the customer's approved secret workflow;
do not put certificate data in a values file:

- Client Secret: `tls.crt`, `tls.key`.
- Server CA Secret: `ca.crt`.

Then set references and public endpoint identity only:

```yaml
controlPlaneURL: https://agent-api.example.internal
mtls:
  enabled: true
  clientCertificateSecretName: kordex-agent-mtls-client
  serverCASecretName: kordex-agent-mtls-ca
  serverName: agent-api.example.internal
```

`controlPlaneURL` must be the HTTPS origin (no path/query), and its hostname
must equal `mtls.serverName`. The chart mounts the client Secret read-only at
`/var/run/kordex/mtls-client` and the public CA at
`/var/run/kordex/mtls-ca`. It injects only file paths and the public DNS name.
The Secret data is not rendered into manifests.

### Kustomize

The base and existing overlays keep `mtlsEnabled: "false"`. For the
self-managed overlay, provision the same two Secrets outside Git, set
`mtlsServerName` in the agent settings to the HTTPS origin hostname, and add
`agent-mtls.patch.yaml` to the `patches` list in that overlay's
`kustomization.yaml` after `agent-settings.patch.yaml`. The patch sets mTLS on,
mounts the named Secrets
`kordex-agent-mtls-client` and `kordex-agent-mtls-ca`, and supplies file paths.
It also disables the Cloudflare Access header mode for this explicit private
mTLS profile; the existing Cloudflare overlay behavior is unchanged unless
this opt-in patch is selected. It contains no credentials. Remove that patch
and restart the agent to return to the explicitly configured overlay behavior;
do not remove trust while an agent still depends on the private endpoint.

## Verification and failure behavior

Before rollout, the customer should independently inspect the Secret key names
and permissions without printing values, verify the server chain and DNS SAN
against the independently delivered CA, and confirm the client certificate is
valid for client authentication. For example, a PKI operator with authorized
access to the mounted files can check the endpoint with:

```sh
openssl s_client -connect agent-api.example.internal:443 \
  -servername agent-api.example.internal \
  -CAfile /secure/pki/relay-ca.crt \
  -cert /secure/pki/agent.crt \
  -key /secure/pki/agent.key \
  -verify_return_error -brief </dev/null
```

This checks the supplied test client's TLS path, not the running agent. For the
agent, inspect only Deployment env names/file paths and Secret key names (for
example `kubectl describe secret kordex-agent-mtls-client`); do not print
Secret data. Then confirm a connection and client-certificate identity in the
relay's sanitized TLS logs and a separately authenticated Kordex API result.
A successful TLS handshake proves only the transport identities. Verify
Kordex enrollment, signed API calls, and organization/cluster authorization
separately. An unsigned request with a valid client certificate must still be
rejected by the API.

If a certificate is missing, unreadable, expired, mismatched, untrusted, or
has the wrong DNS identity, mTLS startup or handshake fails closed. Inspect
the agent's sanitized startup/transport error category and customer relay TLS
logs; never enable insecure TLS or send certificate contents to logs for
troubleshooting.

### Placeholder-only example environment

```text
KORDEX_MTLS_ENABLED=true
KORDEX_MTLS_CLIENT_CERT_FILE=/var/run/kordex/mtls-client/tls.crt
KORDEX_MTLS_CLIENT_KEY_FILE=/var/run/kordex/mtls-client/tls.key
KORDEX_MTLS_SERVER_CA_FILE=/var/run/kordex/mtls-ca/ca.crt
KORDEX_MTLS_SERVER_NAME=agent-api.example.internal
```

No real certificate, trust bundle, relay, route, or mTLS deployment has been
provisioned or qualified by this implementation.
