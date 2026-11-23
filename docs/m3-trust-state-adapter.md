# M3 customer trust-state adapter contract

This document separates the Kordex-owned verifier from the customer-operated
trust-state service. Kordex ships the protocol, fail-closed client, production
loader, and conformance harness. The customer owns the HTTPS backend, its
durable storage, signing keys, deployment, operational controls, and independent
review. This checkout contains no production backend adapter.

## Adapter interface

Implement `scripts/m3_trust_state.py:TrustStateTransport`. An adapter object
must provide exactly these operations:

```python
identity() -> dict
read_state(customer_id: str, namespace: str, transition_id: str) -> dict
compare_and_swap(request: dict) -> dict
```

`identity()` returns exactly `protocolVersion`, `customerId`,
`backendIdentity`, `namespace`, and `endpointReference`. The protocol version
is `kordex-m3-trust-state-v1`; the endpoint reference is the approved HTTPS
service reference without credentials, query parameters, or fragments. The
identity values must match the customer-rooted configuration on every adapter
instance.

`read_state` returns a signed receipt for action `read-state`, status `current`,
and the current durable sequence and configuration digest. A new backend
namespace begins at sequence `0` and digest `0` repeated 64 times.

`compare_and_swap` accepts exactly the request created by
`CustomerTrustStateClient.verify_and_advance`: schema version, protocol/action,
customer/backend/namespace identity, deterministic transition ID, expected
sequence and digest, and new sequence and digest. It must atomically commit
only when both expected values still match. A successful result has status
`committed` and binds the exact new sequence and digest. A race may return
`conflict`; it must not partially apply a generation.

Both operations return receipts with exactly these fields:

```text
schemaVersion, protocolVersion, action, backendIdentity, customerId,
namespace, transitionId, sequence, configurationSha256, durable, status,
observedAt, recordedAt, auditId, attestationFingerprint, signature
```

The backend attestor signs the canonical UTF-8 JSON bytes of the receipt with
the `signature` member omitted, using Ed25519. The signature is 64 bytes encoded
as 128 lowercase hexadecimal characters. `durable` must be true only after the
transaction is committed to storage with the durability promised by the
customer service. Receipts must be fresh (at most two minutes old), timestamps
must be timezone-aware, and the attestation fingerprint must match the
independently rooted key. The attestor identity and key must be distinct from
the conformance reviewer.

## Required backend behavior

- Reads are authenticated, customer- and namespace-bound, and durable across
  process and service restart.
- Compare-and-swap is atomic across concurrent service instances. Only the
  transition from generation `n` to `n+1` is accepted; no skipped generation,
  rollback, or same-generation/different-digest update is allowed.
- Replaying an old transition cannot change state. Every response binds the
  transition ID, customer, backend, namespace, current sequence, digest, and
  audit ID.
- After a lost CAS acknowledgement, the client performs one signed read. The
  backend must make that read sufficient to establish whether the exact
  transition committed. The client will not blindly retry the mutation.
- Backend outage, malformed or stale receipt, wrong identity, failed signature,
  ambiguous state, or a non-durable result blocks trust loading.
- The backend retains an independently auditable mutation history and has a
  customer-defined backup and recovery process. Kordex does not choose its
  availability, retention, or key-custody policy.

## Customer-rooted configuration and evidence

Install these files as root-owned regular files under `/etc/kordex/m3`; parent
directories and files must not be group/world writable:

- `qualification-root.pub`: customer-distributed Ed25519 public root in PEM
  format, supplied out of band.
- `qualification-trust.json`: canonical JSON, schema version 1, customer ID,
  consecutive sequence, issue/expiry times (maximum 30 days), and authorized
  Ed25519 public keys with identity, role, fingerprint, validity, and revocation
  fields. It contains the `trustState` object described below and must be signed
  by the customer root.
- `qualification-trust.json.sig`: detached Ed25519 signature over the exact
  canonical JSON bytes.
- `trust-state-conformance.json` and `.sig`: independently reviewed conformance
  report and detached reviewer signature.

The trust document's `trustState` object has exactly:
`backendIdentity`, `namespace`, `endpointReference`, `attestorIdentity`,
`conformanceReportSha256`, `conformanceReviewerIdentity`,
`conformanceReviewedAt`, and `conformanceExpiresAt`. The backend endpoint must
be HTTPS. The authorized keys must contain exactly one trust-state attestor and
a separate reviewer, with distinct fingerprints.

The conformance report has exactly `schemaVersion`, `protocolVersion`,
`customerId`, `backendIdentity`, `endpointReference`, `conformanceNamespace`,
`contractSuiteSha256`, `resultsSha256`, `decision`, `reviewerIdentity`,
`reviewedAt`, `expiresAt`, and `evidenceReference`. It binds the exact current
conformance suite hash, identifies a `kordex-conformance-...` isolated test
namespace, and expires no more than 30 days after review. The independent
reviewer signs the canonical report. The report digest and reviewer identity
must then be included in the root-signed trust document. The conformance
harness's candidate says `pending-independent-review` and is not accepted
production evidence.

## Conformance execution and acceptance

The customer supplies and operates an adapter package that exposes
`transport_factory(namespace)`. Run
`scripts/m3_trust_state_conformance.py:run_conformance` only against a newly
isolated customer test namespace over the approved HTTPS endpoint. The adapter
must expose one-shot `lose_next_ack()` fault injection restricted to that test
namespace. The suite checks concurrent identical CAS, restart durability,
rollback rejection, sequence/digest conflict rejection, and lost-ack
reconciliation. It must not point at the production trust generation.

Example invocation shape (the customer supplies the module and values from
their approved environment; no credentials or signing keys belong in this
command or repository):

```sh
PYTHONPATH="$CUSTOMER_ADAPTER_PATH:$PWD/scripts" python3 -c '
import json, customer_trust_adapter
from m3_trust_state_conformance import run_conformance
result = run_conformance(
    transport_factory=customer_trust_adapter.transport_factory,
    customer_id=customer_trust_adapter.customer_id(),
    backend_identity=customer_trust_adapter.backend_identity(),
    endpoint_reference=customer_trust_adapter.endpoint_reference(),
    attestation_public_key=customer_trust_adapter.attestation_public_key(),
    attestation_fingerprint=customer_trust_adapter.attestation_fingerprint(),
    evidence_reference=customer_trust_adapter.evidence_reference(),
)
print(json.dumps(result, sort_keys=True, indent=2))
'
```

The customer preserves the raw test output, suite hash, result digest, isolated
namespace audit, backend identity, and attestor fingerprint in its evidence
custody system. A separate authorized reviewer inspects those records and signs
an accepted report. Only then can the customer install the reviewed report and
root-sign a trust document that pins it. Independent evidence must establish
that the reviewer did not operate or attest the backend.

Kordex's production integration point is
`m3_trust_state.load_customer_trust(transport)`. It verifies the root-owned
trust files, signed current conformance report, backend identity, signed
receipts, and monotonic generation before returning an opaque verified trust
object. The adapter must be supplied by the customer runtime integration; the
local harness or synthetic test adapter cannot create a production pass.

The manifest intake commands remain structural checks and do not verify
customer trust:

```sh
python3 scripts/m3_qualification.py inputs --manifest PATH_TO_CUSTOMER_MANIFEST
python3 scripts/m3_qualification.py status --manifest PATH_TO_CUSTOMER_MANIFEST
```

Production acceptance requires valid customer-rooted files, a customer
implementation passing the conformance contract, independent signed review,
durable evidence custody, and the existing production trust loader to accept
that exact pinned configuration. No customer backend, key, trust root, or
conformance evidence is included in this repository.

The customer manifest uses `docs/schemas/m3-customer-inputs-v1.json`. Its
`inputs` object has exact evidence references in these slots:

- `maintenanceTrustConfiguration`: customer root, canonical trust JSON, and
  detached root signature as one customer-custodied input package.
- `trustStateBackendConformance`: accepted signed report, detached signature,
  suite/results digests, reviewer identity, and evidence reference.
- `replayRegistryConformance`: separate replay-registry conformance evidence;
  trust-state conformance does not satisfy replay protection.
- `evidenceCustody`: customer evidence location and custody controls.
- `reviewerIdentity`: independent authorized reviewer identity.

Each non-null slot is exactly `{ "reference": "...", "sha256": "<64 lowercase hex>",
"expiresAt": "<RFC3339 timestamp or null>" }`. The reference resolves in the
customer's approved evidence system; it must not contain a secret or private
key. The manifest digest only binds the referenced bytes and does not make
them verified or accepted. Intake and current local status are checked with:

```sh
python3 scripts/m3_qualification.py inputs --manifest PATH_TO_CUSTOMER_MANIFEST
python3 scripts/m3_qualification.py status --manifest PATH_TO_CUSTOMER_MANIFEST
```

The production verifier separately opens and validates the actual root-owned
files and conformance report. A structurally valid manifest cannot substitute
for that verification or for independent acceptance.
