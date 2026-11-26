# M3 customer trust-state adapter contract

This document separates the Kordex-owned verifier from the customer-operated
trust-state service. Kordex ships the protocol, fail-closed client, production
loader, and conformance harness. The customer owns the HTTPS backend, its
durable storage, signing keys, deployment, operational controls, and independent
review. This checkout contains no production backend adapter.

The Python `TrustStateTransport` protocol is the complete backend interface.
Production callers discover one installed Python entry point named `customer`
in group `kordex.m3.trust_state`. Its distribution name and version must match
the root-signed `trustState.adapterDistribution` and `adapterVersion` values;
the SHA-256 of its deterministic installed-file manifest must match
`adapterTreeSha256`.
The adapter is installed by the customer-controlled protected runtime supply
chain; Kordex does not select an arbitrary module path or environment variable.
The customer records its source revision, wheel/image digest, publisher, and
runtime identity as external evidence. No adapter package is included here.
The entry-point factory has the contract
`factory(trust_state_settings: dict) -> TrustStateTransport`; it must obtain
credentials from its protected runtime, and it must not accept endpoint or
identity overrides from command-line flags or environment variables.
`adapterTreeSha256` is SHA-256 over canonical UTF-8 JSON containing the sorted
list of every installed distribution file as `{path, sha256}` records. Missing,
changed, symlinked, or out-of-distribution files fail loading.
The installation root, package directories, and files must be root-owned and
not group/world writable; production verifies those properties before importing
the adapter. The independently reviewed backend-conformance signature is
checked before adapter code is imported.

## Adapter interface

Implement `scripts/m3_trust_state.py:TrustStateTransport`. An adapter object
must provide exactly these operations:

```python
identity() -> dict
read_state(customer_id: str, namespace: str, transition_id: str, request_id: str) -> dict
compare_and_swap(request: dict) -> dict
```

`identity()` returns exactly `protocolVersion`, `customerId`,
`backendIdentity`, `namespace`, and `endpointReference`. The protocol version
is `kordex-m3-trust-state-v2`; v1 receipts are rejected because they do not
bind each response to a unique request challenge. The endpoint reference is the approved HTTPS
service reference without credentials, query parameters, or fragments. The
identity values must match the customer-rooted configuration on every adapter
instance.

Every read request carries a fresh 256-bit random `request_id` encoded as 64
lowercase hexadecimal characters. The backend echoes it as `requestId` in the
signed receipt. A receipt for an earlier request is rejected even when its
signature and two-minute freshness window remain valid. CAS requests carry a
fresh `requestId` of the same form, and the signed response binds that exact
ID. `transitionId` identifies an idempotent generation change; `requestId`
prevents replay of an earlier response for that transition.

`read_state` returns a signed receipt for action `read-state`, status `current`,
and the current durable sequence and configuration digest. A new backend
namespace begins at sequence `0` and digest `0` repeated 64 times.

`compare_and_swap` accepts exactly the request created by
`CustomerTrustStateClient.verify_and_advance`: schema version, protocol/action,
customer/backend/namespace identity, deterministic transition ID, unique
request ID, expected sequence and digest, new sequence and digest, canonical configuration object,
root fingerprint, SHA-256 digest of the detached root signature, and detached
root signature (128 lowercase hexadecimal characters). The backend must
independently verify that the configuration digest matches the canonical
object, that the object names the requested customer/backend/namespace and
next sequence, and that the signature chains to the root fingerprint pinned by
backend policy. It must atomically commit only when both expected values still
match. A successful result has status `committed` and binds the exact new
sequence, configuration digest, root fingerprint, and root-signature digest.
A race may return `conflict`; it must not partially apply a generation. The
service must store the root-authorized configuration version, root-signature
identity, and digest with the monotonic head; it must not store signing private
keys. The initial empty head uses all-zero SHA-256 values for both root fields.

Both operations return receipts with exactly these fields:

```text
schemaVersion, protocolVersion, action, backendIdentity, customerId,
namespace, transitionId, requestId, sequence, configurationSha256, durable, status,
observedAt, recordedAt, auditId, attestationFingerprint, rootFingerprint,
rootSignatureSha256, signature
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
  transition ID, unique request ID, customer, backend, namespace, current
  sequence, digest, and audit ID. The durable audit event retains the request
  ID so reviewers can correlate each response with its unique challenge.
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
`adapterDistribution`, `adapterVersion`, `adapterTreeSha256`,
`conformanceReportSha256`, `conformanceReviewerIdentity`,
`conformanceReviewedAt`, and `conformanceExpiresAt`. The backend endpoint must
be HTTPS. The authorized keys must contain exactly one trust-state attestor and
a separate reviewer, with distinct fingerprints.

The accepted conformance report has exactly `schemaVersion` (2),
`protocolVersion` (`kordex-m3-trust-state-conformance-v2`),
`customerId`, `backendIdentity`, `endpointReference`, `conformanceNamespace`,
`contractSuiteSha256`, `resultsSha256`, `decision`, `reviewerIdentity`,
`reviewedAt`, `expiresAt`, and `evidenceReference`. It binds the exact current
conformance suite hash, identifies a `kordex-conformance-...` isolated test
namespace, and expires no more than 30 days after review. The independent
reviewer signs the canonical report. The report digest and reviewer identity
must then be included in the root-signed trust document. The conformance
harness's candidate says `pending-independent-review` and is not accepted
production evidence.
The runner's separate execution package is validated against
[`m3-trust-state-conformance-run-report-v2.json`](../schemas/m3-trust-state-conformance-run-report-v2.json);
it records request-bound audit events and always states that production trust
was not accepted and no qualification row advanced.

## Conformance execution and acceptance

The customer supplies and operates an adapter package. The old example below
used a caller-controlled `PYTHONPATH` and imported an arbitrary module before
any package pin check; do not use that invocation. The supported runner is
`scripts/run_m3_trust_state_conformance.py`. It requires a detached-signature-
verified bootstrap using
[`m3-trust-state-conformance-bootstrap-v1.json`](../schemas/m3-trust-state-conformance-bootstrap-v1.json),
rooted at the out-of-band `/etc/kordex/m3/qualification-root.pub`. The signed
bootstrap pins the clean runner Git commit and the exact installed adapter
distribution, version, and deterministic installed-tree SHA-256. The runner
checks root-owned, non-writable installed files before importing the unique
`kordex.m3.trust_state.conformance:customer` entry point. It accepts no module
path, `PYTHONPATH`, endpoint, or factory override. The adapter factory returns
only `transportFactory(namespace)` and
`signConformanceConfiguration(document)`; the signer is limited to isolated
test configurations and cannot expose the production root.

Run only against a newly isolated customer test namespace over its approved
HTTPS endpoint, never against production trust state. The customer adapter
must expose one-shot `lose_next_ack()` fault injection restricted to that test
namespace. The suite checks the root-signed trust-policy input and invalid
signature, expired trust configuration and role, expired backend-conformance
review, revoked role, duplicate identity, signer/verifier and reviewer/signer
conflict cases, plus initial backend state, valid root-authorized CAS, rejected
unauthorized backend update, digest mismatch, outage, stale/corrupt reads,
concurrent update conflict, restart, rollback/replay, lost-ack reconciliation,
and signed audit references. It also replays a valid signed read receipt
against a fresh request ID and requires rejection, including when the old
receipt remains inside its two-minute timestamp window. Receipts bind the exact
request challenge, root fingerprint, and root-signature digest for each
persisted generation.

Use the exact root-signature/source-check/output-capture command in
[`m3-external-owner-delivery.md`](m3-external-owner-delivery.md#a0-trust-backend-owner-and-security-custodian).
The adapter, bootstrap, trust root, signed policy and isolated namespace are
owner-supplied; the command does not invent or create them.

`/opt/kordex/m3-runner` must be a clean checkout of the exact commit in the
root-signed bootstrap. It must contain no untracked or git-ignored files
(including `__pycache__`), and should be root-owned and non-writable by the
runner account. The CLI requires Python isolated mode (`-I`), writes no
bytecode, scrubs `GIT_*` environment variables, and treats any ignored file as
dirty. Before importing, it verifies every package and submodule component
resolves to a file inside the digest-pinned distribution and rejects unpinned
bytecode caches, then rechecks loaded module paths after import. A same-named
module earlier on `sys.path` is rejected. The pinned adapter still runs
in-process, so its output remains candidate evidence that needs independent
review. The adapter is installed into the protected system
Python environment from the owner-approved distribution; isolated Python mode
ignores caller `PYTHONPATH` and user-site packages. The output directory must
already be mode `0700`; reports are created exclusively as mode `0600`.
`run_conformance` returning zero is only backend contract execution: its
candidate report is still `pending-independent-review`, the runner records
`productionTrustAccepted: false`, and no trust or qualification state advances.
The customer must preserve complete output/error logs, exit status, backend
receipts and audit IDs, observed sequence/digest values, restart evidence,
backup/recovery and availability evidence, adapter provenance and protected
installation details. Every listed case must pass with corresponding actual
backend records; an exit code alone is insufficient.

Direct Python imports of `run_conformance` with a caller-provided transport
factory are reserved for isolated unit tests. They are not an owner execution
path and must not be used against a customer service. Use the signed-bootstrap
runner command above; it verifies the package and source pins before loading
adapter code.

The adapter's conformance-only signer must sign test configurations under a
separate root pinned only to the generated conformance namespace. It must not
use or expose the production root key. The customer preserves the raw test
output, suite hash, result digest, isolated namespace audit, backend identity,
attestor fingerprint, and conformance-root fingerprint in its evidence custody
system. A separate authorized reviewer inspects those records and signs
an accepted report. Only then can the customer install the reviewed report and
root-sign a trust document that pins it. Independent evidence must establish
that the reviewer did not operate or attest the backend.

Kordex's production integration is
`m3_trust_state.load_production_customer_trust()`. It verifies the root-owned
trust files, resolves exactly one version-matched installed adapter, checks
the signed current conformance report and backend identity, verifies signed
receipts, and enforces the monotonic generation before returning an opaque
verified trust snapshot. Its snapshot records the sequence, configuration
digest, root fingerprint and root-signature digest, backend and attestor
identities, conformance-report digest, and signed backend audit IDs. Every receipt is also emitted to the Kordex trust-state
logger without trust contents or credentials. The public
`load_customer_trust()` API uses the pinned installed entry point and does not
accept a caller-selected transport. The transport-injected implementation is
private and used only by the production adapter loader and isolated tests.

Before importing, the production loader verifies the entry-point module and
package paths against the root-pinned installed file inventory, rejects
preloaded same-name modules and unpinned bytecode caches, then checks loaded
module paths and re-hashes the installed tree. It suppresses bytecode creation
during import and remembers module objects only after verifying them, allowing
later trust reloads to distinguish its own cached imports from caller-preloaded
modules. These checks prevent ordinary import-path substitution; they do not
sandbox the adapter. It runs in-process with the caller's privileges and is
part of the trusted computing base. The protected installation, exact
root-signed distribution digest and independent backend review remain
mandatory. This local code change does not establish or approve a customer
adapter or backend.

The trust validator recognizes the explicit `residual-risk-approver` role used
by image-risk acceptance and requires that identity and key to be distinct
from artifact, image, deployment, release-lock and reviewer authorities. A
residual-risk signature still requires the separately configured independent
review; the role does not accept risk or advance a qualification row by itself.

The CAS client verifies the root signature before sending an update, and the
backend contract independently verifies the same authorization before commit.
Every signed read and update receipt binds both the root public-key fingerprint
and the exact detached root-signature digest for the persisted generation; a
same-sequence response with a different root authorization is rejected.
The low-level `_advance_generation` method requires root signature material and
is used only by the production root-verified closure or isolated conformance
tests. Direct production
`m3_customer_trust.load_trust()` calls delegate to the durable loader; omitting
the adapter, conformance evidence, or authenticated backend receipt remains a
hard failure. Offline release verification records the trust-state version and
audit IDs in its signed verification manifest. The separate signing step
re-reads durable state, rejects a changed version, and records its own backend
audit IDs in the signing receipt.

Fixture and unit-test runs report `backendContractChecks: EXECUTED`,
`customerAdapterConformance: NOT ESTABLISHED`, and
`productionTrustAccepted: false`. Only an actual customer backend run, followed
by separately signed independent review and root pinning, can be accepted.

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
