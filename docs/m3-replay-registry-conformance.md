# M3 replay registry protocol and conformance

**Production evidence acceptance remains BLOCKED.** Kordex does not provide a
registry implementation, and no customer-operated registry has been tested or
independently accepted. The local conformance adapter suite is a test harness;
its synthetic tests are not evidence of customer service durability.

## Protocol version 1

The service is customer-operated, reachable only at an approved HTTPS endpoint,
and configured in the root-signed qualification trust document. The service
must authenticate callers under the customer's service policy and sign every
response with the exact public key authorized for the `replay-registry` role.
Kordex disables HTTP proxies, refuses redirects, bounds the response size, and
checks the receipt signature, identity, request bindings, status, sequence,
and timestamp.

`reserve-run` binds `runId`, 256-bit `runNonce`, canonical matrix digest,
customer trust digest, creation time, and expiry. A single atomic transaction
must reserve both the run ID and nonce under unique constraints. Competing
requests for either value cannot each receive `newly-reserved`. Receipts and
lookups must bind those values and the durable reservation identifier.

`accept-run` binds the run ID and nonce, manifest digest, reviewer-decision
digest, trust digest, matrix digest, reservation digest, and an unpredictable
verifier challenge. A transaction must consume the reservation and insert
unique run ID, nonce, and package-digest records together. A claim is accepted
only once. A changed challenge or package digest cannot create another claim.

For an exact retry after a lost acknowledgement, the service must return the
same durable reservation or acceptance outcome and sequence, with an
authenticated receipt bound to the identical request. A request with altered
bindings must be rejected. The verifier currently does not automatically
retry or reconcile an ambiguous transport outcome: it returns BLOCKED. The
operator must reconcile the customer service audit record and preserve the
original run; a new run must not be created to conceal an uncertain result.
No positive verifier result is permitted on timeout, lost acknowledgement,
conflicting state, unverified response, or incomplete reconciliation.

The service must retain monotonic records across process restart, failover,
backup restore, and regional recovery. It must not discard a reservation or
acceptance to make a retry succeed. Its operational design must specify backup,
restore, uniqueness enforcement, transaction isolation, retention, service
identity, key rotation, and audit retention. A mock, process memory, or local
file cannot satisfy these requirements.

## Customer conformance test suite

Implement a thin adapter for the customer's isolated conformance endpoint and
run the repository harness from a controlled customer environment. The adapter
must verify the service's signed receipts against the pinned customer trust
configuration; a service-returned `signatureValid` boolean is not accepted.
The adapter contract and tests are in
[`scripts/m3_replay_registry_conformance.py`](../scripts/m3_replay_registry_conformance.py).
The harness refuses an adapter that does not identify an isolated HTTPS test
endpoint. It must never point to the production acceptance endpoint.

The customer adapter must execute and retain signed or independently auditable
results for all of these cases:

| Case | Required result |
|---|---|
| 12 concurrent reservations for one run and nonce | Exactly one new reservation; all others report the same existing reservation or conflict. |
| Same run ID with a changed nonce | Rejected; no second reservation. |
| Same nonce with a changed run ID | Rejected; no second reservation. |
| Service restart after reservation | Authenticated lookup returns the exact reservation and sequence. |
| 12 concurrent acceptances for one exact request | Exactly one new claim; remaining responses refer to the same committed claim. |
| Changed challenge or manifest digest after acceptance | Rejected as already consumed; no new claim. |
| Commit succeeds but response is lost, then exact request is retried | Same durable state and sequence are returned; no duplicate row or second transition. |
| Commit succeeds but response is lost, then service restarts | Lookup and exact retry return the committed state and authenticated receipt. |
| Failure between reservation and acceptance | Reservation remains durable; it cannot be silently deleted or reused. |
| Forged, stale, wrong-identity, or incorrectly bound receipt | Client verification rejects it. |
| Concurrent identical operations at the storage layer | Database evidence shows unique constraints/serializable transaction behavior; a mocked adapter result is insufficient. |

The suite returns an unsigned test summary with `qualificationAccepted: false`.
It is not an approval. A customer reviewer must inspect the actual isolated
service, database constraints and transaction logs, restart/failover records,
signing identity, and complete test results. The reviewer signs a conformance
report whose SHA-256 is pinned in the root-signed trust configuration; the
report is separately signed by a trusted, distinct `reviewer` identity and is
valid for no more than 30 days. The verifier requires that report and checks
its signature, registry URL/identity, protocol version, exact harness digest,
results digest, reviewer identity, and expiry before either run reservation or
final acceptance.

The report files belong at the protected paths
`/etc/kordex/m3/replay-registry-conformance.json` and `.sig`. The trust
configuration's `replayRegistry` entry binds the report digest, reviewer,
review time, and expiry. Updating the endpoint, registry key, report, harness,
or review invalidates the conformance approval. Conformance approval does not
replace the separate trust-configuration rollback protection. Production
trust loading also requires an independently protected durable monotonic
sequence verifier; until one is integrated, trust acceptance remains BLOCKED.

The root-signed trust entry has exactly these fields:

```json
{
  "url": "https://<customer-private-registry>/v1/claims",
  "identity": "<authorized-replay-registry-identity>",
  "conformanceReportSha256": "<sha256-of-canonical-report-bytes>",
  "conformanceReviewerIdentity": "<distinct-authorized-reviewer>",
  "conformanceReviewedAt": "<RFC3339-UTC>",
  "conformanceExpiresAt": "<RFC3339-UTC-within-30-days>"
}
```

The signed report has exactly: `schemaVersion: 1`, `protocolVersion`,
`registryUrl`, `registryIdentity`, `contractSuiteSha256`, `resultsSha256`,
`decision: "accepted"`, `reviewerIdentity`, `reviewedAt`, `expiresAt`, and
`evidenceReference`. Its detached Ed25519 signature is verified with the
trusted reviewer key. The report's contract-suite digest must equal the
repository's current conformance harness digest; results must retain the
actual customer adapter output, service-side transaction evidence, and
independent review evidence. The test harness summary itself is unsigned and
cannot authorize acceptance.

## Current limitations

- No customer registry endpoint or credentials were supplied or contacted.
- The customer adapter and service-side tests have not been run.
- The verifier cannot recover an ambiguous acceptance acknowledgement; it
  fails closed pending independent service-side reconciliation.
- The repository does not implement customer durable storage or prove its
  atomicity. Customer conformance evidence and independent review are required.
- No customer trust root, conformance report, or signature is supplied here.
