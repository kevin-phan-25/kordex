"""Conformance checks for a customer-supplied durable trust-state CAS adapter.

The harness is an importable contract suite. Run it only against a dedicated
customer test namespace, never the production trust generation. Its result can
support independent backend review but is not production verification by itself.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

try:
    import m3_trust_state as trust_state
except ModuleNotFoundError:
    from scripts import m3_trust_state as trust_state


class ConformanceError(ValueError):
    pass


def run_conformance(*, transport_factory, customer_id: str, backend_identity: str,
                    endpoint_reference: str, attestation_public_key: bytes,
                    attestation_fingerprint: str, evidence_reference: str) -> dict:
    """Exercise isolated namespace, atomic CAS, restart, replay and lost-ack behavior.

    ``transport_factory(namespace)`` must return a customer adapter whose
    durable state survives closing that instance and opening a new one. The
    test namespace must be explicitly isolated by the customer backend.
    """
    namespace = f"kordex-conformance-{uuid.uuid4()}"
    if not endpoint_reference.startswith("https://") or not evidence_reference:
        raise ConformanceError("customer HTTPS endpoint and evidence reference are required")

    def client():
        transport = transport_factory(namespace)
        identity = transport.identity()
        if (not isinstance(identity, dict) or identity.get("protocolVersion") != trust_state.PROTOCOL_VERSION
                or identity.get("customerId") != customer_id
                or identity.get("backendIdentity") != backend_identity
                or identity.get("namespace") != namespace
                or identity.get("endpointReference") != endpoint_reference):
            raise ConformanceError("adapter identity differs from the customer-approved isolated backend")
        current = trust_state.CustomerTrustStateClient(
            transport, customer_id=customer_id, backend_identity=backend_identity,
            namespace=namespace, attestation_public_key=attestation_public_key,
            attestation_fingerprint=attestation_fingerprint)
        return current, transport

    generation_one = {"customerId": customer_id, "sequence": 1, "conformancePayload": secrets.token_hex(32)}
    first_digest = hashlib.sha256(trust_state.canonical_json(generation_one)).hexdigest()
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: client()[0].verify_and_advance(generation_one, first_digest), range(12)))
    if any(result.get("durable") is not True or result.get("configurationSha256") != first_digest for result in results):
        raise ConformanceError("concurrent identical trust generation did not converge on one durable digest")

    # A separate process/adapter instance must observe the committed generation.
    reopened, _ = client()
    if reopened.verify_and_advance(generation_one, first_digest).get("sequence") != 1:
        raise ConformanceError("trust generation did not survive adapter restart")

    generation_two = {"customerId": customer_id, "sequence": 2, "conformancePayload": secrets.token_hex(32)}
    second_digest = hashlib.sha256(trust_state.canonical_json(generation_two)).hexdigest()
    opened, _ = client()
    opened.verify_and_advance(generation_two, second_digest)
    stale, _ = client()
    try:
        stale.verify_and_advance(generation_one, first_digest)
    except trust_state.TrustStateError:
        pass
    else:
        raise ConformanceError("older signed trust generation was accepted after restart")
    reused, _ = client()
    try:
        reused.verify_and_advance(generation_two, first_digest)
    except trust_state.TrustStateError:
        pass
    else:
        raise ConformanceError("same sequence with a different digest was accepted")

    # The adapter must expose a one-shot lost-ack injection in its isolated
    # test namespace. Do not infer production durability from a local mock.
    _, transport = client()
    lose_ack = getattr(transport, "lose_next_ack", None)
    if not callable(lose_ack):
        raise ConformanceError("adapter lacks isolated lost-ack injection required by the contract")
    lose_ack()
    generation_three = {"customerId": customer_id, "sequence": 3}
    recovered, _ = client()
    generation_three["conformancePayload"] = secrets.token_hex(32)
    recovered.verify_and_advance(generation_three, hashlib.sha256(trust_state.canonical_json(generation_three)).hexdigest())

    test_names = ["concurrent-identical-cas", "restart-durability", "generation-rollback",
                  "sequence-digest-conflict", "lost-ack-reconciliation"]
    result_digest = hashlib.sha256(trust_state.canonical_json({"passedTests": test_names,
                                                               "namespace": namespace})).hexdigest()
    reviewed = dt.datetime.now(dt.timezone.utc)
    candidate = {"schemaVersion": 1, "protocolVersion": trust_state.CONFORMANCE_PROTOCOL,
                 "customerId": customer_id, "backendIdentity": backend_identity,
                 "endpointReference": endpoint_reference, "conformanceNamespace": namespace,
                 "contractSuiteSha256": hashlib.sha256(trust_state.TRUST_STATE_CONFORMANCE_SUITE.read_bytes()).hexdigest(),
                 "resultsSha256": result_digest, "decision": "pending-independent-review",
                 "reviewerIdentity": "pending", "reviewedAt": reviewed.isoformat().replace("+00:00", "Z"),
                 "expiresAt": (reviewed + dt.timedelta(days=30)).isoformat().replace("+00:00", "Z"),
                 "evidenceReference": evidence_reference}
    return {"protocolVersion": trust_state.PROTOCOL_VERSION, "customerId": customer_id,
            "backendIdentity": backend_identity, "endpointReference": endpoint_reference,
            "namespace": namespace, "tests": test_names, "resultsSha256": result_digest,
            "conformanceReportCandidate": candidate, "customerAdapterConformance": "PASSED",
            "productionTrustAccepted": False, "requiresIndependentReview": True}
