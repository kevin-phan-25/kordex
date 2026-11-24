"""Conformance checks for a customer-supplied durable trust-state CAS adapter.

The harness is an importable contract suite. Run it only against a dedicated
customer test namespace, never the production trust generation. Its result can
support independent backend review but is not production verification by itself.
"""

from __future__ import annotations

import datetime as dt
import copy
import hashlib
import re
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

try:
    import m3_trust_state as trust_state
except ModuleNotFoundError:
    from scripts import m3_trust_state as trust_state


class ConformanceError(ValueError):
    pass


class _FaultingTransport:
    """Read-only test wrapper used to prove the client fails closed on bad reads."""

    def __init__(self, wrapped, *, fault: str, stale_receipt: dict | None = None):
        self.wrapped = wrapped
        self.fault = fault
        self.stale_receipt = stale_receipt

    def identity(self):
        return self.wrapped.identity()

    def read_state(self, customer_id, namespace, transition_id):
        if self.fault == "unavailable":
            raise OSError("injected isolated conformance outage")
        if self.fault == "stale":
            return self.stale_receipt
        receipt = self.wrapped.read_state(customer_id, namespace, transition_id)
        if self.fault == "corrupt":
            damaged = dict(receipt)
            damaged["configurationSha256"] = "f" * 64
            return damaged
        return receipt

    def compare_and_swap(self, request):
        return self.wrapped.compare_and_swap(request)


def run_conformance(*, transport_factory, customer_id: str, backend_identity: str,
                    endpoint_reference: str, attestation_public_key: bytes,
                    attestation_fingerprint: str, evidence_reference: str,
                    conformance_root_public_key: bytes, sign_conformance_configuration,
                    trust_policy_document: dict, trust_policy_signature: bytes,
                    trust_policy_root_public_key: bytes) -> dict:
    """Exercise isolated namespace, atomic CAS, restart, replay and lost-ack behavior.

    ``transport_factory(namespace)`` must return a customer adapter whose
    durable state survives closing that instance and opening a new one. The
    test namespace must be explicitly isolated by the customer backend.
    """
    namespace = f"kordex-conformance-{uuid.uuid4()}"
    if not endpoint_reference.startswith("https://") or not evidence_reference:
        raise ConformanceError("customer HTTPS endpoint and evidence reference are required")
    policy_tests = _verify_trust_policy_cases(trust_policy_document, trust_policy_signature,
                                              trust_policy_root_public_key, customer_id)

    clients_used = []

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
        clients_used.append(current)
        return current, transport

    def candidate(sequence: int, payload: str) -> dict:
        return {"schemaVersion": 1, "customerId": customer_id, "sequence": sequence,
                "trustState": {"backendIdentity": backend_identity, "namespace": namespace},
                "conformancePayload": payload}

    def advance(current, document, digest_override=None):
        raw = trust_state.customer_trust.canonical_json(document)
        signature = sign_conformance_configuration(document)
        if not isinstance(signature, bytes):
            raise ConformanceError("conformance root signer must return detached signature bytes")
        try:
            trust_state.customer_trust.verify_signature(raw, signature, conformance_root_public_key)
        except trust_state.customer_trust.TrustError as error:
            raise ConformanceError("test trust configuration is not signed by the isolated conformance root") from error
        return current._advance_generation(document, digest_override or hashlib.sha256(raw).hexdigest(),
                                           root_signature=signature,
                                           root_public_key=conformance_root_public_key)

    generation_one = candidate(1, secrets.token_hex(32))
    first_digest = hashlib.sha256(trust_state.canonical_json(generation_one)).hexdigest()
    initial_client, initial_transport = client()
    transition_id = hashlib.sha256(trust_state.canonical_json({
        "protocolVersion": trust_state.PROTOCOL_VERSION, "customerId": customer_id,
        "backendIdentity": backend_identity, "namespace": namespace,
        "targetSequence": 1, "targetDigest": first_digest,
    })).hexdigest()[:32]
    initial_receipt = initial_client._verify_receipt(
        initial_transport.read_state(customer_id, namespace, transition_id),
        action="read-state", transition_id=transition_id)
    invalid_root_client, invalid_root_transport = client()
    try:
        invalid_root_client._advance_generation(
            generation_one, first_digest, root_signature=b"\x00" * 64,
            root_public_key=conformance_root_public_key)
    except trust_state.TrustStateError:
        pass
    else:
        raise ConformanceError("unsigned or invalid-root-signed trust update was accepted")
    if invalid_root_client._read(transition_id)["sequence"] != 0:
        raise ConformanceError("invalid root signature changed durable trust state")
    unauthenticated_request = {"schemaVersion": 1, "protocolVersion": trust_state.PROTOCOL_VERSION,
        "action": "compare-and-swap", "customerId": customer_id, "backendIdentity": backend_identity,
        "namespace": namespace, "transitionId": transition_id, "expectedSequence": 0,
        "expectedConfigurationSha256": trust_state.EMPTY_DIGEST, "newSequence": 1,
        "newConfigurationSha256": first_digest, "configuration": generation_one,
        "rootFingerprint": trust_state.customer_trust.fingerprint(conformance_root_public_key),
        "rootSignatureSha256": hashlib.sha256(b"\x00" * 64).hexdigest(),
        "rootSignature": (b"\x00" * 64).hex()}
    try:
        invalid_root_transport.compare_and_swap(unauthenticated_request)
    except Exception:
        pass
    else:
        raise ConformanceError("backend accepted an unauthenticated trust-state update request")
    if invalid_root_client._read(transition_id)["sequence"] != 0:
        raise ConformanceError("unauthenticated backend update changed durable trust state")
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: advance(client()[0], generation_one), range(12)))
    if any(result.get("durable") is not True or result.get("configurationSha256") != first_digest for result in results):
        raise ConformanceError("concurrent identical trust generation did not converge on one durable digest")
    test_client, test_transport = client()
    for fault in ("unavailable", "stale", "corrupt"):
        faulty = _FaultingTransport(test_transport, fault=fault,
                                    stale_receipt=initial_receipt if fault == "stale" else None)
        guarded = trust_state.CustomerTrustStateClient(
            faulty, customer_id=customer_id, backend_identity=backend_identity, namespace=namespace,
            attestation_public_key=attestation_public_key, attestation_fingerprint=attestation_fingerprint)
        try:
            advance(guarded, generation_one)
        except trust_state.TrustStateError:
            pass
        else:
            raise ConformanceError(f"client accepted {fault} trust-state response")
    try:
        test_client._advance_generation(generation_one, "0" * 64,
                                        root_signature=b"invalid",
                                        root_public_key=conformance_root_public_key)
    except trust_state.TrustStateError:
        pass
    else:
        raise ConformanceError("trust configuration digest mismatch was accepted")

    # A separate process/adapter instance must observe the committed generation.
    reopened, _ = client()
    if advance(reopened, generation_one).get("sequence") != 1:
        raise ConformanceError("trust generation did not survive adapter restart")

    generation_two = candidate(2, secrets.token_hex(32))
    second_digest = hashlib.sha256(trust_state.canonical_json(generation_two)).hexdigest()
    opened, _ = client()
    advance(opened, generation_two)
    stale, _ = client()
    try:
        advance(stale, generation_one)
    except trust_state.TrustStateError:
        pass
    else:
        raise ConformanceError("older signed trust generation was accepted after restart")
    reused, _ = client()
    try:
        advance(reused, generation_two, digest_override=first_digest)
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
    generation_three = candidate(3, secrets.token_hex(32))
    recovered, _ = client()
    advance(recovered, generation_three)

    # An invalid expected version must be an authenticated conflict and must
    # leave the durable generation unchanged.
    before = reopened._read(transition_id)
    rejected_document = generation_two
    rejected_raw = trust_state.customer_trust.canonical_json(rejected_document)
    rejected_signature = sign_conformance_configuration(rejected_document)
    rejected_transition = hashlib.sha256(trust_state.canonical_json({
        "protocolVersion": trust_state.PROTOCOL_VERSION, "customerId": customer_id,
        "backendIdentity": backend_identity, "namespace": namespace,
        "targetSequence": 2, "targetDigest": second_digest,
    })).hexdigest()[:32]
    rejected_request = {"schemaVersion": 1, "protocolVersion": trust_state.PROTOCOL_VERSION,
                        "action": "compare-and-swap", "customerId": customer_id,
                        "backendIdentity": backend_identity, "namespace": namespace,
                        "transitionId": rejected_transition, "expectedSequence": 0,
                        "expectedConfigurationSha256": trust_state.EMPTY_DIGEST,
                        "newSequence": 2, "newConfigurationSha256": second_digest,
                        "configuration": rejected_document,
                        "rootFingerprint": trust_state.customer_trust.fingerprint(conformance_root_public_key),
                        "rootSignatureSha256": hashlib.sha256(rejected_signature).hexdigest(),
                        "rootSignature": rejected_signature.hex()}
    conflict = test_transport.compare_and_swap(rejected_request)
    conflict_body = test_client._verify_receipt(conflict, action="compare-and-swap", transition_id=rejected_transition)
    if conflict_body["status"] != "conflict" or conflict_body["sequence"] != before["sequence"]:
        raise ConformanceError("unauthorized stale-version update changed the durable trust state")

    test_names = ["initial-empty-generation", "invalid-root-signature-rejected",
                  "backend-unauthorized-trust-update-rejected",
                  "root-authorized-test-generation",
                  "valid-consecutive-generation", "concurrent-identical-cas", "restart-durability",
                  "generation-rollback", "sequence-digest-conflict", "configuration-digest-mismatch",
                  "backend-unavailable-fail-closed", "stale-state-fail-closed", "corrupt-receipt-fail-closed",
                  "unauthorized-stale-cas-conflict", "lost-ack-reconciliation", "signed-audit-receipts"]
    audit_events = [event for current in clients_used for event in current.audit_events]
    audit_ids = [event["auditId"] for event in audit_events]
    if (not audit_events or len(audit_ids) != len(set(audit_ids))
            or any(set(event) != {"action", "backendIdentity", "customerId", "namespace", "transitionId",
                                  "sequence", "configurationSha256", "auditId", "observedAt", "recordedAt",
                                  "attestationFingerprint", "rootFingerprint", "rootSignatureSha256"}
                   for event in audit_events)):
        raise ConformanceError("signed trust-state audit events are missing, duplicated, or incomplete")
    result_document = {"passedTests": test_names, "trustPolicyTests": policy_tests,
                       "namespace": namespace,
                       "auditEvents": audit_events,
                       "conformanceRootFingerprint": trust_state.customer_trust.fingerprint(conformance_root_public_key),
                       "attestationFingerprint": attestation_fingerprint}
    result_digest = hashlib.sha256(trust_state.canonical_json(result_document)).hexdigest()
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
            "namespace": namespace, "tests": test_names, "auditEvents": audit_events,
            "trustPolicyTests": policy_tests,
            "resultsSha256": result_digest,
            "conformanceRootFingerprint": result_document["conformanceRootFingerprint"],
            "conformanceReportCandidate": candidate, "backendContractChecks": "EXECUTED",
            "customerAdapterConformance": "NOT ESTABLISHED",
            "unitOrFixtureExecution": bool(re.match(r"(?i)^(fixture|synthetic|test)[-_:/.]", evidence_reference)),
            "productionTrustAccepted": False, "requiresIndependentReview": True}


def _verify_trust_policy_cases(document: dict, signature: bytes, root_public_key: bytes,
                               customer_id: str) -> list[str]:
    """Check root-signed policy and role rejection paths using owner-supplied material."""
    current = dt.datetime.now(dt.timezone.utc)
    raw = trust_state.customer_trust.canonical_json(document)
    try:
        trust_state.customer_trust.verify_signature(raw, signature, root_public_key)
        trust_state.customer_trust.validate_document(document, now=current)
    except trust_state.customer_trust.TrustError as error:
        raise ConformanceError("supplied trust-policy test input is not a current root-signed configuration") from error
    if document.get("customerId") != customer_id:
        raise ConformanceError("trust-policy test input is bound to another customer")
    tests = ["root-signed-policy-accepted"]
    try:
        trust_state.customer_trust.verify_signature(raw + b" ", signature, root_public_key)
    except trust_state.customer_trust.TrustError:
        tests.append("invalid-root-signature-rejected")
    else:
        raise ConformanceError("modified root-signed trust configuration was accepted")
    invalid_cases = [
        ("expired-trust-configuration-rejected", lambda candidate: candidate.update(
            expiresAt=(current - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z"))),
        ("expired-role-rejected", lambda candidate: candidate["keys"][0].update(
            validUntil=(current - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z"))),
        ("revoked-role-rejected", lambda candidate: candidate["keys"][0].update(
            revokedAt=(current - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z"))),
        ("duplicate-role-identity-rejected", lambda candidate: candidate["keys"].append(
            copy.deepcopy(candidate["keys"][0]))),
        ("signer-verifier-conflict-rejected", lambda candidate: candidate["releaseLockVerification"].update(
            verifierIdentity=candidate["releaseLockSigning"]["signerIdentity"],
            verifierFingerprint=candidate["releaseLockSigning"]["signerFingerprint"])),
        ("reviewer-signer-conflict-rejected", lambda candidate: candidate["trustState"].update(
            conformanceReviewerIdentity=candidate["releaseLockSigning"]["signerIdentity"])),
        ("expired-conformance-review-rejected", lambda candidate: candidate["trustState"].update(
            conformanceExpiresAt=(current - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z"))),
        ("missing-trust-state-rejected", lambda candidate: candidate.pop("trustState")),
    ]
    for name, mutate in invalid_cases:
        candidate = copy.deepcopy(document)
        mutate(candidate)
        try:
            if not isinstance(candidate.get("trustState"), dict):
                raise trust_state.customer_trust.TrustError("durable trust state is required")
            trust_state.customer_trust.validate_document(candidate, now=current)
        except trust_state.customer_trust.TrustError:
            tests.append(name)
        else:
            raise ConformanceError(f"trust policy accepted invalid case: {name}")
    return tests
