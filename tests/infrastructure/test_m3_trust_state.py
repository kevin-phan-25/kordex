"""Synthetic Ed25519 receipts exercise the customer CAS client only; no production backend is implied."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m3_trust_state", ROOT / "scripts/m3_trust_state.py")
trust_state = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(trust_state)
CONFORMANCE_SPEC = importlib.util.spec_from_file_location("m3_trust_state_conformance", ROOT / "scripts/m3_trust_state_conformance.py")
conformance = importlib.util.module_from_spec(CONFORMANCE_SPEC)
assert CONFORMANCE_SPEC and CONFORMANCE_SPEC.loader
CONFORMANCE_SPEC.loader.exec_module(conformance)


class SyntheticCustomerCAS:
    def __init__(self, private_key: Path, public_key: bytes):
        self.private_key = private_key
        self.public_key = public_key
        self.sequence = 0
        self.digest = trust_state.EMPTY_DIGEST
        self.namespace = "qualification-production"
        self.lock = threading.Lock()
        self.fail_read = False
        self.lose_ack = False

    def identity(self):
        return {"protocolVersion": trust_state.PROTOCOL_VERSION, "customerId": "synthetic-customer",
                "backendIdentity": "synthetic-cas-backend", "namespace": self.namespace,
                "endpointReference": "https://fixture.invalid/cas"}

    def _signed(self, action, transition, status):
        now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        body = {"schemaVersion": 1, "protocolVersion": trust_state.PROTOCOL_VERSION, "action": action,
                "backendIdentity": "synthetic-cas-backend", "customerId": "synthetic-customer",
                "namespace": self.namespace, "transitionId": transition,
                "sequence": self.sequence, "configurationSha256": self.digest,
                "durable": True, "status": status, "observedAt": now, "recordedAt": now,
                "auditId": "synthetic-audit-001", "attestationFingerprint": trust_state.customer_trust.fingerprint(self.public_key)}
        with tempfile.TemporaryDirectory() as directory:
            payload, signature = Path(directory) / "payload", Path(directory) / "sig"
            payload.write_bytes(trust_state.canonical_json(body))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(self.private_key), "-rawin",
                            "-in", str(payload), "-out", str(signature)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            body["signature"] = signature.read_bytes().hex()
        return body

    def read_state(self, customer_id, namespace, transition_id):
        if self.fail_read:
            raise OSError("synthetic outage")
        if namespace != self.namespace:
            raise OSError("wrong namespace")
        with self.lock:
            return self._signed("read-state", transition_id, "current")

    def compare_and_swap(self, request):
        with self.lock:
            if request["namespace"] != self.namespace:
                raise OSError("wrong namespace")
            if (request["expectedSequence"] == self.sequence
                    and request["expectedConfigurationSha256"] == self.digest):
                self.sequence = request["newSequence"]
                self.digest = request["newConfigurationSha256"]
                receipt = self._signed("compare-and-swap", request["transitionId"], "committed")
                if self.lose_ack:
                    self.lose_ack = False
                    raise OSError("synthetic acknowledgement lost after commit")
                return receipt
            return self._signed("compare-and-swap", request["transitionId"], "conflict")

    def lose_next_ack(self):
        self.lose_ack = True


class TrustStateClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.private, self.public = root / "fixture.key", root / "fixture.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.key = self.public.read_bytes()
        self.transport = SyntheticCustomerCAS(self.private, self.key)
        self.client = self.new_client()

    def tearDown(self):
        self.temp.cleanup()

    def new_client(self, transport=None):
        return trust_state.CustomerTrustStateClient(
            transport or self.transport, customer_id="synthetic-customer", backend_identity="synthetic-cas-backend",
            namespace="qualification-production", attestation_public_key=self.key,
            attestation_fingerprint=trust_state.customer_trust.fingerprint(self.key))

    def document(self, sequence):
        return {"customerId": "synthetic-customer", "sequence": sequence}

    def sign(self, private_key: Path, payload: bytes) -> bytes:
        source, signature = Path(self.temp.name) / "signed-report", Path(self.temp.name) / "signed-report.sig"
        source.write_bytes(payload)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private_key), "-rawin",
                        "-in", str(source), "-out", str(signature)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return signature.read_bytes()

    def digest(self, document):
        import hashlib
        return hashlib.sha256(trust_state.customer_trust.canonical_json(document)).hexdigest()

    def test_verified_trust_snapshot_cannot_be_mutated_through_its_public_document(self):
        document = {"customerId": "synthetic-customer", "sequence": 1,
                    "keys": [{"identity": "synthetic-reviewer", "role": "reviewer"}]}
        digest = self.digest(document)
        snapshot = trust_state.VerifiedCustomerTrust(
            document, digest, self.client, "b" * 64, _token=trust_state._VERIFIED_TRUST_TOKEN)
        exposed = snapshot.document
        exposed["customerId"] = "attacker-selected-customer"
        self.assertEqual(snapshot.document["customerId"], "synthetic-customer")
        with self.assertRaises(AttributeError):
            snapshot.sha256 = "c" * 64
        with self.assertRaises(trust_state.TrustStateError):
            trust_state.VerifiedCustomerTrust(document, digest, self.client, "b" * 64)

    def test_customer_signed_compare_and_swap_advances_one_generation(self):
        document = self.document(1)
        digest = self.digest(document)
        result = self.client.verify_and_advance(document, digest)
        self.assertEqual(result, {"sequence": 1, "configurationSha256": digest, "durable": True})
        self.assertEqual(self.transport.sequence, 1)

    def test_rollback_and_same_sequence_different_digest_rejected(self):
        first, second = self.document(1), self.document(2)
        self.client.verify_and_advance(first, self.digest(first))
        self.client.verify_and_advance(second, self.digest(second))
        with self.assertRaisesRegex(trust_state.TrustStateError, "rollback"):
            self.client.verify_and_advance(first, self.digest(first))
        conflicting = dict(second, changedConfiguration="other")
        with self.assertRaisesRegex(trust_state.TrustStateError, "different digest"):
            self.client.verify_and_advance(conflicting, self.digest(conflicting))

    def test_lost_acknowledgement_is_resolved_by_one_signed_read(self):
        self.transport.lose_ack = True
        document = self.document(1)
        result = self.client.verify_and_advance(document, self.digest(document))
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(self.transport.sequence, 1)

    def test_backend_outage_and_unpinned_attestor_fail_closed(self):
        self.transport.fail_read = True
        with self.assertRaisesRegex(trust_state.TrustStateError, "unavailable"):
            document = self.document(1)
            self.client.verify_and_advance(document, self.digest(document))
        with self.assertRaisesRegex(trust_state.TrustStateError, "fingerprint"):
            trust_state.CustomerTrustStateClient(self.transport, customer_id="synthetic-customer",
                backend_identity="synthetic-cas-backend", attestation_public_key=self.key,
                namespace="qualification-production", attestation_fingerprint="0" * 64)

    def test_concurrent_conflicting_updates_have_one_generation_winner(self):
        import concurrent.futures
        def update(value):
            try:
                document = {"customerId": "synthetic-customer", "sequence": 1, "candidate": value[:4]}
                digest = self.digest(document)
                return self.new_client().verify_and_advance(document, digest)
            except trust_state.TrustStateError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(update, [f"{index:x}" * 64 for index in range(1, 9)]))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.transport.sequence, 1)

    def test_contract_harness_runs_only_in_a_synthetic_namespace_and_never_qualifies_production(self):
        adapter = SyntheticCustomerCAS(self.private, self.key)
        result = conformance.run_conformance(
            transport_factory=lambda namespace: setattr(adapter, "namespace", namespace) or adapter,
            customer_id="synthetic-customer", backend_identity="synthetic-cas-backend",
            endpoint_reference="https://fixture.invalid/cas", evidence_reference="synthetic-fixture",
            attestation_public_key=self.key,
            attestation_fingerprint=trust_state.customer_trust.fingerprint(self.key))
        self.assertEqual(result["customerAdapterConformance"], "PASSED")
        self.assertFalse(result["productionTrustAccepted"])
        self.assertTrue(result["namespace"].startswith("kordex-conformance-"))
        self.assertEqual(result["conformanceReportCandidate"]["decision"], "pending-independent-review")

    def test_root_trust_configuration_pins_one_attestor_and_distinct_reviewed_backend(self):
        reviewer_private, reviewer_public = Path(self.temp.name) / "reviewer.key", Path(self.temp.name) / "reviewer.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(reviewer_private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(reviewer_private), "-pubout", "-out", str(reviewer_public)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        reviewer_key = reviewer_public.read_bytes()
        now = dt.datetime.now(dt.timezone.utc)
        stamp = lambda delta: (now + delta).isoformat().replace("+00:00", "Z")
        key_record = lambda identity, role, key: {
            "identity": identity, "role": role,
            "fingerprint": trust_state.customer_trust.fingerprint(key), "publicKeyPem": key.decode(),
            "validFrom": stamp(-dt.timedelta(minutes=1)), "validUntil": stamp(dt.timedelta(days=3)), "revokedAt": None}
        document = {"schemaVersion": 1, "customerId": "synthetic-customer", "sequence": 1,
                    "issuedAt": stamp(-dt.timedelta(minutes=1)), "expiresAt": stamp(dt.timedelta(days=2)),
                    "keys": [key_record("synthetic-attestor", "trust-state-attestor", self.key),
                             key_record("synthetic-reviewer", "reviewer", reviewer_key)],
                    "trustState": {"backendIdentity": "synthetic-cas-backend", "namespace": "qualification-production",
                                   "endpointReference": "https://fixture.invalid/cas", "attestorIdentity": "synthetic-attestor",
                                   "conformanceReportSha256": "a" * 64, "conformanceReviewerIdentity": "synthetic-reviewer",
                                   "conformanceReviewedAt": stamp(-dt.timedelta(minutes=1)),
                                   "conformanceExpiresAt": stamp(dt.timedelta(days=1))}}
        report = {"schemaVersion": 1, "protocolVersion": trust_state.CONFORMANCE_PROTOCOL,
                  "customerId": "synthetic-customer", "backendIdentity": "synthetic-cas-backend",
                  "endpointReference": "https://fixture.invalid/cas", "conformanceNamespace": "kordex-conformance-synthetic",
                  "contractSuiteSha256": hashlib.sha256(trust_state.TRUST_STATE_CONFORMANCE_SUITE.read_bytes()).hexdigest(),
                  "resultsSha256": "b" * 64, "decision": "accepted", "reviewerIdentity": "synthetic-reviewer",
                  "reviewedAt": stamp(-dt.timedelta(minutes=1)), "expiresAt": stamp(dt.timedelta(days=1)),
                  "evidenceReference": "customer-change/42"}
        raw_report = trust_state.customer_trust.canonical_json(report)
        document["trustState"]["conformanceReportSha256"] = hashlib.sha256(raw_report).hexdigest()
        report_path = Path(self.temp.name) / "backend-conformance.json"
        signature_path = Path(self.temp.name) / "backend-conformance.sig"
        report_path.write_bytes(raw_report)
        signature_path.write_bytes(self.sign(reviewer_private, raw_report))
        trust_state.customer_trust.validate_document(document, now=now)
        self.assertEqual(trust_state.CustomerTrustStateClient._from_customer_trust_candidate(self.transport, document).namespace,
                         "qualification-production")
        self.assertEqual(trust_state.verify_customer_backend_conformance(document, report_path=report_path,
                                                                         signature_path=signature_path, now=now),
                         hashlib.sha256(raw_report).hexdigest())
        signature_path.write_bytes(b"x" * 64)
        with self.assertRaisesRegex(trust_state.TrustStateError, "conformance"):
            trust_state.verify_customer_backend_conformance(document, report_path=report_path,
                                                             signature_path=signature_path, now=now)
        duplicate = dict(document)
        duplicate["trustState"] = dict(document["trustState"], conformanceReviewerIdentity="synthetic-attestor")
        with self.assertRaises(trust_state.customer_trust.TrustError):
            trust_state.customer_trust.validate_document(duplicate, now=now)


if __name__ == "__main__":
    unittest.main()
