"""Synthetic Ed25519 receipts exercise the customer CAS client only; no production backend is implied."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

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
    def __init__(self, private_key: Path, public_key: bytes, root_public_key: bytes):
        self.private_key = private_key
        self.public_key = public_key
        self.root_public_key = root_public_key
        self.sequence = 0
        self.digest = trust_state.EMPTY_DIGEST
        self.root_fingerprint = trust_state.EMPTY_DIGEST
        self.root_signature_sha256 = trust_state.EMPTY_DIGEST
        self.namespace = "qualification-production"
        self.lock = threading.Lock()
        self.fail_read = False
        self.lose_ack = False
        self.audit_counter = 0

    def identity(self):
        return {"protocolVersion": trust_state.PROTOCOL_VERSION, "customerId": "synthetic-customer",
                "backendIdentity": "synthetic-cas-backend", "namespace": self.namespace,
                "endpointReference": "https://fixture.invalid/cas"}

    def _signed(self, action, transition, status):
        self.audit_counter += 1
        now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        body = {"schemaVersion": 1, "protocolVersion": trust_state.PROTOCOL_VERSION, "action": action,
                "backendIdentity": "synthetic-cas-backend", "customerId": "synthetic-customer",
                "namespace": self.namespace, "transitionId": transition,
                "sequence": self.sequence, "configurationSha256": self.digest,
                "durable": True, "status": status, "observedAt": now, "recordedAt": now,
                "auditId": f"synthetic-audit-{self.audit_counter:06d}",
                "attestationFingerprint": trust_state.customer_trust.fingerprint(self.public_key),
                "rootFingerprint": self.root_fingerprint,
                "rootSignatureSha256": self.root_signature_sha256}
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
            config_raw = trust_state.customer_trust.canonical_json(request["configuration"])
            if (hashlib.sha256(config_raw).hexdigest() != request["newConfigurationSha256"]
                    or request["rootFingerprint"] != trust_state.customer_trust.fingerprint(self.root_public_key)
                    or request["rootSignatureSha256"] != hashlib.sha256(
                        bytes.fromhex(request["rootSignature"])).hexdigest()):
                raise OSError("root authorization binding invalid")
            trust_state.customer_trust.verify_signature(config_raw, bytes.fromhex(request["rootSignature"]),
                                                        self.root_public_key)
            if (request["configuration"].get("sequence") != request["newSequence"]
                    or request["configuration"].get("trustState", {}).get("backendIdentity") != "synthetic-cas-backend"
                    or request["configuration"].get("trustState", {}).get("namespace") != self.namespace):
                raise OSError("root-authorized configuration target mismatch")
            expected_transition = hashlib.sha256(trust_state.canonical_json({
                "protocolVersion": trust_state.PROTOCOL_VERSION,
                "customerId": request["customerId"], "backendIdentity": request["backendIdentity"],
                "namespace": request["namespace"], "targetSequence": request["newSequence"],
                "targetDigest": request["newConfigurationSha256"],
            })).hexdigest()[:32]
            if request["transitionId"] != expected_transition:
                raise OSError("transition identity mismatch")
            if (request["expectedSequence"] == self.sequence
                    and request["expectedConfigurationSha256"] == self.digest):
                self.sequence = request["newSequence"]
                self.digest = request["newConfigurationSha256"]
                self.root_fingerprint = request["rootFingerprint"]
                self.root_signature_sha256 = request["rootSignatureSha256"]
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
        self.root_private, self.root_public = root / "root.key", root / "root.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.root_private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(self.root_private), "-pubout", "-out", str(self.root_public)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.key = self.public.read_bytes()
        self.root_key = self.root_public.read_bytes()
        self.transport = SyntheticCustomerCAS(self.private, self.key, self.root_key)
        self.client = self.new_client()

    def tearDown(self):
        self.temp.cleanup()

    def new_client(self, transport=None):
        return trust_state.CustomerTrustStateClient(
            transport or self.transport, customer_id="synthetic-customer", backend_identity="synthetic-cas-backend",
            namespace="qualification-production", attestation_public_key=self.key,
            attestation_fingerprint=trust_state.customer_trust.fingerprint(self.key))

    def document(self, sequence):
        return {"customerId": "synthetic-customer", "sequence": sequence,
                "trustState": {"backendIdentity": "synthetic-cas-backend",
                               "namespace": "qualification-production"}}

    def advance(self, client, document):
        return client._advance_generation(document, self.digest(document),
                                          root_signature=self.sign(self.root_private,
                                              trust_state.customer_trust.canonical_json(document)),
                                          root_public_key=self.root_key)

    def sign(self, private_key: Path, payload: bytes) -> bytes:
        source, signature = Path(self.temp.name) / f"signed-report-{uuid.uuid4()}", Path(self.temp.name) / f"signed-report-{uuid.uuid4()}.sig"
        source.write_bytes(payload)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private_key), "-rawin",
                        "-in", str(source), "-out", str(signature)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return signature.read_bytes()

    def policy_fixture(self):
        now = dt.datetime.now(dt.timezone.utc)
        stamp = lambda delta: (now + delta).isoformat().replace("+00:00", "Z")
        records, private = [], {}
        roles = {"release-signer": "release-lock-signer", "release-verifier": "release-lock-verifier",
                 "artifact-reviewer": "reviewer", "artifact-owner": "artifact-owner",
                 "artifact-signer": "artifact-signer", "security-custodian": "security-custodian",
                 "trust-attestor": "trust-state-attestor"}
        for identity, role in roles.items():
            key_path = Path(self.temp.name) / f"{identity}.key"
            public_path = Path(self.temp.name) / f"{identity}.pub"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key_path)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "pkey", "-in", str(key_path), "-pubout", "-out", str(public_path)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            public = public_path.read_bytes()
            private[identity] = key_path
            records.append({"identity": identity, "role": role,
                "fingerprint": trust_state.customer_trust.fingerprint(public), "publicKeyPem": public.decode(),
                "validFrom": stamp(-dt.timedelta(minutes=1)), "validUntil": stamp(dt.timedelta(days=3)),
                "revokedAt": None})
        record_by_id = {item["identity"]: item for item in records}
        document = {"schemaVersion": 1, "customerId": "synthetic-customer", "sequence": 1,
            "issuedAt": stamp(-dt.timedelta(minutes=1)), "expiresAt": stamp(dt.timedelta(days=2)),
            "keys": records,
            "releaseLockSigning": {"signerIdentity": "release-signer",
                "signerFingerprint": record_by_id["release-signer"]["fingerprint"],
                "signerSourceCommit": "a" * 40, "verifierSourceCommit": "b" * 40},
            "releaseLockVerification": {"verifierIdentity": "release-verifier",
                "verifierFingerprint": record_by_id["release-verifier"]["fingerprint"],
                "sourceCommit": "b" * 40},
            "trustState": {"backendIdentity": "synthetic-cas-backend", "namespace": "qualification-production",
                "endpointReference": "https://fixture.invalid/cas", "attestorIdentity": "trust-attestor",
                "adapterDistribution": "fixture-cas-adapter", "adapterVersion": "1.0.0",
                "adapterTreeSha256": "a" * 64, "conformanceReportSha256": "b" * 64,
                "conformanceReviewerIdentity": "artifact-reviewer",
                "conformanceReviewedAt": stamp(-dt.timedelta(minutes=1)),
                "conformanceExpiresAt": stamp(dt.timedelta(days=1))}}
        raw = trust_state.customer_trust.canonical_json(document)
        signature = self.sign(self.root_private, raw)
        return document, signature

    def digest(self, document):
        import hashlib
        return hashlib.sha256(trust_state.customer_trust.canonical_json(document)).hexdigest()

    def test_verified_trust_snapshot_cannot_be_mutated_through_its_public_document(self):
        document = {"customerId": "synthetic-customer", "sequence": 1,
                    "keys": [{"identity": "synthetic-reviewer", "role": "reviewer"}]}
        digest = self.digest(document)
        snapshot = trust_state.VerifiedCustomerTrust(
            document, digest, self.client, "b" * 64,
            {"sequence": 1, "configurationSha256": digest, "durable": True,
             "backendIdentity": "synthetic-cas-backend", "namespace": "qualification-production",
             "attestationFingerprint": "c" * 64, "rootFingerprint": "d" * 64,
             "rootSignatureSha256": "e" * 64, "auditIds": ["synthetic-audit-001"]},
            _token=trust_state._VERIFIED_TRUST_TOKEN)
        exposed = snapshot.document
        exposed["customerId"] = "attacker-selected-customer"
        self.assertEqual(snapshot.document["customerId"], "synthetic-customer")
        with self.assertRaises(AttributeError):
            snapshot.sha256 = "c" * 64
        with self.assertRaises(trust_state.TrustStateError):
            trust_state.VerifiedCustomerTrust(document, digest, self.client, "b" * 64, {})

    def test_production_loader_requires_one_root_pinned_installed_adapter(self):
        settings = {"adapterDistribution": "customer-trust-adapter", "adapterVersion": "2.4.1",
                    "adapterTreeSha256": "a" * 64,
                    "backendIdentity": "synthetic-cas-backend", "namespace": "qualification-production",
                    "endpointReference": "https://fixture.invalid/cas"}
        document = {"customerId": "synthetic-customer", "sequence": 1, "trustState": settings}
        digest = hashlib.sha256(trust_state.customer_trust.canonical_json(document)).hexdigest()
        snapshot = trust_state.VerifiedCustomerTrust(
            document, digest, self.client, "b" * 64,
            {"sequence": 1, "configurationSha256": digest, "durable": True,
             "backendIdentity": "synthetic-cas-backend", "namespace": "qualification-production",
             "attestationFingerprint": "c" * 64, "rootFingerprint": "d" * 64,
             "rootSignatureSha256": "e" * 64, "auditIds": ["synthetic-audit-000001"]},
            _token=trust_state._VERIFIED_TRUST_TOKEN)
        loaded_settings = []
        entry = SimpleNamespace(name="customer",
            dist=SimpleNamespace(name="customer-trust-adapter", version="2.4.1"),
            load=lambda: lambda value: loaded_settings.append(value) or self.transport)
        with patch.object(trust_state, "verify_customer_backend_conformance", return_value="b" * 64), \
             patch.object(trust_state, "adapter_distribution_sha256", return_value="a" * 64), \
             patch.object(trust_state.customer_trust, "load_signed_trust_candidate",
                          return_value=(document, digest)), \
             patch.object(trust_state, "_entry_points", return_value=[entry]), \
             patch.object(trust_state, "_load_customer_trust_with_transport", return_value=snapshot):
            result = trust_state.load_production_customer_trust()
        self.assertIs(result, snapshot)
        self.assertEqual(loaded_settings, [settings])

    def test_public_production_loader_cannot_select_a_caller_supplied_transport(self):
        with self.assertRaises(TypeError):
            trust_state.load_customer_trust(self.transport)

    def test_production_loader_rejects_missing_duplicate_or_wrong_adapter_package(self):
        settings = {"adapterDistribution": "customer-trust-adapter", "adapterVersion": "2.4.1",
                    "adapterTreeSha256": "a" * 64}
        document = {"customerId": "synthetic-customer", "sequence": 1, "trustState": settings}
        digest = hashlib.sha256(trust_state.customer_trust.canonical_json(document)).hexdigest()
        with patch.object(trust_state, "verify_customer_backend_conformance", return_value="b" * 64), \
             patch.object(trust_state.customer_trust, "load_signed_trust_candidate",
                          return_value=(document, digest)), patch.object(trust_state, "_entry_points", return_value=[]):
            with self.assertRaisesRegex(trust_state.TrustStateError, "exactly one"):
                trust_state.load_production_customer_trust()
        wrong = SimpleNamespace(name="customer", dist=SimpleNamespace(name="other-adapter", version="2.4.1"),
                                load=lambda: self.fail("mismatched adapter must not be imported"))
        with patch.object(trust_state, "verify_customer_backend_conformance", return_value="b" * 64), \
             patch.object(trust_state.customer_trust, "load_signed_trust_candidate",
                          return_value=(document, digest)), patch.object(trust_state, "_entry_points", return_value=[wrong]):
            with self.assertRaisesRegex(trust_state.TrustStateError, "differs from root-authorized"):
                trust_state.load_production_customer_trust()

    def test_customer_trust_wrapper_records_exact_durable_version_without_secret_material(self):
        document = {"customerId": "synthetic-customer", "sequence": 1}
        digest = hashlib.sha256(trust_state.customer_trust.canonical_json(document)).hexdigest()
        state = {"sequence": 1, "configurationSha256": digest, "durable": True,
                 "backendIdentity": "synthetic-cas-backend", "namespace": "qualification-production",
                 "attestationFingerprint": "c" * 64, "rootFingerprint": "d" * 64,
                 "rootSignatureSha256": "e" * 64, "auditIds": ["synthetic-audit-000002"]}
        snapshot = trust_state.VerifiedCustomerTrust(document, digest, self.client, "f" * 64, state,
            _token=trust_state._VERIFIED_TRUST_TOKEN)
        production_trust_state = SimpleNamespace(load_production_customer_trust=lambda **_kwargs: snapshot)
        with patch.object(trust_state.customer_trust, "load_signed_trust_candidate",
                          return_value=(document, digest)), \
             patch.dict("sys.modules", {"m3_trust_state": production_trust_state}), \
             patch.object(trust_state.customer_trust.LOG, "info") as log_info:
            result = trust_state.customer_trust.load_trust()
        self.assertEqual(result, (document, digest))
        event = log_info.call_args.kwargs["extra"]["trust_state_load"]
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["configurationSha256"], digest)
        self.assertEqual(event["rootFingerprint"], "d" * 64)
        self.assertEqual(event["auditIds"], ["synthetic-audit-000002"])
        self.assertNotIn("privateKey", event)

    def test_adapter_distribution_integrity_hash_is_deterministic_and_detects_changes(self):
        root = Path(self.temp.name) / "adapter-dist"
        (root / "customer_adapter").mkdir(parents=True)
        # Ensure directories have restrictive permissions regardless of umask,
        # since adapter_distribution_sha256 rejects group/world-writable roots.
        root.chmod(0o755)
        (root / "customer_adapter").chmod(0o755)
        module = root / "customer_adapter" / "__init__.py"
        module.write_text("# fixture adapter package\n", encoding="utf-8")
        module.chmod(0o644)
        distribution = SimpleNamespace(files=[Path("customer_adapter/__init__.py")],
                                        locate_file=lambda value: root / value)
        first = trust_state.adapter_distribution_sha256(distribution, owner_uid=os.geteuid())
        self.assertEqual(first, trust_state.adapter_distribution_sha256(distribution, owner_uid=os.geteuid()))
        module.write_text("# changed fixture adapter package\n", encoding="utf-8")
        module.chmod(0o644)
        self.assertNotEqual(first, trust_state.adapter_distribution_sha256(distribution, owner_uid=os.geteuid()))
        module.chmod(0o666)
        with self.assertRaisesRegex(trust_state.TrustStateError, "unsafe|not protected"):
            trust_state.adapter_distribution_sha256(distribution, owner_uid=os.geteuid())

    def test_customer_signed_compare_and_swap_advances_one_generation(self):
        document = self.document(1)
        digest = self.digest(document)
        result = self.advance(self.client, document)
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(result["configurationSha256"], digest)
        self.assertEqual(result["durable"], True)
        self.assertEqual(result["backendIdentity"], "synthetic-cas-backend")
        self.assertTrue(result["auditIds"])
        self.assertEqual(len(self.client.audit_events), 2)
        with self.assertRaisesRegex(trust_state.TrustStateError, "root-authorized"):
            self.client.verify_and_advance(document, digest, root_signature=b"", root_public_key=self.root_key)
        self.assertEqual(self.transport.sequence, 1)

    def test_backend_rejects_cas_without_root_authorized_configuration(self):
        document = self.document(1)
        digest = self.digest(document)
        request = {"schemaVersion": 1, "protocolVersion": trust_state.PROTOCOL_VERSION,
                   "action": "compare-and-swap", "customerId": "synthetic-customer",
                   "backendIdentity": "synthetic-cas-backend", "namespace": "qualification-production",
                   "transitionId": "a" * 32, "expectedSequence": 0,
                   "expectedConfigurationSha256": trust_state.EMPTY_DIGEST,
                   "newSequence": 1, "newConfigurationSha256": digest,
                   "configuration": document,
                   "rootFingerprint": trust_state.customer_trust.fingerprint(self.root_key),
                   "rootSignatureSha256": hashlib.sha256(b"\x00" * 64).hexdigest(),
                   "rootSignature": (b"\x00" * 64).hex()}
        with self.assertRaises(trust_state.customer_trust.TrustError):
            self.transport.compare_and_swap(request)
        self.assertEqual(self.transport.sequence, 0)

    def test_rollback_and_same_sequence_different_digest_rejected(self):
        first, second = self.document(1), self.document(2)
        self.advance(self.client, first)
        self.advance(self.client, second)
        with self.assertRaisesRegex(trust_state.TrustStateError, "rollback"):
            self.advance(self.client, first)
        conflicting = dict(second, changedConfiguration="other")
        with self.assertRaisesRegex(trust_state.TrustStateError, "different digest"):
            self.advance(self.client, conflicting)

    def test_same_generation_with_different_root_signature_identity_is_rejected(self):
        document = self.document(1)
        self.advance(self.client, document)
        other_private, other_public_path = Path(self.temp.name) / "other-root.key", Path(self.temp.name) / "other-root.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(other_private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(other_private), "-pubout", "-out", str(other_public_path)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        other_signature = self.sign(other_private, trust_state.customer_trust.canonical_json(document))
        with self.assertRaisesRegex(trust_state.TrustStateError, "different digest or root signature"):
            self.client._advance_generation(document, self.digest(document),
                root_signature=other_signature, root_public_key=other_public_path.read_bytes())

    def test_lost_acknowledgement_is_resolved_by_one_signed_read(self):
        self.transport.lose_ack = True
        document = self.document(1)
        result = self.advance(self.client, document)
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(self.transport.sequence, 1)

    def test_backend_outage_and_unpinned_attestor_fail_closed(self):
        self.transport.fail_read = True
        with self.assertRaisesRegex(trust_state.TrustStateError, "unavailable"):
            document = self.document(1)
            self.advance(self.client, document)
        with self.assertRaisesRegex(trust_state.TrustStateError, "fingerprint"):
            trust_state.CustomerTrustStateClient(self.transport, customer_id="synthetic-customer",
                backend_identity="synthetic-cas-backend", attestation_public_key=self.key,
                namespace="qualification-production", attestation_fingerprint="0" * 64)

    def test_concurrent_conflicting_updates_have_one_generation_winner(self):
        import concurrent.futures
        def update(value):
            try:
                document = {"customerId": "synthetic-customer", "sequence": 1,
                            "trustState": {"backendIdentity": "synthetic-cas-backend",
                                           "namespace": "qualification-production"},
                            "candidate": value[:4]}
                digest = self.digest(document)
                return self.advance(self.new_client(), document)
            except trust_state.TrustStateError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(update, [f"{index:x}" * 64 for index in range(1, 9)]))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.transport.sequence, 1)

    def test_contract_harness_runs_only_in_a_synthetic_namespace_and_never_qualifies_production(self):
        adapter = SyntheticCustomerCAS(self.private, self.key, self.root_key)
        policy, policy_signature = self.policy_fixture()
        result = conformance.run_conformance(
            transport_factory=lambda namespace: setattr(adapter, "namespace", namespace) or adapter,
            customer_id="synthetic-customer", backend_identity="synthetic-cas-backend",
            endpoint_reference="https://fixture.invalid/cas", evidence_reference="synthetic-fixture",
            attestation_public_key=self.key,
            attestation_fingerprint=trust_state.customer_trust.fingerprint(self.key),
            conformance_root_public_key=self.root_key,
            sign_conformance_configuration=lambda document: self.sign(
                self.root_private, trust_state.customer_trust.canonical_json(document)),
            trust_policy_document=policy, trust_policy_signature=policy_signature,
            trust_policy_root_public_key=self.root_key)
        self.assertEqual(result["backendContractChecks"], "EXECUTED")
        self.assertEqual(result["customerAdapterConformance"], "NOT ESTABLISHED")
        self.assertFalse(result["productionTrustAccepted"])
        self.assertTrue(result["namespace"].startswith("kordex-conformance-"))
        self.assertEqual(result["conformanceReportCandidate"]["decision"], "pending-independent-review")
        self.assertTrue(result["unitOrFixtureExecution"])
        self.assertFalse(result["productionTrustAccepted"])

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
                                   "adapterDistribution": "kordex-fixture-adapter", "adapterVersion": "1.0.0",
                                   "adapterTreeSha256": "a" * 64,
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
        expired = json.loads(json.dumps(document))
        expired["keys"][0]["validUntil"] = stamp(-dt.timedelta(seconds=1))
        with self.assertRaisesRegex(trust_state.customer_trust.TrustError, "expired"):
            trust_state.customer_trust.validate_document(expired, now=now)
        revoked = json.loads(json.dumps(document))
        revoked["keys"][1]["revokedAt"] = stamp(-dt.timedelta(seconds=1))
        with self.assertRaisesRegex(trust_state.customer_trust.TrustError, "revoked"):
            trust_state.customer_trust.validate_document(revoked, now=now)
        duplicate = json.loads(json.dumps(document))
        duplicate["keys"].append(dict(duplicate["keys"][0]))
        with self.assertRaisesRegex(trust_state.customer_trust.TrustError, "duplicate"):
            trust_state.customer_trust.validate_document(duplicate, now=now)
        shared = json.loads(json.dumps(document))
        shared["trustState"]["conformanceReviewerIdentity"] = "synthetic-attestor"
        with self.assertRaisesRegex(trust_state.customer_trust.TrustError, "distinct"):
            trust_state.customer_trust.validate_document(shared, now=now)
        wrong_adapter = json.loads(json.dumps(document))
        wrong_adapter["trustState"]["adapterTreeSha256"] = "not-a-digest"
        with self.assertRaisesRegex(trust_state.customer_trust.TrustError, "configuration"):
            trust_state.customer_trust.validate_document(wrong_adapter, now=now)
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
