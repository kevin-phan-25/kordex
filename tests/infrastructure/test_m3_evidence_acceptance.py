"""Synthetic-only acceptance tests. Fixtures cannot be used as M3 evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
import copy
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m3_evidence_acceptance", ROOT / "scripts/verify-m3-evidence-provenance.py")
acceptance = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(acceptance)


class SyntheticAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.keys = {}
        records = []
        for identity, role in (("collector-fixture", "collector"), ("reviewer-fixture", "reviewer"),
                               ("custodian-fixture", "corroborator"), ("registry-fixture", "replay-registry")):
            private, public = self.make_key(identity)
            fingerprint = acceptance.public_key_fingerprint(public)
            self.keys[identity] = (private, public, fingerprint)
            records.append({"identity": identity, "role": role, "fingerprint": fingerprint,
                            "publicKeyPem": public.read_text(), "validFrom": (self.now-dt.timedelta(days=1)).isoformat(),
                            "validUntil": (self.now+dt.timedelta(days=10)).isoformat(), "revokedAt": None})
        reviewed = self.now - dt.timedelta(minutes=5)
        expires = self.now + dt.timedelta(days=10)
        self.registry_report = {"schemaVersion": 1, "protocolVersion": acceptance.REPLAY_CONFORMANCE_PROTOCOL,
            "registryUrl": "https://registry.customer.invalid/v1/claims", "registryIdentity": "registry-fixture",
            "contractSuiteSha256": hashlib.sha256(acceptance.read_file(acceptance.REPLAY_CONFORMANCE_SUITE)).hexdigest(),
            "resultsSha256": "2" * 64, "decision": "accepted",
            "reviewerIdentity": "reviewer-fixture", "reviewedAt": reviewed.isoformat(),
            "expiresAt": expires.isoformat(), "evidenceReference": "customer-change/replay-registry-review-42"}
        self.registry_report_raw = acceptance.canonical_json(self.registry_report)
        self.registry_report_path = self.root / "replay-registry-conformance.json"
        self.registry_signature_path = self.root / "replay-registry-conformance.json.sig"
        self.registry_report_path.write_bytes(self.registry_report_raw)
        self.registry_signature_path.write_bytes(self.sign(self.keys["reviewer-fixture"][0], self.registry_report_raw))
        self.trust = {"schemaVersion": 1, "customerId": "synthetic-fixture-customer", "sequence": 1,
                      "issuedAt": (self.now-dt.timedelta(hours=1)).isoformat(),
                      "expiresAt": (self.now+dt.timedelta(days=2)).isoformat(), "keys": records,
                      "replayRegistry": {"url": "https://registry.customer.invalid/v1/claims",
                                         "identity": "registry-fixture",
                                         "conformanceReportSha256": hashlib.sha256(self.registry_report_raw).hexdigest(),
                                         "conformanceReviewerIdentity": "reviewer-fixture",
                                         "conformanceReviewedAt": reviewed.isoformat(),
                                         "conformanceExpiresAt": expires.isoformat()}}
        self.trust_digest = hashlib.sha256(acceptance.canonical_json(self.trust)).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def make_key(self, name):
        private, public = self.root / f"{name}.private.pem", self.root / f"{name}.public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return private, public

    def sign(self, private: Path, payload: bytes) -> bytes:
        source, signature = self.root / "payload", self.root / "payload.sig"
        source.write_bytes(payload)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private), "-rawin",
                        "-in", str(source), "-out", str(signature)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return signature.read_bytes()

    def test_root_anchored_trust_rejects_caller_selected_key_and_unknown_role(self):
        root_private, root_public = self.make_key("customer-root-fixture")
        raw = acceptance.canonical_json(self.trust)
        config, signature = self.root / "trust.json", self.root / "trust.sig"
        config.write_bytes(raw)
        signature.write_bytes(self.sign(root_private, raw))
        loaded, digest = acceptance.customer_trust.load_trust(
            config, signature, root_public, root_public_key=root_public.read_bytes(),
            now=self.now, require_root_owned=False)
        self.assertEqual(digest, self.trust_digest)
        self.assertEqual(acceptance.customer_trust.authorized_key(
            loaded, "collector-fixture", "collector", now=self.now)[1], self.keys["collector-fixture"][2])
        with self.assertRaisesRegex(acceptance.customer_trust.TrustError, "not authorized"):
            acceptance.customer_trust.authorized_key(loaded, "unknown-caller-key", "collector", now=self.now)

    def test_production_trust_requires_exact_durable_monotonic_state(self):
        root_private, root_public = self.make_key("monotonic-root-fixture")
        raw = acceptance.canonical_json(self.trust)
        config, signature = self.root / "monotonic-trust.json", self.root / "monotonic-trust.sig"
        config.write_bytes(raw)
        signature.write_bytes(self.sign(root_private, raw))
        loader = acceptance.customer_trust.load_trust
        args = (config, signature, root_public)
        kwargs = {"root_public_key": root_public.read_bytes(), "now": self.now, "require_root_owned": True}
        with self.assertRaisesRegex(acceptance.customer_trust.TrustError, "rollback state is unavailable"):
            loader(*args, **kwargs)
        digest = hashlib.sha256(raw).hexdigest()
        loader(*args, **kwargs, monotonic_state_verifier=lambda doc, actual: {
            "sequence": doc["sequence"], "configurationSha256": actual, "durable": True})
        for state in ({"sequence": 0, "configurationSha256": digest, "durable": True},
                      {"sequence": self.trust["sequence"], "configurationSha256": "0" * 64, "durable": True},
                      {"sequence": self.trust["sequence"], "configurationSha256": digest, "durable": False},
                      {"sequence": True, "configurationSha256": digest, "durable": True},
                      {"sequence": self.trust["sequence"], "configurationSha256": digest,
                       "durable": True, "unreviewed": True}):
            with self.subTest(state=state), self.assertRaisesRegex(acceptance.customer_trust.TrustError, "stale|rolled back"):
                loader(*args, **kwargs, monotonic_state_verifier=lambda _doc, _digest, state=state: state)
        def interrupted(_doc, _digest):
            raise OSError("synthetic interrupted state check")
        with self.assertRaisesRegex(acceptance.customer_trust.TrustError, "could not be verified"):
            loader(*args, **kwargs, monotonic_state_verifier=interrupted)

    def test_registry_conformance_requires_exact_current_customer_signed_report(self):
        digest = acceptance.verify_replay_registry_conformance(self.trust,
            report_path=self.registry_report_path, signature_path=self.registry_signature_path, now=self.now)
        self.assertEqual(digest, self.trust["replayRegistry"]["conformanceReportSha256"])
        self.registry_report_path.write_bytes(acceptance.canonical_json(
            dict(self.registry_report, registryIdentity="substituted-registry")))
        with self.assertRaisesRegex(acceptance.ProvenanceError, "no matching independent"):
            acceptance.verify_replay_registry_conformance(self.trust,
                report_path=self.registry_report_path, signature_path=self.registry_signature_path, now=self.now)

    def test_registry_conformance_rejects_shared_reviewer_identity_or_fingerprint(self):
        trust = copy.deepcopy(self.trust)
        trust["replayRegistry"]["conformanceReviewerIdentity"] = "registry-fixture"
        with self.assertRaisesRegex(acceptance.customer_trust.TrustError, "must be distinct"):
            acceptance.customer_trust.validate_document(trust, now=self.now)

    def test_missing_registry_conformance_blocks_before_network_exchange(self):
        manifest = {"runId": "a8179d98-4a9d-4ab6-aac9-0c25dd3b2257", "runNonce": "a"*64,
                    "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                    "collectorSignedAt": self.now.isoformat(), "runReservation": {}}
        with patch.object(acceptance.urllib.request, "build_opener") as opener, \
                self.assertRaisesRegex(acceptance.ProvenanceError, "conformance evidence is unavailable"):
            acceptance.claim_durable_replay_registry(self.trust, self.trust_digest, manifest,
                "b"*64, "c"*64, self.now.isoformat(), now=self.now)
        opener.assert_not_called()

    def test_expired_and_revoked_customer_signers_are_rejected(self):
        expired = copy.deepcopy(self.trust)
        expired["keys"][0]["validUntil"] = (self.now-dt.timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(acceptance.customer_trust.TrustError, "expired"):
            acceptance.customer_trust.authorized_key(expired, "collector-fixture", "collector", now=self.now)
        revoked = copy.deepcopy(self.trust)
        revoked["keys"][0]["revokedAt"] = (self.now-dt.timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(acceptance.customer_trust.TrustError, "revoked"):
            acceptance.customer_trust.authorized_key(revoked, "collector-fixture", "collector", now=self.now)

    def test_freshness_rejects_expired_future_and_reordered_evidence(self):
        manifest = {"runCreatedAt": (self.now-dt.timedelta(days=8)).isoformat(),
                    "runExpiresAt": (self.now-dt.timedelta(days=1)).isoformat(),
                    "collectedAt": (self.now-dt.timedelta(days=8)).isoformat(),
                    "collectorSignedAt": (self.now-dt.timedelta(days=8)).isoformat()}
        review = {"reviewedAt": self.now.isoformat()}
        with self.assertRaisesRegex(acceptance.ProvenanceError, "expired"):
            acceptance.validate_freshness(manifest, review, now=self.now)
        manifest.update({"runCreatedAt": (self.now-dt.timedelta(minutes=1)).isoformat(),
                         "runExpiresAt": (self.now+dt.timedelta(days=1)).isoformat(),
                         "collectedAt": (self.now+dt.timedelta(minutes=5)).isoformat(),
                         "collectorSignedAt": (self.now+dt.timedelta(minutes=6)).isoformat()})
        with self.assertRaisesRegex(acceptance.ProvenanceError, "future-dated"):
            acceptance.validate_freshness(manifest, review, now=self.now)
        manifest["collectedAt"] = (self.now-dt.timedelta(minutes=2)).isoformat()
        manifest["collectorSignedAt"] = (self.now-dt.timedelta(minutes=3)).isoformat()
        with self.assertRaisesRegex(acceptance.ProvenanceError, "out of order"):
            acceptance.validate_freshness(manifest, review, now=self.now)

    def test_run_context_is_unique_matrix_bound_and_expires(self):
        first, second = acceptance.create_run_context(self.root / "run-one.json", now=self.now), \
                        acceptance.create_run_context(self.root / "run-two.json", now=self.now)
        self.assertNotEqual(first["runId"], second["runId"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertEqual(len(first["nonce"]), 64)
        with self.assertRaisesRegex(acceptance.ProvenanceError, "different canonical matrix"):
            acceptance.validate_run_context(dict(first, canonicalMatrixSha256="0"*64), now=self.now)
        with self.assertRaisesRegex(acceptance.ProvenanceError, "expired"):
            acceptance.validate_run_context(dict(first, expiresAt=(self.now-dt.timedelta(seconds=1)).isoformat()), now=self.now)

    def test_run_reservation_requires_a_new_atomic_claim_not_a_replayed_reservation(self):
        context = {"runId": "a8179d98-4a9d-4ab6-aac9-0c25dd3b2257", "nonce": "a"*64,
                   "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                   "createdAt": (self.now-dt.timedelta(seconds=2)).isoformat(),
                   "expiresAt": (self.now+dt.timedelta(days=1)).isoformat()}
        base = {"schemaVersion": 1, "action": "reserve-run", "registryIdentity": "registry-fixture",
                "runId": context["runId"], "runNonce": context["nonce"],
                "canonicalMatrixSha256": context["canonicalMatrixSha256"],
                "trustConfigurationSha256": self.trust_digest, "sequence": 7,
                "registeredAt": (self.now-dt.timedelta(seconds=1)).isoformat()}
        for status in ("newly-reserved", "already-reserved", "already-accepted"):
            unsigned = dict(base, status=status)
            reservation = dict(unsigned, signature=self.sign(
                self.keys["registry-fixture"][0], acceptance.canonical_json(unsigned)).hex())
            with self.subTest(status=status):
                if status == "newly-reserved":
                    self.assertIsNone(acceptance.validate_run_reservation(
                        reservation, self.trust, context, self.trust_digest, now=self.now))
                else:
                    with self.assertRaisesRegex(acceptance.ProvenanceError, "does not match"):
                        acceptance.validate_run_reservation(
                            reservation, self.trust, context, self.trust_digest, now=self.now)

    def test_corrobation_must_bind_exact_signed_host_record_and_authorized_identity(self):
        manifest = {"runId": "a8179d98-4a9d-4ab6-aac9-0c25dd3b2257", "runNonce": "a"*64,
                    "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                    "collectorIdentity": "collector-fixture", "collectedAt": self.now.isoformat()}
        row = {"scenario": "clean-upgrade", "platform": "debian", "osVersion": "13.8",
               "profile": "m3-debian-13-k3s-test-linux-amd64", "osId": "debian", "osMajor": "13",
               "osMinor": "", "osPointRelease": "13.8", "architecture": "linux/amd64",
               "imageIdentity": "https://compute.example/image/approved", "imageUniqueId": "123456789",
               "imageProject": "compute.example", "imageName": "approved",
               "packagePolicySha256": "b"*64, "machineIdentity": "machine-fixture", "nodeIdentity": "uid-fixture",
               "imageApprovalReference": "approval-fixture", "imageApprovalSha256": "d"*64,
               "artifactPreflightReportSha256": "e"*64, "packageArchiveSha256": "f"*64,
               "packageRepositorySnapshotId": "snapshot-fixture", "planDigest": "a"*64,
               "operationId": "operation-fixture", "evidenceSha256": "c"*64,
               "collectorIdentity": "collector-fixture", "collectedAt": self.now.isoformat(),
               "faultInjectionMethod": "not-applicable",
               "faultInjectionOperatorIdentity": "not-applicable"}
        binding = acceptance.corroboration_binding(manifest, row)
        record = {"schemaVersion": 1, "bindings": binding, "customerSourceSystem": "customer-audit-test",
                  "evidenceLocation": "customer-audit://qualification-record-123", "collectedAt": self.now.isoformat(),
                  "corroboratedAt": (self.now+dt.timedelta(seconds=1)).isoformat(),
                  "corroboratorIdentity": "custodian-fixture", "decision": "confirmed",
                  "rationale": "Synthetic fixture exercises exact field binding."}
        path = self.root / "clean-upgrade-debian.json"
        raw = acceptance.canonical_json(record)
        path.write_bytes(raw)
        (self.root / (path.name + ".sig")).write_bytes(self.sign(self.keys["custodian-fixture"][0], raw))
        verified, _digest, fingerprint = acceptance.verify_corroboration(
            self.root, manifest, row, self.trust, self.keys["collector-fixture"][2], now=self.now)
        self.assertEqual(verified, record)
        self.assertEqual(fingerprint, self.keys["custodian-fixture"][2])
        record["evidenceLocation"] = "fixture://not-production"
        fixture_raw = acceptance.canonical_json(record)
        path.write_bytes(fixture_raw)
        (self.root / (path.name + ".sig")).write_bytes(self.sign(self.keys["custodian-fixture"][0], fixture_raw))
        with self.assertRaisesRegex(acceptance.ProvenanceError, "synthetic fixture references"):
            acceptance.verify_corroboration(self.root, manifest, row, self.trust,
                                             self.keys["collector-fixture"][2], now=self.now)
        record["bindings"] = dict(binding, machineIdentity="substituted-machine")
        record["evidenceLocation"] = "customer-audit://qualification-record-123"
        path.write_bytes(acceptance.canonical_json(record))
        with self.assertRaisesRegex(acceptance.ProvenanceError, "does not match"):
            acceptance.verify_corroboration(self.root, manifest, row, self.trust,
                                             self.keys["collector-fixture"][2], now=self.now)

    def test_durable_registry_requires_new_atomic_claim_and_signed_fresh_receipt(self):
        manifest = {"runId": "a8179d98-4a9d-4ab6-aac9-0c25dd3b2257", "runNonce": "a"*64,
                    "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                    "collectorSignedAt": self.now.isoformat(), "runReservation": {"synthetic": "fixture"}}
        manifest_sha, review_sha = "b"*64, "c"*64
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def read(self, _limit): return self.raw
        response = Response()
        self.registry_claim = "newly-accepted"
        class Opener:
            def open(self, request, timeout):
                payload = json.loads(request.data)
                unsigned = {"schemaVersion": 1, "action": "accept-run", "registryIdentity": "registry-fixture",
                            "challenge": payload["challenge"], "runId": payload["runId"],
                            "runNonce": payload["runNonce"], "manifestSha256": manifest_sha,
                            "reviewSha256": review_sha, "trustConfigurationSha256": self_outer.trust_digest,
                            "canonicalMatrixSha256": manifest["canonicalMatrixSha256"],
                            "reservationSha256": hashlib.sha256(acceptance.canonical_json(manifest["runReservation"])).hexdigest(),
                            "claim": self_outer.registry_claim,
                            "sequence": 42, "committedAt": self_outer.now.isoformat()}
                signature = self_outer.sign(self_outer.keys["registry-fixture"][0], acceptance.canonical_json(unsigned)).hex()
                response.raw = acceptance.canonical_json(dict(unsigned, signature=signature))
                return response
        self_outer = self
        with patch.object(acceptance, "verify_replay_registry_conformance", return_value="d"*64), \
                patch.object(acceptance.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(acceptance.ProvenanceError, "predates independent review"):
                acceptance.claim_durable_replay_registry(
                    self.trust, self.trust_digest, manifest, manifest_sha, review_sha,
                    (self.now+dt.timedelta(seconds=1)).isoformat(), now=self.now)
            result = acceptance.claim_durable_replay_registry(self.trust, self.trust_digest, manifest,
                manifest_sha, review_sha, (self.now-dt.timedelta(seconds=1)).isoformat(), now=self.now)
        self.assertEqual(result["claim"], "newly-accepted")
        self.assertEqual(result["sequence"], 42)
        self.registry_claim = "already-accepted"
        with patch.object(acceptance, "verify_replay_registry_conformance", return_value="d"*64), \
                patch.object(acceptance.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(acceptance.ProvenanceError, "conflicting qualification claim"):
                acceptance.claim_durable_replay_registry(
                    self.trust, self.trust_digest, manifest, manifest_sha, review_sha,
                    (self.now-dt.timedelta(seconds=1)).isoformat(), now=self.now)

    def test_missing_durable_registry_blocks_even_reviewed_package_acceptance(self):
        manifest = {"runId": "a8179d98-4a9d-4ab6-aac9-0c25dd3b2257", "runNonce": "a"*64,
                    "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                    "collectorSignedAt": self.now.isoformat()}
        with self.assertRaisesRegex(acceptance.ProvenanceError, "durable replay registry is not configured"):
            acceptance.claim_durable_replay_registry({"keys": []}, "d"*64, manifest,
                "b"*64, "c"*64, self.now.isoformat(), now=self.now)

    def test_canonical_matrix_requires_all_22_original_platform_records(self):
        matrix = json.loads(acceptance.read_file(acceptance.MATRIX))
        expected = {(case["id"], family) for case in matrix["cases"] for family in matrix["osFamilies"]}
        self.assertEqual(len(expected), 22)
        rows = [{"scenario": scenario, "platform": platform} for scenario, platform in sorted(expected)]
        acceptance.validate_case_index(rows, expected)
        with self.assertRaisesRegex(acceptance.ProvenanceError, "do not match"):
            acceptance.validate_case_index(rows[:-1], expected)

    def test_corroboration_inventory_rejects_extra_or_missing_records(self):
        expected = {(f"scenario-{number}", platform)
                    for number in range(11) for platform in ("debian", "rhel")}
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for scenario, platform in expected:
                (directory / f"{scenario}-{platform}.json").write_text("{}")
                (directory / f"{scenario}-{platform}.json.sig").write_text("signature")
            acceptance.validate_corroboration_inventory(directory, expected)
            (directory / "unexpected.json").write_text("{}")
            with self.assertRaisesRegex(acceptance.ProvenanceError, "unexpected records"):
                acceptance.validate_corroboration_inventory(directory, expected)

    def synthetic_package(self, *, reviewer_decision="accepted"):
        evidence = self.root / "evidence"
        corroborations = self.root / "corroborations"
        evidence.mkdir(exist_ok=True)
        corroborations.mkdir(exist_ok=True)
        matrix = json.loads(acceptance.read_file(acceptance.MATRIX))
        run_id = "a8179d98-4a9d-4ab6-aac9-0c25dd3b2257"
        nonce = "a" * 64
        created = self.now - dt.timedelta(minutes=2)
        collected = self.now - dt.timedelta(minutes=1)
        signed = self.now - dt.timedelta(seconds=40)
        corroborated = self.now - dt.timedelta(seconds=20)
        reviewed = self.now - dt.timedelta(seconds=10)
        run_expires = self.now + dt.timedelta(days=1)
        rows = []
        for case in matrix["cases"]:
            for platform in matrix["osFamilies"]:
                filename = f"{case['id']}-{platform}.json"
                fixture_evidence = {"qualificationCase": case["id"], "osFamily": platform,
                                    "mode": "execute", "admissionChecksPassed": True,
                                    "evidenceOrigin": "real-host", "environmentClaim": "real-host",
                                    "testFixture": True, "platformEvidence": {},
                                    "hostPreflightReceipt": {}, "node": {}}
                (evidence / filename).write_bytes(acceptance.canonical_json(fixture_evidence))
                row = {"scenario": case["id"], "platform": platform, "evidenceFile": filename,
                       "evidenceSha256": hashlib.sha256((evidence / filename).read_bytes()).hexdigest(),
                       "operationId": f"operation-{case['id']}-{platform}", "planDigest": "1"*64,
                       "profile": "debian-13" if platform == "debian" else "rhel-9",
                       "osVersion": "13" if platform == "debian" else "9",
                       "imageIdentity": f"https://compute.invalid/{platform}/image", "imageUniqueId": f"{platform}-image-id",
                       "imageProject": "compute.invalid", "imageName": platform,
                       "osId": "debian" if platform == "debian" else "rhel",
                       "osMajor": "13" if platform == "debian" else "9",
                       "osMinor": "" if platform == "debian" else "8",
                       "osPointRelease": "13.8" if platform == "debian" else "9.8",
                       "architecture": "linux/amd64",
                       "imageApprovalReference": f"approval-{platform}", "imageApprovalSha256": "2"*64,
                       "artifactPreflightReportSha256": "3"*64, "packagePolicySha256": "4"*64,
                       "packageArchiveSha256": "5"*64, "packageRepositorySnapshotId": f"snapshot-{platform}",
                       "machineIdentity": "a"*32,
                       "nodeIdentity": f"nodeuid-{case['id']}-{platform}", "collectorIdentity": "collector-fixture",
                       "collectedAt": collected.isoformat(), "faultInjectionMethod": "synthetic-only",
                       "faultInjectionOperatorIdentity": "synthetic-operator", "environmentClaim": "real-host",
                       "planDigest": "1"*64}
                rows.append(row)
        context = {"schemaVersion": 1, "runId": run_id, "nonce": nonce,
                   "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                   "createdAt": created.isoformat(), "expiresAt": run_expires.isoformat()}
        reservation = {"schemaVersion": 1, "action": "reserve-run", "registryIdentity": "registry-fixture",
                       "runId": run_id, "runNonce": nonce,
                       "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                       "trustConfigurationSha256": self.trust_digest, "sequence": 1, "status": "newly-reserved",
                       "registeredAt": (created+dt.timedelta(seconds=1)).isoformat()}
        reservation["signature"] = self.sign(self.keys["registry-fixture"][0],
                                               acceptance.canonical_json(reservation)).hex()
        context["trustConfigurationSha256"] = self.trust_digest
        context["registryReservation"] = reservation
        manifest = {"schemaVersion": 2, "canonicalMatrixSha256": acceptance.structural.FAILURE_MATRIX_SHA256,
                    "environmentClaim": "real-host", "runId": run_id, "runNonce": nonce,
                    "runCreatedAt": context["createdAt"], "runExpiresAt": context["expiresAt"],
                    "runReservation": reservation,
                    "trustConfigurationSha256": self.trust_digest, "collectorIdentity": "collector-fixture",
                    "collectedAt": collected.isoformat(), "collectorSignedAt": signed.isoformat(),
                    "evidenceArtifacts": acceptance.file_inventory(evidence), "cases": rows}
        manifest_path = self.root / "manifest.json"
        manifest_raw = acceptance.canonical_json(manifest)
        manifest_path.write_bytes(manifest_raw)
        manifest_sig = self.root / "manifest.sig"
        manifest_sig.write_bytes(self.sign(self.keys["collector-fixture"][0], manifest_raw))
        corroboration_digests = []
        for row in rows:
            record = {"schemaVersion": 1, "bindings": acceptance.corroboration_binding(manifest, row),
                      "customerSourceSystem": "customer-audit-test", "evidenceLocation": "customer-audit://synthetic-fixture-only",
                      "collectedAt": row["collectedAt"], "corroboratedAt": corroborated.isoformat(),
                      "corroboratorIdentity": "custodian-fixture", "decision": "confirmed",
                      "rationale": "Synthetic test fixture does not attest to a real host."}
            raw = acceptance.canonical_json(record)
            path = corroborations / f"{row['scenario']}-{row['platform']}.json"
            path.write_bytes(raw)
            (corroborations / (path.name + ".sig")).write_bytes(self.sign(self.keys["custodian-fixture"][0], raw))
            corroboration_digests.append({"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
        review = {"schemaVersion": 1, "manifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
                  "trustConfigurationSha256": self.trust_digest,
                  "corroborationSetSha256": hashlib.sha256(acceptance.canonical_json(corroboration_digests)).hexdigest(),
                  "reviewerIdentity": "reviewer-fixture", "decision": reviewer_decision,
                  "reviewedAt": reviewed.isoformat(), "reason": "Synthetic fixture review only; never customer acceptance."}
        review_path = self.root / "review.json"
        review_raw = acceptance.canonical_json(review)
        review_path.write_bytes(review_raw)
        review_sig = self.root / "review.json.sig"
        review_sig.write_bytes(self.sign(self.keys["reviewer-fixture"][0], review_raw))
        args = types.SimpleNamespace(evidence_directory=evidence, manifest=manifest_path,
            manifest_signature=manifest_sig, review=review_path, review_signature=review_sig,
            corroboration_directory=corroborations)
        return args, rows, self.now + dt.timedelta(seconds=20)

    def test_synthetic_fixture_package_cannot_be_accepted(self):
        args, _rows, _now = self.synthetic_package()
        with patch.object(acceptance.structural, "verify_pinned_matrix"), \
             patch.object(acceptance.structural, "verify_directory", return_value=[]), \
             patch.object(acceptance.customer_trust, "load_trust", return_value=(self.trust, self.trust_digest)):
            with self.assertRaisesRegex(acceptance.ProvenanceError, "synthetic or unmarked fixtures"):
                acceptance.verify_package(args)

    def test_rejected_review_never_claims_durable_acceptance(self):
        args, rows, _now = self.synthetic_package(reviewer_decision="rejected")
        with patch.object(acceptance.structural, "verify_pinned_matrix"), \
             patch.object(acceptance.structural, "verify_directory", return_value=[]), \
             patch.object(acceptance, "evidence_case_rows", return_value=rows), \
             patch.object(acceptance.customer_trust, "load_trust", return_value=(self.trust, self.trust_digest)), \
             patch.object(acceptance, "claim_durable_replay_registry") as claim:
            result = acceptance.verify_package(args)
        self.assertEqual(result["reviewDecision"], "REJECTED")
        self.assertFalse(result["qualificationAccepted"])
        self.assertFalse(result["durableReplayStateVerified"])
        claim.assert_not_called()

    def test_customer_corroboration_for_another_nonce_fails_package_verification(self):
        args, rows, now = self.synthetic_package()
        path = args.corroboration_directory / "clean-upgrade-debian.json"
        record = json.loads(path.read_bytes())
        record["bindings"]["runNonce"] = "f"*64
        raw = acceptance.canonical_json(record)
        path.write_bytes(raw)
        (args.corroboration_directory / (path.name + ".sig")).write_bytes(
            self.sign(self.keys["custodian-fixture"][0], raw))
        with patch.object(acceptance.structural, "verify_pinned_matrix"), \
             patch.object(acceptance.structural, "verify_directory", return_value=[]), \
             patch.object(acceptance, "evidence_case_rows", return_value=rows), \
             patch.object(acceptance.customer_trust, "load_trust", return_value=(self.trust, self.trust_digest)):
            with self.assertRaisesRegex(acceptance.ProvenanceError, "does not match"):
                acceptance.verify_package(args)


if __name__ == "__main__":
    unittest.main()
