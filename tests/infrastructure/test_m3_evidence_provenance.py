"""Synthetic-only tests for M3 evidence provenance and review separation."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "m3_evidence_provenance", ROOT / "scripts/verify-m3-evidence-provenance.py")
provenance = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(provenance)


class EvidenceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.collector_private = self.root / "synthetic-collector-private.pem"
        self.collector_public = self.root / "synthetic-collector-public.pem"
        self.reviewer_private = self.root / "synthetic-reviewer-private.pem"
        self.reviewer_public = self.root / "synthetic-reviewer-public.pem"
        for private, public in ((self.collector_private, self.collector_public),
                                (self.reviewer_private, self.reviewer_public)):
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def tearDown(self):
        self.temp.cleanup()

    def sign(self, private: Path, source: Path, signature: Path):
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private), "-rawin",
                        "-in", str(source), "-out", str(signature)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_synthetic_ed25519_signature_and_key_fingerprint_are_verified(self):
        record = self.root / "manifest.json"
        signature = self.root / "manifest.sig"
        record.write_bytes(provenance.canonical_json({"fixture": "synthetic-only"}))
        self.sign(self.collector_private, record, signature)
        fingerprint = provenance.public_key_fingerprint(self.collector_public)
        self.assertEqual(provenance.verify_signature(record, signature, self.collector_public, fingerprint), fingerprint)
        self.assertEqual(provenance.verify_detached_signature(
            record.read_bytes(), signature.read_bytes(), self.collector_public.read_bytes(), fingerprint), fingerprint)
        record.write_bytes(provenance.canonical_json({"fixture": "modified-synthetic-only"}))
        with self.assertRaisesRegex(provenance.ProvenanceError, "signature verification failed"):
            provenance.verify_signature(record, signature, self.collector_public, fingerprint)
        with self.assertRaisesRegex(provenance.ProvenanceError, "signature verification failed"):
            provenance.verify_detached_signature(record.read_bytes(), signature.read_bytes(),
                                                  self.collector_public.read_bytes(), fingerprint)

    def test_wrong_fingerprint_duplicate_fields_and_noncanonical_record_fail(self):
        record = self.root / "manifest.json"
        record.write_text('{"x":1,"x":2}\n', encoding="utf-8")
        with self.assertRaisesRegex(provenance.ProvenanceError, "duplicate JSON field"):
            provenance.load_json(record)
        record.write_text('{"schemaVersion": 1}\n', encoding="utf-8")
        value, raw = provenance.load_json(record)
        self.assertNotEqual(raw, provenance.canonical_json(value))
        with self.assertRaisesRegex(provenance.ProvenanceError, "fingerprint"):
            provenance.verify_signature(record, self.collector_public, self.collector_public, "0" * 64)

    def test_non_ed25519_public_keys_are_rejected(self):
        private = self.root / "synthetic-rsa-private.pem"
        public = self.root / "synthetic-rsa-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.assertRaisesRegex(provenance.ProvenanceError, "must use Ed25519"):
            provenance.public_key_fingerprint(public)

    def test_matrix_header_rejects_changed_matrix_and_synthetic_origin(self):
        manifest = {
            "schemaVersion": 2,
            "canonicalMatrixSha256": provenance.structural.FAILURE_MATRIX_SHA256,
            "environmentClaim": "real-host", "runId": "a8179d98-4a9d-4ab6-aac9-0c25dd3b2257",
            "runNonce": "a" * 64, "runCreatedAt": "2026-11-21T11:00:00Z",
            "runExpiresAt": "2026-11-28T11:00:00Z", "trustConfigurationSha256": "b" * 64,
            "runReservation": {},
            "collectorIdentity": "collector-1", "collectedAt": "2026-11-21T12:00:00Z",
            "collectorSignedAt": "2026-11-21T12:01:00Z", "evidenceArtifacts": [], "cases": [],
        }
        provenance.validate_manifest_header(manifest)
        with self.assertRaisesRegex(provenance.ProvenanceError, "matrix digest"):
            provenance.validate_manifest_header(dict(manifest, canonicalMatrixSha256="0" * 64))
        with self.assertRaisesRegex(provenance.ProvenanceError, "synthetic or supplemental"):
            provenance.validate_manifest_header(dict(manifest, environmentClaim="synthetic"))

    def test_synthetic_or_unmarked_case_evidence_is_rejected_before_manifest_creation(self):
        matrix = json.loads(provenance.read_file(provenance.MATRIX))
        case = matrix["cases"][0]
        family = matrix["osFamilies"][0]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / f"{case['id']}-{family}.json").write_text(json.dumps({
                "qualificationCase": case["id"], "osFamily": family,
                "mode": "execute", "admissionChecksPassed": True,
                "evidenceOrigin": "synthetic", "platformEvidence": {},
                "hostPreflightReceipt": {}, "node": {},
            }), encoding="utf-8")
            with self.assertRaisesRegex(provenance.ProvenanceError, "explicitly identify real-host"):
                provenance.evidence_case_rows(directory, matrix, "collector-1", "2026-11-21T12:00:00Z")
            unmarked = {"qualificationCase": case["id"], "osFamily": family,
                        "mode": "execute", "admissionChecksPassed": True,
                        "platformEvidence": {}, "hostPreflightReceipt": {}, "node": {}}
            (directory / f"{case['id']}-{family}.json").write_text(json.dumps(unmarked), encoding="utf-8")
            with self.assertRaisesRegex(provenance.ProvenanceError, "explicitly identify real-host"):
                provenance.evidence_case_rows(directory, matrix, "collector-1", "2026-11-21T12:00:00Z")
            unmarked["evidenceOrigin"] = "real-host"
            unmarked["environmentClaim"] = "real-host"
            unmarked["testFixture"] = False
            unmarked["mode"] = "preflight"
            (directory / f"{case['id']}-{family}.json").write_text(json.dumps(unmarked), encoding="utf-8")
            with self.assertRaisesRegex(provenance.ProvenanceError, "only an executed"):
                provenance.evidence_case_rows(directory, matrix, "collector-1", "2026-11-21T12:00:00Z")

    def test_duplicate_and_contradictory_case_rows_are_rejected(self):
        expected = {(f"case-{index}", platform) for index in range(11) for platform in ("debian", "rhel")}
        rows = [{"scenario": scenario, "platform": platform} for scenario, platform in sorted(expected)]
        provenance.validate_case_index(rows, expected)
        with self.assertRaisesRegex(provenance.ProvenanceError, "duplicate"):
            provenance.validate_case_index(rows + [rows[0]], expected)
        with self.assertRaisesRegex(provenance.ProvenanceError, "do not match"):
            provenance.validate_case_index(rows[:-1], expected)

    def test_review_must_bind_same_manifest_and_distinct_identity(self):
        review = {"schemaVersion": 1, "manifestSha256": "a" * 64,
                  "trustConfigurationSha256": "c" * 64, "corroborationSetSha256": "d" * 64,
                  "reviewerIdentity": "independent-reviewer", "decision": "accepted",
                  "reviewedAt": "2026-11-21T12:00:00Z", "reason": "evidence checked"}
        provenance.verify_review(review, "a" * 64, "collector", "c" * 64, "d" * 64)
        rejected = dict(review, decision="rejected", reason="image evidence mismatch")
        provenance.verify_review(rejected, "a" * 64, "collector", "c" * 64, "d" * 64)
        self.assertNotEqual(rejected["decision"], "accepted")
        with self.assertRaisesRegex(provenance.ProvenanceError, "not bound"):
            provenance.verify_review(review, "b" * 64, "collector", "c" * 64, "d" * 64)
        with self.assertRaisesRegex(provenance.ProvenanceError, "separately"):
            provenance.verify_review(dict(review, reviewerIdentity="collector"), "a" * 64, "collector", "c" * 64, "d" * 64)

    def test_collector_and_reviewer_keys_must_be_distinct(self):
        provenance.require_distinct_signers("a" * 64, "b" * 64)
        with self.assertRaisesRegex(provenance.ProvenanceError, "distinct independently trusted"):
            provenance.require_distinct_signers("a" * 64, "a" * 64)


if __name__ == "__main__":
    unittest.main()
