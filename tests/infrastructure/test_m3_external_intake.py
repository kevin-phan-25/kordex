"""Synthetic-only unit tests; these never establish customer receipt or qualification."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("m3_external_intake", ROOT / "scripts/m3_external_intake.py")
intake = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(intake)


class ExternalIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.inputs_path = self.root / "customer-inputs.json"
        self.report_path = self.root / "intake-report.json"
        self.payload_path = self.root / "delivered.bin"
        self.payload = b"synthetic test payload; not an M3 artifact"
        self.payload_path.write_bytes(self.payload)
        self.payload_path.chmod(0o600)
        import m3_qualification
        self.document = {
            "schemaVersion": 1, "customerId": "synthetic-customer",
            "projectId": m3_qualification.PROJECT, "region": m3_qualification.REGION,
            "zone": m3_qualification.ZONE, "labId": m3_qualification.LAB_ID,
            "fixtureOnly": False, "canonicalMatrixSha256": m3_qualification.MATRIX_SHA256,
            "k3sVersion": m3_qualification.K3S_VERSION,
            "platformTargets": {platform: None for platform in m3_qualification.PLATFORMS},
            "residualRiskAcceptance": {platform: None for platform in m3_qualification.PLATFORMS},
            "inputs": {key: None for key in m3_qualification.INPUTS},
        }

    def tearDown(self):
        self.temp.cleanup()

    def write_inputs(self):
        self.inputs_path.write_text(json.dumps(self.document), encoding="utf-8")
        self.inputs_path.chmod(0o600)

    def receive_one(self):
        self.document["inputs"]["signedReleaseBundle"] = {
            "reference": "delivered.bin", "sha256": hashlib.sha256(self.payload).hexdigest(),
            "expiresAt": None,
        }

    def test_all_47_slots_report_not_provided_without_advancing_qualification(self):
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        self.assertEqual(report["inputCount"], 47)
        self.assertEqual(report["summary"]["notProvided"], 47)
        self.assertEqual(report["summary"]["verified"], 0)
        self.assertEqual(report["summary"]["approved"], 0)
        self.assertFalse(report["qualificationAccepted"])
        self.assertEqual(report["qualificationRowsAdvanced"], 0)
        schema = json.loads((ROOT / "schemas/m3-external-intake-report-v1.json").read_text())
        Draft202012Validator(schema).validate(report)

    def test_matching_delivery_is_received_but_not_verified_or_approved(self):
        self.receive_one()
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entries = {entry["inputId"]: entry for entry in report["entries"]}
        item = entries["signedReleaseBundle"]
        self.assertEqual(item["status"], "RECEIVED")
        self.assertEqual(item["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(item["domainVerification"], "NOT RUN")
        self.assertEqual(item["independentApproval"], "NOT RUN")
        self.assertEqual(report["summary"]["verified"], 0)
        self.assertEqual(report["summary"]["approved"], 0)

    def test_duplicate_payload_reference_is_rejected(self):
        self.receive_one()
        self.document["inputs"]["toolProvenance"] = dict(self.document["inputs"]["signedReleaseBundle"])
        self.write_inputs()
        with self.assertRaisesRegex(intake.IntakeError, "duplicate payload reference"):
            intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                inputs_path=self.inputs_path)

    def test_digest_mismatch_and_expiry_are_rejected(self):
        self.receive_one()
        self.document["inputs"]["signedReleaseBundle"]["sha256"] = "0" * 64
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entry = next(entry for entry in report["entries"] if entry["inputId"] == "signedReleaseBundle")
        self.assertEqual(entry["status"], "REJECTED")
        self.assertEqual(entry["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(entry["expectedSha256"], "0" * 64)

        self.document["inputs"]["signedReleaseBundle"]["sha256"] = hashlib.sha256(self.payload).hexdigest()
        self.document["inputs"]["signedReleaseBundle"]["expiresAt"] = "2000-01-01T00:00:00Z"
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entry = next(entry for entry in report["entries"] if entry["inputId"] == "signedReleaseBundle")
        self.assertEqual(entry["status"], "REJECTED")
        self.assertEqual(entry["sha256"], hashlib.sha256(self.payload).hexdigest())

    def test_fixture_manifest_and_world_readable_payload_are_rejected(self):
        self.receive_one()
        self.document["fixtureOnly"] = True
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entry = next(entry for entry in report["entries"] if entry["inputId"] == "signedReleaseBundle")
        self.assertEqual(entry["status"], "REJECTED")

        self.document["fixtureOnly"] = False
        self.write_inputs()
        self.payload_path.chmod(0o644)
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entry = next(entry for entry in report["entries"] if entry["inputId"] == "signedReleaseBundle")
        self.assertEqual(entry["status"], "REJECTED")

    def test_report_is_private_and_never_overwritten(self):
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        intake.write_report(self.report_path, report)
        self.assertEqual(self.report_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(intake.IntakeError, "cannot overwrite"):
            intake.write_report(self.report_path, report)

    def test_report_violating_published_schema_is_never_written(self):
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        report["qualificationAccepted"] = True
        with self.assertRaisesRegex(intake.IntakeError, "published schema"):
            intake.write_report(self.report_path, report)
        self.assertFalse(self.report_path.exists())

    def test_entry_status_cannot_claim_verified_or_approved_in_report_schema(self):
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        for forbidden in ("VERIFIED", "APPROVED"):
            tampered = json.loads(json.dumps(report))
            tampered["entries"][0]["status"] = forbidden
            with self.assertRaisesRegex(intake.IntakeError, "published schema"):
                intake.validate_report(tampered)

    def test_non_canonical_and_hard_linked_duplicate_references_are_rejected(self):
        self.receive_one()
        self.document["inputs"]["toolProvenance"] = {
            "reference": "./delivered.bin",
            "sha256": hashlib.sha256(self.payload).hexdigest(),
            "expiresAt": None,
        }
        self.write_inputs()
        with self.assertRaisesRegex(intake.IntakeError, "canonical relative POSIX path"):
            intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                inputs_path=self.inputs_path)

        hardlink = self.root / "alias.bin"
        os.link(self.payload_path, hardlink)
        self.document["inputs"]["toolProvenance"]["reference"] = "alias.bin"
        self.write_inputs()
        with self.assertRaisesRegex(intake.IntakeError, "duplicate payload inode"):
            intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                inputs_path=self.inputs_path)

    def test_empty_payload_is_rejected_and_report_satisfies_schema(self):
        empty_path = self.root / "empty.bin"
        empty_path.write_bytes(b"")
        empty_path.chmod(0o600)
        self.document["inputs"]["signedReleaseBundle"] = {
            "reference": "empty.bin",
            "sha256": hashlib.sha256(b"").hexdigest(),
            "expiresAt": None,
        }
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entry = next(entry for entry in report["entries"] if entry["inputId"] == "signedReleaseBundle")
        self.assertEqual(entry["status"], "REJECTED")
        self.assertIsNone(entry["sizeBytes"])
        self.assertIn("empty", entry["reason"])
        intake.write_report(self.report_path, report)
        self.assertTrue(self.report_path.exists())

    def test_non_private_or_symlink_intermediate_directory_is_rejected(self):
        sub = self.root / "evidence"
        sub.mkdir(mode=0o755)
        sub.chmod(0o755)
        nested = sub / "bundle.bin"
        nested.write_bytes(self.payload)
        nested.chmod(0o600)
        self.document["inputs"]["signedReleaseBundle"] = {
            "reference": "evidence/bundle.bin",
            "sha256": hashlib.sha256(self.payload).hexdigest(),
            "expiresAt": None,
        }
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entry = next(entry for entry in report["entries"] if entry["inputId"] == "signedReleaseBundle")
        self.assertEqual(entry["status"], "REJECTED")
        self.assertIn("subdirectory must be private", entry["reason"])

        sub.chmod(0o700)
        link_dir = self.root / "linked"
        link_dir.symlink_to(sub)
        self.document["inputs"]["signedReleaseBundle"]["reference"] = "linked/bundle.bin"
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        entry = next(entry for entry in report["entries"] if entry["inputId"] == "signedReleaseBundle")
        self.assertEqual(entry["status"], "REJECTED")

    def test_fixture_only_manifest_with_no_populated_slots_still_rejects(self):
        self.document["fixtureOnly"] = True
        self.write_inputs()
        report = intake.build_report(delivery_manifest_path=intake.DELIVERY_MANIFEST,
                                     inputs_path=self.inputs_path)
        self.assertEqual(report["summary"]["overall"], "REJECTED")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = intake.main(["--inputs", str(self.inputs_path), "--report", str(self.report_path)])
        self.assertEqual(rc, 1)

    def test_cli_does_not_allow_overriding_delivery_manifest(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            intake.main(["--delivery-manifest", "/tmp/fake.json",
                         "--inputs", str(self.inputs_path),
                         "--report", str(self.report_path)])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
