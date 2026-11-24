from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import m3_qualification  # noqa: E402


MANIFEST_PATH = ROOT / "docs/m3-external-delivery-manifest.json"
SCHEMA_PATH = ROOT / "schemas/m3-external-delivery-manifest-v1.json"
REQUIRED_COMPONENTS = {
    "control-plane", "agent", "operator", "dashboard", "ansible-ee", "postgres"
}


class M3ExternalDeliveryManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_schema_and_manifest_validate(self) -> None:
        Draft202012Validator.check_schema(self.schema)
        Draft202012Validator(self.schema).validate(self.manifest)

    def test_manifest_contains_each_authoritative_input_exactly_once(self) -> None:
        rows = self.manifest["inputs"]
        ids = [row["inputId"] for row in rows]
        self.assertEqual(len(rows), 47)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(m3_qualification.INPUTS))
        for row in rows:
            with self.subTest(input_id=row["inputId"]):
                self.assertEqual(row["campaigns"], m3_qualification.INPUTS[row["inputId"]]["platforms"])
                self.assertEqual(row["status"], "NOT PROVIDED")
                self.assertEqual(
                    row["validator"]["inventoryCommand"],
                    "python3 scripts/m3_qualification.py inputs --manifest /secure/m3/customer-inputs.json",
                )
                self.assertIn("UNVERIFIED", row["validator"]["inventoryEffect"])
                self.assertNotIn("scripts/m3-artifact-review.py schema", row["expectedFormatAndSchema"])

    def test_roles_are_role_names_and_six_build_owners_are_explicit(self) -> None:
        rows = {row["inputId"]: row for row in self.manifest["inputs"]}
        for row in rows.values():
            self.assertIsInstance(row["ownerRole"], str)
            self.assertNotIn("@", row["ownerRole"])
            self.assertNotIn("kphan25", row["ownerRole"].lower())
        roles = {
            item["component"]: item["ownerRole"]
            for item in rows["kordexOciDigestLock"]["componentOwnerRoles"]
        }
        self.assertEqual(set(roles), REQUIRED_COMPONENTS)
        self.assertIn("reviewer", rows["reviewerIdentity"]["ownerRole"].lower())
        self.assertIn("billing", rows["gcpBillingBudget"]["ownerRole"].lower())
        self.assertIn("custodian", rows["maintenanceTrustConfiguration"]["ownerRole"].lower())
        role_ids = {role["roleId"] for role in self.manifest["requiredOwnerRoles"]}
        self.assertTrue({
            "lab-security-custodian", "kiqt-artifact-signer",
            "independent-artifact-reviewer", "debian-image-approval-authority",
            "debian-repository-custodian", "rhel-image-approval-authority",
            "rhel-repository-custodian", "billing-owner",
            "control-plane-build-owner", "agent-build-owner", "operator-build-owner",
            "dashboard-build-owner", "ansible-ee-build-owner", "postgres-build-owner",
        }.issubset(role_ids))

    def test_campaign_scoping_and_review_do_not_conflate_input_approval(self) -> None:
        rows = {row["inputId"]: row for row in self.manifest["inputs"]}
        self.assertEqual(rows["debianImageApproval"]["campaigns"], ["debian-13"])
        self.assertEqual(rows["rhelImageApproval"]["campaigns"], ["rhel-9.8+"])
        self.assertIn("m3_artifact_review.validate_review", rows["reviewerIdentity"]["validator"]["domainValidator"])
        for row in rows.values():
            self.assertIn("private keys", row["accessRestrictions"].lower())


if __name__ == "__main__":
    unittest.main()
