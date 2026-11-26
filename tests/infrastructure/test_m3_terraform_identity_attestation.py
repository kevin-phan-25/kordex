"""Synthetic-only tests for customer-rooted Terraform provider identity attestations."""

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("m3_terraform_context_identity_test",
                                               ROOT / "scripts/m3_terraform_context.py")
context = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(context)
import m3_customer_trust


class TerraformIdentityAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.private, self.public = self.root / "key.pem", self.root / "key.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.private)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.fingerprint = m3_customer_trust.fingerprint(self.public.read_bytes())
        self.trust = {"schemaVersion": 1, "customerId": "synthetic-only", "sequence": 1,
            "issuedAt": (self.now-dt.timedelta(minutes=1)).isoformat(),
            "expiresAt": (self.now+dt.timedelta(days=1)).isoformat(), "keys": [{
                "identity": "synthetic-terraform-attestor", "role": "terraform-principal-attestor",
                "fingerprint": self.fingerprint, "publicKeyPem": self.public.read_text(),
                "validFrom": (self.now-dt.timedelta(minutes=1)).isoformat(),
                "validUntil": (self.now+dt.timedelta(hours=1)).isoformat(), "revokedAt": None}]}
        self.trust_digest = hashlib.sha256(m3_customer_trust.canonical_json(self.trust)).hexdigest()
        self.project = "kordex-fleet-platform-515416"
        self.target = "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"
        self.provider_context = {"providerPrincipal": self.target, "workspace": "default"}
        self.path = self.root / "identity-attestation.json"

    def tearDown(self):
        self.temp.cleanup()

    def write(self, **changes):
        record = {"schemaVersion": 1, "projectId": self.project, "effectivePrincipal": self.target,
            "impersonationTarget": self.target, "sourcePrincipal": "platform-admin@example.test",
            "providerContextSha256": context.canonical_sha256(self.provider_context),
            "authenticationMethod": "terraform-google-provider-identity", "decision": "verified",
            "attestorIdentity": "synthetic-terraform-attestor",
            "authenticatedAt": (self.now-dt.timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
            "expiresAt": (self.now+dt.timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
            "evidenceReference": "audit://synthetic/provider-authentication"}
        record.update(changes)
        raw = m3_customer_trust.canonical_json(record)
        self.path.write_bytes(raw)
        source, signature = self.root / "payload", self.root / "signature"
        source.write_bytes(raw)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
                        "-in", str(source), "-out", str(signature)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.path.with_name(self.path.name + ".sig").write_bytes(signature.read_bytes())

    def verify(self, now=None):
        return context.verify_provider_identity_attestation(self.path, project_id=self.project,
            target_principal=self.target, context=self.provider_context,
            trust_loader=lambda: (self.trust, self.trust_digest), now=now or self.now)

    def test_customer_rooted_identity_attestation_is_bound_to_project_target_and_provider_context(self):
        self.write()
        record, digest = self.verify()
        self.assertEqual(record["effectivePrincipal"], self.target)
        self.assertEqual(len(digest), 64)

    def test_manual_mismatch_stale_fixture_and_signature_substitution_are_rejected(self):
        for changes, reason in [({"effectivePrincipal": "someone-else@example.test"}, "does not match"),
            ({"projectId": "another-project"}, "does not match"),
            ({"evidenceReference": "synthetic://made-up"}, "does not match"),
            ({"expiresAt": (self.now-dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")}, "stale, expired")]:
            self.write(**changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(context.ContextError, reason):
                self.verify()
        self.write()
        self.path.with_name(self.path.name + ".sig").write_bytes(b"bad-signature")
        with self.assertRaisesRegex(context.ContextError, "signature is invalid"):
            self.verify()

    def test_project_role_uses_valid_project_permissions_and_can_restore_snapshots(self):
        role = json.loads((ROOT / "infrastructure/terraform/gcp/self-managed-lab/terraform-deployer-role.json").read_text())
        permissions = set(role["includedPermissions"])
        self.assertTrue({"resourcemanager.projects.get", "resourcemanager.projects.list",
                         "compute.networks.updatePolicy", "compute.snapshots.useReadOnly"}.issubset(permissions))
        self.assertFalse(any(permission.startswith("cloudresourcemanager.") for permission in permissions))
        self.assertNotIn("compute.snapshots.create", permissions)
        self.assertNotIn("compute.snapshots.delete", permissions)
        inventory = json.loads((ROOT / "infrastructure/terraform/gcp/self-managed-lab/lab-inventory-role.json").read_text())
        self.assertIn("resourcemanager.projects.get", inventory["includedPermissions"])
        self.assertFalse(any(permission.startswith("cloudresourcemanager.")
                             for permission in inventory["includedPermissions"]))

    def test_secret_manager_resource_condition_uses_verified_numeric_project_number(self):
        runbook = (ROOT / "docs/m3-persistent-lab-lifecycle.md").read_text()
        self.assertIn('PROJECT_NUMBER="$ACTUAL_PROJECT_NUMBER"', runbook)
        self.assertIn("resource.name == 'projects/${PROJECT_NUMBER}/secrets/${LAB_PREFIX}-agent-join'", runbook)
        self.assertNotIn("resource.name == 'projects/${PROJECT}/secrets/${LAB_PREFIX}-agent-join'", runbook)


if __name__ == "__main__":
    unittest.main()
