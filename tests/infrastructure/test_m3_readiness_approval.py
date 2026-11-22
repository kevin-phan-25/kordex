"""Synthetic-only tests for signed, short-lived M3 plan authorization."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m3_readiness_approval", ROOT / "scripts/m3_readiness_binding.py")
binding = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(binding)


class ReadinessApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.private, self.public = self.root / "approver.private.pem", self.root / "approver.public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.private)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.fingerprint = binding.m3_customer_trust.fingerprint(self.public.read_bytes())
        self.trust = {"schemaVersion": 1, "customerId": "synthetic-only", "sequence": 1,
                      "issuedAt": (self.now-dt.timedelta(minutes=5)).isoformat(),
                      "expiresAt": (self.now+dt.timedelta(days=2)).isoformat(),
                      "keys": [{"identity": "deployment-reviewer-fixture", "role": "deployment-approver",
                                "fingerprint": self.fingerprint, "publicKeyPem": self.public.read_text(),
                                "validFrom": (self.now-dt.timedelta(minutes=5)).isoformat(),
                                "validUntil": (self.now+dt.timedelta(days=1)).isoformat(), "revokedAt": None}]}
        self.trust_digest = hashlib.sha256(binding.m3_customer_trust.canonical_json(self.trust)).hexdigest()
        self.path = self.root / "readiness.json"
        checks = {name: self.check(name, "PASS") for name in binding.READINESS_APPROVAL_CHECKS}
        # These customer-supplied values are structurally bound but are not
        # independently verified. Approval covers their exact report digest;
        # their status must remain PROVIDED throughout the flow.
        checks.update({name: self.check(name, "PROVIDED")
                       for name in binding.READINESS_PROVIDED_INPUT_CHECKS})
        self.report = {"schemaVersion": 2, "generatedAt": (self.now-dt.timedelta(minutes=2)).isoformat(),
                       "overallStatus": "PROVIDED", "checks": checks, "planBinding": {"sha256": "a"*64}}
        self.report_raw = binding.m3_customer_trust.canonical_json(self.report)
        self.path.write_bytes(self.report_raw)
        self.approval_path = self.path.with_name(self.path.name + ".approval.json")
        approval = {"schemaVersion": 1, "readinessReportSha256": hashlib.sha256(self.report_raw).hexdigest(),
                    "planBindingSha256": binding.canonical_sha256(self.report["planBinding"]),
                    "trustConfigurationSha256": self.trust_digest,
                    "approvedChecks": sorted(binding.READINESS_APPROVAL_CHECKS),
                    "reviewerIdentity": "deployment-reviewer-fixture", "decision": "approved",
                    "approvedAt": self.now.isoformat(), "expiresAt": (self.now+dt.timedelta(hours=1)).isoformat(),
                    "rationale": "Synthetic fixture for the signed readiness approval test."}
        self.approval_raw = binding.m3_customer_trust.canonical_json(approval)
        self.approval_path.write_bytes(self.approval_raw)
        self.signature_path = self.approval_path.with_name(self.approval_path.name + ".sig")
        source, signature = self.root / "approval.payload", self.root / "approval.sig"
        source.write_bytes(self.approval_raw)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
                        "-in", str(source), "-out", str(signature)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.signature_path.write_bytes(signature.read_bytes())

    def tearDown(self):
        self.temp.cleanup()

    def check(self, name, status):
        schema = binding.READINESS_CHECK_SCHEMA[name]
        return {"status": status, "result": status, "code": "SyntheticFixture",
                "reason": "SyntheticFixture", "requirementId": schema["requirementId"],
                "platformApplicability": schema["platformApplicability"],
                "inputReference": schema["inputReference"], "verificationMethod": schema["verificationMethod"],
                "verificationTimestamp": self.now.isoformat(),
                "independentReviewRequired": schema["independentReviewRequired"]}

    def verify(self, now=None):
        return binding.validate_readiness_approval(self.path, self.report, self.report_raw,
            trust_loader=lambda: (self.trust, self.trust_digest), now=now or self.now)

    def test_trusted_deployment_approver_signature_binds_exact_report_and_plan(self):
        result = self.verify()
        self.assertEqual(result["identity"], "deployment-reviewer-fixture")
        self.assertEqual(result["fingerprint"], self.fingerprint)

    def test_noncanonical_readiness_bytes_are_not_approval_input(self):
        noncanonical = json.dumps(self.report, sort_keys=False, indent=1).encode()
        with self.assertRaisesRegex(binding.BindingError, "not canonical"):
            binding.validate_readiness_approval(self.path, self.report, noncanonical,
                trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

    def test_blocked_or_provided_gate_cannot_be_overridden_by_approval_signature(self):
        for state in ("BLOCKED", "PROVIDED", "FAIL", "NOT PROVIDED"):
            report = json.loads(self.report_raw)
            report["checks"]["billingBudget"]["result"] = state
            raw = binding.m3_customer_trust.canonical_json(report)
            with self.subTest(state=state), self.assertRaisesRegex(binding.BindingError, "cannot override"):
                binding.validate_readiness_approval(self.path, report, raw,
                    trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

    def test_only_the_three_input_checks_may_remain_provided_under_separate_approval(self):
        result = self.verify()
        self.assertEqual(result["identity"], "deployment-reviewer-fixture")
        for name in binding.READINESS_PROVIDED_INPUT_CHECKS:
            self.assertEqual(self.report["checks"][name]["result"], "PROVIDED")

        for name in binding.READINESS_APPROVAL_CHECKS:
            report = json.loads(self.report_raw)
            report["checks"][name]["result"] = "PROVIDED"
            raw = binding.m3_customer_trust.canonical_json(report)
            with self.subTest(name=name), self.assertRaises(binding.BindingError):
                binding.validate_readiness_approval(self.path, report, raw,
                    trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

    def test_conflicting_aggregate_or_input_status_is_rejected(self):
        report = json.loads(self.report_raw)
        report["overallStatus"] = "PASS"
        for name in binding.READINESS_PROVIDED_INPUT_CHECKS:
            report["checks"][name]["result"] = "PASS"
        report["overallStatus"] = "PROVIDED"
        raw = binding.m3_customer_trust.canonical_json(report)
        with self.assertRaisesRegex(binding.BindingError, "cannot override"):
            binding.validate_readiness_approval(self.path, report, raw,
                trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

        # A customer-supplied value must not be relabeled PASS by changing both
        # status fields and the aggregate state, even if an approver signs it.
        report = json.loads(self.report_raw)
        for name in binding.READINESS_PROVIDED_INPUT_CHECKS:
            report["checks"][name]["status"] = "PASS"
            report["checks"][name]["result"] = "PASS"
        report["overallStatus"] = "PASS"
        raw = binding.m3_customer_trust.canonical_json(report)
        with self.assertRaisesRegex(binding.BindingError, "cannot override"):
            binding.validate_readiness_approval(self.path, report, raw,
                trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

        report = json.loads(self.report_raw)
        report["overallStatus"] = "PASS"
        report["checks"]["customerNetworkInputs"]["result"] = "PASS"
        raw = binding.m3_customer_trust.canonical_json(report)
        with self.assertRaisesRegex(binding.BindingError, "cannot override"):
            binding.validate_readiness_approval(self.path, report, raw,
                trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

    def test_check_schema_metadata_cannot_be_substituted(self):
        for field, value in (("requirementId", "M3-OPTIONAL"),
                             ("inputReference", "operator says ok"),
                             ("verificationMethod", "manual assertion"),
                             ("independentReviewRequired", True)):
            report = json.loads(self.report_raw)
            report["checks"]["localTools"][field] = value
            raw = binding.m3_customer_trust.canonical_json(report)
            with self.subTest(field=field), self.assertRaisesRegex(binding.BindingError, "metadata"):
                binding.validate_readiness_results(report)

    def test_unlisted_provided_input_is_rejected(self):
        report = json.loads(self.report_raw)
        report["checks"]["unrecognizedInput"] = {"result": "PROVIDED"}
        raw = binding.m3_customer_trust.canonical_json(report)
        with self.assertRaisesRegex(binding.BindingError, "cannot override"):
            binding.validate_readiness_approval(self.path, report, raw,
                trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

    def test_complete_readiness_schema_rejects_each_omission_unknown_and_platform_drift(self):
        for name in binding.READINESS_CHECK_PLATFORMS:
            report = json.loads(self.report_raw)
            report["checks"].pop(name)
            with self.subTest(omitted=name), self.assertRaisesRegex(binding.BindingError, "check set"):
                binding.validate_readiness_results(report)
        report = json.loads(self.report_raw)
        report["checks"]["futureUnknownCheck"] = self.check("localTools", "PASS")
        with self.assertRaisesRegex(binding.BindingError, "check set"):
            binding.validate_readiness_results(report)
        report = json.loads(self.report_raw)
        report["checks"]["localTools"]["platformApplicability"] = ["debian-13"]
        with self.assertRaisesRegex(binding.BindingError, "platform applicability"):
            binding.validate_readiness_results(report)
        report = json.loads(self.report_raw)
        report["checks"]["localTools"]["result"] = "BLOCKED"
        with self.assertRaisesRegex(binding.BindingError, "metadata"):
            binding.validate_readiness_results(report)

    def test_duplicate_json_check_names_are_rejected_at_the_canonical_parse_boundary(self):
        duplicate = b'{"localTools":{"result":"PASS"},"localTools":{"result":"PASS"}}'
        with self.assertRaisesRegex(binding.m3_customer_trust.TrustError, "duplicate"):
            json.loads(duplicate, object_pairs_hook=binding.m3_customer_trust.unique_object)

    def test_changed_report_or_plan_binding_invalidates_customer_signature(self):
        report = json.loads(self.report_raw)
        report["planBinding"]["sha256"] = "b"*64
        raw = binding.m3_customer_trust.canonical_json(report)
        with self.assertRaisesRegex(binding.BindingError, "does not bind"):
            binding.validate_readiness_approval(self.path, report, raw,
                trust_loader=lambda: (self.trust, self.trust_digest), now=self.now)

    def test_expired_and_future_approval_times_are_rejected(self):
        approval = json.loads(self.approval_raw)
        approval["expiresAt"] = (self.now-dt.timedelta(seconds=1)).isoformat()
        self._resign(approval)
        with self.assertRaisesRegex(binding.BindingError, "stale, expired"):
            self.verify()
        approval["approvedAt"] = (self.now+dt.timedelta(minutes=5)).isoformat()
        approval["expiresAt"] = (self.now+dt.timedelta(hours=1)).isoformat()
        self._resign(approval)
        with self.assertRaisesRegex(binding.BindingError, "stale, expired"):
            self.verify()

    def _resign(self, approval):
        raw = binding.m3_customer_trust.canonical_json(approval)
        self.approval_path.write_bytes(raw)
        self.report_raw = self.path.read_bytes()
        source, signature = self.root / "approval.payload", self.root / "approval.sig"
        source.write_bytes(raw)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
                        "-in", str(source), "-out", str(signature)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.signature_path.write_bytes(signature.read_bytes())


if __name__ == "__main__":
    unittest.main()
