"""Synthetic-only tests for the M3 stage controller and customer input contract."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import datetime as dt
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from io import StringIO

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m3_qualification_controller", ROOT / "scripts/m3_qualification.py")
controller = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(controller)


class QualificationControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manifest_path = self.root / "inputs.json"
        self.document = {"schemaVersion": 1, "customerId": "synthetic-customer", "projectId": controller.PROJECT,
                         "region": controller.REGION, "zone": controller.ZONE, "labId": controller.LAB_ID,
                         "fixtureOnly": False, "canonicalMatrixSha256": controller.MATRIX_SHA256,
                         "k3sVersion": controller.K3S_VERSION,
                         "platformTargets": {platform: None for platform in controller.PLATFORMS},
                         "residualRiskAcceptance": {platform: None for platform in controller.PLATFORMS},
                         "inputs": {name: None for name in controller.INPUTS}}

    def tearDown(self):
        self.temp.cleanup()

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.document), encoding="utf-8")

    def test_manifest_requires_every_input_and_rejects_unknown_or_duplicate_json_fields(self):
        # Every authoritative contract slot is required; callers cannot add or omit fields.
        del self.document["inputs"][next(iter(controller.INPUTS))]
        with self.assertRaises(controller.QualificationError):
            controller.validate_manifest(self.document)
        self.document["inputs"][next(iter(controller.INPUTS))] = None
        self.document["inputs"]["unexpected"] = None
        with self.assertRaises(controller.QualificationError):
            controller.validate_manifest(self.document)
        self.manifest_path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        with self.assertRaises(controller.QualificationError):
            controller.read_json(self.manifest_path)

    def test_malformed_manifest_value_types_fail_closed_without_type_errors(self):
        self.document["inputs"]["signedReleaseBundle"] = {"reference": "release", "sha256": [],
                                                            "expiresAt": None}
        with self.assertRaises(controller.QualificationError):
            controller.validate_manifest(self.document)
        self.document["inputs"]["signedReleaseBundle"] = None
        self.document["platformTargets"]["rhel-9.8+"] = {
            "osId": "rhel", "osVersion": [], "architecture": "amd64", "imageProject": "rhel-project",
            "imageSelfLink": "https://www.googleapis.com/compute/v1/projects/rhel-project/global/images/rhel-9-test",
            "imageId": "987654321", "packagePolicySha256": "a" * 64}
        with self.assertRaises(controller.QualificationError):
            controller.validate_manifest(self.document)

    def test_wrong_project_or_fixture_cannot_become_production_readiness(self):
        self.document["projectId"] = "other-project"
        with self.assertRaises(controller.QualificationError):
            controller.validate_manifest(self.document)
        self.document["projectId"] = controller.PROJECT
        self.document["fixtureOnly"] = True
        self.write_manifest()
        report = controller.load_input_report(self.manifest_path)
        self.assertEqual(report["productionReadiness"], "BLOCKED")
        self.assertFalse(controller.status_report(inputs_path=self.manifest_path)["qualificationAccepted"])

    def test_matching_file_hash_is_only_unverified_and_missing_is_not_provided(self):
        data = b"synthetic artifact, not customer material"
        (self.root / "public-artifact.bin").write_bytes(data)
        name = "signedReleaseBundle"
        self.document["inputs"][name] = {"reference": "public-artifact.bin", "sha256": hashlib.sha256(data).hexdigest(), "expiresAt": None}
        self.write_manifest()
        report = controller.load_input_report(self.manifest_path)
        by_name = {item["inputId"]: item for item in report["inputs"]}
        self.assertEqual(by_name[name]["status"], "UNVERIFIED")
        self.assertEqual(by_name["maintenanceTrustConfiguration"]["status"], "NOT_PROVIDED")

    def test_manifest_digest_is_independent_of_input_slot_order(self):
        ordered = {"schemaVersion": 1, "customerId": "synthetic-customer", "projectId": controller.PROJECT,
                   "region": controller.REGION, "zone": controller.ZONE, "labId": controller.LAB_ID,
                   "fixtureOnly": False, "canonicalMatrixSha256": controller.MATRIX_SHA256,
                   "k3sVersion": controller.K3S_VERSION,
                   "platformTargets": {platform: None for platform in controller.PLATFORMS},
                   "residualRiskAcceptance": {platform: None for platform in controller.PLATFORMS},
                   "inputs": {key: None for key in sorted(controller.INPUTS)}}
        self.manifest_path.write_text(json.dumps(ordered), encoding="utf-8")
        first = controller.load_input_report(self.manifest_path)["inputManifestSha256"]
        ordered["inputs"] = dict(reversed(list(ordered["inputs"].items())))
        self.manifest_path.write_text(json.dumps(ordered), encoding="utf-8")
        second = controller.load_input_report(self.manifest_path)["inputManifestSha256"]
        self.assertEqual(first, second)

    def test_digest_mismatch_expiry_path_escape_and_symlink_fail_closed(self):
        (self.root / "artifact").write_bytes(b"synthetic")
        item = {"reference": "artifact", "sha256": "0" * 64, "expiresAt": None}
        now = dt.datetime.now(dt.timezone.utc)
        self.assertEqual(controller.inspect_reference(self.manifest_path, "signedReleaseBundle", item, now)["status"], "INVALID")
        item["reference"] = "../outside"
        self.assertEqual(controller.inspect_reference(self.manifest_path, "signedReleaseBundle", item, now)["status"], "INVALID")
        (self.root / "link").symlink_to(self.root / "artifact")
        item["reference"] = "link"
        self.assertEqual(controller.inspect_reference(self.manifest_path, "signedReleaseBundle", item, now)["status"], "INVALID")

    def test_expired_input_is_not_provided_as_current_evidence(self):
        (self.root / "artifact").write_bytes(b"synthetic")
        import hashlib
        item = {"reference": "artifact", "sha256": hashlib.sha256(b"synthetic").hexdigest(),
                "expiresAt": "2020-01-01T00:00:00Z"}
        result = controller.inspect_reference(self.manifest_path, "signedReleaseBundle", item,
                                              dt.datetime.now(dt.timezone.utc))
        self.assertEqual(result["status"], "EXPIRED")

    def test_checked_in_example_is_fixture_only_and_never_qualifies(self):
        example = ROOT / "docs/examples/m3-customer-inputs.synthetic.json"
        report = controller.load_input_report(example)
        self.assertTrue(report["fixtureOnly"])
        self.assertEqual(report["productionReadiness"], "BLOCKED")

    def test_checked_in_schema_and_example_are_reproducible(self):
        for command, path in (("schema", ROOT / "docs/schemas/m3-customer-inputs-v1.json"),
                              ("example", ROOT / "docs/examples/m3-customer-inputs.synthetic.json")):
            output = StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(controller.main([command]), 0)
            self.assertEqual(json.loads(output.getvalue()), json.loads(path.read_text(encoding="utf-8")))

    def test_customer_supplied_status_cannot_be_used_as_proof(self):
        self.document["inputs"]["signedReleaseBundle"] = {"reference": "x", "sha256": "a" * 64,
                                                            "expiresAt": None, "status": "APPROVED"}
        with self.assertRaises(controller.QualificationError):
            controller.validate_manifest(self.document)

    def test_authoritative_status_never_claims_acceptance_without_registry_or_real_evidence(self):
        # The status report may execute local tooling checks, but it must not
        # contact customer endpoints or perform qualification operations.
        with patch("socket.getaddrinfo", side_effect=AssertionError("network lookup attempted")):
            report = controller.status_report()
        self.assertFalse(report["qualificationAccepted"])
        self.assertEqual(report["overallStatus"], "M3 NOT COMPLETE")
        self.assertEqual(report["canonicalScenarioCount"], 22)
        self.assertEqual(len(report["canonicalRows"]), 22)
        self.assertEqual({row["status"] for row in report["canonicalRows"]}, {"NOT RUN"})
        self.assertTrue(all(x["status"] not in {"APPROVED", "VERIFIED"} for x in report["stages"]))
        self.assertEqual([x["stage"] for x in report["stages"]],
                         ["inspect", "inputs", "trust", "cloud-review", "plan-review", "connectivity",
                          "qualification", "evidence", "status"])
        self.assertEqual(len(report["missingInputs"]), len(controller.INPUTS))
        self.assertEqual(report["operationsPerformed"], {"gcp": "NONE", "terraform": "NONE",
                                                         "customerSystems": "NONE", "hostMaintenance": "NONE",
                                                         "faultInjection": "NONE"})
        expected_pairs = {(scenario, f"{family}-13" if family == "debian" else "rhel-9.8+")
                          for scenario in [case["id"] for case in json.loads(
                              (ROOT / "tests/integration/host_upgrade_failure_matrix.json").read_text())["cases"]]
                          for family in ("debian", "rhel")}
        observed_pairs = {(row["scenarioId"], row["platformId"]) for row in report["canonicalRows"]}
        self.assertEqual(observed_pairs, expected_pairs)
        for row in report["canonicalRows"]:
            self.assertIsNone(row["hostIdentity"])
            self.assertIsNone(row["operationId"])
            self.assertEqual(row["evidenceReferences"], [])
            self.assertEqual(row["executionState"], "NOT RUN")
            self.assertEqual(row["evidenceVerification"], "NOT RUN")
            self.assertEqual(row["reviewerDecision"], "NOT RUN")
            self.assertEqual(row["finalRowState"], "NOT RUN")
        self.assertTrue(report["dependencyGraph"]["openDependencies"])
        self.assertEqual(report["overallStatus"], "M3 NOT COMPLETE")

    def test_status_serialization_is_deterministic_for_the_same_local_state(self):
        first = controller.status_report()
        second = controller.status_report()
        self.assertEqual(controller.canonical_json(first), controller.canonical_json(second))

    def test_blocked_stages_name_their_open_dependencies_and_owners(self):
        for stage in ("trust", "cloud-review", "plan-review", "connectivity", "evidence"):
            result = controller.run_stage(stage)
            self.assertEqual(result["status"], "BLOCKED")
            dependencies = result["details"]["dependencies"]
            self.assertTrue(dependencies, stage)
            self.assertTrue(all(item["owner"] and item["nextAction"] for item in dependencies))
            self.assertTrue(all(item["currentStatus"] not in {"IMPLEMENTED", "LOCALLY VERIFIED"}
                                for item in dependencies))

    def test_dependency_graph_requires_unique_valid_acyclic_nodes(self):
        graph = controller.read_json(ROOT / "docs/m3-qualification-dependencies.json")
        controller.validate_dependency_graph(graph)
        cyclic = json.loads(json.dumps(graph))
        cyclic["edges"].append({"from": cyclic["dependencies"][-1]["id"],
                                "to": cyclic["dependencies"][0]["id"]})
        with self.assertRaisesRegex(controller.QualificationError, "cycle"):
            controller.validate_dependency_graph(cyclic)
        duplicate = json.loads(json.dumps(graph))
        duplicate["dependencies"].append(dict(duplicate["dependencies"][0]))
        with self.assertRaises(controller.QualificationError):
            controller.validate_dependency_graph(duplicate)
        malformed = json.loads(json.dumps(graph))
        malformed["edges"][0]["from"] = []
        with self.assertRaises(controller.QualificationError):
            controller.validate_dependency_graph(malformed)

    def test_dependency_graph_does_not_reopen_locally_verified_skopeo(self):
        graph = controller.read_json(ROOT / "docs/m3-qualification-dependencies.json")
        dependency = next(item for item in graph["dependencies"] if item["id"] == "M3-LOCAL-SKOPEO")
        self.assertEqual(dependency["classification"], "repo-complete")
        self.assertEqual(dependency["currentStatus"], "LOCALLY VERIFIED")
        self.assertIn("pinned skopeo acquisition", dependency["description"].lower())
        self.assertNotIn("environment is missing", dependency["description"].lower())

    def test_platform_targets_require_exact_supported_os_and_policy_binding(self):
        self.document["inputs"]["debianPackagePolicy"] = {"reference": "policy.json", "sha256": "a" * 64,
                                                               "expiresAt": None}
        self.document["inputs"]["debianImageApproval"] = {"reference": "approval.json", "sha256": "b" * 64,
                                                             "expiresAt": None}
        self.document["platformTargets"]["debian-13"] = {
            "osId": "debian", "osVersion": "13.1", "architecture": "amd64",
            "imageProject": "debian-cloud",
            "imageSelfLink": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-test",
            "imageId": "123456789", "packagePolicySha256": "a" * 64}
        controller.validate_platform_targets(self.document)
        self.document["platformTargets"]["debian-13"]["imageProject"] = "debian-mirror"
        self.document["platformTargets"]["debian-13"]["imageSelfLink"] = (
            "https://www.googleapis.com/compute/v1/projects/debian-mirror/global/images/debian-13-test")
        with self.assertRaisesRegex(controller.QualificationError, "Debian target"):
            controller.validate_platform_targets(self.document)
        self.document["platformTargets"]["debian-13"]["imageProject"] = "debian-cloud"
        self.document["platformTargets"]["debian-13"]["imageSelfLink"] = (
            "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-test")
        self.document["platformTargets"]["debian-13"]["osVersion"] = "12.11"
        with self.assertRaisesRegex(controller.QualificationError, "Debian 13"):
            controller.validate_platform_targets(self.document)
        self.document["platformTargets"]["debian-13"]["osVersion"] = "13.1"
        self.document["platformTargets"]["debian-13"]["packagePolicySha256"] = "c" * 64
        with self.assertRaisesRegex(controller.QualificationError, "package policy"):
            controller.validate_platform_targets(self.document)

    def test_rhel_below_minimum_or_derivative_fails_closed(self):
        self.document["inputs"]["rhelPackagePolicy"] = {"reference": "policy.json", "sha256": "a" * 64,
                                                            "expiresAt": None}
        self.document["inputs"]["rhelImageApproval"] = {"reference": "approval.json", "sha256": "b" * 64,
                                                          "expiresAt": None}
        self.document["platformTargets"]["rhel-9.8+"] = {
            "osId": "rhel", "osVersion": "9.8", "architecture": "amd64",
            "imageProject": "customer-rhel-images",
            "imageSelfLink": "https://www.googleapis.com/compute/v1/projects/customer-rhel-images/global/images/rhel-9-test",
            "imageId": "987654321", "packagePolicySha256": "a" * 64}
        controller.validate_platform_targets(self.document)
        self.document["platformTargets"]["rhel-9.8+"]["osVersion"] = "9.7"
        with self.assertRaisesRegex(controller.QualificationError, "RHEL 9.8"):
            controller.validate_platform_targets(self.document)
        self.document["platformTargets"]["rhel-9.8+"]["osVersion"] = "9.8"
        self.document["platformTargets"]["rhel-9.8+"]["osId"] = "rocky"
        with self.assertRaisesRegex(controller.QualificationError, "RHEL 9.8"):
            controller.validate_platform_targets(self.document)

    def test_qualification_stage_requires_all_verified_inputs_targets_and_residual_acceptance(self):
        self.write_manifest()
        result = controller.run_stage("qualification", inputs_path=self.manifest_path)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(len(result["details"]["unverifiedInputs"]), len(controller.INPUTS))
        self.assertEqual(set(result["details"]["unverifiedPlatformTargets"]), set(controller.PLATFORMS))
        self.assertEqual(set(result["details"]["unverifiedResidualRiskAcceptances"]), set(controller.PLATFORMS))

    def test_artifact_preflight_report_is_locally_rechecked_but_never_promoted_to_verified(self):
        import hashlib
        config_path, report_path = self.root / "artifact-inputs.json", self.root / "artifact-report.json"
        config_path.write_text("{}", encoding="utf-8")
        report = {"schemaVersion": 1, "overallStatus": "PASS", "artifacts": {
            "hostPackageArtifacts": {"osId": "debian", "osPointRelease": "13.1", "architecture": "amd64",
                                     "policySha256": "a" * 64}}}
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.document["inputs"]["debianPackagePolicy"] = {"reference": "policy.json", "sha256": "a" * 64,
                                                               "expiresAt": None}
        self.document["inputs"]["debianImageApproval"] = {"reference": "image-approval.json", "sha256": "b" * 64,
                                                             "expiresAt": None}
        self.document["platformTargets"]["debian-13"] = {
            "osId": "debian", "osVersion": "13.1", "architecture": "amd64",
            "imageProject": "debian-cloud",
            "imageSelfLink": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-test",
            "imageId": "123456789", "packagePolicySha256": "a" * 64}
        self.document["inputs"]["debianArtifactPreflightInputs"] = {
            "reference": config_path.name, "sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(), "expiresAt": None}
        self.document["inputs"]["debianArtifactPreflightReport"] = {
            "reference": report_path.name, "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(), "expiresAt": None}
        self.write_manifest()
        with patch.object(controller, "recheck_existing_artifact_preflight", return_value={"status": "PASS"}):
            result = controller.load_input_report(self.manifest_path)
        self.assertEqual(result["artifactPreflights"]["debian-13"]["status"], "UNVERIFIED")
        self.assertNotEqual(result["productionReadiness"], "VERIFIED")
        report["artifacts"]["hostPackageArtifacts"]["policySha256"] = "c" * 64
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.document["inputs"]["debianArtifactPreflightReport"]["sha256"] = hashlib.sha256(
            report_path.read_bytes()).hexdigest()
        self.write_manifest()
        with patch.object(controller, "recheck_existing_artifact_preflight", return_value={"status": "PASS"}):
            mismatch = controller.load_input_report(self.manifest_path)
        self.assertEqual(mismatch["artifactPreflights"]["debian-13"]["status"], "FAIL")

    def test_inspect_reports_project_designation_not_live_project_verification(self):
        result = controller.run_stage("inspect")
        configured = result["details"]["checks"]["trackedProjectDesignation"]
        self.assertEqual(configured["projectId"], controller.PROJECT)
        self.assertFalse(configured["liveProjectVerified"])
        self.assertIn("hostUpgradeGateDefaultOff", result["details"]["checks"])
        if result["details"]["checks"]["localTools"]["status"] == "NOT PROVIDED":
            self.assertEqual(result["status"], "BLOCKED")

    def test_only_defined_stages_exist_and_no_stage_invokes_external_execution(self):
        for stage in ("trust", "cloud-review", "plan-review", "connectivity", "evidence"):
            result = controller.run_stage(stage)
            self.assertEqual(result["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
