"""Synthetic local-only tests for canonical M3 plan-input binding."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


binding = load("m3_readiness_binding", "scripts/m3_readiness_binding.py")
readiness = load("m3_deployment_readiness", "scripts/m3_deployment_readiness.py")
lab = load("self_managed_lab_for_plan_binding", "scripts/self_managed_lab.py")


def network() -> dict:
    return {
        "schemaVersion": 1, "projectId": readiness.EXPECTED_PROJECT,
        "region": readiness.EXPECTED_REGION, "zone": readiness.EXPECTED_ZONE,
        "labId": readiness.EXPECTED_LAB_ID, "osFamily": "debian-13",
        "nodeRoles": list(readiness.EXPECTED_NODE_ROLES), "subnetCIDR": readiness.EXPECTED_SUBNET,
        "labSourceCIDR": readiness.EXPECTED_SUBNET, "approvedPrivateMirrorCIDRs": ["10.90.0.0/24"],
        "approvedPrivateRelayCIDRs": ["10.91.0.0/24"],
        "restrictedGoogleApisCIDR": readiness.EXPECTED_GOOGLE_APIS_CIDR,
        "mirrorPort": 443, "relayPort": 18443, "noVMExternalIPs": True, "noCloudNAT": True,
        "relayDNSName": "relay.example.internal", "mirrorDNSNames": [
            "apt.example.internal", "mirror.example.internal", "registry.example.internal", "rpm.example.internal",
        ],
    }


def terraform_inputs(profile: str = "debian-13", minor: str = "", point: str = "13.8") -> dict:
    result = {
        "project_id": readiness.EXPECTED_PROJECT,
        "allowed_project_ids": [readiness.EXPECTED_PROJECT],
        "project_id_confirmation": readiness.EXPECTED_PROJECT,
        "region": readiness.EXPECTED_REGION, "zone": readiness.EXPECTED_ZONE,
        "name_prefix": readiness.EXPECTED_LAB_ID,
        "recovery_snapshot_ids": {}, "recovery_project_id": "", "recovery_lab_id": "",
        "recovery_zone": "", "recovery_internal_ips": {}, "recovery_operation_id": "",
        "upgrade_ssh_user": "kordex", "k3s_version": "v1.36.6+k3s1",
        "k3s_binary_sha256": "a" * 64,
        "k3s_binary_mirror_url": "https://mirror.example.internal/k3s/v1.36.6+k3s1/linux-amd64/k3s",
        "k3s_system_images_manifest_version": "1", "k3s_system_images_k3s_version": "v1.36.6+k3s1",
        "k3s_system_images_architecture": "linux/amd64", "k3s_system_images_bundle_sha256": "b" * 64,
        "k3s_system_images_bundle_mirror_url": "https://mirror.example.internal/k3s/v1.36.6+k3s1/images.tar",
        "k3s_system_images_mirror_host": "registry.example.internal",
        "approved_private_mirror_cidrs": ["10.90.0.0/24"],
        "approved_private_relay_cidrs": ["10.91.0.0/24"],
        "ubuntu_apt_mirror_url": "", "debian_archive_mirror_url": "https://apt.example.internal/debian",
        "debian_security_mirror_url": "https://apt.example.internal/debian-security",
        "qualification_os_profile": profile, "qualification_os_minor": minor,
        "qualification_os_point_release": point,
        "qualification_image_approval_reference": "custodian-record-2026-11-21",
        "qualification_image_approval_sha256": "c" * 64,
        "qualification_image_unique_id": "1234567890123456789" if profile != "ubuntu-24.04" else "",
        "debian_image_self_link": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-approved-20261121",
        "rhel_image_self_link": "", "rhel_repository_baseurl": "",
        "rhel_repository_gpg_key_path": "", "rhel_repository_gpg_fingerprint": "",
        "os_family": "debian", "machine_type": "e2-standard-2", "boot_disk_size_gb": 40,
    }
    if profile == "rhel-9":
        result.update({"qualification_os_minor": "9", "qualification_os_point_release": "9.9",
                       "os_family": "rhel", "debian_image_self_link": "",
                       "debian_archive_mirror_url": "", "debian_security_mirror_url": "",
                       "rhel_image_self_link": "https://www.googleapis.com/compute/v1/projects/customer-images/global/images/rhel-9-9-approved",
                       "rhel_repository_baseurl": "https://rpm.example.internal/rhel/9.9",
                       "rhel_repository_gpg_key_path": "/etc/pki/rpm-gpg/RPM-GPG-KEY-customer",
                       "rhel_repository_gpg_fingerprint": "f" * 40})
    elif profile == "ubuntu-24.04":
        result.update({"qualification_os_point_release": "", "debian_image_self_link": "",
                       "debian_archive_mirror_url": "", "debian_security_mirror_url": "",
                       "ubuntu_apt_mirror_url": "https://apt.example.internal/ubuntu"})
    return result


def artifact_report(profile: str = "debian-13", minor: str = "", point: str = "13.8") -> dict:
    osid, major = ("rhel", "9") if profile == "rhel-9" else (("ubuntu", "24") if profile == "ubuntu-24.04" else ("debian", "13"))
    osminor = minor if profile == "rhel-9" else "04" if profile == "ubuntu-24.04" else ""
    return {"profile": f"m3-{osid}-{major}{'.' + osminor if osminor else ''}-k3s-v1.36.6+k3s1-linux-amd64",
            "artifacts": {
        "hostPackageArtifacts": {"osId": osid, "osMajor": major, "osMinor": osminor,
                                         "osPointRelease": point, "profile": f"m3-{osid}-{major}{'.' + osminor if osminor else ''}-k3s-v1.36.6+k3s1-linux-amd64",
                                         "policySha256": "1" * 64, "packageArchiveSha256": "2" * 64,
                                         "privateMirrorURLHost": "rpm.example.internal" if profile == "rhel-9" else "apt.example.internal"},
                "k3sBinaryApproval": {"binarySha256": "a" * 64,
                                      "mirrorReference": "https://mirror.example.internal/k3s/v1.36.6+k3s1/linux-amd64/k3s"},
                "k3sSystemImageApproval": {"version": "v1.36.6+k3s1", "architecture": "linux/amd64",
                                           "bundleSha256": "b" * 64,
                                           "bundleMirrorReference": "https://mirror.example.internal/k3s/v1.36.6+k3s1/images.tar",
                                           "mirrorHost": "registry.example.internal"},
                "privateRegistryImages": {"status": "PASS", "registryHost": "registry.example.internal"},
            }}


class ReadinessBindingTests(unittest.TestCase):
    def validate(self, values, network_doc=None, report=None):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "terraform-inputs.json"
            path.write_text(json.dumps(values), encoding="utf-8")
            return binding.validate_plan_inputs(
                path, reader=readiness._safe_json,
                terraform_source=(ROOT / "infrastructure/terraform/gcp/self-managed-lab/variables.tf").read_text(),
                network=network_doc or network(), artifact_report=report or artifact_report(),
                expected_project=readiness.EXPECTED_PROJECT, expected_region=readiness.EXPECTED_REGION,
                expected_zone=readiness.EXPECTED_ZONE, expected_lab_id=readiness.EXPECTED_LAB_ID)

    def test_complete_debian13_inputs_are_canonical_and_key_order_independent(self):
        original = terraform_inputs()
        normalized, first = self.validate(original)
        reordered, second = self.validate(dict(reversed(list(original.items()))))
        self.assertEqual(normalized, reordered)
        self.assertEqual(first, second)
        self.assertEqual(first, binding.canonical_sha256(normalized))

    def test_network_set_reordering_has_the_same_effective_binding(self):
        network_doc = network()
        network_doc["approvedPrivateMirrorCIDRs"] = ["10.90.0.0/24", "10.92.0.0/24"]
        network_doc["approvedPrivateRelayCIDRs"] = ["10.91.0.0/24", "10.93.0.0/24"]
        reordered = dict(reversed(list(network_doc.items())))
        reordered["approvedPrivateMirrorCIDRs"] = list(reversed(network_doc["approvedPrivateMirrorCIDRs"]))
        reordered["approvedPrivateRelayCIDRs"] = list(reversed(network_doc["approvedPrivateRelayCIDRs"]))
        reordered["mirrorDNSNames"] = list(reversed(network_doc["mirrorDNSNames"]))
        self.assertEqual(binding.canonical_sha256(binding.canonical_network_inputs(network_doc)),
                         binding.canonical_sha256(binding.canonical_network_inputs(reordered)))

    def test_changed_or_omitted_effective_input_fails_closed(self):
        for mutate in (
            lambda value: value.update(region="us-west1"),
            lambda value: value.update(approved_private_relay_cidrs=["10.92.0.0/24"]),
            lambda value: value.pop("boot_disk_size_gb"),
            lambda value: value.update(k3s_binary_sha256="c" * 64),
            lambda value: value.update(k3s_system_images_bundle_mirror_url="https://other.example.internal/images.tar"),
            lambda value: value.update(k3s_system_images_architecture="linux/arm64"),
            lambda value: value.update(qualification_image_unique_id="0"),
        ):
            value = terraform_inputs()
            mutate(value)
            with self.subTest(value=value):
                with self.assertRaises(binding.BindingError):
                    self.validate(value)

    def test_duplicate_terraform_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "terraform-inputs.json"
            path.write_text('{"project_id":"first","project_id":"second"}', encoding="utf-8")
            with self.assertRaises(binding.BindingError):
                binding.validate_plan_inputs(
                    path, reader=readiness._safe_json,
                    terraform_source=(ROOT / "infrastructure/terraform/gcp/self-managed-lab/variables.tf").read_text(),
                    network=network(), artifact_report=artifact_report(), expected_project=readiness.EXPECTED_PROJECT,
                    expected_region=readiness.EXPECTED_REGION, expected_zone=readiness.EXPECTED_ZONE,
                    expected_lab_id=readiness.EXPECTED_LAB_ID)

    def test_source_fingerprint_includes_embedded_helpers_and_excludes_tfvars(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = Path(temp)
            module = repository / "infrastructure/terraform/gcp/self-managed-lab"
            module.mkdir(parents=True)
            names = ["main.tf", "server-startup.sh.tftpl", "secret_manager_bootstrap.py",
                     ".terraform.lock.hcl"]
            for name in names:
                (module / name).write_text(f"initial {name}\n", encoding="utf-8")
            # The ignored file is deliberately not enumerated or read.
            (module / "terraform.tfvars").write_text("unread-variable-material\n", encoding="utf-8")
            listing = "\n".join(f"infrastructure/terraform/gcp/self-managed-lab/{name}" for name in names)

            def fake_run(command, *, cwd, capture):
                self.assertEqual(cwd, repository)
                return listing

            initial = binding.source_fingerprint(module, fake_run)
            (module / "secret_manager_bootstrap.py").write_text("changed embedded helper\n", encoding="utf-8")
            self.assertNotEqual(initial, binding.source_fingerprint(module, fake_run))

    def test_image_approval_binds_exact_debian_image_and_os_release(self):
        values = terraform_inputs()
        image_record = {
            "schemaVersion": 1, "approvalStatus": "approved",
            "approvalReference": values["qualification_image_approval_reference"],
            "platformProfile": "debian-13", "imageSelfLink": values["debian_image_self_link"],
            "imageUniqueId": values["qualification_image_unique_id"],
            "osId": "debian", "osVersion": "13", "pointRelease": "13.8",
            "architecture": "linux/amd64", "imageOwner": "customer-image-owner",
            "approvedAt": "2026-11-21T12:00:00Z", "evidenceReference": "change-record-123",
        }
        values["qualification_image_approval_sha256"] = binding.canonical_sha256(image_record)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "image-approval.json"
            path.write_text(json.dumps(image_record), encoding="utf-8")
            _verified, digest = binding.validate_image_approval(
                path, reader=readiness._safe_json, terraform_values=values,
                artifact_report=artifact_report())
            self.assertEqual(digest, binding.canonical_sha256(image_record))
            changed = dict(image_record, imageSelfLink="https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/other")
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(binding.BindingError):
                binding.validate_image_approval(path, reader=readiness._safe_json,
                    terraform_values=values, artifact_report=artifact_report())
            mismatched_id = dict(image_record, imageUniqueId="987654321")
            path.write_text(json.dumps(mismatched_id), encoding="utf-8")
            with self.assertRaises(binding.BindingError):
                binding.validate_image_approval(path, reader=readiness._safe_json,
                    terraform_values=values, artifact_report=artifact_report())

    def test_debian_point_release_and_rhel_minimum_are_policy_bound(self):
        values = terraform_inputs(point="13.7")
        with self.assertRaises(binding.BindingError):
            self.validate(values)
        values = terraform_inputs("rhel-9", "9", "9.9")
        report = artifact_report("rhel-9", "9", "9.9")
        self.validate(values, network_doc={**network(), "osFamily": "rhel-9"}, report=report)
        values["qualification_os_minor"] = "7"
        values["qualification_os_point_release"] = "9.7"
        with self.assertRaises(binding.BindingError):
            self.validate(values, network_doc={**network(), "osFamily": "rhel-9"},
                          report=artifact_report("rhel-9", "7", "9.7"))

    def test_customer_values_are_not_mislabeled_as_independently_verified(self):
        status = readiness.check_selected_lab_os_profile("debian-13")
        self.assertEqual(status["status"], "PROVIDED")
        report = readiness.report(readiness.EXPECTED_PROJECT, None, None, None,
                                  now=__import__("datetime").datetime(2026, 11, 21, tzinfo=__import__("datetime").timezone.utc))
        self.assertEqual(report["checks"]["liveProjectLabelAndLifecycle"]["result"], "BLOCKED")
        self.assertTrue(report["checks"]["artifactTrustCustody"]["independentReviewRequired"])
        self.assertEqual(report["schemaVersion"], 2)
        for item in report["checks"].values():
            self.assertIn(item["result"], readiness.VALID_STATUSES)
            self.assertTrue(item["requirementId"])
            self.assertTrue(item["platformApplicability"])
            self.assertTrue(item["inputReference"])
            self.assertTrue(item["verificationMethod"])
            self.assertIn("verificationTimestamp", item)
            self.assertTrue(item["reason"])
            self.assertIn("independentReviewRequired", item)

    def test_manual_fault_procedures_are_disposable_and_fail_closed(self):
        document = (ROOT / "docs/m3-manual-failure-procedures.md").read_text(encoding="utf-8")
        matrix = json.loads((ROOT / "tests/integration/host_upgrade_failure_matrix.json").read_text())
        manual = [case["id"] for case in matrix["cases"] if case.get("execution") == "manual-injection"]
        self.assertEqual(len(manual), 7)
        for case in manual:
            self.assertIn(f"`{case}`", document)
        for required in ("Common entry gate", "Abort before injection", "does not implement",
                         "authorize provisioning", "does not inject", "serial", "baseline"):
            self.assertIn(required, document)

    def test_plan_gate_binds_readiness_to_report_inputs_source_and_exact_image(self):
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        values = terraform_inputs()
        approval = {
            "schemaVersion": 1, "approvalStatus": "approved",
            "approvalReference": values["qualification_image_approval_reference"],
            "platformProfile": "debian-13", "imageSelfLink": values["debian_image_self_link"],
            "imageUniqueId": values["qualification_image_unique_id"], "osId": "debian",
            "osVersion": "13", "pointRelease": "13.8", "architecture": "linux/amd64",
            "imageOwner": "customer-image-owner", "approvedAt": now.isoformat().replace("+00:00", "Z"),
            "evidenceReference": "change-record-123",
        }
        values["qualification_image_approval_sha256"] = binding.canonical_sha256(approval)
        artifact_result = artifact_report()
        artifact_result.update({"schemaVersion": 1, "overallStatus": "PASS"})
        for name in readiness.artifact_preflight.REQUIRED_ARTIFACTS:
            artifact_result["artifacts"].setdefault(name, {})["status"] = "PASS"
        network_doc = network()
        artifact_config = {"schemaVersion": 1, "syntheticFixture": True}
        source_hash = "e" * 64
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = {name: root / f"{name}.json" for name in
                     ("terraform", "network", "artifact-inputs", "artifact-report", "image-approval", "readiness")}
            paths["terraform"].write_text(json.dumps(values, sort_keys=True), encoding="utf-8")
            paths["network"].write_text(json.dumps(network_doc), encoding="utf-8")
            paths["artifact-inputs"].write_text(json.dumps(artifact_config), encoding="utf-8")
            paths["artifact-report"].write_text(json.dumps(artifact_result), encoding="utf-8")
            paths["image-approval"].write_text(json.dumps(approval), encoding="utf-8")
            normalized, terraform_digest = self.validate(values, network_doc, artifact_result)
            approval_digest = binding.canonical_sha256(approval)
            checks = {name: {"result": status} for name, status in {
                "planInputBinding": "PASS", "artifactPreflight": "PASS", "trackedTerraformProfile": "PASS",
                "designatedProject": "PASS", "actualTerraformInputs": "PROVIDED", "imageOwnerApproval": "PROVIDED",
            }.items()}
            bound = {
                "schemaVersion": 1, "terraformInputsSha256": terraform_digest,
                "networkInputsSha256": binding.canonical_sha256(binding.canonical_network_inputs(network_doc)),
                "artifactInputsSha256": binding.canonical_sha256(artifact_config),
                "artifactReportSha256": binding.canonical_sha256(artifact_result),
                "imageApprovalSha256": approval_digest, "terraformSourceSha256": source_hash,
                "profile": "debian-13", "imageSelfLink": values["debian_image_self_link"],
                "imageUniqueId": values["qualification_image_unique_id"],
                "imageApprovalReference": values["qualification_image_approval_reference"],
                "imageApprovalRequiresIndependentReview": True,
                "k3sVersion": values["k3s_version"],
                "k3sBinarySha256": values["k3s_binary_sha256"],
                "k3sSystemImagesBundleSha256": values["k3s_system_images_bundle_sha256"],
                "packagePolicySha256": artifact_result["artifacts"]["hostPackageArtifacts"]["policySha256"],
                "boundAt": now.isoformat(),
            }
            paths["readiness"].write_text(json.dumps({"schemaVersion": 2, "generatedAt": now.isoformat(),
                "overallStatus": "BLOCKED", "checks": checks, "planBinding": bound}), encoding="utf-8")
            with patch.object(lab.readiness_binding, "source_fingerprint", return_value=source_hash):
                result, _digest = lab.verify_readiness_plan_binding(
                    project_id=readiness.EXPECTED_PROJECT, readiness_report=paths["readiness"],
                    terraform_inputs=paths["terraform"], network_inputs=paths["network"],
                    artifact_inputs=paths["artifact-inputs"], artifact_report=paths["artifact-report"],
                    image_approval_path=paths["image-approval"])
                self.assertEqual(result, normalized)

                for field, replacement in (("k3sBinarySha256", "9" * 64),
                                            ("packagePolicySha256", "8" * 64),
                                            ("imageApprovalRequiresIndependentReview", False)):
                    altered_binding = dict(bound, **{field: replacement})
                    paths["readiness"].write_text(json.dumps({"schemaVersion": 2, "generatedAt": now.isoformat(),
                        "overallStatus": "BLOCKED", "checks": checks, "planBinding": altered_binding}), encoding="utf-8")
                    with self.assertRaisesRegex(lab.LabError, "artifact or policy binding"):
                        lab.verify_readiness_plan_binding(
                            project_id=readiness.EXPECTED_PROJECT, readiness_report=paths["readiness"],
                            terraform_inputs=paths["terraform"], network_inputs=paths["network"],
                            artifact_inputs=paths["artifact-inputs"], artifact_report=paths["artifact-report"],
                            image_approval_path=paths["image-approval"])
                paths["readiness"].write_text(json.dumps({"schemaVersion": 2, "generatedAt": now.isoformat(),
                    "overallStatus": "BLOCKED", "checks": checks, "planBinding": bound}), encoding="utf-8")

                stale = {"schemaVersion": 2,
                         "generatedAt": (now - __import__("datetime").timedelta(hours=5)).isoformat(),
                         "overallStatus": "BLOCKED", "checks": checks, "planBinding": bound}
                paths["readiness"].write_text(json.dumps(stale), encoding="utf-8")
                with self.assertRaisesRegex(lab.LabError, "stale"):
                    lab.verify_readiness_plan_binding(
                        project_id=readiness.EXPECTED_PROJECT, readiness_report=paths["readiness"],
                        terraform_inputs=paths["terraform"], network_inputs=paths["network"],
                        artifact_inputs=paths["artifact-inputs"], artifact_report=paths["artifact-report"],
                        image_approval_path=paths["image-approval"])
                paths["readiness"].write_text(json.dumps({"schemaVersion": 2, "generatedAt": now.isoformat(),
                    "overallStatus": "BLOCKED", "checks": checks, "planBinding": bound}), encoding="utf-8")

                # JSON key order and network set order do not change effective inputs.
                paths["terraform"].write_text(json.dumps(dict(reversed(list(values.items())))), encoding="utf-8")
                reversed_network = dict(network_doc)
                reversed_network["approvedPrivateMirrorCIDRs"] = list(reversed(network_doc["approvedPrivateMirrorCIDRs"]))
                paths["network"].write_text(json.dumps(reversed_network), encoding="utf-8")
                result, _digest = lab.verify_readiness_plan_binding(
                    project_id=readiness.EXPECTED_PROJECT, readiness_report=paths["readiness"],
                    terraform_inputs=paths["terraform"], network_inputs=paths["network"],
                    artifact_inputs=paths["artifact-inputs"], artifact_report=paths["artifact-report"],
                    image_approval_path=paths["image-approval"])
                self.assertEqual(result, normalized)

                changed_values = dict(values, machine_type="e2-standard-4")
                paths["terraform"].write_text(json.dumps(changed_values), encoding="utf-8")
                with self.assertRaisesRegex(lab.LabError, "effective Terraform inputs changed"):
                    lab.verify_readiness_plan_binding(
                        project_id=readiness.EXPECTED_PROJECT, readiness_report=paths["readiness"],
                        terraform_inputs=paths["terraform"], network_inputs=paths["network"],
                        artifact_inputs=paths["artifact-inputs"], artifact_report=paths["artifact-report"],
                        image_approval_path=paths["image-approval"])

                changed_image = dict(values, qualification_image_unique_id="987654321")
                paths["terraform"].write_text(json.dumps(changed_image), encoding="utf-8")
                with self.assertRaisesRegex(lab.LabError, "effective Terraform inputs changed"):
                    lab.verify_readiness_plan_binding(
                        project_id=readiness.EXPECTED_PROJECT, readiness_report=paths["readiness"],
                        terraform_inputs=paths["terraform"], network_inputs=paths["network"],
                        artifact_inputs=paths["artifact-inputs"], artifact_report=paths["artifact-report"],
                        image_approval_path=paths["image-approval"])

                paths["terraform"].write_text(json.dumps(values), encoding="utf-8")
                changed_report = dict(artifact_result, reportMarker="changed")
                paths["artifact-report"].write_text(json.dumps(changed_report), encoding="utf-8")
                with self.assertRaisesRegex(lab.LabError, "artifact preflight report changed"):
                    lab.verify_readiness_plan_binding(
                        project_id=readiness.EXPECTED_PROJECT, readiness_report=paths["readiness"],
                        terraform_inputs=paths["terraform"], network_inputs=paths["network"],
                        artifact_inputs=paths["artifact-inputs"], artifact_report=paths["artifact-report"],
                        image_approval_path=paths["image-approval"])


if __name__ == "__main__":
    unittest.main()
