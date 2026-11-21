"""Synthetic local fixtures for the M3 readiness report; never customer evidence."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


readiness = load("m3_deployment_readiness", "scripts/m3_deployment_readiness.py")
artifact_preflight = readiness.artifact_preflight


def synthetic_network_inputs() -> dict:
    return {
        "schemaVersion": 1,
        "projectId": readiness.EXPECTED_PROJECT,
        "region": readiness.EXPECTED_REGION,
        "zone": readiness.EXPECTED_ZONE,
        "labId": readiness.EXPECTED_LAB_ID,
        "osFamily": "ubuntu-24.04",
        "nodeRoles": ["server", "worker-1", "worker-2"],
        "subnetCIDR": readiness.EXPECTED_SUBNET,
        "labSourceCIDR": readiness.EXPECTED_SUBNET,
        "approvedPrivateMirrorCIDRs": ["10.90.0.0/24"],
        "approvedPrivateRelayCIDRs": ["10.91.0.0/24"],
        "restrictedGoogleApisCIDR": readiness.EXPECTED_GOOGLE_APIS_CIDR,
        "mirrorPort": 443,
        "relayPort": 18443,
        "noVMExternalIPs": True,
        "noCloudNAT": True,
        "relayDNSName": "relay.example.internal",
        "mirrorDNSNames": ["apt.example.internal", "registry.example.internal"],
    }


class DeploymentReadinessTests(unittest.TestCase):
    def test_missing_customer_inputs_are_not_provided_and_report_is_deterministic(self):
        first = readiness.report(readiness.EXPECTED_PROJECT, None, None, None)
        second = readiness.report(readiness.EXPECTED_PROJECT, None, None, None)
        self.assertEqual(first, second)
        self.assertEqual(first["overallStatus"], "NOT PROVIDED")
        self.assertEqual(first["profile"], readiness.EXPECTED_ARTIFACT_PROFILE)
        self.assertEqual(first["checks"]["designatedProject"]["status"], "PASS")
        self.assertEqual(first["checks"]["trackedTerraformProfile"]["status"], "PASS")
        self.assertEqual(first["checks"]["artifactPreflight"]["status"], "NOT PROVIDED")

    def test_report_generation_performs_no_dns_or_network_calls(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("network lookup attempted")) as lookup:
            result = readiness.report(readiness.EXPECTED_PROJECT, None, None, None)
        lookup.assert_not_called()
        self.assertEqual(result["overallStatus"], "NOT PROVIDED")

    def test_only_designated_project_passes(self):
        self.assertEqual(readiness.validate_project(readiness.EXPECTED_PROJECT)["status"], "PASS")
        self.assertEqual(readiness.validate_project("unrelated-project")["status"], "FAIL")

    def test_ubuntu_supplemental_debian13_and_customer_input_rhel9_profiles(self):
        self.assertEqual(readiness.check_selected_lab_os_profile("ubuntu-24.04")["status"], "PASS")
        self.assertEqual(readiness.check_selected_lab_os_profile("debian-13"), {
            "status": "PASS", "code": "TrackedDebian13TrixieLabProfile",
        })
        self.assertEqual(readiness.check_selected_lab_os_profile("rhel-9"), {
            "status": "PASS", "code": "TrackedRHEL9LabProfileRequiresCustomerImageAndSignedPrivateRPMInputs",
        })

    def test_network_contract_accepts_private_three_node_profile(self):
        readiness.validate_network_inputs(synthetic_network_inputs())
        for profile in ("debian-13", "rhel-9"):
            with self.subTest(profile=profile):
                config = synthetic_network_inputs()
                config["osFamily"] = profile
                readiness.validate_network_inputs(config)

    def test_network_contract_rejects_public_cidr_wrong_port_and_topology_drift(self):
        for field, value in (
            ("approvedPrivateMirrorCIDRs", ["0.0.0.0/0"]),
            ("relayPort", 443),
            ("nodeRoles", ["server", "worker-1"]),
            ("labSourceCIDR", "10.77.0.0/24"),
        ):
            with self.subTest(field=field):
                config = synthetic_network_inputs()
                config[field] = value
                with self.assertRaises(readiness.ReadinessError):
                    readiness.validate_network_inputs(config)

    def test_network_contract_rejects_overlapping_or_noncanonical_cidrs(self):
        config = synthetic_network_inputs()
        config["approvedPrivateRelayCIDRs"] = ["10.90.0.0/24"]
        with self.assertRaisesRegex(readiness.ReadinessError, "unique and disjoint"):
            readiness.validate_network_inputs(config)
        config = synthetic_network_inputs()
        config["approvedPrivateMirrorCIDRs"] = ["10.90.1.1/24"]
        with self.assertRaises(readiness.ReadinessError):
            readiness.validate_network_inputs(config)

    def make_synthetic_preflight(self, root: Path, now: dt.datetime):
        """Create a report and files solely to exercise local binding logic."""
        files: dict[str, Path] = {}

        def write(name: str, content: bytes = b"synthetic fixture only") -> str:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            files[name] = path
            return str(path)

        trust = {
            "maintenanceBundle": write("public/maintenance.json"),
            "artifactApprovalBundle": write("public/artifact.trust"),
            "releasePublicKey": write("public/release.pub"),
            "toolProvenancePublicKey": write("public/tool.pub"),
            "helmSignerAllowlist": write("public/helm-signers.txt"),
            "maintenanceExpectedKeyIds": ["a" * 64],
            "artifactApprovalExpectedKeyIds": ["b" * 64],
            "releaseExpectedFingerprint": "c" * 64,
            "toolProvenanceExpectedFingerprint": "d" * 64,
            "artifactApprovalMaxAgeDays": 30,
        }
        bundle = root / "release-bundle"
        bundle.mkdir()
        (bundle / "SHA256SUMS").write_text("synthetic bundle manifest\n", encoding="utf-8")
        image_lock = write("release/image-lock.tsv")
        image_sig = write("release/image-lock.sig")
        k3s_binary = write("k3s/k3s")
        k3s_lock = write("k3s/k3s.lock")
        k3s_sig = write("k3s/k3s.lock.sig")
        k3s_trust = write("k3s/artifact.trust")
        system_bundle = write("k3s/system-images.tar")
        system_lock = write("k3s/system-images.lock")
        system_sig = write("k3s/system-images.lock.sig")
        system_trust = write("k3s/system-artifact.trust")
        package_policy = write("ubuntu/package-policy.json")
        package_archive = write("ubuntu/packages.tar")
        # This deliberately nonexistent path is a credential location. The
        # readiness command must never open, stat, hash, or print it.
        auth_path = root / "must-not-read-registry-credentials.json"
        config = {
            "schemaVersion": 1,
            "trust": trust,
            "release": {"bundleDirectory": str(bundle), "imageDigestLock": image_lock,
                        "imageDigestSignature": image_sig},
            "k3sBinary": {"binary": k3s_binary, "lock": k3s_lock, "signature": k3s_sig,
                          "trustBundle": k3s_trust},
            "k3sSystemImages": {"bundle": system_bundle, "lock": system_lock,
                                "signature": system_sig, "trustBundle": system_trust},
            "privateRegistry": {"host": "registry.example.internal", "authFile": str(auth_path),
                                "privateCIDRs": ["10.90.0.0/24"]},
            "packageArtifacts": {"policy": package_policy, "archive": package_archive},
            "network": {"privateMirrorCIDRs": ["10.90.0.0/24"]},
        }
        input_path = root / "artifact-inputs.json"
        input_path.write_text(json.dumps(config), encoding="utf-8")
        input_hashes = {
            "maintenancePublicTrust": artifact_preflight.hash_file(Path(trust["maintenanceBundle"])),
            "artifactApprovalTrust": artifact_preflight.hash_file(Path(trust["artifactApprovalBundle"])),
            "releasePublicTrust": artifact_preflight.hash_file(Path(trust["releasePublicKey"])),
            "toolProvenancePublicTrust": artifact_preflight.hash_file(Path(trust["toolProvenancePublicKey"])),
            "helmSignerAllowlist": artifact_preflight.hash_file(Path(trust["helmSignerAllowlist"])),
            "signedReleaseBundle": artifact_preflight.hash_release_bundle(bundle),
            "signedImageDigestLock": artifact_preflight.hash_file(Path(image_lock)),
            "signedImageDigestSignature": artifact_preflight.hash_file(Path(image_sig)),
            "k3sBinary.binary": artifact_preflight.hash_file(Path(k3s_binary)),
            "k3sBinary.lock": artifact_preflight.hash_file(Path(k3s_lock)),
            "k3sBinary.signature": artifact_preflight.hash_file(Path(k3s_sig)),
            "k3sBinary.trustBundle": artifact_preflight.hash_file(Path(k3s_trust)),
            "k3sSystemImages.bundle": artifact_preflight.hash_file(Path(system_bundle)),
            "k3sSystemImages.lock": artifact_preflight.hash_file(Path(system_lock)),
            "k3sSystemImages.signature": artifact_preflight.hash_file(Path(system_sig)),
            "k3sSystemImages.trustBundle": artifact_preflight.hash_file(Path(system_trust)),
            "packagePolicy": artifact_preflight.hash_file(Path(package_policy)),
            "packageArchive": artifact_preflight.hash_file(Path(package_archive)),
            "privateRegistryVerification": "e" * 64,
        }
        rows = {name: {"status": "PASS"} for name in artifact_preflight.REQUIRED_ARTIFACTS}
        rows["hostPackageArtifacts"].update({
            "profile": readiness.EXPECTED_ARTIFACT_PROFILE,
            "osFamily": "debian", "osId": "ubuntu", "osMajor": "24", "osMinor": "04",
            "architecture": artifact_preflight.EXPECTED_ARCH,
            "repositorySnapshotID": "ubuntu-noble-snapshot-2026-11-21",
            "osPointRelease": "",
        })
        approved_at = (now - dt.timedelta(days=1)).isoformat().replace("+00:00", "Z")
        rows["k3sBinaryApproval"].update({"version": artifact_preflight.EXPECTED_K3S,
                                          "architecture": artifact_preflight.EXPECTED_ARCH,
                                          "approvedAt": approved_at, "approvalValidForDays": 30})
        rows["k3sSystemImageApproval"].update({"version": artifact_preflight.EXPECTED_K3S,
                                              "architecture": artifact_preflight.EXPECTED_ARCH,
                                              "imageCount": 8, "approvedAt": approved_at,
                                              "approvalValidForDays": 30})
        report = {
            "schemaVersion": 1,
            "profile": "m3-ubuntu-24.04-k3s-v1.36.6+k3s1-linux-amd64",
            "overallStatus": "PASS",
            "artifacts": rows,
            "inputSha256": input_hashes,
        }
        report_path = root / "artifact-preflight.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        os.utime(report_path, (now.timestamp(), now.timestamp()))
        return input_path, report_path, files, config

    def test_fresh_preflight_is_bound_to_local_artifacts_without_opening_registry_credentials(self):
        now = dt.datetime(2026, 11, 21, 15, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            input_path, report_path, _files, _config = self.make_synthetic_preflight(Path(temp), now)
            result = readiness.check_artifact_preflight(input_path, report_path, now=now)
            self.assertEqual(result["status"], "PASS")
            self.assertFalse((Path(temp) / "must-not-read-registry-credentials.json").exists())

    def test_artifact_report_rejects_stale_report_modified_artifact_and_wrong_architecture(self):
        now = dt.datetime(2026, 11, 21, 15, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            input_path, report_path, files, _config = self.make_synthetic_preflight(root, now)
            os.utime(report_path, ((now - dt.timedelta(hours=5)).timestamp(),) * 2)
            self.assertEqual(readiness.check_artifact_preflight(input_path, report_path, now=now)["status"], "FAIL")

            os.utime(report_path, (now.timestamp(), now.timestamp()))
            files["k3s/k3s"].write_bytes(b"substituted fixture")
            self.assertEqual(readiness.check_artifact_preflight(input_path, report_path, now=now)["status"], "FAIL")

            files["k3s/system-images.tar"].write_bytes(b"substituted system-image fixture")
            self.assertEqual(readiness.check_artifact_preflight(input_path, report_path, now=now)["status"], "FAIL")

            second_root = root / "second"
            second_root.mkdir()
            input_path, report_path, _files, _config = self.make_synthetic_preflight(second_root, now)
            raw = json.loads(report_path.read_text(encoding="utf-8"))
            raw["artifacts"]["k3sBinaryApproval"]["architecture"] = "linux/arm64"
            report_path.write_text(json.dumps(raw), encoding="utf-8")
            os.utime(report_path, (now.timestamp(), now.timestamp()))
            self.assertEqual(readiness.check_artifact_preflight(input_path, report_path, now=now)["status"], "FAIL")

            third_root = root / "third"
            third_root.mkdir()
            input_path, report_path, _files, _config = self.make_synthetic_preflight(third_root, now)
            raw = json.loads(report_path.read_text(encoding="utf-8"))
            raw["artifacts"]["hostPackageArtifacts"].update({
                "profile": "m3-rhel-9.7-k3s-v1.36.6+k3s1-linux-amd64",
                "osFamily": "rhel", "osId": "rhel", "osMajor": "9", "osMinor": "7",
                "osPointRelease": "9.7",
            })
            report_path.write_text(json.dumps(raw), encoding="utf-8")
            os.utime(report_path, (now.timestamp(), now.timestamp()))
            self.assertEqual(readiness.check_artifact_preflight(input_path, report_path, now=now)["status"], "FAIL")

    def test_report_does_not_emit_customer_paths_or_credential_locations(self):
        now = dt.datetime(2026, 11, 21, 15, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            input_path, report_path, _files, _config = self.make_synthetic_preflight(Path(temp), now)
            result = readiness.check_artifact_preflight(input_path, report_path, now=now)
            encoded = json.dumps(result)
            self.assertNotIn(temp, encoded)
            self.assertNotIn("must-not-read-registry-credentials", encoded)
            self.assertNotIn("sha256", encoded.lower())

    def test_readiness_command_contract_never_mentions_ignored_tfvars_as_an_input(self):
        source = (ROOT / "scripts/m3_deployment_readiness.py").read_text(encoding="utf-8")
        self.assertNotIn('"terraform.tfvars"', source)
        self.assertEqual(readiness.check_static_profile()["status"], "PASS")

    def test_report_file_is_private_and_existing_outputs_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "readiness.json"
            value = readiness.report(readiness.EXPECTED_PROJECT, None, None, None)
            readiness.write_report(output, value)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            before = output.read_bytes()
            with self.assertRaisesRegex(readiness.ReadinessError, "refusing to overwrite"):
                readiness.write_report(output, {"changed": True})
            self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
