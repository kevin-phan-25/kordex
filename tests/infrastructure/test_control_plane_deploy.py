import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import control_plane_deploy as deploy


class FakeRunner:
    def __init__(self, results=None, fail_match=None):
        self.results = list(results or [])
        self.fail_match = fail_match
        self.calls = []

    def run(self, command, *, env=None, input_data=None, timeout=60):
        self.calls.append(command)
        if self.fail_match and self.fail_match(command):
            return subprocess.CompletedProcess(command, 1, "SENSITIVE_OUTPUT", "SENSITIVE_ERROR")
        if self.results:
            return self.results.pop(0)
        return subprocess.CompletedProcess(command, 0, "", "")


def completed(command, stdout="", status=0):
    return subprocess.CompletedProcess(command, status, stdout, "")


class ControlPlaneDeploymentTests(unittest.TestCase):
    def test_missing_manifest_reports_required_inputs_not_pass(self):
        report = deploy._preflight(None, FakeRunner(), backup_key_sha256="")
        self.assertEqual(report["overall"], "BLOCKED")
        self.assertFalse(report["deploymentAllowed"])
        self.assertTrue(report["checks"])
        self.assertTrue(all(row["status"] == "NOT PROVIDED" for row in report["checks"]))

    def test_missing_manifest_path_is_reported_not_provided(self):
        with tempfile.TemporaryDirectory() as temp:
            report_path = Path(temp) / "report.json"
            self.assertEqual(deploy.main(["preflight", "--inputs", str(Path(temp) / "missing.json"),
                                          "--report", str(report_path)]), 2)
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["overall"], "BLOCKED")
        self.assertEqual(report["checks"][0]["status"], "NOT PROVIDED")

    def test_missing_customer_artifact_file_is_not_provided(self):
        status, doc = deploy._verify_evidence(
            FakeRunner(), {"path": "/missing/evidence.json", "signature": "/missing/evidence.sig",
                          "publicKey": "/missing/reviewer.pub", "targetID": "target",
                          "observedAt": "2026-01-01T00:00:00Z", "expiresAt": "2026-01-02T00:00:00Z"},
            "a" * 64, target_id="target", kind="backup", now=1_767_225_600,
        )
        self.assertEqual((status, doc), ("NOT PROVIDED", None))

    def test_empty_manifest_enumerates_missing_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inputs.json"
            path.write_text('{"schemaVersion":1}', encoding="utf-8")
            cfg = deploy.read_manifest(path)
        report = deploy._preflight(cfg, FakeRunner(), backup_key_sha256="")
        statuses = {row["id"]: row["status"] for row in report["checks"]}
        self.assertEqual(report["overall"], "BLOCKED")
        self.assertEqual(statuses["input.target.kubeContext"], "NOT PROVIDED")
        self.assertEqual(statuses["input.evidence.backup.signature"], "NOT PROVIDED")

    def test_fixture_manifest_is_rejected_before_any_commands(self):
        path = Path(__file__).resolve().parents[2] / "docs/examples/control-plane-deployment-inputs.synthetic.json"
        with self.assertRaisesRegex(deploy.DeployError, "not a production"):
            deploy.read_manifest(path)

    def test_mutable_image_tag_fails_before_signature_command(self):
        cfg = {"release": {"imageRepository": "ghcr.io/kevin-phan-25/kordex-control-plane",
                            "imageDigest": "latest", "tag": "v1.2.3", "sourceCommit": "a" * 40}}
        runner = FakeRunner()
        with self.assertRaisesRegex(deploy.DeployError, "mutable or malformed"):
            deploy._check_release(runner, cfg)
        self.assertEqual(runner.calls, [])

    def test_absent_cosign_signature_blocks_release(self):
        cfg = {"release": {"imageRepository": "ghcr.io/kevin-phan-25/kordex-control-plane",
                            "imageDigest": "sha256:" + "a" * 64, "tag": "v1.2.3", "sourceCommit": "a" * 40}}
        runner = FakeRunner([
            completed([], ""), completed([], "a" * 40), completed([], "a" * 40),
            completed([], status=1),
        ])
        with self.assertRaisesRegex(deploy.DeployError, "required command failed"):
            deploy._check_release(runner, cfg)
        self.assertTrue(any(command[0] == "cosign" for command in runner.calls))
        self.assertFalse(any(command[0] == "gh" for command in runner.calls))

    def test_invalid_release_attestation_blocks_deployment(self):
        cfg = {"release": {"imageRepository": "ghcr.io/kevin-phan-25/kordex-control-plane",
                            "imageDigest": "sha256:" + "a" * 64, "tag": "v1.2.3", "sourceCommit": "a" * 40}}
        runner = FakeRunner([
            completed([], ""), completed([], "a" * 40), completed([], "a" * 40),
            completed([], "verified image"), completed([], "bad attestation", status=1),
        ])
        with self.assertRaisesRegex(deploy.DeployError, "required command failed"):
            deploy._check_release(runner, cfg)
        self.assertTrue(any(command[0] == "gh" and command[1:3] == ["attestation", "verify"]
                            for command in runner.calls))

    def test_wrong_tag_or_commit_binding_fails_before_image_verification(self):
        cfg = {"release": {"imageRepository": "ghcr.io/kevin-phan-25/kordex-control-plane",
                            "imageDigest": "sha256:" + "a" * 64, "tag": "v1.2.3", "sourceCommit": "a" * 40}}
        runner = FakeRunner([completed([], ""), completed([], "b" * 40), completed([], "a" * 40)])
        with self.assertRaisesRegex(deploy.DeployError, "does not exactly match"):
            deploy._check_release(runner, cfg)
        self.assertFalse(any(command[0] == "cosign" for command in runner.calls))

    def test_incorrect_migration_checksum_fails(self):
        with self.assertRaisesRegex(deploy.DeployError, "valid prefix"):
            deploy.verify_migration_ledger([(1, "0" * 64)])

    def test_migration_016_must_be_present_once_with_expected_checksum(self):
        with self.assertRaisesRegex(deploy.DeployError, "absent, duplicated"):
            deploy.verify_migration_016([(16, "0" * 64)])
        with self.assertRaisesRegex(deploy.DeployError, "absent, duplicated"):
            deploy.verify_migration_016([(16, deploy.EXPECTED_MIGRATION_SHA256),
                                         (16, deploy.EXPECTED_MIGRATION_SHA256)])

    def test_database_failure_is_safe_and_does_not_expose_psql_output(self):
        with tempfile.TemporaryDirectory() as temp:
            service = Path(temp) / "pg_service.conf"
            service.write_text("[m3]\nhost=db.example\ndbname=kordex\nsslmode=verify-full\n", encoding="utf-8")
            service.chmod(0o600)
            runner = FakeRunner([completed([], "password=super-secret", status=2)])
            cfg = {"database": {"pgServiceFile": str(service), "pgServiceName": "m3"}}
            with self.assertRaises(deploy.DeployError) as ctx:
                deploy._database_check(runner, cfg)
            self.assertNotIn("super-secret", str(ctx.exception))

    def test_oidc_failure_fails_closed(self):
        with patch.object(deploy, "urlopen", side_effect=OSError("private response content")):
            with self.assertRaisesRegex(deploy.DeployError, "OIDC discovery is unreachable"):
                deploy._fetch_oidc("https://issuer.example")

    def test_tls_secret_failure_rejects_wrong_secret_type(self):
        with tempfile.TemporaryDirectory() as temp:
            ca = Path(temp) / "ca.pem"
            ca.write_text("synthetic", encoding="utf-8")
            with self.assertRaisesRegex(deploy.DeployError, "wrong type"):
                deploy._verify_tls_secret({"type": "Opaque"}, "api.example", ca)

    def test_non_admin_must_receive_forbidden_and_restart_state_must_match(self):
        deploy.require_viewer_denied(403)
        with self.assertRaisesRegex(deploy.DeployError, "HTTP 403"):
            deploy.require_viewer_denied(200)
        self.assertTrue(deploy.lifecycle_state_unchanged({"state": "RUNNING", "generation": 1},
                                                         {"state": "RUNNING", "generation": 1}))
        self.assertFalse(deploy.lifecycle_state_unchanged({"state": "RUNNING"}, {"state": "STOPPED"}))

    def test_kubernetes_can_i_output_must_explicitly_be_yes(self):
        deploy._require_can_i(completed([], "yes\n"))
        with self.assertRaisesRegex(deploy.DeployError, "lacks a required permission"):
            deploy._require_can_i(completed([], "no\n"))

    def test_deployment_journal_is_durable_and_recoverable(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "deployment.json"
            deploy._write_report({"deploymentState": "IN_PROGRESS", "recoveryRequired": False}, path)
            mode = path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            with self.assertRaisesRegex(deploy.DeployError, "already exists"):
                deploy._write_report({"deploymentState": "COMPLETE"}, path)
            deploy._write_report({"deploymentState": "RECOVERY_REQUIRED", "recoveryRequired": True},
                                 path, replace=True)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["deploymentState"], "RECOVERY_REQUIRED")

    def test_read_only_authorization_probe_requires_admin_without_mutation(self):
        deploy.require_admin_authorized(200, {"authorized": True, "role": "administrator"})
        with self.assertRaisesRegex(deploy.DeployError, "not an authenticated"):
            deploy.require_admin_authorized(403, {"error": "forbidden"})

    def test_wrong_deployment_approval_never_invokes_helm(self):
        cfg = {"target": {"kubeSystemNamespaceUID": "cluster-uid", "namespace": "ns", "releaseName": "cp",
                          "kubeContext": "ctx"},
               "release": {"imageDigest": "sha256:" + "a" * 64, "sourceCommit": "b" * 40}}
        bindings = {"manifestSha256": "c" * 64, "helmValuesSha256": "d" * 64,
                    "sourceCommit": "b" * 40, "imageDigest": "sha256:" + "a" * 64}
        report = {"overall": "PASS", "deploymentAllowed": True, "deploymentBindings": bindings, "checks": []}
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as temp:
            cfg["helmValuesFile"] = str(Path(temp) / "values.yaml")
            Path(cfg["helmValuesFile"]).write_text("oidc: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(deploy.DeployError, "authorization did not match"):
                deploy.deployment_command(cfg, runner, report, "APPROVE", "https://api.example")
        self.assertEqual(runner.calls, [])

    def test_interrupted_helm_leaves_recovery_fence_and_does_not_retry(self):
        cfg = {"target": {"kubeSystemNamespaceUID": "cluster-uid", "namespace": "ns", "releaseName": "cp"},
               "release": {"imageRepository": "ghcr.io/kevin-phan-25/kordex-control-plane",
                           "imageDigest": "sha256:" + "a" * 64, "sourceCommit": "b" * 40}}
        report = {"overall": "PASS", "deploymentAllowed": True,
                  "deploymentBindings": {"manifestSha256": "c" * 64, "helmValuesSha256": "d" * 64,
                                         "sourceCommit": "b" * 40, "imageDigest": "sha256:" + "a" * 64},
                  "checks": []}
        runner = FakeRunner(fail_match=lambda command: command[:2] == ["helm", "upgrade"])
        with tempfile.TemporaryDirectory() as temp:
            values = Path(temp) / "values.yaml"
            values.write_text("oidc: {}\n", encoding="utf-8")
            values.chmod(0o600)
            cfg["helmValuesFile"] = str(values)
            report["deploymentBindings"]["helmValuesSha256"] = deploy._hash_file(values)
            approval = deploy._deployment_approval(cfg, report["deploymentBindings"])
            with patch.object(deploy, "_verify_inputs_unchanged"):
                with self.assertRaisesRegex(deploy.DeployError, "required command failed"):
                    deploy.deployment_command(cfg, runner, report, approval, "https://api.example")
        self.assertTrue(report["recoveryRequired"])
        self.assertEqual(report["checks"][-1]["status"], "FAIL")
        self.assertEqual(sum(command[:2] == ["helm", "upgrade"] for command in runner.calls), 1)

    def test_values_changed_after_approval_blocks_helm(self):
        cfg = {"target": {"kubeSystemNamespaceUID": "cluster-uid", "namespace": "ns", "releaseName": "cp",
                          "kubeContext": "ctx"},
               "release": {"imageRepository": "ghcr.io/kevin-phan-25/kordex-control-plane",
                           "imageDigest": "sha256:" + "a" * 64, "sourceCommit": "b" * 40}}
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as temp:
            values = Path(temp) / "values.yaml"
            values.write_text("oidc: {}\n", encoding="utf-8")
            values.chmod(0o600)
            service = Path(temp) / "pg_service.conf"
            service.write_text("[m3]\nhost=db.example\ndbname=kordex\nsslmode=verify-full\n", encoding="utf-8")
            service.chmod(0o600)
            ca_bundle = Path(temp) / "ca.pem"
            ca_bundle.write_text("synthetic CA bundle", encoding="utf-8")
            ca_bundle.chmod(0o600)
            cfg["helmValuesFile"] = str(values)
            cfg["database"] = {"pgServiceFile": str(service)}
            cfg["ingress"] = {"caBundlePath": str(ca_bundle)}
            cfg["_databaseServiceSha256"] = deploy._hash_file(service)
            cfg["_tlsBundleSha256"] = deploy._hash_file(ca_bundle)
            cfg["_backupEvidenceSha256"] = {}
            cfg["_lifecycleTokenSha256"] = {}
            bindings = {"manifestSha256": "c" * 64, "helmValuesSha256": deploy._hash_file(values),
                        "sourceCommit": "b" * 40, "imageDigest": "sha256:" + "a" * 64}
            approval = deploy._deployment_approval(cfg, bindings)
            report = {"overall": "PASS", "deploymentAllowed": True, "deploymentBindings": bindings, "checks": []}
            values.write_text("oidc:\n  audience: changed\n", encoding="utf-8")
            values.chmod(0o600)
            with self.assertRaisesRegex(deploy.DeployError, "changed after preflight"):
                deploy.deployment_command(cfg, runner, report, approval, "https://api.example")
        self.assertFalse(any(command[:2] == ["helm", "upgrade"] for command in runner.calls))

    def test_gcp_readiness_blocks_without_billing_headroom(self):
        report = deploy.gcp_readiness_report()
        self.assertEqual(report["overall"], "BLOCKED_BILLING_HEADROOM_NOT_PROVIDED")
        self.assertEqual(report["projectId"], "kordex-fleet-platform-515416")


if __name__ == "__main__":
    unittest.main()
