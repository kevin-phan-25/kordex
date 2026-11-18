import importlib.util
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).with_name("self_managed_upgrade_smoke.py")
SPEC = importlib.util.spec_from_file_location("self_managed_upgrade_smoke", SCRIPT)
drill = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = drill
SPEC.loader.exec_module(drill)


class OperatorRestartDrillTests(unittest.TestCase):
    def test_restart_requires_a_ready_old_pod_and_records_new_ready_uid(self):
        old_uid = "11111111-1111-4111-8111-111111111111"
        new_uid = "22222222-2222-4222-8222-222222222222"
        with patch.object(drill, "ready_operator_pod_uids", side_effect=[[old_uid], [new_uid]]), \
                patch.object(drill.subprocess, "run") as run:
            evidence = drill.restart_operator("kubectl", "kordex-system", timeout_seconds=5)
        self.assertEqual(evidence["oldPodUID"], old_uid)
        self.assertEqual(evidence["newPodUID"], new_uid)
        self.assertEqual(evidence["phaseAtRestart"], "Executing")
        self.assertEqual(evidence["deployment"], "kordex-operator")
        self.assertIn("rollout", run.call_args_list[0].args[0])
        self.assertIn("restart", run.call_args_list[0].args[0])
        self.assertIn("status", run.call_args_list[1].args[0])

    def test_restart_refuses_to_restart_when_operator_pod_is_not_ready(self):
        with patch.object(drill, "ready_operator_pod_uids", return_value=[]), \
                patch.object(drill.subprocess, "run") as run:
            with self.assertRaisesRegex(drill.DrillError, "no Ready Kordex operator pod"):
                drill.restart_operator("kubectl", "kordex-system", timeout_seconds=5)
        run.assert_not_called()


class DurableObserverTests(unittest.TestCase):
    operation_id = "7f2d6808-5f3b-462a-bc18-06e1a00c7a55"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "execution.json"
        self.output = self.root / "observation.json"
        self.policy = {"name": "ubuntu-lab", "uid": "policy-uid", "generation": 1}
        self.source = {
            "drill": "self-managed-linux-upgrade", "mode": "execute", "admissionChecksPassed": True,
            "organization": "org-1", "cluster": "cluster-1", "clusterUid": "cluster-uid",
            "context": "ubuntu-lab", "apiOrigin": "https://hub.example.internal",
            "operationId": self.operation_id, "node": {"name": "worker-1", "uid": "node-uid"},
            "policyIdentity": self.policy, "planDigest": "a" * 64,
            "upgradePlan": {"osFamily": "debian", "executionBackend": "ansible-ee",
                            "actionMarkerVersion": 1, "playbookCatalogId": "kordex.os-upgrade.debian.v2",
                            "packages": [{"name": "curl", "version": "8.5.0-1"}]},
        }
        self.request = {"operationId": self.operation_id, "nodeName": "worker-1", "nodeUid": "node-uid",
                        "policy": self.policy, "action": "UpgradePackages", "planDigest": "a" * 64}
        self.operation = {"id": self.operation_id, "organizationId": "org-1", "clusterId": "cluster-1",
                          "request": self.request, "phase": "RecoveryRequired",
                          "status": {"upgradeCheckpoint": {"phase": "RecoveryRequired"}},
                          "command": {"authorization": "secret", "signature": "secret"}}
        self.live_node = {"metadata": {"name": "worker-1", "uid": "node-uid"},
                          "spec": {"unschedulable": True},
                          "status": {"nodeInfo": {"osImage": "Ubuntu 24.04 LTS"}, "conditions": []}}
        self.env = {"KORDEX_API": self.source["apiOrigin"], "KORDEX_ADMIN_TOKEN": "secret",
                    "KORDEX_ORG_ID": "org-1", "KORDEX_CLUSTER_ID": "cluster-1",
                    "KORDEX_EXPECTED_CONTEXT": "ubuntu-lab"}
        drill.write_evidence(self.path, self.source)

    def test_lost_submission_response_retains_identity_before_request(self):
        hub = Mock()

        def lose_response(*args):
            saved = json.loads(self.path.read_text())
            self.assertEqual(saved["operationId"], self.operation_id)
            self.assertEqual(saved["outcome"], "SubmissionUnknown")
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            raise drill.DrillError("response lost")

        hub.request.side_effect = lose_response
        with self.assertRaisesRegex(drill.DrillError, "response lost"):
            drill.submit_operation(hub, "/operations", self.request, self.source, self.path)
        self.assertEqual(hub.request.call_count, 1)
        self.assertEqual(json.loads(self.path.read_text())["submission"], "IntentPersisted")

    def test_evidence_write_failure_blocks_submission(self):
        hub = Mock()
        with patch.object(drill, "write_evidence", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                drill.submit_operation(hub, "/operations", self.request, self.source, self.path)
        hub.request.assert_not_called()

    def test_observer_interruption_after_response_keeps_redacted_identity(self):
        hub = Mock()
        hub.request.return_value = self.operation
        drill.submit_operation(hub, "/operations", self.request, self.source, self.path)
        saved = json.loads(self.path.read_text())
        self.assertEqual(saved["submission"], "ResponseReceived")
        self.assertEqual(saved["operationId"], self.operation_id)
        self.assertNotIn("command", saved["lastOperation"])
        self.assertNotIn('"secret"', self.path.read_text())

    def test_process_kill_during_submission_leaves_recoverable_operation_id(self):
        # A real child is killed after its fake transport sees the POST. This
        # checks persistence across process loss without contacting a host/hub.
        arrived = self.root / "post-started"
        program = """
import importlib.util, json, pathlib, sys, time
spec = importlib.util.spec_from_file_location('drill', sys.argv[1])
drill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drill)
class LostTransport:
    def request(self, *args):
        pathlib.Path(sys.argv[3]).write_text('POST reached transport')
        time.sleep(60)
path = pathlib.Path(sys.argv[2])
evidence = json.loads(path.read_text())
drill.submit_operation(LostTransport(), '/operations',
    {'operationId': evidence['operationId']}, evidence, path)
"""
        child = subprocess.Popen([sys.executable, "-c", program, str(SCRIPT), str(self.path), str(arrived)])
        try:
            deadline = time.monotonic() + 5
            while not arrived.exists() and time.monotonic() < deadline and child.poll() is None:
                time.sleep(0.01)
            self.assertTrue(arrived.exists(), "child never reached the fake transport")
            child.kill()
            child.wait(timeout=5)
            self.assertEqual(child.returncode, -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
        saved = json.loads(self.path.read_text())
        self.assertEqual(saved["operationId"], self.operation_id)
        self.assertEqual(saved["submission"], "IntentPersisted")
        self.assertEqual(saved["outcome"], "SubmissionUnknown")

    def run_observation(self, report=None, operations=None, cluster_uid="cluster-uid", reservation_error=None):
        hub = Mock()
        hub.origin = self.source["apiOrigin"]
        hub.request.return_value = {"items": [self.operation] if operations is None else operations,
                                    "limit": 500, "offset": 0}
        report = {} if report is None else report
        with patch.dict(os.environ, self.env, clear=True), patch.object(drill, "Hub", return_value=hub), \
                patch.object(drill.subprocess, "check_output", return_value="ubuntu-lab\n"), \
                patch.object(drill, "run_json", side_effect=[
                    {"metadata": {"uid": cluster_uid}}, self.live_node]), \
                patch.object(drill, "verify_maintenance_reservation", return_value={"held": True},
                             side_effect=reservation_error) as reservation:
            drill.observe_existing_operation(self.path, report, self.output, 5, 0.01)
        for call in hub.request.call_args_list:
            self.assertEqual(call.args[0], "GET")
        return report, hub, reservation

    def test_read_only_observation_accepts_fenced_host_without_fresh_capability(self):
        before = self.path.read_bytes()
        report, hub, reservation = self.run_observation()
        self.assertEqual(report["outcome"], "ObservedRecoveryRequired")
        self.assertEqual(report["sourceEvidenceSHA256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertNotIn("command", report["lastOperation"])
        self.assertEqual(hub.request.call_count, 1)
        reservation.assert_called_once()

    def test_observation_rejects_missing_operation_without_submission(self):
        report = {}
        with self.assertRaisesRegex(drill.DrillError, "do not resubmit"):
            self.run_observation(report, operations=[])
        self.assertEqual(report["outcome"], "OperationNotFoundUnknown")

    def test_observation_rejects_different_live_request_and_tenant(self):
        original = copy.deepcopy(self.operation)
        for field, replacement in [("nodeUid", "other"), ("planDigest", "b" * 64),
                                   ("action", "DrainAndVerify"), ("policy", {**self.policy, "generation": 2})]:
            with self.subTest(field=field):
                self.operation = copy.deepcopy(original)
                self.operation["request"][field] = replacement
                with self.assertRaisesRegex(drill.DrillError, "does not match saved"):
                    self.run_observation()
        self.operation = {**original, "organizationId": "other"}
        with self.assertRaisesRegex(drill.DrillError, "does not match saved"):
            self.run_observation()

    def test_observation_rejects_changed_cluster_or_node_identity(self):
        with self.assertRaisesRegex(drill.DrillError, "cluster UID differs"):
            self.run_observation(cluster_uid="replacement-cluster")
        self.live_node["metadata"]["uid"] = "replacement-node"
        with self.assertRaisesRegex(drill.DrillError, "node UID changed"):
            self.run_observation()

    def test_observation_never_accepts_unfenced_recovery_required(self):
        self.live_node["spec"]["unschedulable"] = False
        with self.assertRaisesRegex(drill.DrillError, "keep the original node fenced"):
            self.run_observation()

    def test_observation_timeout_does_not_submit_or_claim_recovery(self):
        self.operation["phase"] = "Executing"
        report = {}
        with patch.object(drill.time, "monotonic", side_effect=[0, 0, 10]), \
                patch.object(drill.time, "sleep"), self.assertRaisesRegex(drill.DrillError, "observation timed out"):
            self.run_observation(report)
        self.assertEqual(report["outcome"], "TimedOutUnknown")
        self.assertEqual(report["lastOperation"]["phase"], "Executing")

    def test_observation_requires_live_reservation_for_fenced_outcome(self):
        with self.assertRaisesRegex(drill.DrillError, "reservation not held"):
            self.run_observation(reservation_error=drill.DrillError("reservation not held"))

    def test_observation_rejects_duplicate_evidence_keys(self):
        self.path.write_text('{"mode":"execute","mode":"preflight"}')
        with self.assertRaisesRegex(drill.DrillError, "duplicate evidence field"):
            self.run_observation()

    def test_cli_rejects_mutating_observation_flags_or_missing_durable_output(self):
        for args in (["--execute"], ["--observe-evidence", str(self.path)],
                     ["--observe-evidence", str(self.path), "--evidence", str(self.output), "--execute"],
                     ["--observe-evidence", str(self.path), "--evidence", str(self.output), "--cancel-on-phase", "Rebooting"],
                     ["--execute", "--evidence", str(self.path)]):
            with self.subTest(args=args), patch.object(sys, "argv", ["drill", *args]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                drill.main()
            self.assertEqual(result.exception.code, 2)
        self.assertEqual(json.loads(self.path.read_text()), self.source)

    def test_cli_observation_report_remains_separate_from_qualification(self):
        def observe(source_path, report, output, timeout, poll):
            self.assertEqual(report["mode"], "observe")
            self.assertEqual(report["drill"], "self-managed-linux-upgrade-observation")
            self.assertNotIn("qualificationCase", report)
            report["outcome"] = "ObservedRecoveryRequired"

        with patch.object(sys, "argv", ["drill", "--observe-evidence", str(self.path),
                                       "--evidence", str(self.output)]), \
                patch.object(drill, "observe_existing_operation", side_effect=observe), \
                patch.object(drill, "submit_operation") as submit, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(drill.main(), 0)
        submit.assert_not_called()
        self.assertEqual(json.loads(self.output.read_text())["outcome"], "ObservedRecoveryRequired")


if __name__ == "__main__":
    unittest.main()
