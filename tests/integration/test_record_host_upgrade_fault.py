import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

RECORDER_PATH = Path(__file__).with_name("record_host_upgrade_fault.py")
SPEC = importlib.util.spec_from_file_location("host_upgrade_fault_recorder", RECORDER_PATH)
recorder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = recorder
SPEC.loader.exec_module(recorder)


class RecordHostUpgradeFaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.evidence = self.root / "ssh-loss-during-apply-debian.json"
        self.log = self.root / "network.log"
        self.log.write_text("rule enabled\nconnection refused\nrule removed\n")
        events = [
            {"sequence": 1, "phase": "Pending", "reason": "accepted", "time": "2026-11-17T12:00:01Z"},
            {"sequence": 2, "phase": "Executing", "reason": "upgrade job started", "time": "2026-11-17T12:01:00Z"},
            {"sequence": 3, "phase": "RecoveryRequired", "reason": "ssh unavailable", "time": "2026-11-17T12:04:00Z"},
        ]
        self.evidence.write_text(json.dumps({
            "mode": "execute", "qualificationCase": "ssh-loss-during-apply", "osFamily": "debian",
            "outcome": "RecoveryRequired",
            "startedAt": "2026-11-17T12:00:00Z", "finishedAt": "2026-11-17T12:05:00Z",
            "lastOperation": {"phase": "RecoveryRequired", "status": {
                "phase": "RecoveryRequired", "sequence": 3, "events": events,
            }},
        }))

    def tearDown(self):
        self.temp.cleanup()

    def test_attaches_case_bound_observations_and_copied_log_hash(self):
        artifact = recorder.attach(
            self.evidence, "temporary TCP/22 block", "2026-11-17T12:02:00Z", "2026-11-17T12:03:00Z",
            "lab-run-17", "test-operator", self.log,
            {"phase": "Executing", "blockedObserved": True, "restoredObserved": True},
        )
        result = json.loads(self.evidence.read_text())
        injection = result["injection"]
        self.assertEqual(injection["faultType"], "ssh-loss")
        self.assertEqual(injection["observations"]["phase"], "Executing")
        self.assertEqual(injection["evidenceFile"], "injection-logs/ssh-loss-during-apply-debian.log")
        self.assertEqual(injection["evidenceSHA256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
        self.assertEqual(artifact.read_bytes(), self.log.read_bytes())

    def test_rejects_wrong_phase_record_without_leaving_an_artifact(self):
        with self.assertRaisesRegex(recorder.verifier.EvidenceError, "not observed during Executing"):
            recorder.attach(
                self.evidence, "temporary TCP/22 block", "2026-11-17T12:02:00Z", "2026-11-17T12:03:00Z",
                "lab-run-18", "test-operator", self.log,
                {"phase": "Rebooting", "blockedObserved": True, "restoredObserved": True},
            )
        self.assertFalse((self.root / "injection-logs").exists() and
                         any((self.root / "injection-logs").iterdir()))

    def test_rejects_injection_outside_the_runner_interval(self):
        with self.assertRaisesRegex(recorder.FaultEvidenceError, "inside the runner execution interval"):
            recorder.attach(
                self.evidence, "temporary TCP/22 block", "2026-11-17T11:59:00Z", "2026-11-17T12:03:00Z",
                "lab-run-19", "test-operator", self.log,
                {"phase": "Executing", "blockedObserved": True, "restoredObserved": True},
            )

    def test_offline_bundle_adjacent_verifier_and_matrix_are_used(self):
        qualification = self.root / "bundle" / "qualification"
        qualification.mkdir(parents=True)
        for source in (RECORDER_PATH, RECORDER_PATH.with_name("host_upgrade_failure_matrix.json"),
                       RECORDER_PATH.parents[2] / "scripts/verify-host-upgrade-qualification.py"):
            shutil.copyfile(source, qualification / source.name)
        bundled_script = qualification / RECORDER_PATH.name
        bundled_spec = importlib.util.spec_from_file_location("bundled_host_upgrade_fault_recorder", bundled_script)
        bundled = importlib.util.module_from_spec(bundled_spec)
        sys.modules[bundled_spec.name] = bundled
        bundled_spec.loader.exec_module(bundled)
        self.assertEqual(bundled.VERIFIER_PATH, qualification / "verify-host-upgrade-qualification.py")
        bundled.verifier.verify_pinned_matrix(bundled.MATRIX)


if __name__ == "__main__":
    unittest.main()
