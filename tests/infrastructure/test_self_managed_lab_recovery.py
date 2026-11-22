import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import self_managed_lab_recovery as recovery  # noqa: E402


PROJECT = recovery.PROJECT_ID
LAB = "kordex-lab"
ZONE = "us-east1-b"
NODES = recovery.names_for(LAB)


class RecoveryGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.gcloud_executable_patch = patch.object(
            recovery.m3_gcloud_context, "executable_path",
            return_value=Path("/usr/lib64/google-cloud-sdk/bin/gcloud"))
        self.gcloud_executable_patch.start()
        self.addCleanup(self.gcloud_executable_patch.stop)
        self.gcloud_command_patch = patch.object(recovery.m3_gcloud_context, "command", side_effect=lambda args, path=None: (
            [path or "/usr/lib64/google-cloud-sdk/bin/gcloud", *args],
            {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
             "CLOUDSDK_CONFIG": "/etc/kordex/gcloud", "CLOUDSDK_ACTIVE_CONFIG_NAME": "kordex-m3"},
            {"version": "synthetic-test-only"}))
        self.gcloud_command_patch.start()
        self.addCleanup(self.gcloud_command_patch.stop)

    def test_recovery_gcloud_ignores_caller_executable_and_uses_fixed_environment(self):
        fixed_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                     "CLOUDSDK_CONFIG": "/etc/kordex/gcloud",
                     "CLOUDSDK_ACTIVE_CONFIG_NAME": "kordex-m3"}
        calls = []

        def controlled(args, *, path=None):
            self.assertEqual(path, "/usr/lib64/google-cloud-sdk/bin/gcloud")
            calls.append((args, path))
            return ([path, *args], fixed_env, {"version": "fixture"})

        def runner(argv, **kwargs):
            calls.append((argv, kwargs.get("env")))
            return "ok"

        with patch.dict("os.environ", {"GCLOUD": "/tmp/attacker-gcloud", "HOME": "/tmp/attacker-home",
                                        "PATH": "/tmp/attacker-bin", "CLOUDSDK_CONFIG": "/tmp/attacker-config"}), \
                patch.object(recovery.m3_gcloud_context, "executable_path",
                             return_value=Path("/usr/lib64/google-cloud-sdk/bin/gcloud")), \
                patch.object(recovery.m3_gcloud_context, "command", side_effect=controlled):
            prefix = recovery.gcloud_prefix(PROJECT)
            output = recovery.command(prefix + ["projects", "describe", PROJECT], run=runner)
        self.assertEqual(output, "ok")
        self.assertEqual(calls[-1][0][0], "/usr/lib64/google-cloud-sdk/bin/gcloud")
        self.assertEqual(calls[-1][1], fixed_env)
        self.assertNotIn("/tmp/attacker-gcloud", calls[-1][0])

    def test_rejects_wrong_project_zone_lab_and_production_resource_names(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "approved lab project"):
            recovery.validate_target("some-other-project", LAB, ZONE, NODES)
        with self.assertRaisesRegex(recovery.RecoveryError, "approved zone"):
            recovery.validate_target(PROJECT, LAB, "us-east1-c", NODES)
        with self.assertRaisesRegex(recovery.RecoveryError, "exactly match"):
            recovery.validate_target(PROJECT, LAB, ZONE, {**NODES, "worker-1": "production-worker"})

    def test_project_label_is_required(self):
        output = json.dumps({"projectId": PROJECT, "projectNumber": "123", "lifecycleState": "ACTIVE",
                             "labels": {"other": "value"}})
        with self.assertRaisesRegex(recovery.RecoveryError, "explicitly labeled"):
            recovery.verify_project(PROJECT, run=lambda *_args, **_kwargs: output)

    def test_firewall_permission_error_is_not_misread_as_absent_rule(self):
        def unavailable(*_args, **_kwargs):
            raise PermissionError("not authorized")
        with self.assertRaisesRegex(recovery.RecoveryError, "cloud command failed"):
            recovery._firewall(PROJECT, "kordex-lab-fault-lock", run=unavailable)

    def test_fault_and_lock_rules_must_match_exact_narrow_scope(self):
        record = {"destinationCIDR": "10.76.0.20/32", "port": 18443}
        deny = {"network": f"projects/{PROJECT}/global/networks/{LAB}-network", "direction": "EGRESS",
                "priority": 700, "targetTags": [f"{LAB}-worker-1"],
                "destinationRanges": [record["destinationCIDR"]],
                "denied": [{"IPProtocol": "tcp", "ports": ["18443"]}]}
        self.assertTrue(recovery._is_exact_fault_rule(deny, record, f"{LAB}-worker-1", f"{LAB}-network"))
        self.assertFalse(recovery._is_exact_fault_rule({**deny, "targetTags": [f"{LAB}-worker-1", "other"]},
                                                       record, f"{LAB}-worker-1", f"{LAB}-network"))
        lock = {"network": f"projects/{PROJECT}/global/networks/{LAB}-network", "direction": "EGRESS",
                "priority": 799, "targetTags": ["kordex-m3-lock-unused"],
                "destinationRanges": ["0.0.0.0/0"],
                "denied": [{"IPProtocol": "tcp", "ports": ["9"]}]}
        self.assertTrue(recovery._is_inert_lock(lock, f"{LAB}-network"))
        self.assertFalse(recovery._is_inert_lock({**lock, "targetTags": [f"{LAB}-worker-1"]}, f"{LAB}-network"))

    def test_project_id_and_topology_are_explicit(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "exactly"):
            recovery.validate_target(PROJECT, LAB, ZONE, {"server": NODES["server"]})
        with self.assertRaisesRegex(recovery.RecoveryError, "Terraform-designated"):
            recovery.validate_target(PROJECT, "prod", ZONE, recovery.names_for("prod"))

    def test_snapshot_set_rejects_missing_or_malformed_snapshot_set(self):
        path = self.root / "snapshots.json"
        path.write_text(json.dumps({"schema": "kordex-m3-recovery-snapshot-set-v1",
                                    "projectId": PROJECT, "labId": LAB, "zone": ZONE,
                                    "snapshotOutcome": "READY_ALL_THREE", "scenario": "fresh-baseline",
                                    "recoverySetId": "a" * 12, "nodes": {}}))
        with patch.object(recovery, "verify_project"):
            with self.assertRaisesRegex(recovery.RecoveryError, "all three"):
                recovery.verify_snapshot_set(path, PROJECT, LAB, ZONE, NODES, run=lambda *_a, **_k: "[]")

    def test_snapshot_confirmation_is_checked_before_snapshot_creation(self):
        baseline = {"schema": "kordex-m3-recovery-baseline-v1",
                    "project": {"projectId": PROJECT}, "labId": LAB, "zone": ZONE,
                    "capturedAt": recovery.now_utc(), "idleAttestation": "NO_ACTIVE_MAINTENANCE",
                    "recoverySetId": "a" * 12,
                    "nodes": {role: {"name": name, "instanceId": "123", "machineId": "b" * 32,
                               "bootId": "11111111-2222-3333-4444-555555555555",
                               "internalIp": f"10.76.0.{10 + i}"}
                              for i, (role, name) in enumerate(NODES.items())}}
        path = self.root / "baseline.json"
        recovery.write_new_json(path, baseline)
        with patch.object(recovery, "verify_project", side_effect=AssertionError("must not reach GCP")):
            with self.assertRaisesRegex(recovery.RecoveryError, "confirmation"):
                recovery.create_snapshot_set(PROJECT, LAB, ZONE, NODES, path, "before-failure",
                    "NO_ACTIVE_MAINTENANCE", "wrong", self.root / "set.json", self.root / "audit.jsonl",
                    run=lambda *_a, **_k: "")

    def test_existing_snapshot_evidence_path_blocks_cloud_mutation(self):
        baseline = {"schema": "kordex-m3-recovery-baseline-v1",
                    "project": {"projectId": PROJECT}, "labId": LAB, "zone": ZONE,
                    "capturedAt": recovery.now_utc(), "idleAttestation": "NO_ACTIVE_MAINTENANCE",
                    "recoverySetId": "a" * 12,
                    "nodes": {role: {"name": name, "instanceId": "123", "machineId": "b" * 32,
                               "bootId": "11111111-2222-3333-4444-555555555555",
                               "internalIp": f"10.76.0.{10 + i}"}
                              for i, (role, name) in enumerate(NODES.items())}}
        baseline_path = self.root / "baseline.json"
        recovery.write_new_json(baseline_path, baseline)
        output = self.root / "existing-set.json"
        output.write_text("preserve")
        with patch.object(recovery, "verify_project", side_effect=AssertionError("must not reach GCP")):
            with self.assertRaisesRegex(recovery.RecoveryError, "evidence path already exists"):
                recovery.create_snapshot_set(PROJECT, LAB, ZONE, NODES, baseline_path, "before-failure",
                    "NO_ACTIVE_MAINTENANCE", f"SNAPSHOT {PROJECT}/{LAB}/" + "a" * 12,
                    output, self.root / "audit.jsonl", run=lambda *_a, **_k: "")

    def test_evidence_and_audit_paths_must_not_alias(self):
        output = self.root / "same.json"
        with self.assertRaisesRegex(recovery.RecoveryError, "different files"):
            recovery.require_distinct_outputs(output, self.root / "subdir" / ".." / "same.json")

    def test_restore_requires_all_three_exact_roles_and_confirmation(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "all three roles"):
            recovery.restore_snapshot_set(PROJECT, LAB, ZONE, NODES, ["worker-1"], self.root / "missing",
                "context", "", self.root / "restore.json", self.root / "audit.jsonl", lambda *_: None,
                run=lambda *_a, **_k: "")

    def test_serial_recovery_fails_when_instance_level_setting_is_absent(self):
        with patch.object(recovery, "verify_project"), patch.object(recovery, "verify_instance", return_value={
                "serialPortEnabled": False}):
            with self.assertRaisesRegex(recovery.RecoveryError, "instance-level"):
                recovery.serial_diagnostics(PROJECT, LAB, ZONE, "server", NODES["server"],
                    "boot-failure", self.root / "serial.log", self.root / "audit.jsonl", run=lambda *_a, **_k: "")

    def test_connectivity_probe_distinguishes_network_failure_from_iap_failure(self):
        args = (PROJECT, ZONE, NODES["worker-1"], "10.76.0.20", 18443)
        self.assertTrue(recovery.remote_tcp_probe(*args, run=lambda *_a, **_k: "reachable\n"))
        self.assertFalse(recovery.remote_tcp_probe(*args, run=lambda *_a, **_k: "unreachable\n"))

        def iap_unavailable(*_args, **_kwargs):
            raise PermissionError("IAP unavailable")

        with self.assertRaisesRegex(recovery.RecoveryError, "cloud command failed"):
            recovery.remote_tcp_probe(*args, run=iap_unavailable)
        with self.assertRaisesRegex(recovery.RecoveryError, "fault state is unknown"):
            recovery.remote_tcp_probe(*args, run=lambda *_a, **_k: "")

    def test_fault_rejects_unapproved_target_and_invalid_duration_before_mutation(self):
        with patch.object(recovery, "verify_project"), patch.object(recovery, "verify_instance", return_value={
                "instanceId": "1"}):
            with self.assertRaisesRegex(recovery.RecoveryError, "private RFC1918"):
                recovery.inject_network_fault(PROJECT, LAB, ZONE, "worker-1", NODES["worker-1"],
                    "private-mirror-connectivity", "8.8.8.8/32", 10, "", self.root / "fault.json",
                    self.root / "audit.jsonl", run=lambda *_a, **_k: "")
            with self.assertRaisesRegex(recovery.RecoveryError, "duration"):
                recovery.inject_network_fault(PROJECT, LAB, ZONE, "worker-1", NODES["worker-1"],
                    "private-mirror-connectivity", "10.76.0.20/32", recovery.MAX_FAULT_SECONDS + 1,
                    "", self.root / "fault.json", self.root / "audit.jsonl", run=lambda *_a, **_k: "")

    def test_competing_fault_is_rejected_when_lab_lock_exists(self):
        lock = {"name": f"{LAB}-fault-lock"}
        with patch.object(recovery, "verify_project"), patch.object(recovery, "verify_instance", return_value={
                "instanceId": "1"}), patch.object(recovery, "_verify_fault_allowlist", return_value=(18443, f"{LAB}-network", "a" * 64)), \
             patch.object(recovery, "remote_tcp_probe", return_value=True), patch.object(recovery, "_firewall", return_value=lock):
            with self.assertRaisesRegex(recovery.RecoveryError, "another fault operation"):
                recovery.inject_network_fault(PROJECT, LAB, ZONE, "worker-1", NODES["worker-1"],
                    "relay-connectivity", "10.76.0.20/32", 5, "", self.root / "fault.json",
                    self.root / "audit.jsonl", run=lambda *_a, **_k: "")

    def test_failed_automatic_restoration_retains_lock_and_evidence(self):
        state = {}

        def run(argv, **_kwargs):
            if "firewall-rules" in argv and "create" in argv:
                name = argv[argv.index("create") + 1]
                description = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--description="))
                state[name] = {"name": name, "description": description, "network": f"projects/{PROJECT}/global/networks/{LAB}-network",
                               "direction": "EGRESS", "priority": 700, "targetTags": [f"{LAB}-worker-1"],
                               "destinationRanges": ["10.76.0.20/32"], "denied": [{"IPProtocol": "tcp", "ports": ["18443"]}]}
            if "firewall-rules" in argv and "delete" in argv:
                raise RuntimeError("simulated control-plane delete failure")
            return ""

        def firewall(_project, name, *, run):
            return state.get(name)

        def make_lock(_project, lab_id, network, record, *, run):
            state[f"{lab_id}-fault-lock"] = {"name": f"{lab_id}-fault-lock",
                "description": recovery._encoded_description(recovery.LOCK_PREFIX, record),
                "network": f"projects/{PROJECT}/global/networks/{network}", "direction": "EGRESS",
                "priority": 799, "denied": [{"IPProtocol": "tcp", "ports": ["9"]}],
                "targetTags": ["kordex-m3-lock-unused"], "destinationRanges": ["0.0.0.0/0"]}

        probes = iter([True, False, True])
        with patch.object(recovery, "verify_project"), patch.object(recovery, "verify_instance", return_value={"instanceId": "1"}), \
             patch.object(recovery, "_verify_fault_allowlist", return_value=(18443, f"{LAB}-network", "a" * 64)), \
             patch.object(recovery, "_firewall", side_effect=firewall), patch.object(recovery, "_create_inert_lock", side_effect=make_lock), \
             patch.object(recovery, "remote_tcp_probe", side_effect=lambda *_a, **_k: next(probes)), \
             patch.object(recovery, "_delete_firewall", side_effect=RuntimeError("restore failed")):
            with self.assertRaisesRegex(recovery.RecoveryError, "fault operation failed"):
                recovery.inject_network_fault(PROJECT, LAB, ZONE, "worker-1", NODES["worker-1"],
                    "relay-connectivity", "10.76.0.20/32", 1, f"INJECT {PROJECT}/{LAB}/0123456789ab",
                    self.root / "fault.json", self.root / "audit.jsonl", run=run, sleep=lambda _n: None,
                    operation_id="0123456789ab")
        evidence = json.loads((self.root / "fault.json").read_text())
        self.assertEqual(evidence["restoreOutcome"], "RESTORE_FAILED_LOCK_RETAINED")
        self.assertIn(f"{LAB}-fault-lock", state)

    def test_network_fault_is_observed_and_automatically_restored(self):
        state = {}

        def run(argv, **_kwargs):
            if "firewall-rules" in argv and "create" in argv:
                name = argv[argv.index("create") + 1]
                description = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--description="))
                state[name] = {"name": name, "description": description,
                    "network": f"projects/{PROJECT}/global/networks/{LAB}-network", "direction": "EGRESS",
                    "priority": 700, "targetTags": [f"{LAB}-worker-1"],
                    "destinationRanges": ["10.76.0.20/32"],
                    "denied": [{"IPProtocol": "tcp", "ports": ["18443"]}]}
            elif "firewall-rules" in argv and "delete" in argv:
                state.pop(argv[argv.index("delete") + 1], None)
            return ""

        def firewall(_project, name, *, run):
            return state.get(name)

        def make_lock(_project, lab_id, network, record, *, run):
            state[f"{lab_id}-fault-lock"] = {"name": f"{lab_id}-fault-lock",
                "description": recovery._encoded_description(recovery.LOCK_PREFIX, record),
                "network": f"projects/{PROJECT}/global/networks/{network}", "direction": "EGRESS",
                "priority": 799, "denied": [{"IPProtocol": "tcp", "ports": ["9"]}],
                "targetTags": ["kordex-m3-lock-unused"], "destinationRanges": ["0.0.0.0/0"]}

        probes = iter([True, False, True])
        with patch.object(recovery, "verify_project"), patch.object(recovery, "verify_instance", return_value={"instanceId": "1"}), \
             patch.object(recovery, "_verify_fault_allowlist", return_value=(18443, f"{LAB}-network", "a" * 64)), \
             patch.object(recovery, "_firewall", side_effect=firewall), patch.object(recovery, "_create_inert_lock", side_effect=make_lock), \
             patch.object(recovery, "remote_tcp_probe", side_effect=lambda *_a, **_k: next(probes)):
            record = recovery.inject_network_fault(PROJECT, LAB, ZONE, "worker-1", NODES["worker-1"],
                "relay-connectivity", "10.76.0.20/32", 2, f"INJECT {PROJECT}/{LAB}/0123456789ab",
                self.root / "fault.json", self.root / "audit.jsonl", run=run, sleep=lambda _n: None,
                operation_id="0123456789ab")
        self.assertTrue(record["faultObserved"])
        self.assertEqual(record["restoreOutcome"], "AUTOMATIC_RESTORE_VERIFIED")
        self.assertFalse(state)
        digest = hashlib.sha256((self.root / "fault.json").read_bytes()).hexdigest()
        self.assertEqual(recovery.verify_recovery_evidence(self.root / "fault.json", digest)["sha256"], digest)

    def test_manual_recovery_after_interruption_removes_only_verified_lab_rules(self):
        operation = "0123456789ab"
        record = {"schema": "kordex-m3-network-fault-v1", "operationId": operation,
                  "scenarioId": "M3-NET-RELAY-CONNECTIVITY", "faultType": "relay-connectivity",
                  "projectId": PROJECT, "labId": LAB, "zone": ZONE, "targetRole": "worker-1",
                  "targetInstance": NODES["worker-1"], "targetInstanceId": "1", "destinationCIDR": "10.76.0.20/32",
                  "protocol": "tcp", "port": 18443, "durationSeconds": 5,
                  "lockRule": f"{LAB}-fault-lock", "denyRule": f"{LAB}-fi-{operation}-deny",
                  "network": f"{LAB}-network", "startedAt": "2026-11-21T00:00:00Z", "before": {},
                  "faultObserved": False}
        state = {
            record["lockRule"]: {"name": record["lockRule"], "description": recovery._encoded_description(recovery.LOCK_PREFIX, record),
                "network": f"projects/{PROJECT}/global/networks/{LAB}-network", "direction": "EGRESS", "priority": 799,
                "denied": [{"IPProtocol": "tcp", "ports": ["9"]}], "targetTags": ["kordex-m3-lock-unused"],
                "destinationRanges": ["0.0.0.0/0"]},
            record["denyRule"]: {"name": record["denyRule"], "description": recovery._encoded_description(recovery.DENY_PREFIX, record),
                "network": f"projects/{PROJECT}/global/networks/{LAB}-network", "direction": "EGRESS", "priority": 700,
                "denied": [{"IPProtocol": "tcp", "ports": ["18443"]}], "targetTags": [f"{LAB}-worker-1"],
                "destinationRanges": ["10.76.0.20/32"]},
        }

        def run(argv, **_kwargs):
            if "firewall-rules" in argv and "delete" in argv:
                state.pop(argv[argv.index("delete") + 1], None)
            return ""

        def firewall(_project, name, *, run):
            return state.get(name)

        with patch.object(recovery, "verify_project"), patch.object(recovery, "verify_instance", return_value={"instanceId": "1"}), \
             patch.object(recovery, "_firewall", side_effect=firewall), \
             patch.object(recovery, "remote_tcp_probe", side_effect=[False, True]):
            recovered = recovery.recover_network_fault(PROJECT, LAB, ZONE, operation,
                f"RESTORE-FAULT {PROJECT}/{LAB}/{operation}", self.root / "recovered.json",
                self.root / "audit.jsonl", run=run)
        self.assertTrue(recovered["faultObserved"])
        self.assertFalse(state)

    def test_evidence_tampering_and_serial_secret_redaction(self):
        record = {"schema": "kordex-m3-network-fault-v1", "restoreOutcome": "AUTOMATIC_RESTORE_VERIFIED",
                  "faultObserved": True, "after": {"temporaryDenyRule": "ABSENT", "lockRule": "ABSENT",
                  "endpointReachable": True}, "startedAt": "2026-11-21T00:00:00Z", "endedAt": "2026-11-21T00:00:01Z"}
        path = self.root / "evidence.json"
        digest = recovery.write_new_json(path, record)
        self.assertEqual(recovery.verify_recovery_evidence(path, digest)["sha256"], digest)
        path.write_text(path.read_text().replace("AUTOMATIC", "MANUAL"))
        with self.assertRaisesRegex(recovery.RecoveryError, "independently retained"):
            recovery.verify_recovery_evidence(path, digest)
        self.assertNotIn("supersecret", recovery.redact_serial_output("token=supersecret\n"))


if __name__ == "__main__":
    unittest.main()
