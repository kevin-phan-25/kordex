import hashlib
import copy
import json
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

VERIFY_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/verify-host-upgrade-qualification.py"
SPEC = importlib.util.spec_from_file_location("host_upgrade_evidence_verifier", VERIFY_SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class HostUpgradeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.matrix = self.root / "matrix.json"
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write_case(self, case, evidence):
        self.matrix.write_text(json.dumps({"schemaVersion": 1, "cases": [case]}))
        (self.evidence_dir / f"{case['id']}.json").write_text(json.dumps(evidence))

    def add_injection_artifact(self, evidence, content=b"lab injection log\n"):
        artifact = self.evidence_dir / "injection-logs" / "lab.log"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(content)
        evidence["injection"]["evidenceFile"] = "injection-logs/lab.log"
        evidence["injection"]["evidenceSHA256"] = hashlib.sha256(content).hexdigest()

    @staticmethod
    def clean_case():
        return {"id": "clean-upgrade", "execution": "runner", "allowedOutcomes": ["Succeeded"]}

    @staticmethod
    def clean_evidence():
        return {
            "qualificationCase": "clean-upgrade", "drill": "self-managed-linux-upgrade", "osFamily": "debian",
            "admissionChecksPassed": True, "planDigest": "a" * 64,
            "cluster": "cluster-1", "clusterUid": "cluster-uid", "context": "lab-context",
            "node": {"name": "worker-1", "uid": "node-uid"},
            "upgradePlan": {"actionMarkerVersion": 1, "packages": [{"name": "curl", "version": "8.5.0-1"}]},
            "startedAt": "2026-11-17T12:00:00Z", "finishedAt": "2026-11-17T12:10:00Z",
            "operationId": "7f2d6808-5f3b-462a-bc18-06e1a00c7a55", "outcome": "Succeeded",
            "hostPreflightReceipt": {"phase": "preflight", "machineId": "a" * 32,
                                     "bootIdBefore": "11111111-1111-4111-8111-111111111111",
                                     "bootIdAfter": "11111111-1111-4111-8111-111111111111",
                                     "reference": "receipt-preflight", "digest": "b" * 64,
                                     "completedAt": "2026-11-17T12:01:00Z"},
            "lastOperation": {"phase": "Succeeded", "status": {"upgradeCheckpoint": {
                "phase": "Succeeded", "planDigest": "a" * 64, "nodeUid": "node-uid",
                "receipts": [
                    {"phase": "preflight", "reference": "receipt-preflight", "digest": "b" * 64},
                    {"phase": "apply", "packages": {"curl": "8.5.0-1"}, "rebootRequired": False,
                     "machineId": "a" * 32,
                     "bootIdBefore": "11111111-1111-4111-8111-111111111111",
                     "bootIdAfter": "11111111-1111-4111-8111-111111111111",
                     "actionMarker": {"version": 1, "operationId": "7f2d6808-5f3b-462a-bc18-06e1a00c7a55",
                         "actionDigest": "a" * 64, "nodeUid": "node-uid", "machineId": "a" * 32,
                         "bootId": "11111111-1111-4111-8111-111111111111", "phase": "packages-verified",
                         "sequence": 2, "sha256": "c" * 64}},
                ]}, "events": [{"sequence": 1, "phase": "Executing", "reason": "host apply started",
                                "time": "2026-11-17T12:02:00Z"}]}},
            "nodeAfter": {"uid": "node-uid", "ready": True, "unschedulable": False},
        }

    def test_accepts_success_bound_to_exact_node_and_plan(self):
        self.write_case(self.clean_case(), self.clean_evidence())
        self.assertEqual(verifier.verify_directory(self.matrix, self.evidence_dir), ["clean-upgrade"])

    def test_supplemental_report_cannot_satisfy_a_matrix_case(self):
        evidence = self.clean_evidence()
        evidence["qualificationScope"] = "supplemental"
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "supplemental evidence"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    @classmethod
    def reboot_evidence(cls):
        evidence = cls.clean_evidence()
        evidence["upgradePlan"]["reboot"] = "Always"
        receipts = evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"]
        apply = receipts[1]
        apply["rebootRequired"] = True
        reboot = copy.deepcopy(apply)
        reboot.update({"phase": "reboot", "rebooted": True,
                       "bootIdAfter": "22222222-2222-4222-8222-222222222222"})
        reboot["actionMarker"].update({"bootId": reboot["bootIdAfter"],
                                      "phase": "reboot-verified", "sequence": 4})
        receipts.append(reboot)
        return evidence

    def test_always_policy_requires_reboot_even_when_apply_says_false(self):
        evidence = self.clean_evidence()
        evidence["upgradePlan"]["reboot"] = "Always"
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "reboot"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_accepts_verified_reboot_for_always_policy(self):
        self.write_case(self.clean_case(), self.reboot_evidence())
        self.assertEqual(verifier.verify_directory(self.matrix, self.evidence_dir), ["clean-upgrade"])

    def test_never_policy_rejects_reboot_or_outstanding_reboot_requirement(self):
        for with_receipt in (True, False):
            with self.subTest(with_receipt=with_receipt):
                evidence = self.reboot_evidence()
                evidence["upgradePlan"]["reboot"] = "Never"
                if not with_receipt:
                    evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"].pop()
                self.write_case(self.clean_case(), evidence)
                with self.assertRaisesRegex(verifier.EvidenceError, "reboot"):
                    verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_optional_reboot_receipt_must_be_verified_even_if_apply_says_false(self):
        for field, value in (("rebooted", False), ("bootIdAfter", "not-a-uuid"),
                             ("machineId", "b" * 32), ("packages", {"curl": "wrong"}),
                             ("actionMarker", None)):
            with self.subTest(field=field):
                evidence = self.reboot_evidence()
                evidence["upgradePlan"]["reboot"] = "IfNeeded"
                receipts = evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"]
                receipts[1]["rebootRequired"] = False
                receipts[2][field] = value
                self.write_case(self.clean_case(), evidence)
                with self.assertRaisesRegex(verifier.EvidenceError, "reboot"):
                    verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_required_reboot_rejects_corrupt_receipt(self):
        for field, value in (("rebooted", False), ("rebootRequired", False),
                             ("bootIdAfter", "not-a-uuid"), ("machineId", "b" * 32),
                             ("packages", {"curl": "wrong"}), ("actionMarker", None)):
            with self.subTest(field=field):
                evidence = self.reboot_evidence()
                evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"][2][field] = value
                self.write_case(self.clean_case(), evidence)
                with self.assertRaisesRegex(verifier.EvidenceError, "reboot"):
                    verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_never_policy_still_accepts_verified_no_reboot_operation(self):
        evidence = self.clean_evidence()
        evidence["upgradePlan"]["reboot"] = "Never"
        self.write_case(self.clean_case(), evidence)
        self.assertEqual(verifier.verify_directory(self.matrix, self.evidence_dir), ["clean-upgrade"])

    def test_malformed_or_duplicate_receipts_cannot_hide_reboot_evidence(self):
        for extra in (None, {"phase": []}, {"phase": "apply"}):
            with self.subTest(extra=extra):
                evidence = self.reboot_evidence()
                evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"].append(extra)
                self.write_case(self.clean_case(), evidence)
                with self.assertRaisesRegex(verifier.EvidenceError, "receipt"):
                    verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_apply_reboot_requirement_must_not_be_a_false_like_non_boolean(self):
        evidence = self.clean_evidence()
        evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"][1]["rebootRequired"] = 0
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "boolean"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_operator_restart_requires_new_ready_pod_uid_after_executing(self):
        evidence = self.clean_evidence()
        case = {"id": "operator-restart-during-executing", "execution": "runner",
                "allowedOutcomes": ["Succeeded"]}
        evidence.update({
            "qualificationCase": case["id"],
            "operatorRestart": {
                "deployment": "kordex-operator", "namespace": "kordex-system",
                "oldPodUID": "11111111-1111-4111-8111-111111111111",
                "newPodUID": "22222222-2222-4222-8222-222222222222",
                "phaseAtRestart": "Executing",
                "requestedAt": "2026-11-17T12:03:00Z",
                "readyAt": "2026-11-17T12:04:00Z",
            },
        })
        self.write_case(case, evidence)
        self.assertEqual(verifier.verify_directory(self.matrix, self.evidence_dir),
                         ["operator-restart-during-executing"])

        evidence["operatorRestart"]["newPodUID"] = evidence["operatorRestart"]["oldPodUID"]
        (self.evidence_dir / f"{case['id']}.json").write_text(json.dumps(evidence))
        with self.assertRaisesRegex(verifier.EvidenceError, "did not replace a pod"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_success_requires_ready_node_evidence(self):
        evidence = self.clean_evidence()
        evidence["nodeAfter"]["ready"] = False
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "not verified Ready"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_cancelled_recovery_requires_ready_node_evidence(self):
        case = {"id": "cancel-during-reboot", "execution": "runner",
                "allowedOutcomes": ["CancellationRecovered"]}
        evidence = self.clean_evidence()
        checkpoint = evidence["lastOperation"]["status"]["upgradeCheckpoint"]
        checkpoint["phase"] = "Cancelled"
        evidence["lastOperation"]["phase"] = "Cancelled"
        evidence["outcome"] = "CancellationRecovered"
        evidence["qualificationCase"] = case["id"]
        evidence["nodeAfter"]["ready"] = False
        self.write_case(case, evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "not verified Ready"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_rejects_missing_matrix_case_evidence(self):
        self.write_case(self.clean_case(), self.clean_evidence())
        self.matrix.write_text(json.dumps({"schemaVersion": 1, "cases": [self.clean_case(), {
            "id": "cancel-during-reboot", "execution": "runner", "allowedOutcomes": ["CancellationRecovered"]
        }]}))
        with self.assertRaisesRegex(verifier.EvidenceError, "missing evidence"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_matrix_requires_independent_evidence_for_each_os_family(self):
        case = self.clean_case()
        self.matrix.write_text(json.dumps({"schemaVersion": 1, "osFamilies": ["debian", "rhel"], "cases": [case]}))
        (self.evidence_dir / "clean-upgrade-debian.json").write_text(json.dumps(self.clean_evidence()))
        with self.assertRaisesRegex(verifier.EvidenceError, "clean-upgrade-rhel.json"):
            verifier.verify_directory(self.matrix, self.evidence_dir)
        rhel_evidence = self.clean_evidence()
        rhel_evidence["osFamily"] = "rhel"
        (self.evidence_dir / "clean-upgrade-rhel.json").write_text(json.dumps(rhel_evidence))
        self.assertEqual(verifier.verify_directory(self.matrix, self.evidence_dir),
                         ["clean-upgrade-debian", "clean-upgrade-rhel"])

    def test_rejects_evidence_without_real_host_preflight_receipt(self):
        evidence = self.clean_evidence()
        evidence.pop("hostPreflightReceipt")
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "host package-resolution"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_success_requires_exact_action_marker_evidence(self):
        evidence = self.clean_evidence()
        checkpoint = evidence["lastOperation"]["status"]["upgradeCheckpoint"]
        checkpoint["receipts"][1].pop("actionMarker")
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "packages-verified action marker missing"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_action_marker_rejects_boolean_version_and_sequence(self):
        evidence = self.clean_evidence()
        marker = evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"][1]["actionMarker"]
        marker["version"] = True
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "action marker does not match"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

        evidence = self.clean_evidence()
        marker = evidence["lastOperation"]["status"]["upgradeCheckpoint"]["receipts"][1]["actionMarker"]
        marker["sequence"] = True
        self.write_case(self.clean_case(), evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "action marker does not match"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_matrix_rejects_duplicate_case_ids(self):
        case = self.clean_case()
        self.matrix.write_text(json.dumps({"schemaVersion": 1, "cases": [case, case]}))
        with self.assertRaisesRegex(verifier.EvidenceError, "duplicate case ID"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_evidence_rejects_duplicate_json_keys(self):
        self.matrix.write_text(json.dumps({"schemaVersion": 1, "cases": [self.clean_case()]}))
        (self.evidence_dir / "clean-upgrade.json").write_text('{"qualificationCase":"clean-upgrade","qualificationCase":"other"}')
        with self.assertRaisesRegex(verifier.EvidenceError, "duplicate JSON object key"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_recovery_required_requires_node_fence_and_live_reservation(self):
        case = {"id": "reboot-never-returns", "execution": "manual-injection", "allowedOutcomes": ["RecoveryRequired"]}
        evidence = self.clean_evidence()
        preflight = evidence["hostPreflightReceipt"]
        checkpoint = {"phase": "RecoveryRequired", "planDigest": evidence["planDigest"],
                      "nodeUid": evidence["node"]["uid"], "receipts": [{"phase": "preflight",
                      "reference": preflight["reference"], "digest": preflight["digest"]}]}
        evidence.update({"qualificationCase": case["id"], "outcome": "RecoveryRequired",
                         "lastOperation": {"phase": "RecoveryRequired", "status": {"upgradeCheckpoint": checkpoint}},
                         "nodeAfter": {"uid": "node-uid", "unschedulable": True},
                         "injection": {"method": "lab power isolation", "startedAt": "2026-11-17T12:02:00Z",
                                       "endedAt": "2026-11-17T12:08:00Z", "evidenceRef": "lab-log-42"}})
        self.add_injection_artifact(evidence)
        self.write_case(case, evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "reservation remains held"):
            verifier.verify_directory(self.matrix, self.evidence_dir)
        evidence["reservationEvidence"] = {"held": True, "reference": "namespace/lease"}
        (self.evidence_dir / f"{case['id']}.json").write_text(json.dumps(evidence))
        self.assertEqual(verifier.verify_directory(self.matrix, self.evidence_dir), [case["id"]])

    def test_manual_case_requires_timed_injection_record(self):
        case = {"id": "reboot-never-returns", "execution": "manual-injection", "allowedOutcomes": ["RecoveryRequired"]}
        evidence = self.clean_evidence()
        preflight = evidence["hostPreflightReceipt"]
        checkpoint = {"phase": "RecoveryRequired", "planDigest": evidence["planDigest"],
                      "nodeUid": evidence["node"]["uid"], "receipts": [{"phase": "preflight",
                      "reference": preflight["reference"], "digest": preflight["digest"]}]}
        evidence.update({"qualificationCase": case["id"], "outcome": "RecoveryRequired",
                         "lastOperation": {"phase": "RecoveryRequired", "status": {"upgradeCheckpoint": checkpoint}},
                         "nodeAfter": {"uid": "node-uid", "unschedulable": True},
                         "reservationEvidence": {"held": True, "reference": "namespace/lease"}})
        self.write_case(case, evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "fault injection record missing"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_manual_case_requires_copied_hash_verified_injection_log(self):
        case = {"id": "reboot-never-returns", "execution": "manual-injection", "allowedOutcomes": ["RecoveryRequired"]}
        evidence = self.clean_evidence()
        preflight = evidence["hostPreflightReceipt"]
        checkpoint = {"phase": "RecoveryRequired", "planDigest": evidence["planDigest"],
                      "nodeUid": evidence["node"]["uid"], "receipts": [{"phase": "preflight",
                      "reference": preflight["reference"], "digest": preflight["digest"]}]}
        evidence.update({"qualificationCase": case["id"], "outcome": "RecoveryRequired",
                         "lastOperation": {"phase": "RecoveryRequired", "status": {"upgradeCheckpoint": checkpoint}},
                         "nodeAfter": {"uid": "node-uid", "unschedulable": True},
                         "reservationEvidence": {"held": True, "reference": "namespace/lease"},
                         "injection": {"method": "lab power isolation", "startedAt": "2026-11-17T12:02:00Z",
                                       "endedAt": "2026-11-17T12:08:00Z", "evidenceRef": "lab-log-42"}})
        self.add_injection_artifact(evidence)
        evidence["injection"].pop("evidenceSHA256")
        self.write_case(case, evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "SHA-256 is missing"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

        evidence["injection"]["evidenceSHA256"] = "0" * 64
        (self.evidence_dir / f"{case['id']}.json").write_text(json.dumps(evidence))
        with self.assertRaisesRegex(verifier.EvidenceError, "SHA-256 mismatch"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_manual_case_rejects_path_traversal_and_symlinks(self):
        case = {"id": "reboot-never-returns", "execution": "manual-injection", "allowedOutcomes": ["RecoveryRequired"]}
        evidence = self.clean_evidence()
        preflight = evidence["hostPreflightReceipt"]
        checkpoint = {"phase": "RecoveryRequired", "planDigest": evidence["planDigest"],
                      "nodeUid": evidence["node"]["uid"], "receipts": [{"phase": "preflight",
                      "reference": preflight["reference"], "digest": preflight["digest"]}]}
        evidence.update({"qualificationCase": case["id"], "outcome": "RecoveryRequired",
                         "lastOperation": {"phase": "RecoveryRequired", "status": {"upgradeCheckpoint": checkpoint}},
                         "nodeAfter": {"uid": "node-uid", "unschedulable": True},
                         "reservationEvidence": {"held": True, "reference": "namespace/lease"},
                         "injection": {"method": "lab power isolation", "startedAt": "2026-11-17T12:02:00Z",
                                       "endedAt": "2026-11-17T12:08:00Z", "evidenceRef": "lab-log-42"}})
        self.add_injection_artifact(evidence)
        evidence["injection"]["evidenceFile"] = "../outside.log"
        self.write_case(case, evidence)
        with self.assertRaisesRegex(verifier.EvidenceError, "safe relative path"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

        evidence["injection"]["evidenceFile"] = "injection-logs/link.log"
        (self.evidence_dir / "injection-logs" / "link.log").symlink_to("lab.log")
        (self.evidence_dir / f"{case['id']}.json").write_text(json.dumps(evidence))
        with self.assertRaisesRegex(verifier.EvidenceError, "symlink"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

        (self.evidence_dir / "linked-logs").symlink_to("injection-logs", target_is_directory=True)
        evidence["injection"]["evidenceFile"] = "linked-logs/lab.log"
        (self.evidence_dir / f"{case['id']}.json").write_text(json.dumps(evidence))
        with self.assertRaisesRegex(verifier.EvidenceError, "symlink"):
            verifier.verify_directory(self.matrix, self.evidence_dir)

    def test_offline_bundle_layout_uses_adjacent_failure_matrix_by_default(self):
        bundle = self.root / "bundle"
        qualification = bundle / "qualification"
        qualification.mkdir(parents=True)
        script = qualification / "verify-host-upgrade-qualification.py"
        script.write_text("# verifier")
        bundled_matrix = qualification / "host_upgrade_failure_matrix.json"
        bundled_matrix.write_text(json.dumps({"schemaVersion": 1, "cases": [self.clean_case()]}))
        evidence = self.clean_evidence()
        (self.evidence_dir / "clean-upgrade.json").write_text(json.dumps(evidence))
        prior_script = verifier.__file__
        try:
            verifier.__file__ = str(script)
            resolved = verifier.default_matrix_path(script)
            self.assertEqual(resolved, bundled_matrix.resolve())
            self.assertEqual(verifier.verify_directory(resolved, self.evidence_dir), ["clean-upgrade"])
        finally:
            verifier.__file__ = prior_script

    def test_cli_matrix_must_match_reviewed_failure_case_digest(self):
        matrix = Path(__file__).with_name("host_upgrade_failure_matrix.json")
        verifier.verify_pinned_matrix(matrix)
        weaker = self.root / "weaker-matrix.json"
        weaker.write_text(json.dumps({"schemaVersion": 1, "cases": [self.clean_case()]}))
        with self.assertRaisesRegex(verifier.EvidenceError, "differs from the reviewed"):
            verifier.verify_pinned_matrix(weaker)

    def test_reviewed_manual_cases_require_specific_fault_observations(self):
        matrix = json.loads(Path(__file__).with_name("host_upgrade_failure_matrix.json").read_text())
        manual_cases = [case for case in matrix["cases"] if case["execution"] == "manual-injection"]
        self.assertTrue(manual_cases)
        for case in manual_cases:
            with self.subTest(case=case["id"]):
                requirement = case.get("faultEvidence")
                self.assertIsInstance(requirement, dict)
                self.assertTrue(requirement.get("faultType"))
                evidence = self.clean_evidence()
                observations = {
                    "phase": requirement["phase"],
                    "oldPodUID": "pod-before", "newPodUID": "pod-after",
                    "blockedObserved": True, "restoredObserved": True,
                    "changedPackageNames": ["curl"], "exitCode": 1,
                    "rebootIntentObserved": True, "unavailableDurationSeconds": 180,
                    "expectedMachineId": "machine-before", "observedMachineId": "machine-after",
                    "originalNodeUID": "node-uid", "replacementNodeUID": "node-replaced",
                    "expectedKernel": "6.8.0-40-generic", "observedKernel": "6.8.0-41-generic",
                }
                evidence["upgradePlan"]["expectedKernelVersion"] = "6.8.0-40-generic"
                evidence["nodeAfter"]["uid"] = "node-replaced"
                phases = ["Pending"]
                if requirement["phase"] != "Pending":
                    phases.append(requirement["phase"])
                if phases[-1] != "RecoveryRequired":
                    phases.append("RecoveryRequired")
                events = [{"sequence": index, "phase": phase, "reason": phase,
                           "time": f"2026-11-17T12:0{index}:00Z"}
                          for index, phase in enumerate(phases, start=1)]
                evidence["lastOperation"] = {
                    "phase": "RecoveryRequired", "sequence": len(events),
                    "status": {"phase": "RecoveryRequired", "sequence": len(events),
                               "events": events},
                }
                injection = {"faultType": requirement["faultType"], "observations": observations}
                verifier.verify_fault_observations(requirement, injection, evidence, case["id"])
                with self.assertRaisesRegex(verifier.EvidenceError, "specific injected fault type"):
                    verifier.verify_fault_observations(
                        requirement, {"faultType": "generic-failure", "observations": observations},
                        evidence, case["id"])
                missing_phase = json.loads(json.dumps(evidence))
                remaining_events = [event for event in events if event["phase"] != requirement["phase"]]
                for sequence, event in enumerate(remaining_events, start=1):
                    event["sequence"] = sequence
                missing_phase["lastOperation"]["status"]["events"] = remaining_events
                missing_phase["lastOperation"]["status"]["sequence"] = len(
                    missing_phase["lastOperation"]["status"]["events"])
                with self.assertRaisesRegex(verifier.EvidenceError, "does not prove the expected"):
                    verifier.verify_fault_observations(requirement, injection, missing_phase, case["id"])


if __name__ == "__main__":
    unittest.main()
