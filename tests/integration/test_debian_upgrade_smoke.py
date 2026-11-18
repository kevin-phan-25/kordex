import unittest

import self_managed_upgrade_smoke as drill


class SelfManagedUpgradeDrillTests(unittest.TestCase):
    def test_execution_requires_exact_cluster_node_uid_confirmation(self):
        target = "cluster-id/worker-01/worker-uid"
        drill.validate_execution_confirmation(target, target)
        for confirmation in ("", "cluster-id/worker-01", target + "/extra"):
            with self.subTest(confirmation=confirmation), self.assertRaises(drill.DrillError):
                drill.validate_execution_confirmation(target, confirmation)

    def test_target_must_be_ready_supported_os_family_and_schedulable(self):
        node = {
            "metadata": {"name": "worker-01", "uid": "uid-1", "labels": {"kubernetes.io/os": "linux"}},
            "spec": {},
            "status": {"conditions": [{"type": "Ready", "status": "True"}],
                       "nodeInfo": {"osImage": "Ubuntu 24.04.1 LTS", "kernelVersion": "6.8.0-40-generic"}},
        }
        self.assertEqual(drill.check_node(node)["uid"], "uid-1")
        self.assertEqual(drill.check_node(node)["osFamily"], "debian")
        self.assertIs(drill.check_node(node)["ready"], True)
        for image in ("Red Hat Enterprise Linux 9.4", "Rocky Linux 9.4", "AlmaLinux 9.4", "Oracle Linux 9.4"):
            rhel_node = {**node, "status": {**node["status"], "nodeInfo": {"osImage": image}}}
            self.assertEqual(drill.check_node(rhel_node)["osFamily"], "rhel")
        bad_os = {**node, "status": {**node["status"], "nodeInfo": {"osImage": "Container-Optimized OS"}}}
        with self.assertRaisesRegex(drill.DrillError, "unsupported host OS image"):
            drill.check_node(bad_os)
        cordoned = {**node, "spec": {"unschedulable": True}}
        with self.assertRaisesRegex(drill.DrillError, "Ready and schedulable"):
            drill.check_node(cordoned)

    def test_malformed_node_fields_fail_closed_with_drill_error(self):
        for node in (
            None,
            {"metadata": [], "spec": {}, "status": {}},
            {"metadata": {}, "spec": {}, "status": {"conditions": {}}},
            {"metadata": {}, "spec": {"unschedulable": "false"}, "status": {}},
            {"metadata": {}, "spec": {}, "status": {"nodeInfo": []}},
        ):
            with self.subTest(node=node), self.assertRaises(drill.DrillError):
                drill.check_node(node)

    def test_node_family_must_match_selected_fixed_catalog(self):
        rhel_node = {
            "metadata": {"name": "worker-01", "uid": "uid-1"}, "spec": {},
            "status": {"conditions": [{"type": "Ready", "status": "True"}],
                       "nodeInfo": {"osImage": "Rocky Linux 9.4"}},
        }
        self.assertEqual(drill.check_node(rhel_node, expected_os_family="rhel")["osFamily"], "rhel")
        with self.assertRaisesRegex(drill.DrillError, "does not match policy family"):
            drill.check_node(rhel_node, expected_os_family="debian")
        coreos = {**rhel_node, "status": {**rhel_node["status"], "nodeInfo": {"osImage": "Red Hat Enterprise Linux CoreOS"}}}
        with self.assertRaisesRegex(drill.DrillError, "immutable node OS"):
            drill.check_node(coreos)

    def test_policy_catalog_must_match_supported_os_family(self):
        entry = {"suspended": False, "upgradePlanInvalid": False, "upgradePlanDigest": "a" * 64,
                 "upgrade": {"osFamily": "rhel", "executionBackend": "ansible-ee",
                             "actionMarkerVersion": 1,
                             "playbookCatalogId": "kordex.os-upgrade.rhel.v1", "packages": [{"name": "bash", "version": "5.1-6.el9"}]}}
        self.assertEqual(drill.validate_policy_entry(entry, "a" * 64), entry)
        bad = {**entry, "upgrade": {**entry["upgrade"], "playbookCatalogId": "kordex.os-upgrade.debian.v2"}}
        with self.assertRaisesRegex(drill.DrillError, "supported fixed Debian/RHEL"):
            drill.validate_policy_entry(bad, "a" * 64)
        malformed = {**entry, "upgrade": {**entry["upgrade"], "osFamily": ["rhel"]}}
        with self.assertRaisesRegex(drill.DrillError, "supported fixed Debian/RHEL"):
            drill.validate_policy_entry(malformed, "a" * 64)
        markerless = {**entry, "upgrade": {key: value for key, value in entry["upgrade"].items() if key != "actionMarkerVersion"}}
        with self.assertRaisesRegex(drill.DrillError, "actionMarkerVersion 1"):
            drill.validate_policy_entry(markerless, "a" * 64)
        duplicated = {**entry, "upgrade": {**entry["upgrade"], "packages": [
            {"name": "bash", "version": "5.1-6.el9"}, {"name": "bash", "version": "5.2-1.el9"},
        ]}}
        with self.assertRaisesRegex(drill.DrillError, "duplicate package"):
            drill.validate_policy_entry(duplicated, "a" * 64)

    def test_success_requires_operator_checkpoint_and_apply_receipt(self):
        preflight = {"phase": "preflight", "machineId": "a" * 32,
                     "bootIdBefore": "11111111-1111-4111-8111-111111111111",
                     "bootIdAfter": "11111111-1111-4111-8111-111111111111"}
        operation = {"id": "7f2d6808-5f3b-462a-bc18-06e1a00c7a55", "status": {"upgradeCheckpoint": {
            "phase": "Succeeded", "planDigest": "a" * 64, "nodeUid": "uid-1",
            "receipts": [preflight, {"phase": "apply", "packages": {"curl": "8.5.0-1"}, "rebootRequired": False,
                                     "kernelVersion": "6.8.0-40-generic", "machineId": preflight["machineId"],
                                     "bootIdBefore": preflight["bootIdAfter"], "bootIdAfter": preflight["bootIdAfter"],
                                     "actionMarker": {"version": 1, "operationId": "7f2d6808-5f3b-462a-bc18-06e1a00c7a55",
                                         "actionDigest": "a" * 64, "nodeUid": "uid-1", "machineId": "a" * 32,
                                         "bootId": preflight["bootIdAfter"], "phase": "packages-verified", "sequence": 2,
                                         "sha256": "c" * 64}}],
        }}}
        plan = {"packages": [{"name": "curl", "version": "8.5.0-1"}], "expectedKernelVersion": "6.8.0-40-generic"}
        self.assertEqual(drill.verify_completed_operation(operation, "a" * 64, "uid-1", plan)["phase"], "Succeeded")
        for invalid in (
            {"status": {"upgradeCheckpoint": {"phase": "Succeeded", "planDigest": "b" * 64, "nodeUid": "uid-1", "receipts": operation["status"]["upgradeCheckpoint"]["receipts"]}}},
            {"status": {"upgradeCheckpoint": {"phase": "Succeeded", "planDigest": "a" * 64, "nodeUid": "uid-2", "receipts": operation["status"]["upgradeCheckpoint"]["receipts"]}}},
            {"status": {"upgradeCheckpoint": {"phase": "Succeeded", "planDigest": "a" * 64, "nodeUid": "uid-1", "receipts": []}}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(drill.DrillError):
                drill.verify_completed_operation(invalid, "a" * 64, "uid-1", plan)

    def test_success_requires_receipt_proving_exact_packages_and_reboot(self):
        base = {"phase": "Succeeded", "planDigest": "a" * 64, "nodeUid": "uid-1"}
        preflight = {"phase": "preflight", "machineId": "a" * 32,
                     "bootIdBefore": "11111111-1111-4111-8111-111111111111",
                     "bootIdAfter": "11111111-1111-4111-8111-111111111111"}
        plan = {"packages": [{"name": "linux-image-generic", "version": "6.8.0-40"}],
                "expectedKernelVersion": "6.8.0-40-generic"}
        wrong_packages = {"id": "7f2d6808-5f3b-462a-bc18-06e1a00c7a55", "status": {"upgradeCheckpoint": {**base, "receipts": [preflight, {"phase": "apply", "packages": {}, "rebootRequired": False}]}}}
        with self.assertRaisesRegex(drill.DrillError, "exact package pin"):
            drill.verify_completed_operation(wrong_packages, "a" * 64, "uid-1", plan)
        operation_id = "7f2d6808-5f3b-462a-bc18-06e1a00c7a55"
        boot_id = preflight["bootIdAfter"]
        apply = {"phase": "apply", "packages": {"linux-image-generic": "6.8.0-40"}, "rebootRequired": True,
                 "machineId": preflight["machineId"], "bootIdBefore": boot_id, "bootIdAfter": boot_id,
                 "actionMarker": {"version": 1, "operationId": operation_id,
                 "actionDigest": "a" * 64, "nodeUid": "uid-1", "machineId": "a" * 32,
                 "bootId": boot_id, "phase": "packages-verified", "sequence": 2, "sha256": "c" * 64}}
        missing_reboot = {"id": operation_id, "status": {"upgradeCheckpoint": {**base, "receipts": [preflight, apply]}}}
        with self.assertRaisesRegex(drill.DrillError, "no verified reboot receipt"):
            drill.verify_completed_operation(missing_reboot, "a" * 64, "uid-1", plan)

    def test_success_requires_exact_action_marker(self):
        operation_id = "7f2d6808-5f3b-462a-bc18-06e1a00c7a55"
        operation = {"id": operation_id, "status": {"upgradeCheckpoint": {
            "phase": "Succeeded", "planDigest": "a" * 64, "nodeUid": "uid-1",
            "receipts": [
                {"phase": "preflight", "machineId": "a" * 32,
                 "bootIdBefore": "11111111-1111-4111-8111-111111111111",
                 "bootIdAfter": "11111111-1111-4111-8111-111111111111"},
                {"phase": "apply", "packages": {"curl": "8.5.0-1"}, "rebootRequired": False,
                 "machineId": "a" * 32, "bootIdBefore": "11111111-1111-4111-8111-111111111111",
                 "bootIdAfter": "11111111-1111-4111-8111-111111111111"},
            ],
        }}}
        with self.assertRaisesRegex(drill.DrillError, "packages-verified action marker"):
            drill.verify_completed_operation(operation, "a" * 64, "uid-1", {"packages": [{"name": "curl", "version": "8.5.0-1"}]})

    def test_malformed_checkpoint_receipts_and_package_pins_fail_closed(self):
        base = {"id": "7f2d6808-5f3b-462a-bc18-06e1a00c7a55", "status": {"upgradeCheckpoint": {
            "phase": "Succeeded", "planDigest": "a" * 64, "nodeUid": "uid-1",
            "receipts": ["not-an-object"],
        }}}
        with self.assertRaisesRegex(drill.DrillError, "receipt history is malformed"):
            drill.verify_completed_operation(base, "a" * 64, "uid-1", {"packages": [{"name": "curl", "version": "8.5.0-1"}]})

        base["status"]["upgradeCheckpoint"]["receipts"] = []
        for packages in (None, ["curl=8.5.0-1"], [{"name": "curl", "version": "8.5.0-1"}, {"name": "curl", "version": "8.5.0-2"}]):
            with self.subTest(packages=packages), self.assertRaises(drill.DrillError):
                drill.verify_completed_operation(base, "a" * 64, "uid-1", {"packages": packages})

    def test_evidence_redacts_signed_command_material(self):
        operation = {"id": "op", "command": {"authorization": "permit"}, "signature": "secret",
                     "status": {"phase": "Succeeded"}}
        self.assertEqual(drill.redacted_operation(operation), {"id": "op", "status": {"phase": "Succeeded"}})

    def test_cancelled_operation_must_recover_or_remain_fenced(self):
        recovered = {"phase": "Cancelled", "status": {"upgradeCheckpoint": {"phase": "Cancelled"}}}
        self.assertEqual(drill.verify_cancellation_fence(
            recovered, {"uid": "uid-1", "ready": True, "unschedulable": False}, "uid-1"), "CancellationRecovered")
        fenced = {"phase": "RecoveryRequired", "status": {"upgradeCheckpoint": {"phase": "RecoveryRequired"}}}
        self.assertEqual(drill.verify_cancellation_fence(
            fenced, {"uid": "uid-1", "unschedulable": True}, "uid-1"), "CancellationFenced")
        for operation, node in (
            (recovered, {"uid": "uid-2", "ready": True, "unschedulable": False}),
            (recovered, {"uid": "uid-1", "ready": True, "unschedulable": True}),
            (recovered, {"uid": "uid-1", "ready": False, "unschedulable": False}),
            (fenced, {"uid": "uid-1", "unschedulable": False}),
        ):
            with self.subTest(operation=operation, node=node), self.assertRaises(drill.DrillError):
                drill.verify_cancellation_fence(operation, node, "uid-1")


if __name__ == "__main__":
    unittest.main()
