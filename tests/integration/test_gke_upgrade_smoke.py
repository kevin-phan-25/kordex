import unittest
from unittest.mock import patch

import gke_upgrade_smoke as drill


class GKEUpgradeDrillTests(unittest.TestCase):
    def test_version_parser_requires_explicit_pinned_gke_version(self):
        self.assertEqual(drill.version_tuple("v1.36.4-gke.2377000"), (1, 36, 4, 2377000))
        for value in ("1.36", "latest", "1.36.4", "1.36.4-gke.latest"):
            with self.subTest(value=value), self.assertRaises(drill.DrillError):
                drill.version_tuple(value)

    @patch.object(drill, "run_json")
    def test_live_pool_requires_exact_safe_settings_and_higher_patch(self, run_json):
        run_json.return_value = {
            "version": "1.36.4-gke.100",
            "status": "RUNNING",
            "etag": "etag-1",
            "config": {"imageType": "COS_CONTAINERD"},
            "upgradeSettings": {"strategy": "SURGE", "maxSurge": 1, "maxUnavailable": 0},
        }
        pool = drill.check_live_pool("gcloud", "project", "us-central1-a", "cluster", "pool", "1.36.5-gke.100")
        self.assertEqual(pool["version"], "1.36.4-gke.100")

        with self.assertRaisesRegex(drill.DrillError, "higher explicit patch"):
            drill.check_live_pool("gcloud", "project", "us-central1-a", "cluster", "pool", "1.36.4-gke.100")

        run_json.return_value["upgradeSettings"]["maxUnavailable"] = 1
        with self.assertRaisesRegex(drill.DrillError, "maxSurge=1"):
            drill.check_live_pool("gcloud", "project", "us-central1-a", "cluster", "pool", "1.36.5-gke.100")

    def test_evidence_never_contains_signed_command_material(self):
        operation = {"id": "op", "command": {"authorization": "permit"}, "signature": "sig", "status": {"phase": "Succeeded"}}
        self.assertEqual(drill.redacted_operation(operation), {"id": "op", "status": {"phase": "Succeeded"}})

    def test_execution_requires_exact_canonical_pool_confirmation(self):
        resource = "projects/project/locations/us-central1-a/clusters/cluster/nodePools/workers"
        drill.validate_execution_confirmation(resource, resource)
        for confirmation in ("", "workers", resource + "/"):
            with self.subTest(confirmation=confirmation), self.assertRaises(drill.DrillError):
                drill.validate_execution_confirmation(resource, confirmation)

    def test_replacement_verification_requires_full_new_pool_at_target_version(self):
        before = [
            {"metadata": {"uid": "old-1"}},
            {"metadata": {"uid": "old-2"}},
        ]
        after = [
            {"metadata": {"uid": "new-1"}, "status": {"nodeInfo": {"kubeletVersion": "v1.36.5-gke.100"}}},
            {"metadata": {"uid": "new-2"}, "status": {"nodeInfo": {"kubeletVersion": "v1.36.5-gke.100"}}},
        ]
        self.assertEqual(drill.verify_replacement_nodes(before, after, "1.36.5-gke.100"), ["new-1", "new-2"])
        with self.assertRaisesRegex(drill.DrillError, "pre-upgrade size"):
            drill.verify_replacement_nodes(before, after[:1], "1.36.5-gke.100")
        stale = [dict(node) for node in after]
        stale[1] = {**stale[1], "status": {"nodeInfo": {"kubeletVersion": "v1.36.4-gke.100"}}}
        with self.assertRaisesRegex(drill.DrillError, "pinned target"):
            drill.verify_replacement_nodes(before, stale, "1.36.5-gke.100")
        overlap = [dict(node) for node in after]
        overlap[0] = {**overlap[0], "metadata": {"uid": "old-1"}}
        with self.assertRaisesRegex(drill.DrillError, "original node identities"):
            drill.verify_replacement_nodes(before, overlap, "1.36.5-gke.100")

    def test_inventory_pagination_reads_all_pages(self):
        class FakeHub:
            def __init__(self):
                self.offsets = []

            def request(self, method, path):
                self.assert_method = method
                offset = int(path.rsplit("offset=", 1)[1])
                self.offsets.append(offset)
                items = [{"id": f"item-{index}"} for index in range(offset, offset + drill.PAGE_SIZE)]
                if offset == drill.PAGE_SIZE:
                    items = [{"id": "last"}]
                return {"items": items, "limit": drill.PAGE_SIZE, "offset": offset}

        hub = FakeHub()
        items = drill.list_all(hub, "/inventory")
        self.assertEqual(hub.offsets, [0, drill.PAGE_SIZE])
        self.assertEqual(len(items), drill.PAGE_SIZE + 1)
        self.assertEqual(items[-1]["id"], "last")

    def test_inventory_pagination_rejects_bad_metadata_and_truncation(self):
        class FakeHub:
            def __init__(self, page):
                self.page = page

            def request(self, method, path):
                return self.page

        with self.assertRaisesRegex(drill.DrillError, "invalid paginated inventory"):
            drill.list_all(FakeHub({"items": [], "limit": 100, "offset": 0}), "/inventory")

        class FullPages:
            def request(self, method, path):
                offset = int(path.rsplit("offset=", 1)[1])
                return {"items": [{}] * drill.PAGE_SIZE, "limit": drill.PAGE_SIZE, "offset": offset}

        with self.assertRaisesRegex(drill.DrillError, "pagination safety limit"):
            drill.list_all(FullPages(), "/inventory")


if __name__ == "__main__":
    unittest.main()
