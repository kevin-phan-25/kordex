"""Contract tests for the fixed Ansible EE request parser."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import upgrade


def request(phase: str, reboot_authorized: bool = False) -> dict:
    payload = {
        "operationId": "2e15e264-6bc4-4574-8e13-11a135b90e58",
        "phase": phase,
        "rebootAuthorized": reboot_authorized,
        "node": {
            "name": "worker-01",
            "uid": "00c85ae4-f827-42c8-b43b-b1b0085b1781",
            "address": "10.0.0.10",
            "machineId": "d" * 32,
            "bootId": "33333333-3333-4333-8333-333333333333",
        },
        "policy": {
            "schemaVersion": 1,
            "id": "debian-test",
            "osFamily": "debian",
            "executionBackend": "ansible-ee",
            "playbookCatalogId": "kordex.os-upgrade.debian.v2",
            "executionEnvironment": "registry.example/kordex/ee@sha256:" + "a" * 64,
            "playbookDigest": "b" * 64,
            "collectionsDigest": "c" * 64,
            "channel": "stable",
            "reboot": "IfNeeded",
            "expectedKernelVersion": "6.1.0-1-generic",
            "preHooks": [],
            "postHooks": [],
            "packages": [{"name": "linux-image-generic", "version": "6.1.0-1"}],
            "executionTimeout": 60_000_000_000,
            "rebootTimeout": 60_000_000_000,
            "verificationTimeout": 60_000_000_000,
            "maxAttempts": 1,
        },
    }
    payload["planDigest"] = upgrade.upgrade_policy_digest(payload["policy"])
    return payload


class RequestContractTest(unittest.TestCase):
    def parse(self, payload: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return upgrade.read_request(path)

    def assert_rejected(self, payload: dict) -> None:
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(payload)

    def test_preflight_and_apply_do_not_need_reboot_authorization(self) -> None:
        preflight = request("preflight")
        preflight["node"].pop("machineId")
        preflight["node"].pop("bootId")
        self.assertEqual(self.parse(preflight)["phase"], "preflight")
        self.assertEqual(self.parse(request("apply"))["phase"], "apply")

    def test_reboot_requires_explicit_durable_authorization(self) -> None:
        self.assertEqual(self.parse(request("reboot", reboot_authorized=True))["phase"], "reboot")
        self.assert_rejected(request("reboot"))

    def test_reboot_authorization_cannot_be_attached_to_apply(self) -> None:
        self.assert_rejected(request("apply", reboot_authorized=True))

    def test_read_only_inspection_requires_identity_but_not_reboot_authorization(self) -> None:
        self.assertEqual(self.parse(request("inspect"))["phase"], "inspect")
        self.assert_rejected(request("inspect", reboot_authorized=True))
        payload = request("inspect")
        payload["node"].pop("machineId")
        self.assert_rejected(payload)

    def test_reboot_never_policy_cannot_start_reboot_phase(self) -> None:
        payload = request("reboot", reboot_authorized=True)
        payload["policy"]["reboot"] = "Never"
        self.assert_rejected(payload)

    def test_package_names_must_be_canonical_lowercase(self) -> None:
        payload = request("apply")
        payload["node"]["machineId"] = "d" * 32
        payload["policy"]["packages"][0]["name"] = "Linux-image-generic"
        payload["planDigest"] = upgrade.upgrade_policy_digest(payload["policy"])
        self.assert_rejected(payload)

    def test_tampered_policy_is_rejected_even_when_digest_is_well_formed(self) -> None:
        payload = request("apply")
        payload["policy"]["packages"][0]["version"] = "6.1.0-2"
        self.assert_rejected(payload)


class CatalogContractTest(unittest.TestCase):
    def test_catalog_pins_base_playbook_collections_and_ansible_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            playbook = root / "upgrade.yml"
            lock = root / "collections.lock"
            catalog_path = root / "catalog.json"
            playbook.write_text("fixed playbook", encoding="utf-8")
            lock.write_text("builtin only", encoding="utf-8")
            policy = request("inspect")["policy"]
            policy["playbookDigest"] = hashlib.sha256(playbook.read_bytes()).hexdigest()
            policy["collectionsDigest"] = hashlib.sha256(lock.read_bytes()).hexdigest()
            catalog_path.write_text(json.dumps({
                "catalogId": policy["playbookCatalogId"],
                "playbookDigest": policy["playbookDigest"],
                "collectionsDigest": policy["collectionsDigest"],
                "baseImage": "registry.example/ansible-ee@sha256:" + "d" * 64,
                "ansibleVersion": "ansible-playbook [core 2.17.3]",
            }), encoding="utf-8")
            version = "ansible-playbook [core 2.17.3]\n  config file = None\n"
            with patch.object(upgrade, "CATALOG_PATH", catalog_path), \
                 patch.object(upgrade, "PLAYBOOK_PATH", playbook), \
                 patch.object(upgrade, "COLLECTIONS_LOCK_PATH", lock), \
                 patch("subprocess.run", return_value=type("Completed", (), {"stdout": version})()):
                upgrade.validate_catalog(policy)
                catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
                catalog["ansibleVersion"] = "ansible-playbook [core 2.17.4]"
                catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    upgrade.validate_catalog(policy)
                catalog["ansibleVersion"] = "ansible-playbook [core 2.17.3]"
                catalog["baseImage"] = "registry.example/ansible-ee:mutable"
                catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    upgrade.validate_catalog(policy)


if __name__ == "__main__":
    unittest.main()
