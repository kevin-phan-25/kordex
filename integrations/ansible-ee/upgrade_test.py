"""Contract tests for the fixed Ansible EE request parser."""

import contextlib
import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import upgrade
import yaml


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
            "actionMarkerVersion": 1,
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
    def test_debian_baseline_tasks_render_installed_absent_and_query_failure(self) -> None:
        ansible = shutil.which("ansible-playbook")
        if not ansible:
            self.skipTest("ansible-playbook is required for the local baseline task check")
        tasks = yaml.safe_load(Path(__file__).with_name("upgrade-debian.yml").read_text())[0]["tasks"]
        baseline_tasks = [task for task in tasks if task.get("name") in {
            "Read installed Debian package versions before mutation", "Record installed Debian package baseline"}]
        for broken in (False, True):
            with self.subTest(query_failure=broken), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                query = root / "dpkg-query"
                query.write_text(f"#!{sys.executable}\n" +
                                 "import sys\n" +
                                 "assert sys.argv[2] == '--showformat=${db:Status-Status} ${Version}'\n" +
                                 "name = sys.argv[-1]\n" +
                                 "if name == 'broken': sys.exit(2)\n" +
                                 "if name == 'absent': sys.exit(1)\n" +
                                 "print('installed 8.4.0-1')\n")
                query.chmod(0o700)
                packages = [{"name": name, "version": "8.5.0-1"} for name in
                            (["curl", "absent", "broken"] if broken else ["curl", "absent"])]
                play = [{"name": "Local baseline contract", "hosts": "localhost", "connection": "local",
                         "gather_facts": False, "vars": {"ansible_python_interpreter": sys.executable,
                         "kordex_request": {"phase": "preflight"}, "kordex_policy": {"packages": packages}},
                         "tasks": baseline_tasks + [{"ansible.builtin.assert": {"that": [
                             "kordex_baseline_packages == {'curl': '8.4.0-1', 'absent': ''}"]}}]}]
                path = root / "baseline.json"
                path.write_text(json.dumps(play))
                config = root / "ansible.cfg"
                config.write_text("[defaults]\nretry_files_enabled=False\n")
                env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                       "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                       "ANSIBLE_REMOTE_TEMP": str(root / "remote"), "Version": "must-not-expand"}
                result = subprocess.run([ansible, "-i", "localhost,", str(path)], cwd=root, env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, not broken, result.stdout)

    def test_debian_baseline_is_read_only_and_precedes_preflight_exit(self) -> None:
        tasks = yaml.safe_load(Path(__file__).with_name("upgrade-debian.yml").read_text())[0]["tasks"]
        baseline = next(task for task in tasks if task.get("name") == "Read installed Debian package versions before mutation")
        self.assertFalse(baseline["changed_when"])
        self.assertEqual(baseline["when"], "kordex_request.phase == 'preflight'")
        self.assertEqual(baseline["ansible.builtin.command"]["argv"][0], "dpkg-query")
        self.assertFalse(baseline["ansible.builtin.command"]["expand_argument_vars"])
        end = next(i for i, task in enumerate(tasks) if task.get("name") == "End after read-only host preflight")
        self.assertLess(tasks.index(baseline), end)
        receipt = next(task for task in tasks if task.get("name") == "Prepare the read-only preflight receipt")
        self.assertIn("baselinePackages", receipt["ansible.builtin.set_fact"]["kordex_receipt"])
        marker_check = next(task for task in tasks if task.get("name") == "Require verified apply marker before reboot phase")
        self.assertIn("fail_msg", marker_check["ansible.builtin.assert"])
        self.assertNotIn("fail_msg", marker_check)

    def parse(self, payload: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return upgrade.read_request(path)

    def assert_rejected(self, payload: dict) -> None:
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(payload)

    def test_preflight_ends_before_any_package_mutation_or_installed_version_check(self) -> None:
        playbooks = {
            "upgrade-debian.yml": {
                "Install exact requested package versions",
                "Install only hash-verified local Debian artifacts without repository downloads",
                "Confirm each pinned package version is installed",
            },
            "upgrade-rhel.yml": {
                "Install exact requested package versions",
                "Install only hash-verified local RPM artifacts without repository access",
                "Confirm each pinned RPM EVR is installed exactly",
            },
        }
        for filename, forbidden_tasks in playbooks.items():
            with self.subTest(playbook=filename):
                plays = yaml.safe_load((Path(__file__).with_name(filename)).read_text(encoding="utf-8"))
                self.assertEqual(len(plays), 1)
                tasks = plays[0]["tasks"]
                end_preflight = next(
                    index for index, task in enumerate(tasks)
                    if task.get("name") == "End after read-only host preflight"
                )
                self.assertEqual(tasks[end_preflight]["when"], "kordex_request.phase == 'preflight'")
                for task_name in forbidden_tasks:
                    task_index = next(index for index, task in enumerate(tasks) if task.get("name") == task_name)
                    self.assertGreater(task_index, end_preflight, f"{filename}: {task_name} moved before the preflight exit")

    def test_preflight_and_apply_do_not_need_reboot_authorization(self) -> None:
        preflight = request("preflight")
        preflight["node"].pop("machineId")
        preflight["node"].pop("bootId")
        self.assertEqual(self.parse(preflight)["phase"], "preflight")
        self.assertEqual(self.parse(request("apply"))["phase"], "apply")

    def test_offline_artifact_policy_requires_and_binds_every_sha256(self) -> None:
        payload = request("preflight")
        policy = payload["policy"]
        policy["schemaVersion"] = 2
        policy["artifactMode"] = "OfflineArtifacts"
        policy["packages"][0]["artifactSHA256"] = "d" * 64
        payload["planDigest"] = upgrade.upgrade_policy_digest(policy)
        self.assertEqual(self.parse(payload)["policy"]["artifactMode"], "OfflineArtifacts")

        missing = json.loads(json.dumps(payload))
        del missing["policy"]["packages"][0]["artifactSHA256"]
        self.assert_rejected(missing)

        wrong_mode = json.loads(json.dumps(payload))
        wrong_mode["policy"]["artifactMode"] = "Repository"
        self.assert_rejected(wrong_mode)

    def test_offline_artifact_digest_matches_go_protocol_canonicalization(self) -> None:
        policy = request("apply")["policy"]
        policy.update({
            "schemaVersion": 2,
            "id": "offline-test",
            "reboot": "Never",
            "artifactMode": "OfflineArtifacts",
            "packages": [{"name": "openssh-server", "version": "1.2.3-1", "artifactSHA256": "d" * 64}],
        })
        policy.pop("expectedKernelVersion")
        self.assertEqual(
            upgrade.upgrade_policy_digest(policy),
            "d9cf85142d1c7c1e41369a175068ac164aaebcb52ae3f2b2b0ccc72942f334b1",
        )

    def test_repository_policy_rejects_artifact_digests(self) -> None:
        payload = request("apply")
        payload["policy"]["packages"][0]["artifactSHA256"] = "d" * 64
        self.assert_rejected(payload)

    def test_policy_schema_version_rejects_boolean(self) -> None:
        payload = request("preflight")
        payload["policy"]["schemaVersion"] = True
        self.assert_rejected(payload)

    def test_rhel_catalog_accepts_rpm_evr_and_kernel_pins(self) -> None:
        payload = request("apply")
        policy = payload["policy"]
        policy.update({
            "id": "rhel-stable",
            "osFamily": "rhel",
            "playbookCatalogId": "kordex.os-upgrade.rhel.v1",
            "expectedKernelVersion": "5.14.0-427.13.1.el9_4.x86_64",
            "packages": [
                {"name": "kernel-core", "version": "5.14.0-427.13.1.el9_4"},
                {"name": "internal_lib", "version": "1.2.3-4.el9_4"},
            ],
        })
        payload["planDigest"] = upgrade.upgrade_policy_digest(policy)
        parsed = self.parse(payload)
        self.assertEqual(parsed["policy"]["osFamily"], "rhel")

    def test_rhel_package_pins_require_complete_evr(self) -> None:
        payload = request("apply")
        policy = payload["policy"]
        policy.update({
            "id": "rhel-stable",
            "osFamily": "rhel",
            "playbookCatalogId": "kordex.os-upgrade.rhel.v1",
            "packages": [{"name": "openssl-libs", "version": "3.0.7-27.el9_4"}],
        })
        policy.pop("expectedKernelVersion")
        payload["planDigest"] = upgrade.upgrade_policy_digest(policy)
        self.assertEqual(self.parse(payload)["policy"]["packages"][0]["version"], "3.0.7-27.el9_4")

        for version in ("3.0.7", "1:3.0.7", "3.0.7-"):
            with self.subTest(version=version):
                payload = request("apply")
                policy = payload["policy"]
                policy.update({
                    "id": "rhel-stable",
                    "osFamily": "rhel",
                    "playbookCatalogId": "kordex.os-upgrade.rhel.v1",
                    "packages": [{"name": "openssl-libs", "version": version}],
                })
                policy.pop("expectedKernelVersion")
                payload["planDigest"] = upgrade.upgrade_policy_digest(policy)
                self.assert_rejected(payload)

    def test_catalog_family_mismatch_is_rejected(self) -> None:
        payload = request("apply")
        payload["policy"]["osFamily"] = "rhel"
        payload["planDigest"] = upgrade.upgrade_policy_digest(payload["policy"])
        self.assert_rejected(payload)

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

    def test_node_name_must_be_safe_for_ssh_host_key_alias(self) -> None:
        payload = request("preflight")
        payload["node"]["name"] = "worker-01\nansible_host=192.0.2.1"
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

    def test_kernel_metapackages_require_expected_kernel_evidence(self) -> None:
        for package_name in ("linux-generic", "linux-headers-generic", "linux-tools-generic", "linux-signed-amd64", "linux-image-amd64:amd64"):
            payload = request("apply")
            payload["policy"]["packages"][0]["name"] = package_name
            payload["policy"].pop("expectedKernelVersion")
            payload["planDigest"] = upgrade.upgrade_policy_digest(payload["policy"])
            self.assert_rejected(payload)

    def test_invalid_debian_package_character_is_rejected(self) -> None:
        payload = request("apply")
        payload["policy"]["packages"][0]["name"] = "linux_image_generic"
        payload["planDigest"] = upgrade.upgrade_policy_digest(payload["policy"])
        self.assert_rejected(payload)

    def test_invalid_debian_version_character_is_rejected(self) -> None:
        payload = request("apply")
        payload["policy"]["packages"][0]["version"] = "6.1.0^vendor1"
        payload["planDigest"] = upgrade.upgrade_policy_digest(payload["policy"])
        self.assert_rejected(payload)

    def test_debian_epoch_version_is_accepted(self) -> None:
        payload = request("apply")
        payload["policy"]["packages"][0]["name"] = "libc6:amd64"
        payload["policy"]["packages"][0]["version"] = "2:2.36-9"
        payload["policy"].pop("expectedKernelVersion")
        payload["planDigest"] = upgrade.upgrade_policy_digest(payload["policy"])
        self.assertEqual(self.parse(payload)["policy"]["packages"][0]["version"], "2:2.36-9")

    def test_tampered_policy_is_rejected_even_when_digest_is_well_formed(self) -> None:
        payload = request("apply")
        payload["policy"]["packages"][0]["version"] = "6.1.0-2"
        self.assert_rejected(payload)

    def test_marker_version_is_bound_to_signed_plan_digest(self) -> None:
        marked = request("apply")
        self.assertEqual(self.parse(marked)["policy"]["actionMarkerVersion"], 1)

    def test_markerless_upgrade_policy_is_rejected(self) -> None:
        payload = request("apply")
        payload["policy"].pop("actionMarkerVersion")
        self.assert_rejected(payload)

    def test_unknown_marker_version_is_rejected(self) -> None:
        payload = request("apply")
        payload["policy"]["actionMarkerVersion"] = 2
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
                "actionMarkerVersion": policy.get("actionMarkerVersion", 0),
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
                marked_policy = dict(policy, actionMarkerVersion=1)
                catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
                catalog["actionMarkerVersion"] = 1
                catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
                upgrade.validate_catalog(marked_policy)
                catalog["actionMarkerVersion"] = 0
                catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    upgrade.validate_catalog(marked_policy)
                catalog["ansibleVersion"] = "ansible-playbook [core 2.17.4]"
                catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    upgrade.validate_catalog(policy)
                catalog["ansibleVersion"] = "ansible-playbook [core 2.17.3]"
                catalog["baseImage"] = "registry.example/ansible-ee:mutable"
                catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    upgrade.validate_catalog(policy)

    def test_versioned_catalog_selects_rhel_fixed_playbook(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            debian = root / "debian.yml"
            rhel = root / "rhel.yml"
            lock = root / "collections.lock"
            catalog_path = root / "catalog.json"
            debian.write_text("fixed Debian playbook", encoding="utf-8")
            rhel.write_text("fixed RHEL playbook", encoding="utf-8")
            lock.write_text("builtin only", encoding="utf-8")
            policy = request("inspect")["policy"]
            policy.update({"osFamily": "rhel", "playbookCatalogId": "kordex.os-upgrade.rhel.v1"})
            policy["playbookDigest"] = hashlib.sha256(rhel.read_bytes()).hexdigest()
            policy["collectionsDigest"] = hashlib.sha256(lock.read_bytes()).hexdigest()
            catalog_path.write_text(json.dumps({
                "schemaVersion": 1,
                "actionMarkerVersion": 1,
                "collectionsDigest": policy["collectionsDigest"],
                "baseImage": "registry.example/ansible-ee@sha256:" + "d" * 64,
                "ansibleVersion": "ansible-playbook [core 2.17.3]",
                "catalogs": {
                    "kordex.os-upgrade.debian.v2": {"osFamily": "debian", "playbook": "debian.yml", "playbookDigest": hashlib.sha256(debian.read_bytes()).hexdigest()},
                    "kordex.os-upgrade.rhel.v1": {"osFamily": "rhel", "playbook": "rhel.yml", "playbookDigest": policy["playbookDigest"]},
                },
            }), encoding="utf-8")
            with patch.object(upgrade, "CATALOG_PATH", catalog_path), \
                    patch.object(upgrade, "PLAYBOOK_PATH", debian), \
                    patch.object(upgrade, "RHEL_PLAYBOOK_PATH", rhel), \
                    patch.object(upgrade, "COLLECTIONS_LOCK_PATH", lock), \
                    patch("subprocess.run", return_value=type("Completed", (), {"stdout": "ansible-playbook [core 2.17.3]\n"})()):
                self.assertEqual(upgrade.validate_catalog(policy), rhel)


class PlaybookPreflightTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook is required for catalog syntax checks")
    def test_both_fixed_catalogs_parse_before_any_host_execution(self):
        for name in ("upgrade-debian.yml", "upgrade-rhel.yml"):
            with self.subTest(catalog=name):
                result = subprocess.run(
                    ["ansible-playbook", "--syntax-check", "-i", "localhost,", str(Path(__file__).with_name(name))],
                    text=True, capture_output=True, timeout=60, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_both_playbooks_require_action_marker_before_host_work(self) -> None:
        for filename in ("upgrade-debian.yml", "upgrade-rhel.yml"):
            with self.subTest(filename=filename):
                plays = yaml.safe_load((Path(__file__).with_name(filename)).read_text(encoding="utf-8"))
                assertion = plays[0]["tasks"][0]["ansible.builtin.assert"]
                self.assertIn("(kordex_policy.actionMarkerVersion | default(0) | int) == 1", assertion["that"])

    def test_host_journal_intents_and_verified_states_are_flushed(self) -> None:
        required_flushes = {
            "Write package apply intent before changing host packages": "Flush package apply intent to the host filesystem",
            "Persist reboot intent before starting the host reboot": "Flush reboot intent to the host filesystem",
            "Persist package verification only after all host checks pass": "Flush package verification to the host filesystem",
            "Persist reboot verification only after all host checks pass": "Flush reboot verification to the host filesystem",
        }
        for filename in ("upgrade-debian.yml", "upgrade-rhel.yml"):
            with self.subTest(filename=filename):
                plays = yaml.safe_load((Path(__file__).with_name(filename)).read_text(encoding="utf-8"))
                tasks = plays[0]["tasks"]
                task_indexes = {task.get("name"): index for index, task in enumerate(tasks)}
                for write_name, flush_name in required_flushes.items():
                    write_index = task_indexes[write_name]
                    flush_index = task_indexes[flush_name]
                    self.assertEqual(flush_index, write_index + 1, f"{filename}: {write_name} is not immediately flushed")
                    flush = tasks[flush_index]
                    self.assertEqual(flush["ansible.builtin.command"]["argv"],
                                     ["/usr/bin/sync", "--file-system", "{{ kordex_marker_directory }}"])
                    self.assertIs(flush["changed_when"], False)
                self.assertLess(task_indexes[required_flushes["Write package apply intent before changing host packages"]],
                                task_indexes["Install exact requested package versions"])
                self.assertLess(task_indexes[required_flushes["Persist reboot intent before starting the host reboot"]],
                                task_indexes["Reboot and wait for the same machine to return when requested"])

    def test_package_pins_are_resolved_offline_before_any_mutation(self) -> None:
        playbook_path = Path(__file__).with_name("upgrade-debian.yml")
        plays = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))
        self.assertIsInstance(plays, list)
        self.assertEqual(len(plays), 1)
        tasks = plays[0]["tasks"]
        preflight = next(
            task for task in tasks
            if task.get("name") == "Verify pinned package versions resolve from the local APT cache"
        )
        self.assertEqual(preflight["when"], "kordex_request.phase == 'preflight' and kordex_policy.schemaVersion == 1")
        self.assertIs(preflight["check_mode"], True)
        apt = preflight["ansible.builtin.apt"]
        self.assertEqual(apt["name"], "{{ item.name }}={{ item.version }}")
        self.assertEqual(apt["state"], "present")
        self.assertIs(apt["update_cache"], False)
        self.assertIs(apt["fail_on_autoremove"], True)
        self.assertIs(apt["allow_downgrade"], False)
        self.assertIs(apt["allow_change_held_packages"], False)
        self.assertIs(apt["install_recommends"], False)

        apply = next(task for task in plays[0]["tasks"] if task.get("name") == "Install exact requested package versions")
        apply_apt = apply["ansible.builtin.apt"]
        self.assertEqual(apply_apt["name"], "{{ item.name }}={{ item.version }}")
        self.assertIs(apply_apt["update_cache"], False)
        self.assertNotIn("cache_valid_time", apply_apt)
        offline_apply = next(task for task in tasks if task.get("name") == "Install only hash-verified local Debian artifacts without repository downloads")
        self.assertIn("--no-download", offline_apply["ansible.builtin.command"]["argv"])
        self.assertIn("kordex_artifact_paths", offline_apply["ansible.builtin.command"]["argv"])
        self.assertEqual(preflight["loop"], "{{ kordex_policy.packages }}")
        apply_index = next(
            index for index, task in enumerate(tasks)
            if task.get("name") == "Install exact requested package versions"
        )
        self.assertLess(tasks.index(preflight), apply_index)
        apply = tasks[apply_index]["ansible.builtin.apt"]
        self.assertIs(apply["fail_on_autoremove"], True)
        self.assertIs(apply["allow_downgrade"], False)
        self.assertIs(apply["allow_change_held_packages"], False)
        self.assertIs(apply["install_recommends"], False)

    def test_rhel_catalog_uses_dnf_pins_and_requires_gpg_verification(self) -> None:
        playbook_path = Path(__file__).with_name("upgrade-rhel.yml")
        plays = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))
        tasks = plays[0]["tasks"]
        preflight = next(task for task in tasks if task.get("name") == "Verify pinned package versions resolve from local DNF metadata")
        dnf = preflight["ansible.builtin.dnf"]
        self.assertEqual(dnf["name"], "{{ item.name }}-{{ item.version }}")
        self.assertIs(dnf["update_cache"], False)
        self.assertIs(dnf["disable_gpg_check"], False)
        self.assertIs(dnf["allowerasing"], False)
        self.assertIs(dnf["allow_downgrade"], False)
        self.assertIs(preflight["check_mode"], True)

        apply = next(task for task in plays[0]["tasks"] if task.get("name") == "Install exact requested package versions")
        apply_dnf = apply["ansible.builtin.dnf"]
        self.assertEqual(apply_dnf["name"], "{{ item.name }}-{{ item.version }}")
        self.assertIs(apply_dnf["update_cache"], False)
        self.assertIn("rpm", str(plays[0]))
        self.assertIn("ansible_facts.os_family == 'RedHat'", str(plays[0]))
        self.assertIn("ansible_facts.distribution == 'Amazon'", str(plays[0]))
        self.assertIn("ansible_facts.distribution_major_version == '2023'", str(plays[0]))

    def test_offline_artifacts_are_verified_before_repository_free_apply(self) -> None:
        cases = (
            ("upgrade-debian.yml", "Require each offline Debian artifact to match its pinned digest",
             "Require offline Debian package name, version, and architecture to match policy",
             "Install only hash-verified local Debian artifacts without repository downloads", "--no-download"),
            ("upgrade-rhel.yml", "Require each offline RPM artifact to match its pinned digest",
             "Require offline RPM package name and EVR to match policy",
             "Install only hash-verified local RPM artifacts without repository access", "--disablerepo=*"),
        )
        for filename, digest_check, metadata_check, install_name, offline_flag in cases:
            with self.subTest(filename=filename):
                tasks = yaml.safe_load(Path(__file__).with_name(filename).read_text(encoding="utf-8"))[0]["tasks"]
                names = [task["name"] for task in tasks]
                digest_index = names.index(digest_check)
                metadata_index = names.index(metadata_check)
                install_index = names.index(install_name)
                self.assertLess(digest_index, install_index)
                self.assertLess(metadata_index, install_index)
                install = tasks[install_index]["ansible.builtin.command"]
                self.assertIn(offline_flag, install["argv"])
                self.assertIn("kordex_artifact_paths", install["argv"])
                if filename == "upgrade-debian.yml":
                    self.assertIn("Dir::Cache::archives=/var/cache/kordex/artifacts/.apt-cache-", install["argv"])
                    cleanup = next(task for task in tasks if task.get("name") == "Remove the isolated APT archive cache after successful package application")
                    self.assertEqual(cleanup["ansible.builtin.file"]["state"], "absent")
                    self.assertLess(install_index, names.index(cleanup["name"]))
                else:
                    self.assertIn("--setopt=cachedir=/var/cache/kordex/artifacts/.dnf-cache-", install["argv"])
                    cleanup = next(task for task in tasks if task.get("name") == "Remove the isolated DNF cache after successful package application")
                    self.assertEqual(cleanup["ansible.builtin.file"]["state"], "absent")
                    self.assertLess(install_index, names.index(cleanup["name"]))
                self.assertIn("kordex_policy.schemaVersion == 2", tasks[install_index]["when"])

    def test_offline_dependency_resolution_runs_before_apply_without_repositories(self) -> None:
        cases = (
            ("upgrade-debian.yml", "Resolve offline Debian dependency transaction without downloads or removals",
             "--simulate", "--no-download", "--no-remove"),
            ("upgrade-rhel.yml", "Test offline RPM dependency transaction without repository access",
             "--disablerepo=*", "--setopt=tsflags=test"),
        )
        for filename, resolver_name, *required_args in cases:
            with self.subTest(filename=filename):
                tasks = yaml.safe_load(Path(__file__).with_name(filename).read_text(encoding="utf-8"))[0]["tasks"]
                names = [task["name"] for task in tasks]
                resolver_index = names.index(resolver_name)
                resolver = tasks[resolver_index]
                argv = resolver["ansible.builtin.command"]["argv"]
                self.assertIn("kordex_artifact_paths", argv)
                self.assertIn("kordex_request.phase == 'preflight'", resolver["when"])
                self.assertIn("kordex_policy.schemaVersion == 2", resolver["when"])
                self.assertIs(resolver["changed_when"], False)
                for arg in required_args:
                    self.assertIn(arg, argv)
                if filename == "upgrade-debian.yml":
                    self.assertIn("Dir::Cache::archives=/var/cache/kordex/artifacts/.apt-cache-", argv)
                    cache_stat = next(task for task in tasks if task.get("name") == "Inspect isolated per-operation APT archive cache without following links")
                    cache_assert = next(task for task in tasks if task.get("name") == "Require any existing per-operation APT archive cache to be private and root-owned")
                    cache_create = next(task for task in tasks if task.get("name") == "Create isolated per-operation APT archive cache")
                    self.assertIs(cache_stat["ansible.builtin.stat"]["follow"], False)
                    self.assertIn("operationId", cache_stat["ansible.builtin.stat"]["path"])
                    self.assertIn("0700", str(cache_assert["ansible.builtin.assert"]["that"]))
                    self.assertEqual(cache_create["ansible.builtin.file"]["mode"], "0700")
                    self.assertLess(names.index(cache_stat["name"]), names.index(cache_assert["name"]))
                    self.assertLess(names.index(cache_assert["name"]), names.index(cache_create["name"]))
                    self.assertLess(names.index(cache_create["name"]), resolver_index)
                    preflight_cleanup = next(task for task in tasks if task.get("name") == "Remove the isolated APT archive cache after successful preflight simulation")
                    self.assertLess(resolver_index, names.index(preflight_cleanup["name"]))
                    self.assertIn("phase == 'preflight'", preflight_cleanup["when"])
                else:
                    self.assertIn("--setopt=cachedir=/var/cache/kordex/artifacts/.dnf-cache-", argv)
                    cache_stat = next(task for task in tasks if task.get("name") == "Inspect isolated per-operation DNF cache without following links")
                    cache_assert = next(task for task in tasks if task.get("name") == "Require any existing per-operation DNF cache to be private and root-owned")
                    cache_create = next(task for task in tasks if task.get("name") == "Create isolated per-operation DNF cache")
                    self.assertIs(cache_stat["ansible.builtin.stat"]["follow"], False)
                    self.assertIn("operationId", cache_stat["ansible.builtin.stat"]["path"])
                    self.assertIn("0700", str(cache_assert["ansible.builtin.assert"]["that"]))
                    self.assertEqual(cache_create["ansible.builtin.file"]["mode"], "0700")
                    self.assertLess(names.index(cache_stat["name"]), names.index(cache_assert["name"]))
                    self.assertLess(names.index(cache_assert["name"]), names.index(cache_create["name"]))
                    self.assertLess(names.index(cache_create["name"]), resolver_index)
                    preflight_cleanup = next(task for task in tasks if task.get("name") == "Remove the isolated DNF cache after successful preflight simulation")
                    self.assertLess(resolver_index, names.index(preflight_cleanup["name"]))
                    self.assertIn("phase == 'preflight'", preflight_cleanup["when"])
                apply_index = next(index for index, task in enumerate(tasks)
                                   if task.get("name", "").startswith("Install only hash-verified local"))
                self.assertLess(resolver_index, apply_index)

    def test_offline_rpm_requires_existing_signature_trust_before_dnf_transaction(self) -> None:
        tasks = yaml.safe_load(Path(__file__).with_name("upgrade-rhel.yml").read_text(encoding="utf-8"))[0]["tasks"]
        names = [task["name"] for task in tasks]
        signature_index = names.index("Verify offline RPM signatures using the existing host keyring")
        transaction_index = names.index("Test offline RPM dependency transaction without repository access")
        apply_index = names.index("Install only hash-verified local RPM artifacts without repository access")
        signature_check = tasks[signature_index]
        self.assertEqual(signature_check["ansible.builtin.command"]["argv"][:2], ["rpmkeys", "--checksig"])
        self.assertNotIn("--verbose", signature_check["ansible.builtin.command"]["argv"])
        self.assertEqual(signature_check["register"], "kordex_rpm_signature_checks")
        self.assertIn("kordex_policy.schemaVersion == 2", signature_check["when"])
        self.assertIn("kordex_request.phase in ['preflight', 'apply']", signature_check["when"])
        signature_assert = tasks[names.index("Require a cryptographically verified offline RPM signature")]
        self.assertIn("item.stdout is search('(?i)signatures OK')", signature_assert["ansible.builtin.assert"]["that"])
        self.assertTrue(any("NOKEY|NOT OK|NOTTRUSTED|UNSIGNED" in condition for condition in signature_assert["ansible.builtin.assert"]["that"]))
        self.assertEqual(signature_assert["loop"], "{{ kordex_rpm_signature_checks.results }}")
        for index in (transaction_index, apply_index):
            task = tasks[index]
            self.assertIn("--setopt=localpkg_gpgcheck=True", task["ansible.builtin.command"]["argv"])
            self.assertIn("--setopt=cachedir=/var/cache/kordex/artifacts/.dnf-cache-", task["ansible.builtin.command"]["argv"])
            self.assertIn("--setopt=obsoletes=False", task["ansible.builtin.command"]["argv"])
        self.assertLess(signature_index, transaction_index)
        self.assertLess(transaction_index, apply_index)

    def test_rhel_detects_preexisting_and_update_triggered_reboot_requirements(self) -> None:
        tasks = yaml.safe_load(Path(__file__).with_name("upgrade-rhel.yml").read_text(encoding="utf-8"))[0]["tasks"]
        task_indexes = {task.get("name"): index for index, task in enumerate(tasks)}
        baseline = next(task for task in tasks if task.get("name") == "Check baseline RPM reboot state without consulting repositories")
        baseline_argv = baseline["ansible.builtin.command"]["argv"]
        self.assertEqual(baseline_argv, ["dnf", "--disablerepo=*", "needs-restarting", "-r"])
        self.assertEqual(baseline["failed_when"], "kordex_baseline_reboot_hint.rc not in [0, 1]")
        self.assertIn("kordex_policy.reboot != 'Required'", baseline["when"])
        clean_baseline = next(task for task in tasks if task.get("name") == "Require a clean baseline before RPM package changes")
        self.assertEqual(clean_baseline["ansible.builtin.assert"]["that"], ["kordex_baseline_reboot_hint.rc == 0"])
        self.assertLess(task_indexes[clean_baseline["name"]], task_indexes["Write package apply intent before changing host packages"])

        after_update = next(task for task in tasks if task.get("name") == "Check whether updated RPMs require a full reboot")
        self.assertEqual(after_update["ansible.builtin.command"]["argv"], baseline_argv)
        self.assertIn("kordex_request.phase in ['apply', 'inspect']", after_update["when"])
        self.assertLess(task_indexes["Install exact requested package versions"], task_indexes[after_update["name"]])
        self.assertLess(task_indexes["Install only hash-verified local RPM artifacts without repository access"], task_indexes[after_update["name"]])
        reboot_policy = next(task for task in tasks if task.get("name") == "Determine whether the immutable policy requires a reboot")
        expression = reboot_policy["ansible.builtin.set_fact"]["kordex_host_reboot_required"]
        self.assertIn("kordex_needs_restarting.rc", expression)
        self.assertLess(task_indexes[after_update["name"]], task_indexes[reboot_policy["name"]])
        never_policy = next(task for task in tasks if task.get("name") == "Reject host state that requires reboot when policy prohibits it")
        self.assertEqual(never_policy["ansible.builtin.assert"]["that"], ["not (kordex_host_reboot_required | bool)"])
        self.assertIn("kordex_request.phase in ['apply', 'inspect']", never_policy["when"])


class ProcessGroupLifecycleTest(unittest.TestCase):
    class Process:
        pid = 4242
        returncode = 0

        def __init__(self, communicate_result=("ok", None)):
            self.communicate_result = communicate_result
            self.waited = False

        def communicate(self, timeout=None):
            if isinstance(self.communicate_result, BaseException):
                raise self.communicate_result
            return self.communicate_result

        def poll(self):
            return None if not self.waited else self.returncode

        def wait(self, timeout=None):
            self.waited = True
            return self.returncode

    def test_ansible_runs_in_its_own_process_group(self):
        process = self.Process()
        with patch.object(upgrade.subprocess, "Popen", return_value=process) as popen:
            result = upgrade.run_process_group(["ansible-playbook", "fixed.yml"], cwd="/tmp", env={}, timeout=60)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ok")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.STDOUT)

    def test_timeout_terminates_the_entire_process_group(self):
        process = self.Process(subprocess.TimeoutExpired("ansible-playbook", 1))
        with patch.object(upgrade.subprocess, "Popen", return_value=process), \
                patch.object(upgrade.os, "killpg") as killpg, \
                patch.object(upgrade.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaises(subprocess.TimeoutExpired):
                upgrade.run_process_group(["ansible-playbook"], cwd="/tmp", env={}, timeout=1)
        self.assertEqual([call.args[1] for call in killpg.call_args_list],
                         [signal.SIGTERM, 0, signal.SIGKILL])
        self.assertTrue(process.waited)

    def test_termination_signal_stops_group_before_returning(self):
        process = self.Process()

        def send_sigterm(timeout=None):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return "unreachable", None

        process.communicate = send_sigterm
        with patch.object(upgrade.subprocess, "Popen", return_value=process), \
                patch.object(upgrade.os, "killpg", side_effect=[None, ProcessLookupError()]) as killpg:
            with self.assertRaises(upgrade.ExecutionInterrupted):
                upgrade.run_process_group(["ansible-playbook"], cwd="/tmp", env={}, timeout=60)
        self.assertEqual([call.args[1] for call in killpg.call_args_list], [signal.SIGTERM, 0])
        self.assertTrue(process.waited)


class EntrypointFailureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.request_path = self.root / "request.json"
        self.result_path = self.root / "result.json"
        self.payload = request("apply")
        self.request_path.write_text(json.dumps(self.payload), encoding="utf-8")
        self.key = self.root / "id_ed25519"
        self.known_hosts = self.root / "known_hosts"
        self.key.write_text("test-private-key", encoding="utf-8")
        self.known_hosts.write_text("worker-01 ssh-ed25519 AAAATEST\n", encoding="utf-8")
        self.work = self.root / "work"
        self.ansible_call = None

    def run_entrypoint(self, subprocess_result=None, subprocess_error=None, playbook_path=None) -> None:
        with patch.object(upgrade, "validate_catalog", return_value=playbook_path or upgrade.PLAYBOOK_PATH), \
                patch.object(upgrade, "KEY_SOURCE", self.key), \
                patch.object(upgrade, "KNOWN_HOSTS", self.known_hosts), \
                patch.object(upgrade, "Path", side_effect=lambda value: self.work if value == "/var/run/kordex" else Path(value)), \
                patch.dict(os.environ, {"KORDEX_ANSIBLE_USER": "kordex"}), \
                patch.object(upgrade, "run_process_group", side_effect=subprocess_error or [subprocess_result]) as ansible_run:
            upgrade.run(self.request_path, self.result_path)
            self.ansible_call = ansible_run.call_args

    def test_success_requires_matching_receipt_identity(self) -> None:
        self.result_path.write_text(json.dumps({
            "operationId": self.payload["operationId"],
            "planDigest": self.payload["planDigest"],
            "nodeUid": self.payload["node"]["uid"],
        }), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess.CompletedProcess([], 0))
        self.assertIn("KORDEX_EE_RECEIPT=", output.getvalue())
        self.assertIn(self.payload["planDigest"], output.getvalue())

    def test_receipt_identity_mismatch_is_rejected(self) -> None:
        self.result_path.write_text(json.dumps({
            "operationId": self.payload["operationId"],
            "planDigest": "0" * 64,
            "nodeUid": self.payload["node"]["uid"],
        }), encoding="utf-8")
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess.CompletedProcess([], 0))
        self.assertIn("KORDEX_EE_ERROR=ReceiptIdentityMismatch", output.getvalue())

    def test_timeout_is_reported_as_ambiguous(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess_error=subprocess.TimeoutExpired("ansible-playbook", 60))
        self.assertIn("KORDEX_EE_ERROR=ExecutionTimedOutAmbiguous", output.getvalue())

    def test_termination_signal_is_reported_as_ambiguous(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess_error=upgrade.ExecutionInterrupted(signal.SIGTERM))
        self.assertIn("KORDEX_EE_ERROR=ExecutionInterruptedAmbiguous", output.getvalue())

    def test_nonzero_playbook_exit_is_reported_as_ambiguous(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess.CompletedProcess([], 2))
        self.assertIn("KORDEX_EE_ERROR=PlaybookFailedAmbiguous", output.getvalue())

    def test_host_key_mismatch_has_safe_structured_failure_code(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess.CompletedProcess([], 2, stdout="Host key verification failed.\n"))
        self.assertIn("KORDEX_EE_ERROR=SSHHostKeyVerificationFailed", output.getvalue())

    def test_ssh_transport_failure_has_safe_structured_code(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess.CompletedProcess([], 2, stdout="ssh: connect to host 10.0.0.10 port 22: Connection timed out\n"))
        self.assertIn("KORDEX_EE_ERROR=SSHTransportUnavailable", output.getvalue())

    def test_ssh_authentication_failure_has_safe_structured_failure_code(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()) as output:
            self.run_entrypoint(subprocess.CompletedProcess([], 2, stdout="Permission denied (publickey).\n"))
        self.assertIn("KORDEX_EE_ERROR=SSHAuthenticationFailed", output.getvalue())

    def test_ansible_subprocess_does_not_inherit_environment_overrides(self) -> None:
        self.result_path.write_text(json.dumps({
            "operationId": self.payload["operationId"],
            "planDigest": self.payload["planDigest"],
            "nodeUid": self.payload["node"]["uid"],
        }), encoding="utf-8")
        poison = {
            "ANSIBLE_CALLBACK_PLUGINS": "/tmp/untrusted-callbacks",
            "ANSIBLE_CONFIG": "/tmp/untrusted-ansible.cfg",
            "PYTHONPATH": "/tmp/untrusted-python",
            "SSH_AUTH_SOCK": "/tmp/untrusted-agent.sock",
        }
        with patch.dict(os.environ, poison), contextlib.redirect_stdout(io.StringIO()):
            self.run_entrypoint(subprocess.CompletedProcess([], 0))
        env = self.ansible_call.kwargs["env"]
        for name in poison:
            self.assertNotEqual(env.get(name), poison[name])
        self.assertEqual(env["ANSIBLE_CONFIG"], str(self.work / "ansible.cfg"))

    def test_inventory_pins_known_host_lookup_to_kubernetes_node_name(self) -> None:
        self.result_path.write_text(json.dumps({
            "operationId": self.payload["operationId"],
            "planDigest": self.payload["planDigest"],
            "nodeUid": self.payload["node"]["uid"],
        }), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.run_entrypoint(subprocess.CompletedProcess([], 0))
        inventory = (self.work / "inventory.ini").read_text(encoding="utf-8")
        self.assertIn("ansible_host=10.0.0.10", inventory)
        self.assertIn("HostKeyAlias=worker-01", inventory)
        ssh_config = (self.work / "ansible.cfg").read_text(encoding="utf-8")
        self.assertIn("CheckHostIP=no", ssh_config)
        self.assertIn("GlobalKnownHostsFile=/dev/null", ssh_config)
        self.assertIn("UserKnownHostsFile=" + str(self.known_hosts), ssh_config)

    def test_rhel_request_invokes_only_the_rhel_playbook(self) -> None:
        policy = self.payload["policy"]
        policy.update({"id": "rhel-test", "osFamily": "rhel", "playbookCatalogId": "kordex.os-upgrade.rhel.v1"})
        policy["packages"] = [{"name": "internal_lib", "version": "1.2.3-4.el9_4"}]
        policy.pop("expectedKernelVersion", None)
        self.payload["planDigest"] = upgrade.upgrade_policy_digest(policy)
        self.request_path.write_text(json.dumps(self.payload), encoding="utf-8")
        self.result_path.write_text(json.dumps({
            "operationId": self.payload["operationId"],
            "planDigest": self.payload["planDigest"],
            "nodeUid": self.payload["node"]["uid"],
        }), encoding="utf-8")
        rhel = self.root / "upgrade-rhel.yml"
        with contextlib.redirect_stdout(io.StringIO()):
            self.run_entrypoint(subprocess_result=subprocess.CompletedProcess([], 0), playbook_path=rhel)
        self.assertEqual(self.ansible_call.args[0][-1], str(rhel))
if __name__ == "__main__":
    unittest.main()
