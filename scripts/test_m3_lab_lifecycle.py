from __future__ import annotations

import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

import m3_lab_lifecycle as lifecycle


def lab_config():
    return {"projectId": lifecycle.PROJECT_ID, "projectNumber": lifecycle.PROJECT_NUMBER,
            "zone": lifecycle.ZONE, "terraformPrincipalEmail": "kordex-lab-tf@kordex-fleet-platform-515416.iam.gserviceaccount.com",
            "lifecyclePrincipalEmail": "kordex-m3-lifecycle@kordex-fleet-platform-515416.iam.gserviceaccount.com",
            "organizationId": "11111111-1111-4111-8111-111111111111",
            "clusterId": "22222222-2222-4222-8222-222222222222",
            "labId": "kordex-m3-lab", "kubeContext": "kordex-m3-lab",
            "osIdentity": {"osId": "debian", "versionId": "13.2", "architecture": "amd64"}}


class FakeAPI:
    def __init__(self, *, safe=True):
        self.state = "RUNNING"
        self.safe = safe
        self.complete_stop_calls = 0
        self.complete_start_calls = 0

    def request(self, action="", *, method="GET"):
        if action == "stop":
            if self.state == "STOPPED":
                return {"state": "STOPPED", "canStop": False, "blockers": []}
            if self.state == "RUNNING":
                self.state = "DRAINING"
            if self.safe:
                self.state = "READY_TO_STOP"
            return {"state": self.state, "canStop": self.state == "READY_TO_STOP",
                    "blockers": [] if self.safe else ["operations_pending"], "unsafeOperations": 0}
        if action == "stop/started":
            self.state = "STOPPING"
        elif action == "stop/complete":
            self.state = "STOPPED"
            self.complete_stop_calls += 1
        elif action == "start":
            self.state = "STARTING"
        elif action == "start/complete":
            self.state = "RUNNING"
            self.complete_start_calls += 1
        return {"state": self.state, "canStop": self.state == "READY_TO_STOP", "blockers": []}


class FakeCloud:
    def __init__(self, state="RUNNING"):
        self.nodes = {r: {"name": n, "role": r, "status": state, "diskStatus": "READY"}
                      for r, n in lifecycle.names_for("kordex-m3-lab").items()}
        self.stopped = []
        self.started = []
        self.fail_stop = None
        self.fail_start = None
        self.fail_health = False

    def inventory(self):
        return {key: dict(value) for key, value in self.nodes.items()}

    def stop(self, name):
        if self.fail_stop == name:
            raise lifecycle.LifecycleError("injected stop failure")
        self.stopped.append(name)
        next(v for v in self.nodes.values() if v["name"] == name)["status"] = "TERMINATED"

    def start(self, name):
        if self.fail_start == name:
            raise lifecycle.LifecycleError("injected start failure")
        self.started.append(name)
        next(v for v in self.nodes.values() if v["name"] == name)["status"] = "RUNNING"

    def wait_for(self, desired, timeout):
        rows = self.inventory()
        if not all(v["status"] == desired for v in rows.values()):
            raise lifecycle.LifecycleError("power state incomplete")
        return rows

    def verify_running_hosts(self, *, require_new_boot=False):
        if self.fail_health:
            raise lifecycle.LifecycleError("identity mismatch")

    def verify_kubernetes(self):
        if self.fail_health:
            raise lifecycle.LifecycleError("Kubernetes health mismatch")


class LifecycleTests(unittest.TestCase):
    def controller(self, *, safe=True, state="RUNNING"):
        api, cloud = FakeAPI(safe=safe), FakeCloud(state)
        return lifecycle.LabLifecycleController(api, cloud, wait_seconds=0, sleep=lambda _: None), api, cloud

    def test_project_number_and_dedicated_principal_are_required(self):
        config = lab_config()
        config["projectNumber"] = "209068399398"
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.validate_config(config)
        config = lab_config()
        config["terraformPrincipalEmail"] = "owner@example.com"
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.validate_config(config)
        config = lab_config()
        config["lifecyclePrincipalEmail"] = config["terraformPrincipalEmail"]
        with self.assertRaisesRegex(lifecycle.LifecycleError, "distinct"):
            lifecycle.validate_config(config)

    def test_gcloud_lifecycle_commands_impersonate_the_distinct_lifecycle_identity(self):
        cloud = object.__new__(lifecycle.GCloudLab)
        cloud.config = lab_config()
        captured = {}
        cloud.run = lambda command, **_kwargs: captured.setdefault("command", command) or "ok"

        def controlled_command(args):
            captured["args"] = args
            return args, {"PATH": "/usr/bin:/bin"}, {}

        with patch.object(lifecycle.gcloud_context, "command", side_effect=controlled_command):
            cloud._gcloud(["compute", "instances", "start", "kordex-m3-lab-server"])

        self.assertIn(f"--impersonate-service-account={cloud.config['lifecyclePrincipalEmail']}",
                      captured["args"])
        self.assertNotIn(f"--impersonate-service-account={cloud.config['terraformPrincipalEmail']}",
                         captured["args"])

    def test_stop_waits_for_terminal_reports_and_keeps_barrier(self):
        controller, api, cloud = self.controller(safe=False)
        with self.assertRaises(lifecycle.LifecycleError):
            controller.stop()
        self.assertEqual(api.state, "DRAINING")
        self.assertEqual(cloud.stopped, [])
        self.assertEqual(api.complete_stop_calls, 0)

    def test_failed_recovery_or_unreleased_reservation_blocks_cloud_stop(self):
        controller, api, cloud = self.controller()

        def failed_request(action="", *, method="GET"):
            if action == "stop":
                api.state = "DRAINING"
                return {"state": "DRAINING", "canStop": False,
                        "blockers": ["failed_or_recovery_required_operation", "unreleased_operation_reservation"],
                        "unsafeOperations": 1, "unreleasedReservations": 1}
            return api.request(action, method=method)

        api.request = failed_request
        with self.assertRaises(lifecycle.LifecycleError):
            controller.stop()
        self.assertEqual(api.state, "DRAINING")
        self.assertEqual(cloud.stopped, [])

    def test_stop_keeps_disks_and_marks_stopped_only_after_verification(self):
        controller, api, cloud = self.controller()
        state = controller.stop()
        self.assertEqual(state["state"], "STOPPED")
        self.assertEqual(set(cloud.stopped), {v["name"] for v in cloud.nodes.values()})
        self.assertTrue(all(v["diskStatus"] == "READY" for v in cloud.nodes.values()))
        self.assertEqual(api.complete_stop_calls, 1)

    def test_idempotent_stop_checks_persisted_vm_and_disk_state(self):
        controller, api, cloud = self.controller(state="TERMINATED")
        api.state = "STOPPED"
        self.assertEqual(controller.stop()["state"], "STOPPED")
        cloud.nodes["worker-1"]["status"] = "RUNNING"
        with self.assertRaises(lifecycle.LifecycleError):
            controller.stop()

    def test_partial_stop_failure_retains_shutdown_barrier(self):
        controller, api, cloud = self.controller()
        cloud.fail_stop = "kordex-m3-lab-worker"
        with self.assertRaises(lifecycle.LifecycleError):
            controller.stop()
        self.assertEqual(api.state, "STOPPING")
        self.assertEqual(api.complete_stop_calls, 0)

    def test_start_failure_and_identity_mismatch_keep_admission_fenced(self):
        controller, api, cloud = self.controller(state="TERMINATED")
        api.state = "STOPPED"
        cloud.fail_start = "kordex-m3-lab-worker"
        with self.assertRaises(lifecycle.LifecycleError):
            controller.start()
        self.assertEqual(api.state, "STARTING")
        self.assertEqual(api.complete_start_calls, 0)

        controller, api, cloud = self.controller(state="TERMINATED")
        api.state = "STOPPED"
        cloud.fail_health = True
        with self.assertRaises(lifecycle.LifecycleError):
            controller.start()
        self.assertEqual(api.state, "STARTING")
        self.assertEqual(api.complete_start_calls, 0)

    def test_restart_preserves_lifecycle_state_and_reuses_only_the_three_nodes(self):
        controller, api, cloud = self.controller()
        state = controller.restart()
        self.assertEqual(state["state"], "RUNNING")
        self.assertEqual(len(cloud.stopped), 3)
        self.assertEqual(len(cloud.started), 3)
        self.assertEqual(api.complete_stop_calls, 1)
        self.assertEqual(api.complete_start_calls, 1)

    def test_identity_file_roles_are_exact_and_unique(self):
        config = lab_config()
        image = "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-test"
        items = [{"role": role, "name": name, "instanceId": str(i + 1), "bootDiskId": str(i + 11),
                  "bootDiskName": f"kordex-m3-lab-{'server' if role == 'server' else 'worker' if role == 'worker-1' else 'worker-2'}",
                  "bootDiskSelfLink": f"https://www.googleapis.com/compute/v1/projects/{lifecycle.PROJECT_ID}/zones/{lifecycle.ZONE}/disks/test-{i}",
                  "sourceImage": image, "sourceImageId": "123"}
                 for i, (role, name) in enumerate(lifecycle.names_for(config["labId"]).items())]
        identity = {"projectId": lifecycle.PROJECT_ID, "zone": lifecycle.ZONE,
                    "labId": config["labId"], "imageUniqueId": "123", "imageSelfLink": image, "instances": items}
        baseline = {"schema": "kordex-m3-recovery-baseline-v1", "project": {"projectId": lifecycle.PROJECT_ID},
                    "labId": config["labId"], "zone": lifecycle.ZONE,
                    "nodes": {r: {"instanceId": str(i + 1), "machineId": f"{i+1:032x}",
                                  "bootId": "11111111-1111-4111-8111-111111111111",
                                  "osId": "debian", "osVersion": "13.2", "kernelVersion": "6.12.1-amd64",
                                  "architecture": "x86_64"}
                              for i, r in enumerate(lifecycle.ROLES)}}
        lifecycle.GCloudLab(config, identity, baseline, lambda *a, **k: "")
        lab = lifecycle.GCloudLab(config, identity, baseline, lambda *a, **k: "")
        def host_output(args, **_kwargs):
            name = args[2]
            role = next(role for role, instance_name in lab.names.items() if instance_name == name)
            return "\n".join((baseline["nodes"][role]["machineId"], "22222222-2222-4222-8222-222222222222",
                              "debian", "13.2", "6.12.1-amd64", "x86_64"))
        lab._gcloud = host_output
        lab.verify_running_hosts()
        def wrong_kernel(args, **_kwargs):
            lines = host_output(args).splitlines()
            lines[-2] = "wrong-kernel"
            return "\n".join(lines)
        lab._gcloud = wrong_kernel
        with self.assertRaises(lifecycle.LifecycleError):
            lab.verify_running_hosts()
        def wrong_machine(args, **_kwargs):
            lines = host_output(args).splitlines()
            lines[0] = "f" * 32
            return "\n".join(lines)
        lab._gcloud = wrong_machine
        with self.assertRaises(lifecycle.LifecycleError):
            lab.verify_running_hosts()
        def wrong_release(args, **_kwargs):
            lines = host_output(args).splitlines()
            lines[3] = "13.3"
            return "\n".join(lines)
        lab._gcloud = wrong_release
        with self.assertRaises(lifecycle.LifecycleError):
            lab.verify_running_hosts()
        identity["instances"].append(items[0])
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.GCloudLab(config, identity, baseline, lambda *a, **k: "")

    def test_control_plane_requires_tls_pin_and_private_token_file(self):
        org = "11111111-1111-4111-8111-111111111111"
        cluster = "22222222-2222-4222-8222-222222222222"
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("not-a-real-token")
            token.chmod(0o600)
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.ControlPlaneClient("https://hub.example", org, cluster, token, "bad-pin")

            calls = []
            def opener(method, url, authorization, pin):
                calls.append((method, url, authorization, pin))
                return b'{"state":"RUNNING"}'

            client = lifecycle.ControlPlaneClient("https://hub.example", org, cluster, token,
                                                  "a" * 64, opener=opener)
            self.assertEqual(client.request()["state"], "RUNNING")
            self.assertEqual(calls[0][0], "GET")
            self.assertEqual(calls[0][2], "Bearer not-a-real-token")
            self.assertEqual(calls[0][3], "a" * 64)

            replacement = Path(directory) / "replacement"
            replacement.write_text("must-not-be-read")
            replacement.chmod(0o600)
            link = Path(directory) / "token-link"
            link.symlink_to(replacement)
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.ControlPlaneClient("https://hub.example", org, cluster, link, "a" * 64)

    def test_stop_accepts_the_current_baseline_boot_and_start_requires_a_new_boot(self):
        config = lab_config()
        image = "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-test"
        instances = [{"role": role, "name": name, "instanceId": str(i + 1), "bootDiskId": str(i + 11),
                      "bootDiskName": f"kordex-m3-lab-{'server' if role == 'server' else 'worker' if role == 'worker-1' else 'worker-2'}",
                      "bootDiskSelfLink": f"https://www.googleapis.com/compute/v1/projects/{lifecycle.PROJECT_ID}/zones/{lifecycle.ZONE}/disks/test-{i}",
                      "sourceImage": image, "sourceImageId": "123"}
                     for i, (role, name) in enumerate(lifecycle.names_for(config["labId"]).items())]
        identity = {"projectId": lifecycle.PROJECT_ID, "zone": lifecycle.ZONE, "labId": config["labId"],
                    "imageUniqueId": "123", "imageSelfLink": image, "instances": instances}
        baseline = {"schema": "kordex-m3-recovery-baseline-v1", "project": {"projectId": lifecycle.PROJECT_ID},
                    "labId": config["labId"], "zone": lifecycle.ZONE,
                    "nodes": {role: {"instanceId": str(i + 1), "machineId": f"{i+1:032x}",
                                     "bootId": "11111111-1111-4111-8111-111111111111",
                                     "osId": "debian", "osVersion": "13.2", "kernelVersion": "6.12.1-amd64",
                                     "architecture": "x86_64"}
                              for i, role in enumerate(lifecycle.ROLES)}}
        lab = lifecycle.GCloudLab(config, identity, baseline, lambda *a, **k: "")
        def host_output(args, **_kwargs):
            name = args[2]
            role = next(role for role, instance_name in lab.names.items() if instance_name == name)
            return "\n".join((baseline["nodes"][role]["machineId"], baseline["nodes"][role]["bootId"],
                              "debian", "13.2", "6.12.1-amd64", "x86_64"))
        lab._gcloud = host_output
        lab.verify_running_hosts(require_new_boot=False)
        with self.assertRaises(lifecycle.LifecycleError):
            lab.verify_running_hosts(require_new_boot=True)


if __name__ == "__main__":
    unittest.main()
