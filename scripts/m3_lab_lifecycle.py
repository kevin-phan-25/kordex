"""Guarded persistent-lab VM lifecycle backed by the control-plane barrier.

This module never deletes Terraform resources. A failed transition intentionally
leaves the durable database barrier in place so maintenance cannot be admitted
while VM power state is uncertain.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import ssl
import subprocess
import time
from typing import Callable
from urllib.parse import urlsplit

import m3_gcloud_context as gcloud_context


PROJECT_ID = "kordex-fleet-platform-515416"
PROJECT_NUMBER = "209068399397"
ZONE = "us-east1-b"
ROLES = ("server", "worker-1", "worker-2")
START_ORDER = ("server", "worker-1", "worker-2")
STOP_ORDER = ("worker-1", "worker-2", "server")
PHASES = ("RUNNING", "DRAINING", "READY_TO_STOP", "STOPPING", "STOPPED", "STARTING")


class LifecycleError(RuntimeError):
    pass


def names_for(lab_id: str) -> dict[str, str]:
    if not isinstance(lab_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,19}", lab_id):
        raise LifecycleError("lab ID must be an approved Terraform resource prefix")
    return {"server": f"{lab_id}-server", "worker-1": f"{lab_id}-worker", "worker-2": f"{lab_id}-worker-2"}


def validate_config(config: dict) -> None:
    if (config.get("projectId") != PROJECT_ID or str(config.get("projectNumber")) != PROJECT_NUMBER
            or config.get("zone") != ZONE):
        raise LifecycleError("lifecycle target must match the designated project number and zone")
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]@kordex-fleet-platform-515416\.iam\.gserviceaccount\.com",
                        str(config.get("terraformPrincipalEmail", ""))):
        raise LifecycleError("dedicated Terraform impersonation target is required")
    if not isinstance(config.get("organizationId"), str) or not re.fullmatch(r"[0-9a-f-]{36}", config["organizationId"]):
        raise LifecycleError("an exact control-plane organization ID is required")
    if not isinstance(config.get("clusterId"), str) or not re.fullmatch(r"[0-9a-f-]{36}", config["clusterId"]):
        raise LifecycleError("an exact registered cluster ID is required")


class ControlPlaneClient:
    """Small TLS-only client for the durable cluster lifecycle API."""

    def __init__(self, base_url: str, organization_id: str, cluster_id: str, token_file: Path,
                 tls_certificate_sha256: str, *, opener=None):
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise LifecycleError("control-plane URL must be an HTTPS origin without embedded credentials")
        if (not re.fullmatch(r"[0-9a-f]{64}", tls_certificate_sha256)
                or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", organization_id)
                or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", cluster_id)):
            raise LifecycleError("a pinned control-plane certificate and exact UUID identities are required")
        try:
            descriptor = os.open(token_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                        or info.st_uid != os.getuid() or info.st_size <= 0 or info.st_size > 16 * 1024):
                    raise LifecycleError("control-plane token file must be a bounded private regular file owned by this user")
                token_bytes = source.read(16 * 1024 + 1)
            if len(token_bytes) > 16 * 1024:
                raise LifecycleError("control-plane token file exceeds its size limit")
            token = token_bytes.decode("utf-8").strip()
        except LifecycleError:
            raise
        except (OSError, UnicodeDecodeError) as error:
            raise LifecycleError("control-plane authentication token is unavailable or unsafe") from error
        if not token or any(ch.isspace() for ch in token):
            raise LifecycleError("control-plane authentication token is malformed")
        self.base_url = base_url.rstrip("/")
        self.path = f"/v1/organizations/{organization_id}/clusters/{cluster_id}/lab-lifecycle"
        self.authorization = "Bearer " + token
        self.tls_certificate_sha256 = tls_certificate_sha256
        self.opener = opener

    def request(self, action: str = "", *, method: str = "GET") -> dict:
        if action and not re.fullmatch(r"[a-z]+(?:/[a-z]+)?", action):
            raise LifecycleError("invalid lifecycle action")
        try:
            if self.opener is not None:
                # Injection is reserved for local tests. Production uses the
                # certificate-pinned HTTPS path below.
                data = self.opener(method, self.base_url + self.path + ("/" + action if action else ""),
                                   self.authorization, self.tls_certificate_sha256)
            else:
                parsed = urlsplit(self.base_url)
                connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                                          context=ssl.create_default_context(), timeout=15)
                try:
                    connection.connect()
                    certificate = connection.sock.getpeercert(binary_form=True)
                    if hashlib.sha256(certificate).hexdigest() != self.tls_certificate_sha256:
                        raise LifecycleError("control-plane TLS certificate pin mismatch")
                    path = (parsed.path.rstrip("/") + self.path + ("/" + action if action else "")) or "/"
                    connection.request(method, path, headers={"Authorization": self.authorization,
                                        "Accept": "application/json", "Content-Length": "0"})
                    response = connection.getresponse()
                    if response.status < 200 or response.status >= 300:
                        raise LifecycleError("control-plane rejected lifecycle request")
                    data = response.read(256 * 1024 + 1)
                finally:
                    connection.close()
        except LifecycleError:
            raise
        except (TimeoutError, OSError, http.client.HTTPException) as error:
            # Authentication material and response bodies are deliberately omitted.
            raise LifecycleError("control-plane lifecycle request failed; barrier state is not assumed") from error
        if len(data) > 256 * 1024:
            raise LifecycleError("control-plane lifecycle response exceeded its size limit")
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LifecycleError("control-plane returned invalid lifecycle JSON") from error
        if not isinstance(value, dict) or value.get("state") not in PHASES:
            raise LifecycleError("control-plane returned an unknown lifecycle state")
        return value


class GCloudLab:
    """Fixed-project GCE adapter; no delete or Terraform mutation methods exist."""

    def __init__(self, config: dict, identity: dict, baseline: dict, run: Callable, *, sleep=time.sleep):
        validate_config(config)
        self.config, self.identity, self.baseline, self.run, self.sleep = config, identity, baseline, run, sleep
        self.names = names_for(config["labId"])
        instance_rows = identity.get("instances")
        if (not isinstance(instance_rows, list) or len(instance_rows) != 3
                or any(not isinstance(item, dict) or item.get("role") not in ROLES for item in instance_rows)
                or len({item["role"] for item in instance_rows}) != 3):
            raise LifecycleError("post-create evidence must contain each lab node role exactly once")
        self.expected = {item["role"]: item for item in instance_rows}
        if (identity.get("projectId") != PROJECT_ID or str(identity.get("zone", "")).split("/")[-1] != ZONE
                or identity.get("labId") != config["labId"]
                or not re.fullmatch(r"[1-9][0-9]{0,19}", str(identity.get("imageUniqueId", "")))
                or set(self.expected) != set(ROLES)
                or any(self.expected[r].get("name") != self.names[r] for r in ROLES)):
            raise LifecycleError("post-create identity evidence does not contain the exact three Terraform lab nodes")
        if not re.fullmatch(r"https://www\.googleapis\.com/compute/v1/projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,62}", str(identity.get("imageSelfLink", ""))):
            raise LifecycleError("identity evidence does not bind a concrete approved image self-link")
        for role, item in self.expected.items():
            if (not re.fullmatch(r"[1-9][0-9]{0,19}", str(item.get("instanceId", "")))
                    or not re.fullmatch(r"[1-9][0-9]{0,19}", str(item.get("bootDiskId", "")))
                    or item.get("sourceImage") != identity["imageSelfLink"]
                    or str(item.get("sourceImageId")) != str(identity["imageUniqueId"])
                    or not isinstance(item.get("bootDiskSelfLink"), str)
                    or item.get("bootDiskName") != f"{config['labId']}-{'server' if role == 'server' else 'worker' if role == 'worker-1' else 'worker-2'}"):
                raise LifecycleError(f"image evidence is incomplete or conflicting for {role}")
        if (baseline.get("schema") != "kordex-m3-recovery-baseline-v1"
                or (baseline.get("project") or {}).get("projectId") != PROJECT_ID
                or baseline.get("labId") != config["labId"] or baseline.get("zone") != ZONE
                or set(baseline.get("nodes", {})) != set(ROLES)):
            raise LifecycleError("a matching three-host recovery baseline is required before VM startup")

    def _gcloud(self, args: list[str], timeout: int = 45) -> str:
        full_args = [*args, f"--project={PROJECT_ID}", f"--impersonate-service-account={self.config['terraformPrincipalEmail']}"]
        try:
            command, env, _context = gcloud_context.command(full_args)
            return self.run(command, cwd=Path.cwd(), capture=True, timeout=timeout, env=env)
        except Exception as error:
            raise LifecycleError("trusted GCP lifecycle command failed; no success is inferred") from error

    def _json(self, args: list[str]) -> dict:
        try:
            result = json.loads(self._gcloud([*args, "--format=json"]))
        except (TypeError, json.JSONDecodeError) as error:
            raise LifecycleError("GCP returned invalid lifecycle inventory") from error
        if not isinstance(result, dict):
            raise LifecycleError("GCP returned an unexpected lifecycle resource")
        return result

    def verify_project(self) -> None:
        project = self._json(["projects", "describe", PROJECT_ID])
        if (project.get("projectId") != PROJECT_ID or str(project.get("projectNumber")) != PROJECT_NUMBER
                or project.get("lifecycleState") != "ACTIVE"
                or (project.get("labels") or {}).get("kordex-disposable") != "qualification"):
            raise LifecycleError("GCP project identity or disposable designation failed verification")

    def instance(self, role: str) -> dict:
        name = self.names[role]
        item = self._json(["compute", "instances", "describe", name, f"--zone={ZONE}"])
        expected_labels = {"application": "kordex", "purpose": "disposable-qualification",
                           "managed-by": "terraform", "lab-id": self.config["labId"], "node-role": role}
        if (item.get("name") != name or str(item.get("id")) != str(self.expected[role].get("instanceId"))
                or item.get("zone", "").rstrip("/").endswith(f"/zones/{ZONE}") is False
                or any((item.get("labels") or {}).get(k) != v for k, v in expected_labels.items())):
            raise LifecycleError(f"VM {name} is not the approved Terraform-managed disposable node")
        interfaces = item.get("networkInterfaces") or []
        if (len(interfaces) != 1 or not interfaces[0].get("networkIP") or interfaces[0].get("accessConfigs")
                or interfaces[0].get("network", "").rstrip("/").endswith(f"/networks/{self.config['labId']}-network") is False):
            raise LifecycleError(f"VM {name} does not have the approved private-only VPC attachment")
        disks = [d for d in item.get("disks", []) if isinstance(d, dict) and d.get("boot") is True]
        if len(disks) != 1 or not isinstance(disks[0].get("source"), str):
            raise LifecycleError(f"VM {name} does not have exactly one identifiable boot disk")
        disk_name = disks[0]["source"].rsplit("/", 1)[-1]
        disk = self._json(["compute", "disks", "describe", disk_name, f"--zone={ZONE}"])
        approved = self.expected[role]
        if (disk.get("name") != approved.get("bootDiskName", disk_name)
                or str(disk.get("id")) != str(approved.get("bootDiskId"))
                or disk.get("selfLink") != approved.get("bootDiskSelfLink")
                or str(disk.get("sourceImageId", "")) != str(self.identity.get("imageUniqueId"))):
            raise LifecycleError(f"VM {name} boot disk no longer matches the approved image/disk identity")
        source_image = disk.get("sourceImage", "")
        prefix = "https://www.googleapis.com/compute/v1/"
        if source_image.startswith(prefix):
            source_image = source_image[len(prefix):]
        approved_image = self.identity.get("imageSelfLink", "")
        if approved_image.startswith(prefix):
            approved_image = approved_image[len(prefix):]
        if source_image != approved_image:
            raise LifecycleError(f"VM {name} boot disk source image changed")
        return {"name": name, "role": role, "status": item.get("status"), "instanceId": str(item["id"]),
                "diskName": disk_name, "diskId": str(disk["id"]), "diskStatus": disk.get("status"),
                "internalIP": interfaces[0]["networkIP"]}

    def inventory(self) -> dict[str, dict]:
        self.verify_project()
        return {role: self.instance(role) for role in ROLES}

    def start(self, name: str) -> None:
        self._gcloud(["compute", "instances", "start", name, f"--zone={ZONE}", "--quiet"], timeout=180)

    def stop(self, name: str) -> None:
        self._gcloud(["compute", "instances", "stop", name, f"--zone={ZONE}", "--quiet"], timeout=180)

    def wait_for(self, desired: str, timeout: int) -> dict[str, dict]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            inventory = {role: self.instance(role) for role in ROLES}
            if all(item["status"] == desired for item in inventory.values()):
                return inventory
            self.sleep(5)
        raise LifecycleError(f"not all three lab VMs reached {desired}; lifecycle barrier remains active")

    def verify_running_hosts(self, *, require_new_boot: bool = False) -> None:
        expected_os = self.config.get("osIdentity")
        if (not isinstance(expected_os, dict) or expected_os.get("osId") not in {"debian", "rhel"}
                or not (re.fullmatch(r"13\.[0-9]+", str(expected_os.get("versionId", "")))
                        if expected_os.get("osId") == "debian" else
                        re.fullmatch(r"9\.(?:[8-9]|[1-9][0-9])", str(expected_os.get("versionId", ""))))
                or expected_os.get("architecture") != "amd64"):
            raise LifecycleError("exact approved Debian 13 point release or RHEL 9.8+ image identity is required")
        for role in ROLES:
            instance = self.expected[role]
            baseline = self.baseline["nodes"][role]
            if (str(instance.get("instanceId")) != str(baseline.get("instanceId"))
                    or not re.fullmatch(r"[a-f0-9]{32}", str(baseline.get("machineId", "")))):
                raise LifecycleError("recovery baseline does not bind the approved VM and machine identity")
            name = self.names[role]
            version_command = ("if [ -r /etc/debian_version ]; then cat /etc/debian_version; "
                               "else . /etc/os-release; printf '%s' \"$VERSION_ID\"; fi")
            script = ("printf '%s\\n' \"$(cat /etc/machine-id)\" \"$(cat /proc/sys/kernel/random/boot_id)\" "+
                      "\"$(. /etc/os-release; printf '%s' \"$ID\")\" "+
                      f"\"$({version_command})\" \"$(uname -r)\" \"$(uname -m)\"")
            lines = [line.strip() for line in self._gcloud(["compute", "ssh", name, f"--zone={ZONE}",
                     "--tunnel-through-iap", f"--command={script}", "--quiet"], timeout=60).splitlines() if line.strip()]
            boot_changed = len(lines) >= 5 and lines[-5] != baseline.get("bootId")
            if (len(lines) < 6 or lines[-6] != baseline["machineId"]
                    or (require_new_boot and not boot_changed)
                    or lines[-4] != expected_os["osId"] or lines[-3] != expected_os["versionId"]
                    or lines[-2] != baseline.get("kernelVersion") or lines[-1] != "x86_64"
                    or baseline.get("osId") != expected_os["osId"]
                    or baseline.get("osVersion") != expected_os["versionId"]
                    or baseline.get("architecture") != "x86_64"):
                raise LifecycleError(f"host or OS identity mismatch on {name}; startup remains fenced")

    def verify_kubernetes(self) -> None:
        context = self.config.get("kubeContext")
        if not isinstance(context, str) or not context:
            raise LifecycleError("an explicit disposable kube context is required for start health checks")
        import self_managed_lab_recovery as recovery

        observed = recovery.kubernetes_baseline(context, self.names, run=self.run)
        expected = {node.get("name"): node.get("uid") for node in self.baseline["kubernetes"]["nodes"]}
        actual = {node.get("name"): node.get("uid") for node in observed["nodes"]}
        if actual != expected:
            raise LifecycleError("Kubernetes Node identities changed since the approved recovery baseline")


class LabLifecycleController:
    def __init__(self, api, cloud, *, wait_seconds=900, sleep=time.sleep):
        self.api, self.cloud, self.wait_seconds, self.sleep = api, cloud, wait_seconds, sleep

    def status(self) -> dict:
        state = self.api.request()
        state["vmInventory"] = self.cloud.inventory()
        state["classification"] = "LIVE_READ_ONLY_STATUS"
        return state

    def stop(self) -> dict:
        state = self.api.request("stop", method="POST")
        if state["state"] == "STOPPED":
            inventory = self.cloud.inventory()
            if (not all(item["status"] == "TERMINATED" for item in inventory.values())
                    or not all(item["diskStatus"] == "READY" for item in inventory.values())):
                raise LifecycleError("durable STOPPED state disagrees with VM/disk inventory; lab remains fenced")
            return state
        deadline = time.monotonic() + self.wait_seconds
        while state["state"] == "DRAINING" and time.monotonic() < deadline:
            if state.get("unsafeOperations") or any(reason.startswith("failed_or_") for reason in state.get("blockers", [])):
                raise LifecycleError("failed or recovery-required operation retains the shutdown fence")
            self.sleep(2)
            # Repeated stop requests atomically re-evaluate and advance the
            # durable DRAINING barrier after terminal reports are persisted.
            state = self.api.request("stop", method="POST")
        if state["state"] != "READY_TO_STOP" or not state.get("canStop"):
            raise LifecycleError("operation recovery, reservation release, or final report is incomplete; VMs left running")
        self.api.request("stop/started", method="POST")
        inventory = self.cloud.inventory()
        if not all(item["status"] == "TERMINATED" for item in inventory.values()):
            self.cloud.verify_running_hosts(require_new_boot=False)
            self.cloud.verify_kubernetes()
        for role in STOP_ORDER:
            if inventory[role]["status"] == "RUNNING":
                self.cloud.stop(inventory[role]["name"])
            elif inventory[role]["status"] != "TERMINATED":
                raise LifecycleError("VM has an ambiguous power state; stop barrier remains active")
        stopped = self.cloud.wait_for("TERMINATED", self.wait_seconds)
        for item in stopped.values():
            if item["diskStatus"] != "READY":
                raise LifecycleError("persistent boot disk did not remain available after stop")
        return self.api.request("stop/complete", method="POST")

    def start(self) -> dict:
        current = self.api.request()
        if current["state"] == "RUNNING":
            self.cloud.inventory()
            self.cloud.verify_running_hosts(require_new_boot=False)
            self.cloud.verify_kubernetes()
            return current
        self.api.request("start", method="POST")
        inventory = self.cloud.inventory()
        for role in START_ORDER:
            item = inventory[role]
            if item["status"] == "TERMINATED":
                self.cloud.start(item["name"])
            elif item["status"] != "RUNNING":
                raise LifecycleError("VM has an ambiguous power state; start barrier remains active")
        inventory = self.cloud.wait_for("RUNNING", self.wait_seconds)
        self.cloud.verify_running_hosts(require_new_boot=True)
        self.cloud.verify_kubernetes()
        # Image and boot-disk identity were checked for every node in inventory;
        # the control-plane barrier opens only after all host checks pass.
        return self.api.request("start/complete", method="POST")

    def restart(self) -> dict:
        state = self.api.request()
        if state["state"] in {"STOPPING", "STARTING"}:
            # Resume an interrupted power transition by bringing the exact lab
            # back to a verified RUNNING state before beginning a new stop.
            self.start()
        elif state["state"] != "STOPPED":
            self.stop()
        return self.start()


def safe_token_path(value: str) -> Path:
    path = Path(value)
    if path.is_symlink():
        raise LifecycleError("token file symlinks are not accepted")
    return path


def json_sha256(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
