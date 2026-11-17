#!/usr/bin/env python3
"""Fixed Kordex Ansible EE entrypoint; accepts only a Kordex request document."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CATALOG_PATH = Path("/usr/share/kordex/catalog.json")
PLAYBOOK_PATH = Path("/usr/share/kordex/upgrade-debian.yml")
COLLECTIONS_LOCK_PATH = Path("/usr/share/kordex/collections.lock")
KEY_SOURCE = Path("/run/kordex/ssh/id_ed25519")
KNOWN_HOSTS = Path("/run/kordex/known-hosts/known_hosts")
RECEIPT_PREFIX = "KORDEX_EE_RECEIPT="
PACKET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:-]{0,127}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:~^-]{0,127}$")
IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$")
MACHINE_ID = re.compile(r"^[0-9a-fA-F]{32}$")
BOOT_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
KERNEL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,127}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def fail(message: str) -> None:
    print("KORDEX_EE_ERROR=" + message, flush=True)
    raise SystemExit(1)


def go_duration_string(value: int) -> str:
    """Format the bounded positive nanosecond values like time.Duration.String."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        fail("InvalidTimeout")
    hour_ns = 3_600_000_000_000
    minute_ns = 60_000_000_000
    second_ns = 1_000_000_000

    def seconds_string(nanoseconds: int) -> str:
        seconds, fractional = divmod(nanoseconds, second_ns)
        if fractional == 0:
            return str(seconds) + "s"
        return str(seconds) + "." + f"{fractional:09d}".rstrip("0") + "s"

    if value >= hour_ns:
        hours, remainder = divmod(value, hour_ns)
        minutes, seconds = divmod(remainder, minute_ns)
        return f"{hours}h{minutes}m" + seconds_string(seconds)
    if value >= minute_ns:
        minutes, remainder = divmod(value, minute_ns)
        return f"{minutes}m" + seconds_string(remainder)
    return seconds_string(value)


def upgrade_policy_digest(policy: dict) -> str:
    """Recompute protocol.UpgradePolicy.Digest from the immutable EE request."""
    try:
        if policy.get("schemaVersion") != 1 or not isinstance(policy.get("id"), str):
            fail("InvalidUpgradePolicy")
        packages = policy["packages"]
        parts = [
            str(policy["schemaVersion"]),
            policy["id"],
            policy["osFamily"],
            policy["executionBackend"],
            policy["playbookCatalogId"],
            policy["executionEnvironment"],
            policy["playbookDigest"],
            policy["collectionsDigest"],
            policy["channel"],
            policy["reboot"],
            go_duration_string(policy["executionTimeout"]),
            go_duration_string(policy["rebootTimeout"]),
            go_duration_string(policy["verificationTimeout"]),
            "attempts=" + str(policy["maxAttempts"]),
        ]
        if policy.get("expectedKernelVersion"):
            parts.append("kernel=" + policy["expectedKernelVersion"])
        parts.extend(name + "=" + version for name, version in sorted((item["name"], item["version"]) for item in packages))
        parts.extend("pre=" + hook for hook in sorted(policy.get("preHooks") or []))
        parts.extend("post=" + hook for hook in sorted(policy.get("postHooks") or []))
    except (KeyError, TypeError, ValueError):
        fail("InvalidUpgradePolicy")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def read_request(path: Path) -> dict:
    try:
        request = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("InvalidRequest")
    if not isinstance(request, dict):
        fail("InvalidRequest")
    policy = request.get("policy")
    node = request.get("node")
    if not isinstance(policy, dict) or not isinstance(node, dict):
        fail("InvalidRequest")
    if request.get("phase") not in ("preflight", "apply", "reboot", "inspect"):
        fail("UnsupportedPhase")
    if not UUID.fullmatch(str(request.get("operationId", ""))) or not UUID.fullmatch(str(node.get("uid", ""))):
        fail("InvalidOperationOrNodeIdentity")
    if not isinstance(node.get("name"), str) or not node["name"] or len(node["name"]) > 253:
        fail("InvalidNodeName")
    if policy.get("osFamily") != "debian" or policy.get("executionBackend") != "ansible-ee":
        fail("UnsupportedCatalog")
    if policy.get("playbookCatalogId") != "kordex.os-upgrade.debian.v2":
        fail("CatalogMismatch")
    if policy.get("channel") != "stable":
        fail("UnsupportedChannel")
    if policy.get("preHooks") or policy.get("postHooks"):
        fail("HooksNotImplementedInCatalog")
    if not IMAGE_DIGEST.fullmatch(str(policy.get("executionEnvironment", ""))) or not re.fullmatch(r"[a-f0-9]{64}", str(policy.get("playbookDigest", ""))) or not re.fullmatch(r"[a-f0-9]{64}", str(policy.get("collectionsDigest", ""))):
        fail("InvalidCatalogDigest")
    if not isinstance(policy.get("packages"), list) or not 1 <= len(policy["packages"]) <= 128:
        fail("InvalidPackageList")
    seen_packages = set()
    has_kernel_package = False
    for package in policy["packages"]:
        if not isinstance(package, dict) or not PACKET.fullmatch(str(package.get("name", ""))) or not VERSION.fullmatch(str(package.get("version", ""))):
            fail("InvalidPackagePin")
        package_name = str(package["name"]).lower()
        if package_name != package["name"]:
            fail("InvalidPackagePin")
        if package_name in seen_packages:
            fail("DuplicatePackagePin")
        seen_packages.add(package_name)
        if package["version"].lower() in ("latest", "stable", "current", "*") or any(char in package["version"] for char in "*?"):
            fail("FloatingPackageVersion")
        is_kernel = package_name.startswith(("linux-image", "linux-modules")) or package_name == "kernel" or package_name.startswith("kernel-")
        has_kernel_package = has_kernel_package or is_kernel
        if is_kernel and policy.get("reboot") == "Never":
            fail("KernelUpgradeRequiresRebootPolicy")
    expected_kernel = policy.get("expectedKernelVersion", "")
    if has_kernel_package != bool(expected_kernel) or expected_kernel and not KERNEL_VERSION.fullmatch(str(expected_kernel)):
        fail("ExpectedKernelVersionRequired")
    if request["phase"] in ("apply", "reboot", "inspect") and (not node.get("machineId") or not node.get("bootId")):
        fail("PreflightIdentityRequired")
    if request["phase"] == "reboot" and policy.get("reboot") == "Never":
        fail("RebootNotAllowedByPolicy")
    reboot_authorized = request.get("rebootAuthorized") is True
    if reboot_authorized != (request["phase"] == "reboot"):
        fail("RebootAuthorizationMismatch")
    try:
        ipaddress.ip_address(node["address"])
    except (ValueError, KeyError, TypeError):
        fail("InvalidTargetAddress")
    if not re.fullmatch(r"[0-9a-f]{64}", str(request.get("planDigest", ""))):
        fail("InvalidPlanDigest")
    if upgrade_policy_digest(policy) != request["planDigest"]:
        fail("UpgradePlanDigestMismatch")
    return request


def validate_catalog(policy: dict) -> None:
    try:
        catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("CatalogUnavailable")
    playbook_digest = hashlib.sha256(PLAYBOOK_PATH.read_bytes()).hexdigest()
    collections_digest = hashlib.sha256(COLLECTIONS_LOCK_PATH.read_bytes()).hexdigest()
    base_image = catalog.get("baseImage")
    ansible_version = catalog.get("ansibleVersion")
    if catalog.get("catalogId") != policy.get("playbookCatalogId") or catalog.get("playbookDigest") != policy.get("playbookDigest") or catalog.get("collectionsDigest") != policy.get("collectionsDigest"):
        fail("CatalogPolicyMismatch")
    if not IMAGE_DIGEST.fullmatch(str(base_image or "")) or not isinstance(ansible_version, str) or not ansible_version.startswith("ansible-playbook ") or len(ansible_version) > 128:
        fail("CatalogRuntimeIdentityInvalid")
    if playbook_digest != catalog.get("playbookDigest") or collections_digest != catalog.get("collectionsDigest"):
        fail("CatalogContentChanged")
    try:
        runtime_version = subprocess.run(["ansible-playbook", "--version"], check=True, capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        fail("AnsibleRuntimeUnavailable")
    if runtime_version != ansible_version:
        fail("CatalogRuntimeChanged")


def run(request_path: Path, result_path: Path) -> None:
    request = read_request(request_path)
    policy = request["policy"]
    validate_catalog(policy)
    ssh_user = os.environ.get("KORDEX_ANSIBLE_USER", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", ssh_user):
        fail("SSHUserUnavailable")
    if not KEY_SOURCE.is_file() or not KNOWN_HOSTS.is_file() or KNOWN_HOSTS.stat().st_size == 0:
        fail("SSHTrustMaterialUnavailable")

    work = Path("/var/run/kordex")
    work.mkdir(parents=True, exist_ok=True)
    for directory in (work / "home", work / "ansible", work / "tmp"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_path = work / "id_ed25519"
    shutil.copyfile(KEY_SOURCE, key_path)
    key_path.chmod(0o600)
    inventory = work / "inventory.ini"
    inventory.write_text(
        "[kordex_target]\n"
        + "target ansible_host=" + str(ipaddress.ip_address(request["node"]["address"]))
        + " ansible_user=" + ssh_user
        + " ansible_ssh_private_key_file=" + str(key_path)
        + " ansible_python_interpreter=auto_silent\n",
        encoding="utf-8",
    )
    inventory.chmod(0o600)
    ansible_cfg = work / "ansible.cfg"
    ansible_cfg.write_text(
        "[defaults]\n"
        "host_key_checking = True\n"
        "retry_files_enabled = False\n"
        "interpreter_python = auto_silent\n"
        "stdout_callback = default\n"
        "[ssh_connection]\n"
        "ssh_args = -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + str(KNOWN_HOSTS) + "\n",
        encoding="utf-8",
    )
    ansible_cfg.chmod(0o600)
    extra_vars = work / "request.json"
    shutil.copyfile(request_path, extra_vars)
    extra_vars.chmod(0o600)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        timeout_ns = int(policy["executionTimeout"]) + int(policy["rebootTimeout"]) + int(policy["verificationTimeout"])
        timeout_seconds = max(60, min(8 * 60 * 60, (timeout_ns + 999_999_999) // 1_000_000_000))
    except (KeyError, TypeError, ValueError):
        fail("InvalidTimeout")
    env = os.environ.copy()
    env["ANSIBLE_CONFIG"] = str(ansible_cfg)
    env["HOME"] = str(work / "home")
    env["ANSIBLE_HOME"] = str(work / "ansible")
    env["ANSIBLE_LOCAL_TEMP"] = str(work / "tmp")
    env["ANSIBLE_NOCOLOR"] = "1"
    env["ANSIBLE_HOST_KEY_CHECKING"] = "True"
    try:
        completed = subprocess.run(
            ["ansible-playbook", "-i", str(inventory), "-e", "@" + str(extra_vars), str(PLAYBOOK_PATH)],
            cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        fail("ExecutionTimedOutAmbiguous")
    except OSError:
        fail("ExecutionEnvironmentUnavailable")
    if completed.returncode != 0:
        fail("PlaybookFailedAmbiguous")
    try:
        receipt = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("ReceiptUnavailable")
    if receipt.get("operationId") != request.get("operationId") or receipt.get("planDigest") != request.get("planDigest") or receipt.get("nodeUid") != request["node"].get("uid"):
        fail("ReceiptIdentityMismatch")
    receipt["completedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    print(RECEIPT_PREFIX + json.dumps(receipt, separators=(",", ":"), sort_keys=True), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    if args.request != "/etc/kordex/request.json" or args.result != "/var/run/kordex/result.json":
        fail("InvalidEntrypointArguments")
    run(Path(args.request), Path(args.result))


if __name__ == "__main__":
    main()
