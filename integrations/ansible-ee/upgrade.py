#!/usr/bin/env python3
"""Fixed Kordex Ansible EE entrypoint; accepts only a Kordex request document."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import signal
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

CATALOG_PATH = Path("/usr/share/kordex/catalog.json")
PLAYBOOK_PATH = Path("/usr/share/kordex/upgrade-debian.yml")
RHEL_PLAYBOOK_PATH = Path("/usr/share/kordex/upgrade-rhel.yml")
PLAYBOOK_PATHS = {
    "kordex.os-upgrade.debian.v2": "debian",
    "kordex.os-upgrade.rhel.v1": "rhel",
}
SUPPORTED_OS_RELEASES = {
    ("ubuntu", "24", "04"): "debian",
    ("debian", "13", ""): "debian",
    ("amzn", "2023", ""): "rhel",
}
COLLECTIONS_LOCK_PATH = Path("/usr/share/kordex/collections.lock")
KEY_SOURCE = Path("/run/kordex/ssh/id_ed25519")
KNOWN_HOSTS = Path("/run/kordex/known-hosts/known_hosts")
RECEIPT_PREFIX = "KORDEX_EE_RECEIPT="


def supported_os_release(identity: tuple[str, str, str], family: str | None) -> bool:
    exact = SUPPORTED_OS_RELEASES.get(identity)
    if exact is not None:
        return exact == family
    os_id, major, minor = identity
    return (family == "rhel" and os_id == "rhel" and major == "9"
            and minor.isdigit() and int(minor) >= 8)
PACKET = re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,127}(?::[a-z0-9][a-z0-9_-]{0,31})?$")
VERSION = re.compile(r"^([0-9]+:)?[0-9][A-Za-z0-9.+:~_-]{0,127}$")
RPM_EVR = re.compile(r"^([0-9]+:)?[0-9][A-Za-z0-9.+~_^]*-[A-Za-z0-9][A-Za-z0-9.+~_^.-]*$")
IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$")
MACHINE_ID = re.compile(r"^[0-9a-fA-F]{32}$")
BOOT_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
KERNEL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,127}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
DNS_LABEL = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
NODE_NAME = re.compile(r"^" + DNS_LABEL + r"(?:\." + DNS_LABEL + r")*$")


def fail(message: str) -> None:
    print("KORDEX_EE_ERROR=" + message, flush=True)
    raise SystemExit(1)


class ExecutionInterrupted(Exception):
    """The EE process received a termination signal while Ansible was active."""


def terminate_process_group(process: subprocess.Popen, grace_seconds: float = 5.0) -> None:
    """Stop Ansible and its local SSH children before the container exits."""
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_seconds
    while True:
        process.poll()  # Reap the group leader so it does not hold its PGID as a zombie.
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                pass
            break
        time.sleep(0.05)
    process.wait()


def run_process_group(args: list[str], *, cwd: str, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    """Run a command in its own session and forward termination to its group."""
    process = subprocess.Popen(
        args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, start_new_session=True,
    )

    def interrupted(signum, _frame):
        raise ExecutionInterrupted(signum)

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in previous:
            signal.signal(sig, interrupted)
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        raise
    except BaseException:
        if process.poll() is None:
            terminate_process_group(process)
        raise
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return subprocess.CompletedProcess(args, process.returncode, stdout=stdout)


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
        identity = (policy["osId"], policy["osMajor"], policy.get("osMinor", ""))
        if any(not isinstance(value, str) for value in identity) or not supported_os_release(identity, policy.get("osFamily")):
            fail("UnsupportedOSIdentity")
        point_release = policy.get("osPointRelease", "")
        if not isinstance(point_release, str):
            fail("InvalidOSPointRelease")
        if identity[0] == "debian" and not re.fullmatch(r"13\.[0-9]+", point_release):
            fail("InvalidOSPointRelease")
        if identity[0] == "rhel" and point_release != f"9.{identity[2]}":
            fail("InvalidOSPointRelease")
        if identity[0] in {"ubuntu", "amzn"} and point_release:
            fail("InvalidOSPointRelease")
        schema_version = policy.get("schemaVersion")
        if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version not in (1, 2) or not isinstance(policy.get("id"), str):
            fail("InvalidUpgradePolicy")
        artifact_mode = policy.get("artifactMode", "")
        if (schema_version == 1 and artifact_mode) or (schema_version == 2 and artifact_mode != "OfflineArtifacts"):
            fail("InvalidArtifactMode")
        packages = policy["packages"]
        parts = [
            str(policy["schemaVersion"]),
            policy["id"],
            policy["osFamily"],
            policy["osId"],
            policy["osMajor"],
            policy.get("osMinor", ""),
            policy.get("osPointRelease", ""),
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
        marker_version = policy.get("actionMarkerVersion", 0)
        if not isinstance(marker_version, int) or isinstance(marker_version, bool) or marker_version != 1:
            fail("ActionMarkerRequired")
        parts.append("marker=" + str(marker_version))
        if schema_version == 2:
            parts.append("artifactMode=" + artifact_mode)
        if policy.get("expectedKernelVersion"):
            parts.append("kernel=" + policy["expectedKernelVersion"])
        for item in sorted(packages, key=lambda package: package["name"]):
            pin = item["name"] + "=" + item["version"]
            if schema_version == 2:
                artifact_sha = item.get("artifactSHA256", "")
                if not re.fullmatch(r"[a-f0-9]{64}", str(artifact_sha)):
                    fail("OfflineArtifactDigestRequired")
                pin += "@sha256:" + artifact_sha
            elif item.get("artifactSHA256"):
                fail("UnexpectedArtifactDigest")
            parts.append(pin)
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
    schema_version = policy.get("schemaVersion")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version not in (1, 2):
        fail("UnsupportedPolicySchema")
    if schema_version == 1 and (policy.get("artifactMode") or any(item.get("artifactSHA256") for item in policy.get("packages", []) if isinstance(item, dict))):
        fail("UnexpectedOfflineArtifactFields")
    if schema_version == 2 and policy.get("artifactMode") != "OfflineArtifacts":
        fail("InvalidArtifactMode")
    if request.get("phase") not in ("preflight", "apply", "reboot", "inspect"):
        fail("UnsupportedPhase")
    if not UUID.fullmatch(str(request.get("operationId", ""))) or not UUID.fullmatch(str(node.get("uid", ""))):
        fail("InvalidOperationOrNodeIdentity")
    if not isinstance(node.get("name"), str) or len(node["name"]) > 253 or not NODE_NAME.fullmatch(node["name"]):
        fail("InvalidNodeName")
    if policy.get("executionBackend") != "ansible-ee":
        fail("UnsupportedCatalog")
    catalog_id = policy.get("playbookCatalogId")
    catalog_spec = PLAYBOOK_PATHS.get(catalog_id)
    if catalog_spec is None:
        fail("CatalogMismatch")
    expected_family = catalog_spec
    if policy.get("osFamily") != expected_family:
        fail("CatalogMismatch")
    identity = (policy.get("osId"), policy.get("osMajor"), policy.get("osMinor", ""))
    if any(not isinstance(value, str) for value in identity) or not supported_os_release(identity, expected_family):
        fail("UnsupportedOSIdentity")
    point_release = policy.get("osPointRelease", "")
    if not isinstance(point_release, str):
        fail("InvalidOSPointRelease")
    if identity[0] == "debian" and not re.fullmatch(r"13\.[0-9]+", point_release):
        fail("InvalidOSPointRelease")
    if identity[0] == "rhel" and point_release != f"9.{identity[2]}":
        fail("InvalidOSPointRelease")
    marker_version = policy.get("actionMarkerVersion", 0)
    if not isinstance(marker_version, int) or isinstance(marker_version, bool) or marker_version != 1:
        fail("ActionMarkerRequired")
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
        if policy.get("osFamily") == "debian" and "_" in package["name"]:
            fail("InvalidPackagePin")
        package_name = str(package["name"]).lower()
        if package_name != package["name"]:
            fail("InvalidPackagePin")
        if package_name in seen_packages:
            fail("DuplicatePackagePin")
        seen_packages.add(package_name)
        if package["version"].lower() in ("latest", "stable", "current", "*") or any(char in package["version"] for char in "*?"):
            fail("FloatingPackageVersion")
        artifact_sha = package.get("artifactSHA256", "")
        if schema_version == 2 and not re.fullmatch(r"[a-f0-9]{64}", str(artifact_sha)):
            fail("OfflineArtifactDigestRequired")
        if schema_version == 1 and artifact_sha:
            fail("UnexpectedOfflineArtifactFields")
        if policy.get("osFamily") == "rhel" and not RPM_EVR.fullmatch(package["version"]):
            fail("RpmPackagePinMustIncludeRelease")
        package_base_name = package_name.split(":", 1)[0]
        is_kernel = (
            package_base_name == "kernel"
            or package_base_name.startswith("kernel-")
            or any(
                package_base_name == family or package_base_name.startswith(family + "-")
                for family in (
                    "linux-image", "linux-modules", "linux-headers", "linux-generic",
                    "linux-virtual", "linux-lowlatency", "linux-oem", "linux-signed", "linux-azure",
                    "linux-gcp", "linux-kvm", "linux-cloud-tools", "linux-tools",
                    "linux-firmware",
                )
            )
        )
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


def validate_catalog(policy: dict) -> Path:
    try:
        catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("CatalogUnavailable")
    expected_family = PLAYBOOK_PATHS.get(policy.get("playbookCatalogId"))
    if expected_family is None or expected_family != policy.get("osFamily"):
        fail("CatalogPolicyMismatch")
    identity = (policy.get("osId"), policy.get("osMajor"), policy.get("osMinor", ""))
    if any(not isinstance(value, str) for value in identity) or not supported_os_release(identity, expected_family):
        fail("UnsupportedOSIdentity")
    playbook_path = PLAYBOOK_PATH if expected_family == "debian" else RHEL_PLAYBOOK_PATH
    playbook_digest = hashlib.sha256(playbook_path.read_bytes()).hexdigest()
    collections_digest = hashlib.sha256(COLLECTIONS_LOCK_PATH.read_bytes()).hexdigest()
    base_image = catalog.get("baseImage")
    ansible_version = catalog.get("ansibleVersion")
    catalogs = catalog.get("catalogs")
    entry = catalogs.get(policy.get("playbookCatalogId")) if isinstance(catalogs, dict) else None
    if catalogs is not None and (catalog.get("schemaVersion") != 1 or not isinstance(entry, dict) or entry.get("playbook") != playbook_path.name):
        fail("CatalogPolicyMismatch")
    if not isinstance(entry, dict) or entry.get("osFamily") != expected_family or entry.get("playbookDigest") != policy.get("playbookDigest") or entry.get("collectionsDigest", catalog.get("collectionsDigest")) != policy.get("collectionsDigest") or entry.get("actionMarkerVersion", catalog.get("actionMarkerVersion", 0)) != policy.get("actionMarkerVersion", 0):
        fail("CatalogPolicyMismatch")
    releases = entry.get("osReleases")
    release = {"osId": identity[0], "major": identity[1], "minor": identity[2]}
    minimum_minor = entry.get("minimumMinor")
    exact_release = isinstance(releases, list) and release in releases
    ranged_rhel = (expected_family == "rhel" and identity[0] == "rhel" and identity[1] == "9"
                   and isinstance(minimum_minor, str) and minimum_minor.isdigit()
                   and identity[2].isdigit() and int(identity[2]) >= int(minimum_minor))
    if not exact_release and not ranged_rhel:
        fail("CatalogOSIdentityMismatch")
    if not IMAGE_DIGEST.fullmatch(str(base_image or "")) or not isinstance(ansible_version, str) or not ansible_version.startswith("ansible-playbook ") or len(ansible_version) > 128:
        fail("CatalogRuntimeIdentityInvalid")
    if playbook_digest != entry.get("playbookDigest") or collections_digest != entry.get("collectionsDigest", catalog.get("collectionsDigest")):
        fail("CatalogContentChanged")
    try:
        runtime_version = subprocess.run(["ansible-playbook", "--version"], check=True, capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        fail("AnsibleRuntimeUnavailable")
    if runtime_version != ansible_version:
        fail("CatalogRuntimeChanged")
    return playbook_path


def run(request_path: Path, result_path: Path) -> None:
    request = read_request(request_path)
    policy = request["policy"]
    playbook_path = validate_catalog(policy)
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
        + " ansible_ssh_common_args='-o HostKeyAlias=" + request["node"]["name"] + "'"
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
        "ssh_args = -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o CheckHostIP=no -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=" + str(KNOWN_HOSTS) + "\n",
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
    # Do not inherit arbitrary ANSIBLE_*, Python, or SSH variables from the
    # pod environment. The execution contract is fixed by the image and files
    # above; unrelated pod configuration must not select plugins, callbacks,
    # Python modules, SSH agents, or alternate configuration.
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "ANSIBLE_CONFIG": str(ansible_cfg),
        "HOME": str(work / "home"),
        "ANSIBLE_HOME": str(work / "ansible"),
        "ANSIBLE_LOCAL_TEMP": str(work / "tmp"),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_HOST_KEY_CHECKING": "True",
    }
    try:
        completed = run_process_group(
            ["ansible-playbook", "-i", str(inventory), "-e", "@" + str(extra_vars), str(playbook_path)],
            cwd=str(work), env=env, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        fail("ExecutionTimedOutAmbiguous")
    except ExecutionInterrupted:
        fail("ExecutionInterruptedAmbiguous")
    except OSError:
        fail("ExecutionEnvironmentUnavailable")
    if completed.returncode != 0:
        output = (completed.stdout or "").casefold()
        if "host key verification failed" in output or "remote host identification has changed" in output:
            fail("SSHHostKeyVerificationFailed")
        if "permission denied" in output and "publickey" in output:
            fail("SSHAuthenticationFailed")
        if any(message in output for message in ("connection timed out", "no route to host", "connection refused", "network is unreachable")):
            fail("SSHTransportUnavailable")
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
