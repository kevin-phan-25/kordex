#!/usr/bin/env python3
"""Compose existing Kordex trust/artifact verifiers into an M3 intake report.

The report is a deterministic point-in-time summary, not a new signature or
trust format. Each trust domain is checked independently with its existing
verifier. Customer inputs are described by paths in a local JSON file; paths
and credential locations are never copied to the report.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Callable
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[a-f0-9]{64}$")
KEY_ID = re.compile(r"^[a-f0-9]{64}$")
EXPECTED_K3S = "v1.36.6+k3s1"
EXPECTED_ARCH = "linux/amd64"
REQUIRED_KORDEX_IMAGES = ("agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres")
REQUIRED_ARTIFACTS = (
    "maintenancePublicTrust", "artifactApprovalTrust", "releasePublicTrust", "toolProvenancePublicTrust",
    "signedReleaseBundle", "signedImageDigestLock", "k3sBinaryApproval", "k3sSystemImageApproval",
    "privateRegistryImages", "hostPackageArtifacts", "helmSignerAllowlist", "requiredKordexImages",
)

SUPPORTED_PACKAGE_OS = {
    ("ubuntu", "24", "04"): "debian",
    ("debian", "13", ""): "debian",
    ("amzn", "2023", ""): "rhel",
}


def supported_package_os(os_id: str, major: str, minor: str) -> str | None:
    """Return the package family for M3-supported identities; RHEL has a floor."""
    exact = SUPPORTED_PACKAGE_OS.get((os_id, major, minor))
    if exact is not None:
        return exact
    if os_id == "rhel" and major == "9" and minor.isdigit() and int(minor) >= 8:
        return "rhel"
    return None


class PreflightError(ValueError):
    pass


def _load_stager():
    path = ROOT / "scripts/install-offline-package-artifacts.py"
    spec = importlib.util.spec_from_file_location("kordex_package_artifact_stager", path)
    if spec is None or spec.loader is None:
        raise PreflightError("fixed package artifact verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path: Path, limit: int = 2 * 1024 * 1024) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
                raise PreflightError("input must be a bounded regular file")
            data = source.read(limit + 1)
            after = os.fstat(source.fileno())
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(data) != info.st_size:
                raise PreflightError("input changed while being read")
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreflightError("input JSON is unavailable or invalid") from error
    if not isinstance(value, dict):
        raise PreflightError("input JSON must be an object")
    return value


def hash_file(path: Path, limit: int = 16 * 1024 * 1024 * 1024) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise PreflightError("input file is unavailable or unsafe") from error
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > limit:
            raise PreflightError("input file must be a bounded regular file")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise PreflightError("input file changed during verification")
    return digest.hexdigest()


def read_regular_bytes(path: Path, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise PreflightError("input file is unavailable or unsafe") from error
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > limit:
            raise PreflightError("input file must be a bounded regular file")
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
        if len(data) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise PreflightError("input file changed while being read")
    return data


def path_value(obj: dict, *parts: str) -> Path | None:
    value = obj
    for key in parts:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    if not isinstance(value, str) or not value:
        return None
    return Path(value)


def artifact(status: str = "NOT PROVIDED", **details) -> dict:
    if status == "NOT PROVIDED":
        details.setdefault("code", "InputNotProvided")
    return {"status": status, **details}


def verify_public_ed25519_bundle(path: Path, expected_ids: list[str]) -> dict:
    bundle = read_json(path, 16 * 1024)
    if (not isinstance(expected_ids, list) or not expected_ids
            or any(not isinstance(item, str) or not KEY_ID.fullmatch(item) for item in expected_ids)
            or len(set(expected_ids)) != len(expected_ids)):
        raise PreflightError("independent expected public key IDs are missing or malformed")
    if not bundle or list(bundle) != sorted(bundle) or set(bundle) != set(expected_ids):
        raise PreflightError("public trust key IDs do not match the independent expected identity")
    for key_id, encoded in bundle.items():
        if not KEY_ID.fullmatch(key_id) or not isinstance(encoded, str):
            raise PreflightError("public trust bundle key entry is malformed")
        try:
            raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise PreflightError("public trust key encoding is invalid") from error
        if len(raw) != 32 or base64.b64encode(raw).decode().rstrip("=") != encoded or hashlib.sha256(raw).hexdigest() != key_id:
            raise PreflightError("public trust key fingerprint does not match its key ID")
    return {"keyIds": sorted(bundle), "fingerprints": sorted(bundle)}


def verify_artifact_trust(path: Path, expected_ids: list[str]) -> dict:
    try:
        lines = read_regular_bytes(path, 16 * 1024).decode("ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise PreflightError("customer artifact trust is unavailable") from error
    if (not lines or lines[0] != "KORDEX-CUSTOMER-ARTIFACT-TRUST-V1"
            or not isinstance(expected_ids, list) or not expected_ids
            or any(not isinstance(item, str) or not KEY_ID.fullmatch(item) for item in expected_ids)
            or len(set(expected_ids)) != len(expected_ids)):
        raise PreflightError("customer artifact trust format or independent key IDs are missing")
    records = {}
    previous = ""
    for line in lines[1:]:
        fields = line.split(" ")
        if len(fields) != 2 or not KEY_ID.fullmatch(fields[0]) or fields[0] <= previous:
            raise PreflightError("customer artifact trust bundle is ambiguous or unsorted")
        try:
            key = base64.b64decode(fields[1] + "=" * (-len(fields[1]) % 4), validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise PreflightError("customer artifact public key encoding is invalid") from error
        if len(key) != 32 or base64.b64encode(key).decode().rstrip("=") != fields[1] or hashlib.sha256(key).hexdigest() != fields[0]:
            raise PreflightError("customer artifact public key fingerprint does not match")
        records[fields[0]] = key
        previous = fields[0]
    if set(records) != set(expected_ids):
        raise PreflightError("customer artifact key IDs differ from independently confirmed IDs")
    return {"keyIds": sorted(records), "fingerprints": sorted(records)}


def public_key_fingerprint(path: Path, expected: str, run: Callable = subprocess.run) -> dict:
    if not SHA256.fullmatch(expected):
        raise PreflightError("independent public-key fingerprint is missing or malformed")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PreflightError("public key must be a regular file")
    try:
        result = run(["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"], check=True,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise PreflightError("public key format is not accepted by OpenSSL") from error
    if not result.stdout.startswith(bytes.fromhex("302a300506032b6570032100")) or len(result.stdout) != 44:
        raise PreflightError("public key is not an Ed25519 SubjectPublicKeyInfo")
    actual = hashlib.sha256(result.stdout).hexdigest()
    if actual != expected:
        raise PreflightError("public key does not match the independently supplied fingerprint")
    return {"fingerprint": actual}


def run_checked(command: list[str], *, cwd: Path | None = None, env: dict | None = None,
                run: Callable = subprocess.run, timeout: int = 900) -> str:
    command_env = dict(os.environ if env is None else env)
    if command and Path(command[0]).name == "go":
        # Artifact verification must remain offline. Use only the locally
        # available module cache and toolchain; missing modules/toolchains fail
        # closed instead of being fetched from public services.
        command_env["GOPROXY"] = "off"
        command_env["GOSUMDB"] = "off"
        command_env["GOTOOLCHAIN"] = "local"
    try:
        result = run(command, cwd=cwd, env=command_env, check=True, text=True, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Commands can include local paths. Keep diagnostics stable and avoid
        # copying stderr that could contain private mirror/auth details.
        raise PreflightError("existing artifact verifier rejected an input") from error
    return result.stdout or ""


def require_fresh_approval(approved_at: str, max_age_days: int, now: dt.datetime) -> None:
    if not isinstance(max_age_days, int) or isinstance(max_age_days, bool) or not 1 <= max_age_days <= 365:
        raise PreflightError("customer artifact approval maximum age must be explicitly set to 1..365 days")
    try:
        parsed = dt.datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise PreflightError("signed artifact approval time is invalid") from error
    if not isinstance(approved_at, str) or not approved_at.endswith("Z") or parsed.utcoffset() != dt.timedelta(0):
        raise PreflightError("signed artifact approval time is not canonical UTC")
    if now.tzinfo is None or parsed > now or now > parsed + dt.timedelta(days=max_age_days):
        raise PreflightError("signed artifact approval is future-dated or expired under customer policy")


def strict_image_lock(path: Path) -> list[dict]:
    data = path.read_text(encoding="utf-8")
    records = {}
    for line in data.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] not in REQUIRED_KORDEX_IMAGES or fields[0] in records:
            raise PreflightError("signed Kordex image lock is malformed")
        if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?/(?:[a-z0-9._-]+/)+" + re.escape(fields[0]) + r"@sha256:[a-f0-9]{64}", fields[1]):
            raise PreflightError("signed Kordex image lock contains a mutable or invalid image reference")
        records[fields[0]] = fields[1]
    if set(records) != set(REQUIRED_KORDEX_IMAGES):
        raise PreflightError("signed Kordex image lock lacks a required image")
    return [{"name": name, "reference": records[name]} for name in REQUIRED_KORDEX_IMAGES]


def validate_registry_report(report: dict, system_images: dict, kordex_images: list[dict], host: str) -> int:
    if (report.get("schemaVersion") != 1 or report.get("registryHost", "").lower() != host.lower()
            or report.get("architecture") != EXPECTED_ARCH or report.get("status") != "PASS"):
        raise PreflightError("private registry report header or status is invalid")
    expected = []
    for index, image in enumerate(system_images.get("images", []), start=1):
        expected.append({"name": f"k3s-{index:02d}",
                         "reference": image.get("MirrorReference"),
                         "digest": str(image.get("Digest", "")).removeprefix("sha256:")})
    for image in kordex_images:
        reference = image["reference"]
        match = re.fullmatch(r"(.+)@sha256:([a-f0-9]{64})", reference)
        if match is None:
            raise PreflightError("signed Kordex image lock contains a malformed digest reference")
        expected.append({"name": image["name"], "reference": reference, "digest": match.group(2)})
    actual = report.get("images")
    if not isinstance(actual, list) or len(actual) != len(expected):
        raise PreflightError("private registry report has a missing or unexpected image")
    for approved, observed in zip(expected, actual):
        if (not isinstance(observed, dict) or observed.get("name") != approved["name"]
                or observed.get("reference") != approved["reference"]
                or observed.get("expectedDigest") != approved["digest"]
                or observed.get("observedDigest") != approved["digest"]
                or observed.get("architecture") != EXPECTED_ARCH or observed.get("status") != "PASS"):
            raise PreflightError("private registry report differs from the signed image locks")
    return len(expected)


def verify_package_inputs(config: dict, run: Callable = subprocess.run) -> dict:
    policy_path = path_value(config, "packageArtifacts", "policy")
    archive_path = path_value(config, "packageArtifacts", "archive")
    if not policy_path or not archive_path:
        raise PreflightError("host package policy or package archive was not provided")
    policy_bytes = read_regular_bytes(policy_path, 2 * 1024 * 1024)
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()
    expected_policy = config.get("packageArtifacts", {}).get("approvedPolicySHA256")
    if not isinstance(expected_policy, str) or not SHA256.fullmatch(expected_policy) or policy_hash != expected_policy:
        raise PreflightError("host package policy does not match its independently approved digest")
    stager = _load_stager()
    # The package stager accepts a path, so snapshot the independently
    # approved policy bytes once and use that exact file for both parsing and
    # archive validation. Reopening the customer-selected path could race a
    # policy replacement between digest approval and package verification.
    with tempfile.TemporaryDirectory(prefix="kordex-m3-policy-") as policy_temp:
        policy_snapshot = Path(policy_temp) / "approved-policy.json"
        fd = os.open(policy_snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(policy_bytes)
            output.flush()
            os.fsync(output.fileno())
        return _verify_package_inputs_snapshot(config, run, stager, policy_snapshot, policy_hash, archive_path)


def _verify_package_inputs_snapshot(config: dict, run: Callable, stager, policy_path: Path,
                                    policy_hash: str, archive_path: Path) -> dict:
    document, plan_digest = stager.read_policy(policy_path)
    plan = document["spec"]["upgrade"]
    os_identity = (plan.get("osId"), str(plan.get("osMajor", "")), str(plan.get("osMinor", "")))
    expected_family = supported_package_os(*os_identity)
    if (expected_family is None or plan.get("osFamily") != expected_family
            or plan.get("artifactMode") != "OfflineArtifacts" or not plan.get("packages")):
        raise PreflightError("package policy is not an exact supported offline Linux artifact plan")
    snapshot_id = config.get("packageArtifacts", {}).get("repositorySnapshotID")
    if (not isinstance(snapshot_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", snapshot_id)
            or ".." in snapshot_id or "@" in snapshot_id):
        raise PreflightError("approved immutable package repository snapshot ID was not provided")
    selected_point_release = config.get("packageArtifacts", {}).get("osPointRelease", "")
    os_id, os_major, os_minor = os_identity
    if os_id == "debian" and os_major == "13":
        if not isinstance(selected_point_release, str) or not re.fullmatch(r"13\.[0-9]+", selected_point_release):
            raise PreflightError("current Debian 13 stable point release was not explicitly approved")
    elif os_id == "rhel" and os_major == "9":
        expected_rhel_point = f"9.{os_minor}"
        if selected_point_release != expected_rhel_point:
            raise PreflightError("selected RHEL 9 point release does not match the approved minor policy")
    elif selected_point_release:
        raise PreflightError("OS point release is only supported for Debian 13 or RHEL 9 package policy")
    if plan.get("osPointRelease", "") != selected_point_release:
        raise PreflightError("selected OS point release differs from the approved maintenance policy")
    baseline = config.get("packageArtifacts", {}).get("baselineVersions")
    if not isinstance(baseline, dict):
        raise PreflightError("host baseline package versions were not supplied")
    targets = {p.get("name"): p.get("version") for p in plan["packages"]}
    if set(baseline) != set(targets) or any(not isinstance(v, str) or not v for v in baseline.values()):
        raise PreflightError("baseline package versions must exactly match the approved package set")
    if not any(baseline[name] != version for name, version in targets.items()):
        raise PreflightError("approved package set contains no real package version change")
    reboot_policy = plan.get("reboot")
    if reboot_policy not in ("Never", "IfNeeded", "Required"):
        raise PreflightError("host package policy has no supported reboot policy")
    kernel_prefixes = ("kernel", "linux-image", "linux-modules", "linux-headers", "linux-generic", "linux-virtual",
                       "linux-lowlatency", "linux-oem", "linux-signed", "linux-azure", "linux-gcp", "linux-kvm",
                       "linux-cloud-tools", "linux-tools", "linux-firmware")
    kernel_packages = [item for item in plan["packages"] if any(item.get("name", "").split(":", 1)[0] == prefix
                       or item.get("name", "").split(":", 1)[0].startswith(prefix + "-") for prefix in kernel_prefixes)]
    expected_kernel = plan.get("expectedKernelVersion", "")
    if kernel_packages and (reboot_policy == "Never" or not isinstance(expected_kernel, str) or not expected_kernel):
        raise PreflightError("kernel package policy requires an expected kernel version and a reboot policy")
    if not kernel_packages and expected_kernel:
        raise PreflightError("expected kernel version is present without a kernel package")
    mirror = config.get("packageArtifacts", {}).get("privateMirrorURL")
    allowed = config.get("packageArtifacts", {}).get("privateMirrorCIDRs")
    resolved = validate_private_https(mirror, allowed)
    local_archive_sha256 = hash_file(archive_path)
    with tempfile.TemporaryDirectory(prefix="kordex-m3-packages-") as temp:
        downloaded_archive = Path(temp) / "packages.tar"
        mirror_result = request_private_https(
            mirror, resolved, expected_sha256=local_archive_sha256,
            max_bytes=stager.MAX_TOTAL_BYTES, destination=downloaded_archive)
        destination = Path(temp) / "stage"
        staged = stager.stage(downloaded_archive, policy_path, destination)
        by_digest = {Path(item).name.split(".", 1)[0]: Path(item) for item in staged}
        package_metadata = []
        rpm_packages = plan["osFamily"] == "rhel"
        for package in plan["packages"]:
            artifact_path = by_digest.get(package["artifactSHA256"])
            if not artifact_path:
                raise PreflightError("staged package archive is incomplete")
            try:
                command = (["rpm", "-qp", "--qf", "%{NAME}\\n%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n%{ARCH}\\n", str(artifact_path)]
                           if rpm_packages else ["dpkg-deb", "-f", str(artifact_path), "Package", "Version", "Architecture"])
                output = run(command,
                             check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                raise PreflightError("host package metadata could not be verified") from error
            lines = output.stdout.splitlines()
            if rpm_packages and len(lines) == 3 and lines[1].startswith("0:"):
                lines[1] = lines[1][2:]
            architectures = ("x86_64", "noarch") if rpm_packages else ("amd64", "all")
            if len(lines) != 3 or lines[0] != package["name"] or lines[1] != package["version"] or lines[2] not in architectures:
                raise PreflightError("host package name, version, or architecture differs from approved policy")
            package_metadata.append({"name": lines[0], "version": lines[1], "architecture": lines[2],
                                     "sha256": package["artifactSHA256"], "baselineVersion": baseline[lines[0]]})
    profile = f"m3-{os_id}-{os_major}" + (f".{os_minor}" if os_minor else "") + f"-k3s-{EXPECTED_K3S}-linux-amd64"
    return {"policySha256": policy_hash, "planDigest": plan_digest, "architecture": EXPECTED_ARCH,
            "osFamily": plan["osFamily"], "osId": os_id, "osMajor": os_major, "osMinor": os_minor,
            "osPointRelease": plan.get("osPointRelease", ""),
            "profile": profile,
            "repositorySnapshotID": snapshot_id,
            "packageCount": len(package_metadata), "packages": package_metadata,
            "rebootPolicy": reboot_policy, "expectedKernelVersion": expected_kernel,
            "privateMirrorURLHost": urlsplit(mirror).hostname, "privateMirrorHTTPStatus": mirror_result["status"],
            "packageArchiveSha256": mirror_result["sha256"], "packageArchiveBytes": mirror_result["size"]}


def validate_private_https(url: str | None, cidrs: list[str] | None, resolver: Callable = socket.getaddrinfo) -> list[str]:
    if not isinstance(url, str):
        raise PreflightError("approved private package mirror URL was not provided")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PreflightError("package mirror must be a path-only HTTPS URL without credentials")
    if re.search(r"%(?!2[Bb])", parsed.path):
        raise PreflightError("private mirror URL contains an unsupported or ambiguous path escape")
    decoded_path = unquote(parsed.path)
    path_parts = decoded_path.split("/")
    if ("\\" in decoded_path or any(part in (".", "..") for part in path_parts)
            or any(part == "" for part in path_parts[1:-1])):
        raise PreflightError("private mirror URL path is not canonical")
    if not isinstance(cidrs, list) or not cidrs:
        raise PreflightError("approved private mirror CIDR allowlist was not provided")
    try:
        networks = [ipaddress.ip_network(item, strict=True) for item in cidrs]
        addresses = sorted({item[4][0] for item in resolver(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)})
        parsed_addresses = [ipaddress.ip_address(item) for item in addresses]
    except (ValueError, OSError, socket.gaierror) as error:
        raise PreflightError("private package mirror DNS resolution failed") from error
    if (not networks or any(not network.is_private or network.is_loopback or network.is_link_local for network in networks)
            or not parsed_addresses or any(not any(address in network for network in networks) for address in parsed_addresses)):
        raise PreflightError("package mirror resolves outside the approved private CIDRs")
    if any(not address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
           for address in parsed_addresses):
        raise PreflightError("package mirror resolves to a non-private address")
    return addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS to a previously checked IP while retaining hostname verification."""
    def __init__(self, host: str, address: str, port: int, timeout: int = 20):
        super().__init__(host, port=port, timeout=timeout, context=__import__("ssl").create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def request_private_https(url: str, addresses: list[str], *, expected_sha256: str | None = None,
                          max_bytes: int = 512 * 1024 * 1024,
                          destination: Path | None = None,
                          connection_factory: Callable = PinnedHTTPSConnection) -> dict:
    parsed = urlsplit(url)
    port = parsed.port or 443
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    errors = []
    for address in addresses:
        connection = connection_factory(parsed.hostname, address, port)
        try:
            connection.request("GET", target, headers={"Host": parsed.netloc, "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status != 200:
                raise PreflightError("private HTTPS endpoint did not return HTTP 200 without redirects")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > max_bytes):
                raise PreflightError("private artifact exceeds its size limit")
            digest = hashlib.sha256()
            total = 0
            output = None
            if destination is not None:
                try:
                    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                except OSError as error:
                    raise PreflightError("private artifact destination must be new and safe") from error
                output = os.fdopen(fd, "wb")
            try:
                while True:
                    block = response.read(min(1024 * 1024, max_bytes + 1 - total))
                    if not block:
                        break
                    total += len(block)
                    if total > max_bytes:
                        raise PreflightError("private artifact exceeds its size limit")
                    digest.update(block)
                    if output is not None:
                        output.write(block)
                if output is not None:
                    output.flush()
                    os.fsync(output.fileno())
            except Exception:
                if output is not None:
                    output.close()
                    destination.unlink(missing_ok=True)
                raise
            finally:
                if output is not None and not output.closed:
                    output.close()
            observed = digest.hexdigest()
            if expected_sha256 and observed != expected_sha256:
                if destination is not None:
                    destination.unlink(missing_ok=True)
                raise PreflightError("private mirror artifact digest differs from the approved lock")
            return {"status": response.status, "address": address, "sha256": observed, "size": total,
                    **({"path": str(destination)} if destination is not None else {})}
        except (OSError, http.client.HTTPException) as error:
            errors.append(error)
        finally:
            connection.close()
    raise PreflightError("private HTTPS endpoint is unavailable or failed TLS verification") from (errors[-1] if errors else None)


def build_report(config: dict, *, run: Callable = subprocess.run, now: dt.datetime | None = None) -> dict:
    checked_at = now or dt.datetime.now(dt.timezone.utc)
    artifacts = {name: artifact() for name in REQUIRED_ARTIFACTS}
    input_hashes: dict[str, str] = {}
    metadata: dict[str, dict] = {}
    try:
        # Trust is independently named and fingerprinted; domains are never
        # merged even where existing artifact locks intentionally share the
        # customer artifact-approval key family.
        definitions = (
            ("maintenancePublicTrust", ("trust", "maintenanceBundle"), lambda p: verify_public_ed25519_bundle(p, config.get("trust", {}).get("maintenanceExpectedKeyIds"))),
            ("artifactApprovalTrust", ("trust", "artifactApprovalBundle"), lambda p: verify_artifact_trust(p, config.get("trust", {}).get("artifactApprovalExpectedKeyIds"))),
            ("releasePublicTrust", ("trust", "releasePublicKey"), lambda p: public_key_fingerprint(p, config.get("trust", {}).get("releaseExpectedFingerprint", ""), run)),
            ("toolProvenancePublicTrust", ("trust", "toolProvenancePublicKey"), lambda p: public_key_fingerprint(p, config.get("trust", {}).get("toolProvenanceExpectedFingerprint", ""), run)),
        )
        for name, keys, verifier in definitions:
            path = path_value(config, *keys)
            if path is None:
                continue
            try:
                metadata[name] = verifier(path)
                input_hashes[name] = hash_file(path, 64 * 1024)
                artifacts[name] = artifact("PASS", **metadata[name])
            except (PreflightError, OSError, TypeError):
                artifacts[name] = artifact("FAIL", code="TrustValidationFailed")

        # Validate Helm allowlist syntax with the existing implementation.
        helm = path_value(config, "trust", "helmSignerAllowlist")
        if helm:
            try:
                run_checked(["bash", str(ROOT / "scripts/verify-offline-tools-lock.sh"), "--check-helm-signers", str(helm)], run=run, timeout=30)
                input_hashes["helmSignerAllowlist"] = hash_file(helm, 64 * 1024)
                artifacts["helmSignerAllowlist"] = artifact("PASS", sha256=input_hashes["helmSignerAllowlist"])
            except (PreflightError, OSError, UnicodeError):
                artifacts["helmSignerAllowlist"] = artifact("FAIL", code="HelmAllowlistInvalid")

        release_dir = path_value(config, "release", "bundleDirectory")
        release_key = path_value(config, "trust", "releasePublicKey")
        tool_key = path_value(config, "trust", "toolProvenancePublicKey")
        helm = path_value(config, "trust", "helmSignerAllowlist")
        if release_dir and release_key and tool_key and helm:
            try:
                env = os.environ.copy()
                env["KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY"] = str(tool_key)
                env["KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE"] = str(helm)
                run_checked(["bash", str(ROOT / "scripts/verify-offline-bundle.sh"), str(release_dir), str(release_key)], env=env, run=run)
                run_checked(["bash", str(ROOT / "scripts/verify-offline-tools-lock.sh"),
                             str(release_dir / "bin/tools/offline-tools.tsv"),
                             str(release_dir / "bin/tools/offline-tools.tsv.sig"), str(tool_key), str(helm)], run=run, timeout=60)
                input_hashes["signedReleaseBundle"] = hash_release_bundle(release_dir)
                artifacts["signedReleaseBundle"] = artifact("PASS", bundleSha256=input_hashes["signedReleaseBundle"])
            except (PreflightError, OSError, UnicodeError):
                artifacts["signedReleaseBundle"] = artifact("FAIL", code="ReleaseBundleVerificationFailed")
        elif release_dir:
            artifacts["signedReleaseBundle"] = artifact("FAIL", code="ReleaseTrustInputsIncomplete")

        image_lock = path_value(config, "release", "imageDigestLock")
        image_sig = path_value(config, "release", "imageDigestSignature")
        if image_lock and image_sig and release_key:
            try:
                run_checked(["bash", str(ROOT / "scripts/verify-image-lock.sh"), str(image_lock), str(image_sig), str(release_key)], run=run, timeout=60)
                refs = strict_image_lock(image_lock)
                input_hashes["signedImageDigestLock"] = hash_file(image_lock, 64 * 1024)
                input_hashes["signedImageDigestSignature"] = hash_file(image_sig, 4096)
                artifacts["signedImageDigestLock"] = artifact("PASS", imageCount=len(refs), sha256=input_hashes["signedImageDigestLock"])
                metadata["requiredKordexImages"] = {"references": refs}
                artifacts["requiredKordexImages"] = artifact("NOT PROVIDED", imageCount=len(refs), code="RegistryNotChecked")
            except (PreflightError, OSError, UnicodeError):
                artifacts["signedImageDigestLock"] = artifact("FAIL", code="ImageDigestLockVerificationFailed")
                artifacts["requiredKordexImages"] = artifact("FAIL", code="ImageLockInvalid")
        elif image_lock or image_sig:
            artifacts["signedImageDigestLock"] = artifact("FAIL", code="ImageDigestLockInputsIncomplete")

        k3s = config.get("k3sBinary") if isinstance(config.get("k3sBinary"), dict) else {}
        k3s_paths = {key: Path(k3s[key]) for key in ("binary", "lock", "signature", "trustBundle") if isinstance(k3s.get(key), str) and k3s[key]}
        if len(k3s_paths) == 4:
            try:
                approved_trust_hash = input_hashes.get("artifactApprovalTrust")
                if not approved_trust_hash or hash_file(k3s_paths["trustBundle"], 16 * 1024) != approved_trust_hash:
                    raise PreflightError("K3s verifier trust is not the independently checked artifact-approval trust domain")
                output = run_checked(["go", "run", "./cmd/kordex-artifact-lock", "verify", "--json", "--binary", str(k3s_paths["binary"]),
                                      "--lock", str(k3s_paths["lock"]), "--signature", str(k3s_paths["signature"]),
                                      "--trust-bundle", str(k3s_paths["trustBundle"])], cwd=ROOT / "api", run=run)
                verified = json.loads(output, object_pairs_hook=unique_object)
                if verified.get("version") != EXPECTED_K3S or verified.get("architecture") != EXPECTED_ARCH:
                    raise PreflightError("K3s binary lock version or architecture mismatch")
                max_age = (config.get("trust") or {}).get("artifactApprovalMaxAgeDays")
                require_fresh_approval(verified.get("approvedAt"), max_age, checked_at)
                binary_digest = verified.get("digest", "")
                binary_mirror = verified.get("mirrorReference", "")
                if not SHA256.fullmatch(binary_digest) or not binary_mirror:
                    raise PreflightError("verified K3s lock omitted its digest or mirror URL")
                cidrs = (config.get("network") or {}).get("privateMirrorCIDRs") if isinstance(config.get("network"), dict) else None
                addresses = validate_private_https(binary_mirror, cidrs)
                mirror_result = request_private_https(binary_mirror, addresses,
                                                     expected_sha256=binary_digest, max_bytes=512 * 1024 * 1024)
                for key, path in k3s_paths.items():
                    input_hashes[f"k3sBinary.{key}"] = hash_file(path, 512 * 1024 * 1024)
                artifacts["k3sBinaryApproval"] = artifact("PASS", version=EXPECTED_K3S, architecture=EXPECTED_ARCH,
                                                          signerKeyId=verified["signerKeyId"], approvedAt=verified["approvedAt"],
                                                          approvalValidForDays=max_age, binarySha256=binary_digest,
                                                          mirrorReference=binary_mirror,
                                                          mirrorSha256=mirror_result["sha256"])
            except (PreflightError, OSError, json.JSONDecodeError, KeyError, TypeError):
                artifacts["k3sBinaryApproval"] = artifact("FAIL", code="K3sBinaryApprovalFailed")
        elif k3s_paths:
            artifacts["k3sBinaryApproval"] = artifact("FAIL", code="K3sBinaryInputsIncomplete")

        system = config.get("k3sSystemImages") if isinstance(config.get("k3sSystemImages"), dict) else {}
        system_paths = {key: Path(system[key]) for key in ("bundle", "lock", "signature", "trustBundle") if isinstance(system.get(key), str) and system[key]}
        if len(system_paths) == 4:
            try:
                approved_trust_hash = input_hashes.get("artifactApprovalTrust")
                if not approved_trust_hash or hash_file(system_paths["trustBundle"], 16 * 1024) != approved_trust_hash:
                    raise PreflightError("system-image verifier trust is not the independently checked artifact-approval trust domain")
                output = run_checked(["go", "run", "./cmd/kordex-artifact-lock", "system-images", "verify", "--bundle", str(system_paths["bundle"]),
                                      "--lock", str(system_paths["lock"]), "--signature", str(system_paths["signature"]),
                                      "--trust-bundle", str(system_paths["trustBundle"]), "--json"], cwd=ROOT / "api", run=run)
                verified = json.loads(output, object_pairs_hook=unique_object)
                if (verified.get("k3sVersion") != EXPECTED_K3S or verified.get("architecture") != EXPECTED_ARCH
                        or verified.get("manifestVersion") != "1" or len(verified.get("images", [])) != 8):
                    raise PreflightError("K3s system image lock version, architecture, or image set is invalid")
                max_age = (config.get("trust") or {}).get("artifactApprovalMaxAgeDays")
                require_fresh_approval(verified.get("approvedAt"), max_age, checked_at)
                cidrs = (config.get("network") or {}).get("privateMirrorCIDRs") if isinstance(config.get("network"), dict) else None
                bundle_addresses = validate_private_https(verified["bundleMirrorReference"], cidrs)
                mirror_bundle = request_private_https(verified["bundleMirrorReference"], bundle_addresses,
                    expected_sha256=verified["bundleSha256"], max_bytes=512 * 1024 * 1024)
                for key, path in system_paths.items():
                    input_hashes[f"k3sSystemImages.{key}"] = hash_file(path, 512 * 1024 * 1024)
                metadata["verifiedSystemImages"] = verified
                artifacts["k3sSystemImageApproval"] = artifact("PASS", version=verified["k3sVersion"], architecture=verified["architecture"],
                                                                signerKeyId=verified["signerKeyId"], imageCount=8,
                                                                approvedAt=verified["approvedAt"], approvalValidForDays=max_age,
                                                                bundleSha256=verified["bundleSha256"],
                                                                bundleMirrorReference=verified["bundleMirrorReference"],
                                                                mirrorHost=verified["mirrorHost"],
                                                                mirrorBundleSha256=mirror_bundle["sha256"])
            except (PreflightError, OSError, json.JSONDecodeError, KeyError, TypeError):
                artifacts["k3sSystemImageApproval"] = artifact("FAIL", code="K3sSystemImageApprovalFailed")
        elif system_paths:
            artifacts["k3sSystemImageApproval"] = artifact("FAIL", code="K3sSystemImageInputsIncomplete")

        # Registry verification re-verifies both signed inventories itself;
        # caller-supplied report or inventory JSON is never accepted as trust.
        registry = config.get("privateRegistry") if isinstance(config.get("privateRegistry"), dict) else {}
        if (artifacts["k3sSystemImageApproval"]["status"] == "PASS"
                and artifacts["signedImageDigestLock"]["status"] == "PASS"
                and len(system_paths) == 4 and image_lock and image_sig and release_key
                and isinstance(registry.get("host"), str) and isinstance(registry.get("authFile"), str)):
            try:
                registry_addresses = validate_private_https(
                    "https://" + registry["host"] + "/", registry.get("privateCIDRs"))
                if not registry_addresses:
                    raise PreflightError("private registry DNS has no approved address")
                with tempfile.TemporaryDirectory(prefix="kordex-m3-registry-") as temp:
                    report_path = Path(temp) / "registry.json"
                    auth = Path(registry["authFile"])
                    command = ["python3", str(ROOT / "scripts/verify-private-registry.py"),
                               "--system-image-bundle", str(system_paths["bundle"]), "--system-image-lock", str(system_paths["lock"]),
                               "--system-image-signature", str(system_paths["signature"]), "--artifact-trust", str(system_paths["trustBundle"]),
                               "--expected-host", registry["host"], "--authfile", str(auth), "--output", str(report_path),
                               "--kordex-image-lock", str(image_lock), "--kordex-image-signature", str(image_sig),
                               "--release-public-key", str(release_key)]
                    for cidr in registry.get("privateCIDRs", []):
                        command.extend(["--private-cidr", str(cidr)])
                    run_checked(command, run=run, timeout=1800)
                    result = read_json(report_path, 1024 * 1024)
                    image_count = validate_registry_report(
                        result, metadata["verifiedSystemImages"], metadata["requiredKordexImages"]["references"],
                        registry["host"])
                    input_hashes["privateRegistryVerification"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
                    artifacts["privateRegistryImages"] = artifact("PASS", imageCount=image_count,
                                                                    registryHost=registry["host"],
                                                                    verificationSha256=input_hashes["privateRegistryVerification"])
                    artifacts["requiredKordexImages"] = artifact("PASS", imageCount=len(REQUIRED_KORDEX_IMAGES))
            except (PreflightError, OSError, KeyError, TypeError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                partial = None
                try:
                    if 'report_path' in locals() and report_path.is_file() and not report_path.is_symlink():
                        partial = read_json(report_path, 1024 * 1024)
                except (OSError, PreflightError, json.JSONDecodeError):
                    partial = None
                if isinstance(partial, dict) and isinstance(partial.get("images"), list):
                    rows = [{key: row[key] for key in ("name", "expectedDigest", "observedDigest", "architecture", "status", "code") if key in row}
                            for row in partial["images"] if isinstance(row, dict)]
                    artifacts["privateRegistryImages"] = artifact("FAIL", code="PrivateRegistryImageVerificationFailed",
                                                                  imageResults=rows, registryHost=registry.get("host"))
                    kordex_rows = [row for row in rows if row.get("name") in REQUIRED_KORDEX_IMAGES]
                    artifacts["requiredKordexImages"] = artifact(
                        "PASS" if len(kordex_rows) == len(REQUIRED_KORDEX_IMAGES) and all(row.get("status") == "PASS" for row in kordex_rows) else "FAIL",
                        imageCount=len(kordex_rows), imageResults=kordex_rows)
                else:
                    artifacts["privateRegistryImages"] = artifact("FAIL", code="PrivateRegistryVerificationFailed")
                    artifacts["requiredKordexImages"] = artifact("FAIL", code="RequiredImagesUnavailable")
        elif any(key in registry for key in ("host", "authFile", "privateCIDRs")):
            complete_registry_config = all(registry.get(key) for key in ("host", "authFile", "privateCIDRs"))
            artifacts["privateRegistryImages"] = artifact(
                "FAIL", code="RegistryApprovalPrerequisitesFailed" if complete_registry_config
                else "PrivateRegistryInputsIncomplete")

        package_cfg = config.get("packageArtifacts") if isinstance(config.get("packageArtifacts"), dict) else {}
        if package_cfg.get("policy") or package_cfg.get("archive"):
            try:
                details = verify_package_inputs(config, run=run)
                input_hashes["packagePolicy"] = details["policySha256"]
                input_hashes["packageArchive"] = details["packageArchiveSha256"]
                artifacts["hostPackageArtifacts"] = artifact("PASS", **details)
            except (ValueError, OSError, KeyError, TypeError):
                artifacts["hostPackageArtifacts"] = artifact("FAIL", code="HostPackagePreflightFailed")
    except Exception:
        # A malformed top-level config is represented as a failed report by the
        # CLI caller. Do not hide programming errors from unit tests.
        raise

    overall = overall_status(artifacts)
    package_details = artifacts["hostPackageArtifacts"]
    profile = package_details.get("profile", "m3-ubuntu-24.04-k3s-v1.36.6+k3s1-linux-amd64")
    return {"schemaVersion": 1, "profile": profile,
            "overallStatus": overall, "artifacts": {key: artifacts[key] for key in REQUIRED_ARTIFACTS},
            "inputSha256": dict(sorted(input_hashes.items()))}


def overall_status(artifacts: dict) -> str:
    """Require every mandatory preflight row to pass; absence is never success."""
    statuses = [artifacts.get(name, {}).get("status") for name in REQUIRED_ARTIFACTS]
    if any(status == "FAIL" for status in statuses):
        return "FAIL"
    if all(status == "PASS" for status in statuses):
        return "PASS"
    return "NOT PROVIDED"


def extract_field(output: str, prefix: str) -> str:
    for token in output.split():
        if token.startswith(prefix):
            return token[len(prefix):]
    return ""


def hash_release_bundle(directory: Path) -> str:
    manifest = directory / "SHA256SUMS"
    return hash_file(manifest, 2 * 1024 * 1024)


def write_report(path: Path, report: dict) -> str:
    encoded = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if path.is_symlink():
        raise PreflightError("report output must not be a symlink")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(encoded).hexdigest()


def validate_input_schema(config: dict) -> None:
    if not isinstance(config, dict):
        raise PreflightError("input document must be a JSON object")
    allowed = {"schemaVersion", "trust", "release", "k3sBinary", "k3sSystemImages",
               "privateRegistry", "packageArtifacts", "network"}
    if set(config) - allowed:
        raise PreflightError("input document contains unsupported top-level fields")
    nested = {
        "trust": {"maintenanceBundle", "maintenanceExpectedKeyIds", "artifactApprovalBundle", "artifactApprovalExpectedKeyIds",
                  "releasePublicKey", "releaseExpectedFingerprint", "toolProvenancePublicKey",
                  "toolProvenanceExpectedFingerprint", "helmSignerAllowlist", "artifactApprovalMaxAgeDays"},
        "release": {"bundleDirectory", "imageDigestLock", "imageDigestSignature"},
        "k3sBinary": {"binary", "lock", "signature", "trustBundle"},
        "k3sSystemImages": {"bundle", "lock", "signature", "trustBundle"},
        "privateRegistry": {"host", "authFile", "privateCIDRs"},
        "packageArtifacts": {"policy", "archive", "approvedPolicySHA256", "baselineVersions", "repositorySnapshotID",
                             "osPointRelease",
                             "privateMirrorURL", "privateMirrorCIDRs"},
        "network": {"privateMirrorCIDRs"},
    }
    for key, fields in nested.items():
        value = config.get(key)
        if value is not None and (not isinstance(value, dict) or set(value) - fields):
            raise PreflightError(f"input section {key!r} is malformed or contains unsupported fields")
    path_fields = {
        "trust": ("maintenanceBundle", "artifactApprovalBundle", "releasePublicKey", "toolProvenancePublicKey", "helmSignerAllowlist"),
        "release": ("bundleDirectory", "imageDigestLock", "imageDigestSignature"),
        "k3sBinary": ("binary", "lock", "signature", "trustBundle"),
        "k3sSystemImages": ("bundle", "lock", "signature", "trustBundle"),
        "privateRegistry": ("authFile",),
        "packageArtifacts": ("policy", "archive"),
    }
    for section, names in path_fields.items():
        value = config.get(section)
        if isinstance(value, dict) and any(name in value and (not isinstance(value[name], str) or not value[name]) for name in names):
            raise PreflightError(f"input section {section!r} contains an invalid file path")
    string_fields = {
        "trust": ("releaseExpectedFingerprint", "toolProvenanceExpectedFingerprint"),
        "release": (), "privateRegistry": ("host",),
        "packageArtifacts": ("approvedPolicySHA256", "privateMirrorURL", "repositorySnapshotID", "osPointRelease"),
    }
    for section, names in string_fields.items():
        value = config.get(section)
        if isinstance(value, dict) and any(name in value and (not isinstance(value[name], str) or not value[name]) for name in names):
            raise PreflightError(f"input section {section!r} contains an invalid string value")
    list_fields = {
        "trust": ("maintenanceExpectedKeyIds", "artifactApprovalExpectedKeyIds"),
        "privateRegistry": ("privateCIDRs",), "packageArtifacts": ("privateMirrorCIDRs",),
        "network": ("privateMirrorCIDRs",),
    }
    for section, names in list_fields.items():
        value = config.get(section)
        if isinstance(value, dict) and any(name in value and (
                not isinstance(value[name], list) or not value[name]
                or any(not isinstance(item, str) or not item for item in value[name])) for name in names):
            raise PreflightError(f"input section {section!r} contains an invalid list value")
    trust = config.get("trust")
    if isinstance(trust, dict) and "artifactApprovalMaxAgeDays" in trust:
        age = trust["artifactApprovalMaxAgeDays"]
        if not isinstance(age, int) or isinstance(age, bool) or not 1 <= age <= 365:
            raise PreflightError("artifact approval maximum age must be an integer from 1 to 365")
    packages = config.get("packageArtifacts")
    if isinstance(packages, dict) and "repositorySnapshotID" in packages:
        snapshot_id = packages["repositorySnapshotID"]
        if (not isinstance(snapshot_id, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", snapshot_id)
                or ".." in snapshot_id or "@" in snapshot_id):
            raise PreflightError("package repository snapshot ID is invalid")
    if isinstance(packages, dict) and "baselineVersions" in packages:
        baseline = packages["baselineVersions"]
        if not isinstance(baseline, dict) or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
                                                for k, v in baseline.items()):
            raise PreflightError("host baseline versions must map package names to non-empty versions")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True, help="customer-local JSON path map; contains no credential values")
    parser.add_argument("--report", type=Path, required=True, help="deterministic report output")
    args = parser.parse_args()
    try:
        config = read_json(args.inputs)
        if type(config.get("schemaVersion")) is not int or config.get("schemaVersion") != 1:
            raise PreflightError("unsupported M3 artifact input schema")
        validate_input_schema(config)
        report = build_report(config)
        report_hash = write_report(args.report, report)
        print(f"M3 artifact preflight: {report['overallStatus']}; report-sha256={report_hash}")
        return 0 if report["overallStatus"] == "PASS" else 1
    except (PreflightError, OSError) as error:
        print(f"M3 artifact preflight failed: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("M3 artifact preflight failed; sensitive inputs were not emitted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
