#!/usr/bin/env python3
"""Generate a local fixed-catalog MaintenancePolicy from a verified offline release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+@sha256:[a-f0-9]{64}$")
POLICY_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,127}(?::[a-z0-9][a-z0-9_-]{0,31})?$")
DEB_VERSION = re.compile(r"^([0-9]+:)?[0-9][A-Za-z0-9.+:~_-]{0,127}$")
RPM_EVR = re.compile(r"^([0-9]+:)?[0-9][A-Za-z0-9.+~_^]*-[A-Za-z0-9][A-Za-z0-9.+~_^.-]*$")
KERNEL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,127}$")
DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
LABEL_VALUE = re.compile(r"^(?:[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
IMAGE_NAMES = {"agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres"}
SUPPORTED_OS_RELEASES = {
    ("ubuntu", "24", "04"): "debian",
    ("debian", "13", ""): "debian",
    ("amzn", "2023", ""): "rhel",
}


def supported_os_release(os_id: str, major: str, minor: str, family: str) -> bool:
    exact = SUPPORTED_OS_RELEASES.get((os_id, major, minor))
    if exact is not None:
        return exact == family
    return family == "rhel" and os_id == "rhel" and major == "9" and minor.isdigit() and int(minor) >= 8


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"error: {message}")


def regular_file(path: Path, description: str) -> Path:
    try:
        if path.is_symlink() or not path.is_file():
            fail(f"{description} must be a regular file, not a symlink")
        return path.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot access {description}: {exc}")


def verify_inputs(bundle: Path, lock: Path) -> dict[str, str]:
    public_key = os.environ.get("KORDEX_RELEASE_PUBLIC_KEY", "")
    verifier = os.environ.get("KORDEX_TRUSTED_BUNDLE_VERIFIER", "")
    if not public_key or not verifier:
        fail("set KORDEX_RELEASE_PUBLIC_KEY and the independently trusted KORDEX_TRUSTED_BUNDLE_VERIFIER")
    key_path = regular_file(Path(public_key), "trusted release public key")
    verifier_path = regular_file(Path(verifier), "trusted bundle verifier")
    if not os.access(verifier_path, os.X_OK):
        fail("trusted bundle verifier must be executable")
    if verifier_path.is_relative_to(bundle):
        fail("trusted bundle verifier must be outside the bundle")
    try:
        subprocess.run([str(verifier_path), str(bundle), str(key_path)], check=True)
    except subprocess.CalledProcessError as exc:
        fail(f"offline bundle verification failed with status {exc.returncode}")

    lock_signature = regular_file(Path(os.environ.get("KORDEX_IMAGE_LOCK_SIGNATURE", str(lock) + ".sig")), "image lock signature")
    verifier_in_bundle = regular_file(bundle / "scripts/verify-image-lock.sh", "bundled image lock verifier")
    try:
        subprocess.run(["bash", str(verifier_in_bundle), str(lock), str(lock_signature), str(key_path)], check=True)
    except subprocess.CalledProcessError as exc:
        fail(f"image lock verification failed with status {exc.returncode}")

    entries: dict[str, str] = {}
    try:
        for line_number, line in enumerate(lock.read_text(encoding="utf-8").splitlines(), 1):
            fields = line.split("\t")
            if len(fields) != 2 or fields[0] not in IMAGE_NAMES or fields[0] in entries or not IMAGE.fullmatch(fields[1]):
                fail(f"invalid or duplicate image lock row {line_number}")
            name, reference = fields
            registry = reference.split("/", 1)[0]
            if ":" in registry:
                port = registry.rsplit(":", 1)[1]
                if not port.isdigit() or not 1 <= int(port) <= 65535:
                    fail(f"image lock registry port is invalid for {name!r}")
            if not reference.rsplit("@", 1)[0].endswith(f"/kordex/{name}"):
                fail(f"image repository does not match {name!r}")
            entries[name] = reference
    except OSError as exc:
        fail(f"cannot read signed image lock: {exc}")
    if set(entries) != IMAGE_NAMES:
        fail("signed image lock must contain exactly the six supported Kordex images")
    return entries


def parse_selector(values: list[str]) -> dict[str, str]:
    if not values:
        fail("provide at least one --selector key=value")
    result: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            fail(f"invalid selector {item!r}; expected key=value")
        key, value = item.split("=", 1)
        if key.count("/") > 1:
            fail(f"invalid selector key {key!r}")
        name = key.rsplit("/", 1)[-1]
        prefix = key.rsplit("/", 1)[0] if "/" in key else ""
        if not DNS_LABEL.fullmatch(name) or len(name) > 63:
            fail(f"invalid selector key {key!r}")
        if prefix and (len(prefix) > 253 or any(not DNS_LABEL.fullmatch(part) for part in prefix.split("."))):
            fail(f"invalid selector key prefix {prefix!r}")
        if len(value) > 63 or not LABEL_VALUE.fullmatch(value):
            fail(f"invalid selector value for {key!r}")
        if key in result:
            fail(f"duplicate selector key {key!r}")
        result[key] = value
    return result


def parse_packages(values: list[str], family: str, reboot: str, expected_kernel: str,
                   artifact_mode: str, artifact_digests: dict[str, str]) -> list[dict[str, str]]:
    if not values or len(values) > 128:
        fail("provide between one and 128 exact --package name=version pins")
    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    kernel_found = False
    kernel_prefixes = ("kernel", "linux-image", "linux-modules", "linux-headers", "linux-generic", "linux-virtual", "linux-lowlatency", "linux-oem", "linux-signed", "linux-azure", "linux-gcp", "linux-kvm", "linux-cloud-tools", "linux-tools", "linux-firmware")
    for value in values:
        if "=" not in value:
            fail(f"invalid package pin {value!r}; expected name=version")
        name, version = value.split("=", 1)
        if not PACKAGE.fullmatch(name) or name != name.lower() or name in seen or ("_" in name and family == "debian"):
            fail(f"invalid or duplicate package name {name!r}")
        valid_version = RPM_EVR.fullmatch(version) if family == "rhel" else DEB_VERSION.fullmatch(version)
        if not valid_version or version.lower() in {"latest", "stable", "current", "*"} or any(char in version for char in "*?"):
            fail(f"invalid or floating package version {version!r}")
        seen.add(name)
        base_name = name.split(":", 1)[0]
        if any(base_name == prefix or base_name.startswith(prefix + "-") for prefix in kernel_prefixes):
            kernel_found = True
        package = {"name": name, "version": version}
        if artifact_mode == "OfflineArtifacts":
            digest = artifact_digests.get(name)
            if not digest or not SHA256.fullmatch(digest):
                fail(f"offline artifact SHA-256 is required for package {name!r}")
            package["artifactSHA256"] = digest
        elif name in artifact_digests:
            fail("--artifact-sha256 is valid only with --artifact-mode OfflineArtifacts")
        packages.append(package)
    if kernel_found and (reboot == "Never" or not expected_kernel):
        fail("kernel package plans require --reboot IfNeeded or Required and --expected-kernel-version")
    if not kernel_found and expected_kernel:
        fail("--expected-kernel-version is valid only when a kernel package is pinned")
    if expected_kernel and not KERNEL_VERSION.fullmatch(expected_kernel):
        fail("invalid expected kernel version")
    return sorted(packages, key=lambda item: item["name"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("image_digest_lock", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--family", required=True, choices=("debian", "rhel"))
    parser.add_argument("--os-id", required=True, choices=("ubuntu", "debian", "rhel", "amzn"))
    parser.add_argument("--os-major", required=True)
    parser.add_argument("--os-minor", default="", help="required only for catalog entries pinned to a minor release")
    parser.add_argument("--os-point-release", default="", help="selected Debian stable point or exact RHEL 9 minor")
    parser.add_argument("--name", required=True, help="Kubernetes MaintenancePolicy name")
    parser.add_argument("--id", dest="plan_id", help="plan ID; defaults to --name")
    parser.add_argument("--selector", action="append", default=[], help="node label selector key=value; repeatable")
    parser.add_argument("--package", action="append", default=[], help="exact package pin name=version; repeatable")
    parser.add_argument("--artifact-mode", choices=("Repository", "OfflineArtifacts"), default="Repository")
    parser.add_argument("--artifact-sha256", action="append", default=[], metavar="NAME=SHA256",
                        help="SHA-256 of the staged local package artifact; required per package in OfflineArtifacts mode")
    parser.add_argument("--reboot", choices=("Never", "IfNeeded", "Required"), default="Never")
    parser.add_argument("--expected-kernel-version", default="")
    parser.add_argument("--execution-timeout-seconds", type=int, default=3600)
    parser.add_argument("--reboot-timeout-seconds", type=int, default=1800)
    parser.add_argument("--verification-timeout-seconds", type=int, default=1800)
    args = parser.parse_args()

    if not supported_os_release(args.os_id, args.os_major, args.os_minor, args.family):
        fail("OS identity is not in the fixed executor catalog or does not match --family")
    if args.os_id == "debian" and not re.fullmatch(r"13\.[0-9]+", args.os_point_release):
        fail("Debian 13 policy must bind its selected stable point release")
    if args.os_id == "rhel" and args.os_point_release != f"9.{args.os_minor}":
        fail("RHEL policy must bind the selected 9.8-or-later minor release")
    if args.os_id in {"ubuntu", "amzn"} and args.os_point_release:
        fail("supplemental Ubuntu and Amazon Linux policies do not set an OS point release")

    if not POLICY_NAME.fullmatch(args.name) or len(args.name) > 63:
        fail("policy name must be a DNS label of at most 63 characters")
    plan_id = args.plan_id or args.name
    if not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", plan_id):
        fail("plan ID must be 1 to 63 alphanumeric, dot, underscore, or hyphen characters")
    for seconds in (args.execution_timeout_seconds, args.reboot_timeout_seconds, args.verification_timeout_seconds):
        if seconds < 60 or seconds > 7200:
            fail("each timeout must be between 60 and 7200 seconds")
    if args.bundle.is_symlink() or not args.bundle.is_dir():
        fail("bundle path must be a directory, not a symlink")
    bundle = args.bundle.resolve(strict=True)
    regular_file(bundle / "SHA256SUMS", "bundle manifest")
    lock = regular_file(args.image_digest_lock, "signed image digest lock")
    if not args.output.parent.is_dir() or args.output.exists() or args.output.is_symlink():
        fail("output parent must exist and output file must not already exist")
    selector = parse_selector(args.selector)
    artifact_digests: dict[str, str] = {}
    for item in args.artifact_sha256:
        if "=" not in item:
            fail(f"invalid --artifact-sha256 {item!r}; expected package=64-character-sha256")
        name, digest = item.split("=", 1)
        if not PACKAGE.fullmatch(name) or name in artifact_digests or not SHA256.fullmatch(digest):
            fail(f"invalid or duplicate --artifact-sha256 for {name!r}")
        artifact_digests[name] = digest
    if artifact_digests and args.artifact_mode != "OfflineArtifacts":
        fail("--artifact-sha256 is valid only with --artifact-mode OfflineArtifacts")
    if args.artifact_mode == "OfflineArtifacts" and set(artifact_digests) != {
        item.split("=", 1)[0] for item in args.package if "=" in item
    }:
        fail("OfflineArtifacts requires exactly one --artifact-sha256 for every --package")
    packages = parse_packages(args.package, args.family, args.reboot, args.expected_kernel_version,
                              args.artifact_mode, artifact_digests)
    images = verify_inputs(bundle, lock)

    catalog = "kordex.os-upgrade.debian.v2" if args.family == "debian" else "kordex.os-upgrade.rhel.v1"
    playbook_file = "upgrade-debian.yml" if args.family == "debian" else "upgrade-rhel.yml"
    playbook_path = bundle / "ansible-ee" / playbook_file
    collections_path = bundle / "ansible-ee" / "collections.lock"
    if not playbook_path.is_file() or not collections_path.is_file():
        fail("bundle is missing the selected playbook catalog or collections lock")
    playbook_digest = hashlib.sha256(playbook_path.read_bytes()).hexdigest()
    collections_digest = hashlib.sha256(collections_path.read_bytes()).hexdigest()
    policy = {
        "apiVersion": "operations.kordex.local/v1alpha1",
        "kind": "MaintenancePolicy",
        "metadata": {"name": args.name, "namespace": "kordex-system"},
        "spec": {
            "nodeSelector": {"matchLabels": selector},
            "suspended": False,
            "recoverySeconds": 10,
            "gracePeriodSeconds": 30,
            "upgrade": {
                "schemaVersion": 2 if args.artifact_mode == "OfflineArtifacts" else 1,
                "id": plan_id,
                "osFamily": args.family,
                "osId": args.os_id,
                "osMajor": args.os_major,
                "osMinor": args.os_minor,
                "osPointRelease": args.os_point_release,
                "executionBackend": "ansible-ee",
                "playbookCatalogId": catalog,
                "executionEnvironment": images["ansible-ee"],
                "playbookDigest": playbook_digest,
                "collectionsDigest": collections_digest,
                "actionMarkerVersion": 1,
                "packages": packages,
                "channel": "stable",
                "reboot": args.reboot,
                "executionTimeout": args.execution_timeout_seconds * 1_000_000_000,
                "rebootTimeout": args.reboot_timeout_seconds * 1_000_000_000,
                "verificationTimeout": args.verification_timeout_seconds * 1_000_000_000,
                "maxAttempts": 1,
            },
        },
    }
    if args.artifact_mode == "OfflineArtifacts":
        policy["spec"]["upgrade"]["artifactMode"] = args.artifact_mode
    if args.expected_kernel_version:
        policy["spec"]["upgrade"]["expectedKernelVersion"] = args.expected_kernel_version
    raw = (json.dumps(policy, indent=2, sort_keys=False) + "\n").encode()
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=args.output.parent, prefix=".kordex-policy-", delete=False) as tmp:
            tmp.write(raw)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_name = tmp.name
        os.link(tmp_name, args.output)
        os.chmod(args.output, 0o644)
    except FileExistsError:
        fail("output file appeared during generation; refusing to overwrite")
    except OSError as exc:
        fail(f"cannot write policy output: {exc}")
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
    print(f"Wrote reviewable offline MaintenancePolicy to {args.output}")
    print("The host-upgrade gate remains disabled by default; review package pins and local safety before applying.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
