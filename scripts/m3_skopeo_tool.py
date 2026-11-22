#!/usr/bin/env python3
"""Verify the pinned Rocky Linux Skopeo package and installed executable."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / "tools/skopeo/rocky-10.json"
KEY_PATH = ROOT / "tools/skopeo/RPM-GPG-KEY-Rocky-10"
SAFE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"}
ARCHES = {"x86_64": "linux-amd64", "aarch64": "linux-arm64"}


class SkopeoError(ValueError):
    pass


class SkopeoMissing(SkopeoError):
    pass


def _run(args: list[str], *, timeout: int = 30, runner=subprocess.run):
    try:
        result = runner(args, text=True, capture_output=True, timeout=timeout, env=SAFE_ENV)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SkopeoError("Skopeo provenance command could not be completed") from error
    if result.returncode != 0:
        raise SkopeoError("Skopeo provenance command failed")
    return result.stdout or ""


def load_pin(path: Path = PIN_PATH) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SkopeoError("Skopeo pin file is missing or malformed") from error
    if (not isinstance(data, dict) or data.get("schemaVersion") != 1
            or data.get("distribution") != "Rocky Linux" or data.get("distributionMajor") != 10
            or set(data.get("profiles", {})) != {"linux-amd64", "linux-arm64"}):
        raise SkopeoError("Skopeo pin file has an unsupported profile")
    return data


def architecture_key(machine: str | None = None) -> str:
    machine = machine or platform.machine()
    try:
        return ARCHES[machine]
    except KeyError as error:
        raise SkopeoError("Skopeo is not pinned for this CPU architecture") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise SkopeoError("Skopeo artifact is unavailable") from error
    return digest.hexdigest()


def _regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise SkopeoMissing("Skopeo artifact is missing") from error
    except OSError as error:
        raise SkopeoError("Skopeo artifact is unavailable") from error
    if not path.is_file() or path.is_symlink():
        raise SkopeoError("Skopeo artifact must be a regular non-symlink file")
    return info


def verify_lock_row(version: str, architecture: str, binary_digest: str,
                    artifact_digest: str, artifact_url: str, verification: str,
                    signer: str, *, pin: dict | None = None) -> None:
    pin = pin or load_pin()
    profile = pin["profiles"].get(architecture)
    key = pin["rockySigningKey"]
    expected = (f"v{profile['version']}" if profile else None,
                profile["binarySha256"] if profile else None,
                profile["rpmSha256"] if profile else None,
                profile["rpmUrl"] if profile else None,
                "rocky-rpm-signature", key["fingerprint"])
    if (version, binary_digest, artifact_digest, artifact_url, verification, signer) != expected:
        raise SkopeoError("Skopeo provenance lock row does not match the pinned Rocky package")


def verify_rpm(rpm_path: Path, architecture: str, *, pin: dict | None = None,
               runner=subprocess.run, key_path: Path = KEY_PATH) -> dict:
    pin = pin or load_pin()
    profile = pin["profiles"].get(architecture)
    if profile is None:
        raise SkopeoError("Skopeo package architecture is not pinned")
    key = pin["rockySigningKey"]
    _regular_file(rpm_path)
    if sha256_file(rpm_path) != profile["rpmSha256"]:
        raise SkopeoError("Skopeo RPM SHA-256 does not match the pin")
    if _regular_file(key_path).st_mode & 0o022:
        raise SkopeoError("Rocky signing key file has unsafe permissions")
    if sha256_file(key_path) != key["sha256"]:
        raise SkopeoError("Rocky signing key digest does not match the pin")
    with tempfile.TemporaryDirectory(prefix="kordex-skopeo-rpmdb-") as temp:
        fingerprint_output = _run(["gpg", "--batch", "--no-options", "--homedir", temp,
                                   "--show-keys", "--with-colons", str(key_path)], runner=runner)
        fingerprints = [line.split(":")[9].upper() for line in fingerprint_output.splitlines()
                        if line.startswith("fpr:") and len(line.split(":")) > 9]
        if not fingerprints or fingerprints[0] != key["fingerprint"]:
            raise SkopeoError("Rocky signing key fingerprint does not match the pin")
        db = Path(temp) / "rpmdb"
        db.mkdir(mode=0o700)
        _run(["rpm", "--dbpath", str(db), "--import", str(key_path)], runner=runner)
        signature = _run(["rpmkeys", "--dbpath", str(db), "--checksig", "--verbose", str(rpm_path)], runner=runner)
        if (f"key ID {key['rpmKeyId']}: OK" not in signature
                or "Header SHA256 digest: OK" not in signature
                or "Payload SHA256 digest: OK" not in signature):
            raise SkopeoError("Skopeo RPM signature or payload digest is invalid")
        nevra = _run(["rpm", "-qp", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", str(rpm_path)], runner=runner).strip()
        if nevra != profile["nevra"]:
            raise SkopeoError("Skopeo RPM package identity does not match the pin")
    return {"status": "PASS", "version": profile["version"], "architecture": architecture,
            "rpmSha256": profile["rpmSha256"], "signerFingerprint": key["fingerprint"]}


def verify_runtime(*, executable: Path | None = None, machine: str | None = None,
                   os_release: Path = Path("/etc/os-release"), runner=subprocess.run,
                   require_root_owner: bool = True, pin: dict | None = None) -> dict:
    pin = pin or load_pin()
    architecture = architecture_key(machine)
    try:
        release_text = os_release.read_text(encoding="utf-8")
    except OSError as error:
        raise SkopeoError("operating-system identity is unavailable for Skopeo verification") from error
    # Parse the two supported values without sourcing or evaluating os-release.
    id_match = re.search(r'(?m)^ID=(?:"([^"]+)"|([^\n]+))$', release_text)
    version_match = re.search(r'(?m)^VERSION_ID=(?:"([^"]+)"|([^\n]+))$', release_text)
    os_id = (id_match.group(1) or id_match.group(2)) if id_match else ""
    os_version = (version_match.group(1) or version_match.group(2)) if version_match else ""
    if os_id != "rocky" or not re.fullmatch(r"10(?:\.[0-9]+)?", os_version):
        raise SkopeoError("pinned Skopeo executable is supported only on Rocky Linux 10")
    profile = pin["profiles"][architecture]
    executable = executable or Path(profile["binaryPath"])
    if executable != Path(profile["binaryPath"]):
        raise SkopeoError("Skopeo executable path differs from the pinned installation path")
    try:
        parent = executable.parent.lstat()
    except OSError as error:
        raise SkopeoError("Skopeo installation directory is unavailable") from error
    if (not stat.S_ISDIR(parent.st_mode) or executable.parent.is_symlink()
            or parent.st_mode & 0o022 or (require_root_owner and parent.st_uid != 0)):
        raise SkopeoError("Skopeo installation directory ownership or permissions are unsafe")
    info = _regular_file(executable)
    if info.st_mode & 0o022 or (require_root_owner and info.st_uid != 0):
        raise SkopeoError("Skopeo executable ownership or permissions are unsafe")
    if not os.access(executable, os.X_OK):
        raise SkopeoError("Skopeo executable is not executable")
    if sha256_file(executable) != profile["binarySha256"]:
        raise SkopeoError("Skopeo executable digest differs from the pinned build")
    output = _run([str(executable), "--version"], runner=runner, timeout=10)
    if not re.match(rf"^skopeo version {re.escape(profile['version'])}(?:\s|$)", output.strip()):
        raise SkopeoError("Skopeo executable version differs from the pin")
    nevra = _run(["rpm", "-q", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", "skopeo"], runner=runner).strip()
    if nevra != profile["nevra"]:
        raise SkopeoError("installed Skopeo package identity differs from the pin")
    return {"status": "PASS", "executable": str(executable), "version": profile["version"],
            "architecture": architecture, "binarySha256": profile["binarySha256"],
            "packageIdentity": profile["nevra"]}


def acquire(output: Path, *, pin: dict | None = None, opener=urllib.request.urlopen) -> list[Path]:
    pin = pin or load_pin()
    if output.exists() or output.is_symlink():
        raise SkopeoError("Skopeo acquisition output must be a new directory")
    output.mkdir(mode=0o700, parents=True)
    acquired = []
    try:
        for architecture, profile in pin["profiles"].items():
            path = output / f"skopeo-{architecture}.rpm"
            try:
                with opener(profile["rpmUrl"], timeout=60) as response, path.open("xb") as target:
                    while True:
                        block = response.read(1024 * 1024)
                        if not block:
                            break
                        target.write(block)
            except (OSError, TimeoutError) as error:
                raise SkopeoError("could not acquire pinned Skopeo package from Rocky Linux") from error
            path.chmod(0o600)
            verify_rpm(path, architecture, pin=pin)
            acquired.append(path)
        return acquired
    except Exception:
        for path in output.iterdir():
            path.unlink(missing_ok=True)
        output.rmdir()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify-runtime")
    rpm = sub.add_parser("verify-rpm")
    rpm.add_argument("--architecture", choices=("linux-amd64", "linux-arm64"), required=True)
    rpm.add_argument("path", type=Path)
    row = sub.add_parser("lock-row")
    row.add_argument("--architecture", choices=("linux-amd64", "linux-arm64"), required=True)
    verify_row = sub.add_parser("verify-lock-row")
    verify_row.add_argument("version")
    verify_row.add_argument("architecture", choices=("linux-amd64", "linux-arm64"))
    verify_row.add_argument("binary_digest")
    verify_row.add_argument("artifact_digest")
    verify_row.add_argument("artifact_url")
    verify_row.add_argument("verification")
    verify_row.add_argument("signer")
    acquire_parser = sub.add_parser("acquire")
    acquire_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify-runtime":
            result = verify_runtime()
        elif args.command == "verify-rpm":
            result = verify_rpm(args.path, args.architecture)
        elif args.command == "lock-row":
            p = load_pin()
            profile = p["profiles"][args.architecture]
            result = {"name": "skopeo", "version": f"v{profile['version']}",
                      "architecture": args.architecture, "binaryDigest": profile["binarySha256"],
                      "artifactDigest": profile["rpmSha256"], "artifactUrl": profile["rpmUrl"],
                      "verification": "rocky-rpm-signature", "signer": p["rockySigningKey"]["fingerprint"]}
        elif args.command == "verify-lock-row":
            verify_lock_row(args.version, args.architecture, args.binary_digest,
                            args.artifact_digest, args.artifact_url,
                            args.verification, args.signer)
            result = {"status": "PASS"}
        else:
            result = {"status": "PASS", "artifacts": [str(path) for path in acquire(args.output)]}
        print(json.dumps(result, sort_keys=True))
        return 0
    except SkopeoError as error:
        print(f"Skopeo verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
