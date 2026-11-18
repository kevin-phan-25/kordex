#!/usr/bin/env python3
"""Verify a policy-bound artifact archive and stage packages for local EE use."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import uuid
from typing import BinaryIO

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class BundleError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def digest_file(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BundleError("staged artifact is not a regular file")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def open_regular_file_no_follow(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise BundleError("input must be a safely opened regular file") from error
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise BundleError("input must be a safely opened regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def policy_digest_function() -> callable:
    here = Path(__file__).resolve()
    candidates = (here.parent.parent / "integrations/ansible-ee/upgrade.py",
                 here.parent.parent / "ansible-ee/upgrade.py")
    module_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if module_path is None:
        raise BundleError("fixed Ansible EE policy validator is unavailable")
    spec = importlib.util.spec_from_file_location("kordex_upgrade_policy", module_path)
    if spec is None or spec.loader is None:
        raise BundleError("cannot load fixed Ansible EE policy validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.upgrade_policy_digest


def read_policy(path: Path) -> tuple[dict, str]:
    try:
        with open_regular_file_no_follow(path) as source:
            document = json.loads(source.read(MAX_MANIFEST_BYTES + 1).decode("utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError("cannot read policy JSON") from error
    if not isinstance(document, dict) or document.get("apiVersion") != "operations.kordex.local/v1alpha1" or document.get("kind") != "MaintenancePolicy":
        raise BundleError("input is not a Kordex MaintenancePolicy")
    plan = (document.get("spec") or {}).get("upgrade")
    if not isinstance(plan, dict) or plan.get("schemaVersion") != 2 or plan.get("artifactMode") != "OfflineArtifacts":
        raise BundleError("policy must select schema v2 OfflineArtifacts")
    digest = policy_digest_function()(plan)
    return document, digest


def read_manifest(archive: tarfile.TarFile, policy: dict, plan_digest: str) -> tuple[dict, dict[str, tarfile.TarInfo]]:
    by_name: dict[str, tarfile.TarInfo] = {}
    total = 0
    # TarFile.getmembers() eagerly parses the complete archive before a limit
    # can be checked. Consume headers incrementally so a malicious package
    # archive cannot force unbounded memory use in the privileged staging tool.
    for member in archive:
        if len(by_name) >= 129:
            raise BundleError("artifact archive contains too many entries")
        if member.name in by_name or not member.isfile() or member.issym() or member.islnk():
            raise BundleError("archive contains duplicate, non-regular, or linked entries")
        if member.name != "manifest.json" and not re.fullmatch(r"artifacts/[a-f0-9]{64}\.(?:deb|rpm)", member.name):
            raise BundleError("archive contains an unexpected path")
        if member.size < 0 or member.size > (MAX_MANIFEST_BYTES if member.name == "manifest.json" else MAX_ARTIFACT_BYTES):
            raise BundleError("archive entry exceeds its size limit")
        total += member.size
        by_name[member.name] = member
    if total > MAX_TOTAL_BYTES or "manifest.json" not in by_name:
        raise BundleError("artifact archive is too large or has no manifest")
    stream = archive.extractfile(by_name["manifest.json"])
    if stream is None:
        raise BundleError("artifact manifest is unreadable")
    try:
        manifest = json.loads(stream.read(MAX_MANIFEST_BYTES + 1), object_pairs_hook=unique_object)
    except (json.JSONDecodeError, BundleError) as error:
        raise BundleError("artifact manifest JSON is invalid") from error
    plan = policy["spec"]["upgrade"]
    expected = []
    extension = ".deb" if plan["osFamily"] == "debian" else ".rpm"
    for package in sorted(plan["packages"], key=lambda item: item["name"]):
        expected.append({"name": package["name"], "version": package["version"],
                         "sha256": package["artifactSHA256"],
                         "file": f"artifacts/{package['artifactSHA256']}{extension}"})
    if (not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1
            or manifest.get("policyName") != (policy.get("metadata") or {}).get("name", "")
            or manifest.get("policyId") != plan["id"] or manifest.get("planDigest") != plan_digest
            or manifest.get("osFamily") != plan["osFamily"] or manifest.get("artifacts") != expected):
        raise BundleError("artifact manifest does not match the exact upgrade policy")
    want_entries = {"manifest.json", *(item["file"] for item in expected)}
    if set(by_name) != want_entries:
        raise BundleError("archive artifact files do not exactly match the policy")
    return manifest, by_name


def hash_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    source = archive.extractfile(member)
    if source is None:
        raise BundleError("artifact archive entry cannot be read")
    digest = hashlib.sha256()
    remaining = member.size
    while remaining:
        block = source.read(min(1024 * 1024, remaining))
        if not block:
            raise BundleError("artifact archive entry is truncated")
        digest.update(block)
        remaining -= len(block)
    if source.read(1):
        raise BundleError("artifact archive entry exceeds its declared size")
    return digest.hexdigest()


def validate_destination(destination: Path) -> int:
    if not destination.is_absolute() or destination == Path("/"):
        raise BundleError("artifact destination must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open("/", flags)
    try:
        for index, part in enumerate(destination.parts[1:]):
            final = index == len(destination.parts[1:]) - 1
            try:
                info = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(part, mode=0o755, dir_fd=current_fd)
                info = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            sticky_shared_dir = mode & 0o1000 and mode & 0o002
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or (info.st_uid not in (0, os.geteuid()) and not sticky_shared_dir)):
                raise BundleError("artifact destination path contains an unsafe or unowned directory")
            next_fd = os.open(part, flags, dir_fd=current_fd)
            opened = os.fstat(next_fd)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                os.close(next_fd)
                raise BundleError("artifact destination changed while opening")
            os.close(current_fd)
            current_fd = next_fd
            if final and mode not in (0o700, 0o750, 0o755):
                raise BundleError("artifact destination directory permissions are unsafe")
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def digest_at(directory_fd: int, filename: str) -> str:
    fd = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise BundleError("staged artifact is not a regular file")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage(archive_path: Path, policy_path: Path, destination: Path) -> list[str]:
    policy, plan_digest = read_policy(policy_path)
    with open_regular_file_no_follow(archive_path) as archive_source, tarfile.open(fileobj=archive_source, mode="r:") as archive:
        _manifest, members = read_manifest(archive, policy, plan_digest)
        plan = policy["spec"]["upgrade"]
        extension = ".deb" if plan["osFamily"] == "debian" else ".rpm"
        for package in plan["packages"]:
            filename = f"artifacts/{package['artifactSHA256']}{extension}"
            if hash_member(archive, members[filename]) != package["artifactSHA256"]:
                raise BundleError(f"artifact digest mismatch for {package['name']!r}")

        destination_fd = validate_destination(destination)
        try:
            staged = []
            for package in plan["packages"]:
                digest = package["artifactSHA256"]
                filename = f"{digest}{extension}"
                target = destination / filename
                try:
                    existing = os.stat(filename, dir_fd=destination_fd, follow_symlinks=False)
                except FileNotFoundError:
                    existing = None
                if existing is not None:
                    if (not stat.S_ISREG(existing.st_mode) or existing.st_uid != os.geteuid()
                            or stat.S_IMODE(existing.st_mode) not in (0o400, 0o440, 0o444, 0o600, 0o640, 0o644)
                            or digest_at(destination_fd, filename) != digest):
                        raise BundleError(f"existing staged artifact {filename!r} is unsafe or has different contents")
                    staged.append(str(target))
                    continue
                member = members[f"artifacts/{filename}"]
                source = archive.extractfile(member)
                if source is None:
                    raise BundleError("validated artifact became unavailable")
                temporary = f".kordex-artifact-{uuid.uuid4().hex}"
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=destination_fd)
                try:
                    artifact_hash = hashlib.sha256()
                    remaining = member.size
                    with os.fdopen(fd, "wb") as output:
                        while remaining:
                            block = source.read(min(1024 * 1024, remaining))
                            if not block:
                                raise BundleError("artifact archive entry was truncated while staging")
                            output.write(block)
                            artifact_hash.update(block)
                            remaining -= len(block)
                        output.flush()
                        os.fsync(output.fileno())
                        if artifact_hash.hexdigest() != digest:
                            raise BundleError(f"artifact digest changed while staging {filename!r}")
                        os.fchmod(output.fileno(), 0o644)
                    try:
                        os.link(temporary, filename, src_dir_fd=destination_fd, dst_dir_fd=destination_fd, follow_symlinks=False)
                    except FileExistsError:
                        raise BundleError(f"another process staged {filename!r} concurrently; retry preflight")
                    staged.append(str(target))
                finally:
                    try:
                        os.unlink(temporary, dir_fd=destination_fd)
                    except FileNotFoundError:
                        pass
            os.fsync(destination_fd)
            return staged
        finally:
            os.close(destination_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path, help="the exact reviewed schema v2 MaintenancePolicy")
    parser.add_argument("archive", type=Path, help="offline package artifact tar archive")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("error: run as root to stage host package artifacts", file=sys.stderr)
        return 2
    try:
        staged = stage(args.archive, args.policy, Path("/var/cache/kordex/artifacts"))
    except (BundleError, OSError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for path in staged:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
