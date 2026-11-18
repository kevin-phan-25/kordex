#!/usr/bin/env python3
"""Build a deterministic, policy-bound tar archive of local Debian/RPM files."""

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
import tempfile
from typing import BinaryIO

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
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
            document = json.loads(source.read(1024 * 1024 + 1).decode("utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, BundleError) as error:
        raise BundleError("cannot read policy JSON") from error
    if (not isinstance(document, dict) or document.get("apiVersion") != "operations.kordex.local/v1alpha1"
            or document.get("kind") != "MaintenancePolicy" or not isinstance(document.get("metadata"), dict)):
        raise BundleError("input is not a Kordex MaintenancePolicy")
    plan = (document.get("spec") or {}).get("upgrade")
    if not isinstance(plan, dict) or plan.get("schemaVersion") != 2 or plan.get("artifactMode") != "OfflineArtifacts":
        raise BundleError("policy must select schema v2 OfflineArtifacts")
    digest = policy_digest_function()(plan)
    return document, digest


def parse_mapping(values: list[str], packages: list[dict], family: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise BundleError(f"invalid --artifact {value!r}; expected package-name=path")
        name, raw_path = value.split("=", 1)
        if name in result or not raw_path:
            raise BundleError(f"duplicate or empty artifact mapping for {name!r}")
        path = Path(raw_path)
        if not SHA256.fullmatch(str(next((p.get("artifactSHA256", "") for p in packages if p["name"] == name), ""))):
            raise BundleError(f"policy artifact digest for {name!r} is invalid")
        result[name] = path
    expected = {item["name"] for item in packages}
    if set(result) != expected:
        raise BundleError("provide exactly one artifact file for every package in the policy")
    extension = ".deb" if family == "debian" else ".rpm"
    for package in packages:
        path = result[package["name"]]
        with open_regular_file_no_follow(path) as source:
            info = os.fstat(source.fileno())
            if info.st_size <= 0 or info.st_size > MAX_ARTIFACT_BYTES:
                raise BundleError(f"artifact for {package['name']!r} is empty or exceeds the size limit")
            digest = hashlib.sha256()
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != package.get("artifactSHA256"):
            raise BundleError(f"artifact SHA-256 mismatch for package {package['name']!r}")
        package["_bundlePath"] = f"artifacts/{package['artifactSHA256']}{extension}"
    return result


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    import io
    archive.addfile(info, io.BytesIO(data))


class HashingReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        self.digest.update(data)
        return data


def build(policy_path: Path, mappings: list[str], output: Path) -> None:
    document, plan_digest = read_policy(policy_path)
    plan = document["spec"]["upgrade"]
    artifacts = parse_mapping(mappings, plan["packages"], plan["osFamily"])
    total = 0
    for path in artifacts.values():
        with open_regular_file_no_follow(path) as source:
            total += os.fstat(source.fileno()).st_size
    if total > MAX_TOTAL_BYTES:
        raise BundleError("total offline package artifacts exceed the bundle size limit")
    output_parent = output.parent.resolve(strict=True)
    if output.is_symlink() or output.exists() or not output_parent.is_dir():
        raise BundleError("output must not exist and its parent must be a directory")
    manifest = {
        "schemaVersion": 1,
        "policyName": document["metadata"].get("name", ""),
        "policyId": plan["id"],
        "planDigest": plan_digest,
        "osFamily": plan["osFamily"],
        "artifacts": [
            {"name": package["name"], "version": package["version"],
             "sha256": package["artifactSHA256"], "file": package["_bundlePath"]}
            for package in sorted(plan["packages"], key=lambda item: item["name"])
        ],
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_parent, prefix=".kordex-artifacts-", delete=False) as temp:
            temporary_name = temp.name
        with tarfile.open(temporary_name, "w", format=tarfile.USTAR_FORMAT) as archive:
            add_bytes(archive, "manifest.json", manifest_bytes)
            for package in sorted(plan["packages"], key=lambda item: item["_bundlePath"]):
                with open_regular_file_no_follow(artifacts[package["name"]]) as source:
                    size = os.fstat(source.fileno()).st_size
                    info = tarfile.TarInfo(package["_bundlePath"])
                    info.size = size
                    info.mode = 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = 0
                    hashing_source = HashingReader(source)
                    archive.addfile(info, hashing_source)
                    if hashing_source.digest.hexdigest() != package["artifactSHA256"]:
                        raise BundleError(f"artifact changed while archiving {package['name']!r}")
        os.link(temporary_name, output)
        os.chmod(output, 0o644)
        dir_fd = os.open(output_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except FileExistsError as error:
        raise BundleError("output appeared during build; refusing to overwrite") from error
    except OSError as error:
        raise BundleError(f"cannot create artifact bundle: {error}") from error
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path, help="reviewed schema v2 MaintenancePolicy JSON")
    parser.add_argument("output", type=Path, help="new tar archive path")
    parser.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH",
                        help="local .deb/.rpm file for a policy package; repeat for every package")
    args = parser.parse_args()
    try:
        build(args.policy, args.artifact, args.output)
    except (BundleError, OSError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"Wrote policy-bound offline package artifact archive to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
