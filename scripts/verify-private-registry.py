#!/usr/bin/env python3
"""Read-only verification of customer-approved OCI references in a private registry.

This tool never pushes images and never falls back to a public registry. Registry
credentials are read by Skopeo from an external auth file whose contents are
never read or copied by this program.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import socket
import tempfile
from typing import Callable

try:
    import m3_skopeo_tool
except ModuleNotFoundError:  # allow focused tests to load this file by path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import m3_skopeo_tool


PUBLIC_REGISTRIES = {"docker.io", "registry-1.docker.io", "ghcr.io", "quay.io"}
KORDEX_IMAGES = ("agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$")


class RegistryError(ValueError):
    pass


def offline_go_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local")
    return environment


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError("duplicate JSON key")
        result[key] = value
    return result


def safe_auth_file(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise RegistryError("registry authentication file is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 0 < info.st_size <= 1024 * 1024:
        raise RegistryError("registry authentication file must be a private regular file")


def validate_private_host(host: str, cidr_values: list[str]) -> None:
    try:
        networks = [ipaddress.ip_network(value, strict=True) for value in cidr_values]
        hostname = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        answers = {ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    except (ValueError, OSError, socket.gaierror) as error:
        raise RegistryError("private registry DNS or CIDR allowlist is invalid") from error
    if not networks or any(not network.is_private or network.is_loopback or network.is_link_local for network in networks):
        raise RegistryError("registry CIDR allowlist must contain only private networks")
    if not answers or any(not address.is_private or address.is_loopback or address.is_link_local or address.is_multicast
                          or address.is_unspecified or not any(address in network for network in networks)
                          for address in answers):
        raise RegistryError("private registry resolves outside the approved private CIDRs")


def parse_image_lock(path: Path, expected_host: str) -> list[dict]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
            raise RegistryError("Kordex image lock is unsafe or oversized")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RegistryError("Kordex image lock is unavailable") from error
    records = {}
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] not in KORDEX_IMAGES or parts[0] in records:
            raise RegistryError("Kordex image lock is malformed, unexpected, or duplicated")
        reference = parts[1]
        match = re.fullmatch(r"([^/@]+(?:/[^/@]+)+)@sha256:([a-f0-9]{64})", reference)
        if not match:
            raise RegistryError("Kordex image lock reference is not immutable")
        repo, digest = match.groups()
        host = repo.split("/", 1)[0]
        if host.lower() in PUBLIC_REGISTRIES or host.lower() != expected_host.lower():
            raise RegistryError("Kordex image reference does not use the approved private registry")
        if any(part in ("", ".", "..") for part in repo.split("/")) or "%" in repo or "\\" in repo:
            raise RegistryError("Kordex image reference contains a noncanonical path")
        if repo.rsplit("/", 1)[-1] != parts[0]:
            raise RegistryError("Kordex image reference does not match its locked component")
        records[parts[0]] = {"name": parts[0], "reference": reference, "digest": digest}
    if set(records) != set(KORDEX_IMAGES):
        raise RegistryError("Kordex image lock does not contain the exact required image set")
    return [records[name] for name in KORDEX_IMAGES]


def snapshot_file(source: Path, destination: Path, limit: int) -> Path:
    try:
        fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise RegistryError("signed registry input is unavailable or unsafe") from error
    with os.fdopen(fd, "rb") as reader:
        before = os.fstat(reader.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > limit:
            raise RegistryError("signed registry input is not a bounded regular file")
        output_fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        digest = hashlib.sha256()
        with os.fdopen(output_fd, "wb") as writer:
            total = 0
            while block := reader.read(1024 * 1024):
                total += len(block)
                if total > limit:
                    raise RegistryError("signed registry input exceeded its size limit")
                writer.write(block)
                digest.update(block)
            writer.flush()
            os.fsync(writer.fileno())
        after = os.fstat(reader.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or total != before.st_size:
            raise RegistryError("signed registry input changed while being snapshotted")
    return destination


def inspect_one(name: str, reference: str, expected_digest: str, expected_host: str,
                auth_file: Path, *, skopeo: str = "skopeo",
                run: Callable = subprocess.run) -> dict:
    repo = reference.rsplit("@", 1)[0] if "@" in reference else reference.rsplit(":", 1)[0]
    host = repo.split("/", 1)[0]
    if host.lower() in PUBLIC_REGISTRIES or host.lower() != expected_host.lower():
        return {"name": name, "reference": reference, "expectedDigest": expected_digest, "status": "FAIL", "code": "UnapprovedRegistry"}
    if not SHA256.fullmatch(expected_digest):
        return {"name": name, "reference": reference, "expectedDigest": expected_digest, "status": "FAIL", "code": "InvalidExpectedDigest"}
    base = [skopeo, "inspect", "--tls-verify=true", f"--authfile={auth_file}"]
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/nonexistent"),
                   "LANG": "C", "LC_ALL": "C"}
    try:
        raw_result = run(base + ["--raw", f"docker://{reference}"], check=True, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, env=environment)
        # Read the config by the digest in the approved lock, not a mutable tag
        # that could move between the manifest and config requests.
        digest_reference = f"docker://{repo}@sha256:{expected_digest}"
        config_result = run(base + ["--override-os=linux", "--override-arch=amd64", "--config", digest_reference],
                            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, env=environment)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return {"name": name, "reference": reference, "expectedDigest": expected_digest, "status": "FAIL", "code": "RegistryUnavailableOrUnauthorized"}
    raw = raw_result.stdout.encode("utf-8")
    try:
        manifest = json.loads(raw, object_pairs_hook=unique_object)
        config = json.loads(config_result.stdout, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, RegistryError):
        return {"name": name, "reference": reference, "expectedDigest": expected_digest, "status": "FAIL", "code": "InvalidRegistryManifest"}
    actual_digest = hashlib.sha256(raw).hexdigest()
    architecture = f"{config.get('os', '')}/{config.get('architecture', '')}" if isinstance(config, dict) else ""
    # The digest is the exact OCI/Docker manifest bytes returned for the signed
    # mirror reference. Skopeo's config inspection selects linux/amd64.
    if not isinstance(manifest, dict):
        code = "InvalidRegistryManifest"
    elif actual_digest != expected_digest:
        code = "DigestMismatch"
    elif architecture != "linux/amd64":
        code = "ArchitectureMismatch"
    else:
        code = ""
    if not code:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name):
            return {"name": name, "reference": reference, "expectedDigest": expected_digest,
                    "observedDigest": actual_digest, "architecture": architecture,
                    "status": "FAIL", "code": "InvalidImageName"}
        # Inspecting a manifest does not prove that every referenced config and
        # layer blob is present. Copy the approved digest to a throwaway local
        # OCI layout so Skopeo validates the complete amd64 content graph. No
        # destination is a registry and no push operation exists in this tool.
        with tempfile.TemporaryDirectory(prefix="kordex-registry-image-") as temp:
            destination = f"oci:{Path(temp) / 'image'}:verified"
            try:
                run([skopeo, "copy", "--src-tls-verify=true", "--dest-tls-verify=true",
                     "--override-os=linux", "--override-arch=amd64", f"--authfile={auth_file}",
                     digest_reference, destination], check=True, text=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900, env=environment)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                code = "RegistryImageContentUnavailable"
    result = {"name": name, "reference": reference, "expectedDigest": expected_digest,
              "observedDigest": actual_digest, "architecture": architecture,
              "status": "PASS" if not code else "FAIL"}
    if code:
        result["code"] = code
    return result


def verify_images(images: list[dict], expected_host: str, auth_file: Path,
                  *, skopeo: str = "skopeo", run: Callable = subprocess.run) -> dict:
    if not HOST.fullmatch(expected_host) or expected_host.lower() in PUBLIC_REGISTRIES:
        raise RegistryError("expected registry host must be an approved private host")
    safe_auth_file(auth_file)
    if not isinstance(images, list) or not images:
        raise RegistryError("verified image inventory is missing")
    names = set()
    results = []
    for image in images:
        if not isinstance(image, dict):
            raise RegistryError("verified image inventory is malformed")
        name = image.get("name")
        reference = image.get("mirrorReference") or image.get("MirrorReference") or image.get("reference")
        digest = image.get("digest") or image.get("Digest")
        if not isinstance(name, str) or not isinstance(reference, str) or name in names:
            raise RegistryError("verified image inventory has duplicate or malformed entries")
        names.add(name)
        if not isinstance(digest, str) or digest.startswith("sha256:"):
            # K3s lock digests include the algorithm prefix; Kordex locks use
            # an immutable reference whose expected digest is hex only.
            digest = digest.removeprefix("sha256:") if isinstance(digest, str) else ""
        if reference.startswith("docker://") or "?" in reference or "#" in reference:
            raise RegistryError("registry image reference is not canonical")
        results.append(inspect_one(name, reference, digest, expected_host, auth_file,
                                   skopeo=skopeo, run=run))
    return {"schemaVersion": 1, "registryHost": expected_host,
            "architecture": "linux/amd64", "images": results,
            "status": "PASS" if all(item["status"] == "PASS" for item in results) else "FAIL"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-image-bundle", type=Path, required=True)
    parser.add_argument("--system-image-lock", type=Path, required=True)
    parser.add_argument("--system-image-signature", type=Path, required=True)
    parser.add_argument("--artifact-trust", type=Path, required=True, help="independently provisioned customer artifact trust bundle")
    parser.add_argument("--expected-host", required=True, help="host in the signed private mirror mappings")
    parser.add_argument("--private-cidr", action="append", required=True, help="customer-approved private registry CIDR; repeat as needed")
    parser.add_argument("--authfile", type=Path, required=True, help="customer-managed Skopeo auth file; never copied or printed")
    parser.add_argument("--output", type=Path, required=True, help="new deterministic JSON report path")
    parser.add_argument("--kordex-image-lock", type=Path, required=True)
    parser.add_argument("--kordex-image-signature", type=Path, required=True)
    parser.add_argument("--release-public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        skopeo = m3_skopeo_tool.verify_runtime()["executable"]
        safe_auth_file(args.authfile)
        validate_private_host(args.expected_host, args.private_cidr)
        with tempfile.TemporaryDirectory(prefix="kordex-registry-verify-") as raw_temp:
            temp = Path(raw_temp)
            system_bundle = snapshot_file(args.system_image_bundle, temp / "system-images.tar", 512 * 1024 * 1024)
            system_lock = snapshot_file(args.system_image_lock, temp / "system-images.lock", 64 * 1024)
            system_sig = snapshot_file(args.system_image_signature, temp / "system-images.sig", 4096)
            artifact_trust = snapshot_file(args.artifact_trust, temp / "artifact.trust", 16 * 1024)
            image_lock = snapshot_file(args.kordex_image_lock, temp / "images.lock", 64 * 1024)
            image_sig = snapshot_file(args.kordex_image_signature, temp / "images.sig", 4096)
            release_key = snapshot_file(args.release_public_key, temp / "release.pub", 64 * 1024)
            # Never accept a caller-created inventory as authority. Derive it
            # from the signed customer lock and archive, and verify the Kordex
            # release image lock with its separate release trust root.
            verified = subprocess.run(
                ["go", "run", "./cmd/kordex-artifact-lock", "system-images", "verify",
                 "--bundle", str(system_bundle), "--lock", str(system_lock),
                 "--signature", str(system_sig), "--trust-bundle", str(artifact_trust), "--json"],
                cwd=Path(__file__).resolve().parents[1] / "api", check=True, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=900,
                env=offline_go_environment(),
            ).stdout
            inventory_data = json.loads(verified, object_pairs_hook=unique_object)
            if (inventory_data.get("k3sVersion") != "v1.36.6+k3s1" or inventory_data.get("architecture") != "linux/amd64"
                    or inventory_data.get("manifestVersion") != "1" or not isinstance(inventory_data.get("images"), list)
                    or len(inventory_data["images"]) != 8):
                raise RegistryError("system-image inventory is not the verified supported K3s lock format")
            if inventory_data.get("mirrorHost", "").lower() != args.expected_host.lower():
                raise RegistryError("configured registry host differs from the signed system-image lock")
            images = [{"name": f"k3s-{index + 1:02d}", **image} for index, image in enumerate(inventory_data["images"])]
            subprocess.run(
                ["bash", str(Path(__file__).with_name("verify-image-lock.sh")),
                 str(image_lock), str(image_sig), str(release_key)],
                check=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
            )
            images.extend(parse_image_lock(image_lock, args.expected_host))
            report = verify_images(images, args.expected_host, args.authfile, skopeo=skopeo)
            output = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
            try:
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except OSError as error:
                raise RegistryError("output must be a new, safe file") from error
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(output)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError:
                args.output.unlink(missing_ok=True)
                raise
            return 0 if report["status"] == "PASS" else 1
    except (OSError, UnicodeError, json.JSONDecodeError, RegistryError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # Never surface Skopeo stderr: authentication helpers can include
        # registry diagnostics that should not be copied into reports/logs.
        print("private registry verification failed; no credentials or registry diagnostics were emitted", file=sys.stderr)
        return 2
    except Exception:
        # Do not print subprocess errors or file paths: Skopeo helper diagnostics
        # can contain authentication details supplied by the customer's host.
        print("private registry verification failed; no credentials or registry diagnostics were emitted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
