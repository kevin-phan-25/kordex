#!/usr/bin/env python3
"""M3 repository metadata and container-image supply-chain verification.

This module uses native OpenPGP repository signatures and GitHub's established
in-toto/Sigstore artifact attestation format. It never creates trust material.
Test-only callers may provide synthetic fixture inputs; production callers must
provide owner-approved fingerprints, bundles, and the independently acquired
Sigstore trusted root.
"""

from __future__ import annotations

import bz2
import datetime as dt
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

try:
    from validate_image_sbom import SBOMError, validate_sbom_bytes
except ImportError:
    from scripts.validate_image_sbom import SBOMError, validate_sbom_bytes

HEX256 = re.compile(r"^[a-f0-9]{64}$")
FINGERPRINT = re.compile(r"^[A-F0-9]{40,64}$")
IMAGE_DIGEST = re.compile(r"^([^@\s]+)@sha256:([a-f0-9]{64})$")
REPOSITORY = "kevin-phan-25/kordex"
WORKFLOW = "kevin-phan-25/kordex/.github/workflows/ci.yaml"
WORKFLOW_IDENTITY = "https://github.com/kevin-phan-25/kordex/.github/workflows/ci.yaml"
GH_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
EXPECTED_BUILDER_ID = "https://github.com/actions/runner/github-hosted"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"
MAX_METADATA_BYTES = 1024 * 1024 * 1024


class SupplyChainError(ValueError):
    pass


class ImageVerificationError(SupplyChainError):
    """A component-specific SBOM or provenance failure for preflight reporting."""

    def __init__(self, phase: str, component: str, cause: Exception, *, missing: bool = False,
                 sbom_results: dict | None = None):
        self.phase = phase
        self.component = component
        self.missing = missing
        self.sbom_results = sbom_results or {}
        super().__init__(f"{component} {phase} verification failed: {cause}")


def _path_is_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _regular_bytes(path: Path, limit: int = MAX_METADATA_BYTES) -> bytes:
    import stat

    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            data = source.read(limit + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise SupplyChainError("required supply-chain input is unavailable or unsafe") from error
    if (not stat.S_ISREG(before.st_mode) or len(data) != before.st_size or len(data) > limit
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise SupplyChainError("supply-chain input is not a stable bounded regular file")
    return data


def _safe_directory(path: Path) -> None:
    import stat

    current = Path(path.anchor or ".")
    for part in path.parts[1:] if path.is_absolute() else path.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise SupplyChainError("repository metadata directory is unavailable") from error
        if stat.S_ISLNK(info.st_mode):
            raise SupplyChainError("repository metadata directory contains a symlink")
    if not stat.S_ISDIR(current.lstat().st_mode):
        raise SupplyChainError("repository metadata root must be a real directory")


def _safe_child(root: Path, relative: str) -> Path:
    """Resolve a relative repository path while rejecting symlink components."""
    parts = Path(relative).parts
    if Path(relative).is_absolute() or not parts or any(item in ("", ".", "..") for item in parts):
        raise SupplyChainError("repository metadata path is unsafe")
    current = root
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise SupplyChainError("repository metadata file is unavailable") from error
        import stat
        if stat.S_ISLNK(info.st_mode):
            raise SupplyChainError("repository metadata path contains a symlink")
    return current


def _time(value: str, name: str) -> dt.datetime:
    try:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = parsedate_to_datetime(value)
    except (AttributeError, ValueError) as error:
        raise SupplyChainError(f"repository {name} timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise SupplyChainError(f"repository {name} timestamp has no timezone")
    return parsed.astimezone(dt.timezone.utc)


def _write_private(path: Path, contents: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())


def _verify_gpgv_bytes(keyring: bytes, signature: bytes, data: bytes | None, fingerprints: list[str], run,
                      *, inline: bool = False) -> str:
    allowed = {item.upper() for item in fingerprints if isinstance(item, str)}
    if (not allowed or any(not FINGERPRINT.fullmatch(item) for item in allowed)
            or len(allowed) != len(fingerprints)):
        raise SupplyChainError("approved full repository signing-key fingerprints are missing or malformed")
    if not keyring or len(keyring) > 16 * 1024 * 1024 or not signature or (not inline and data is None):
        raise SupplyChainError("repository signature input is empty or exceeds its size limit")
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-repo-signature-") as temporary:
            root = Path(temporary)
            keyring_path = root / "approved-keyring.gpg"
            signature_path = root / ("inrelease" if inline else "metadata.asc")
            _write_private(keyring_path, keyring)
            _write_private(signature_path, signature)
            command = ["gpgv", "--status-fd", "1", "--keyring", str(keyring_path), str(signature_path)]
            if not inline:
                data_path = root / "metadata"
                _write_private(data_path, data or b"")
                command.append(str(data_path))
            result = run(command, check=True, text=True, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SupplyChainError("repository metadata OpenPGP signature is invalid or untrusted") from error
    valid = []
    for line in result.stdout.splitlines():
        marker = "[GNUPG:] VALIDSIG "
        if line.startswith(marker):
            fields = line[len(marker):].split()
            if fields:
                valid.append(fields[0].upper())
                if len(fields) >= 10 and FINGERPRINT.fullmatch(fields[9].upper()):
                    valid.append(fields[9].upper())
    observed = set(valid) & allowed
    if not observed:
        raise SupplyChainError("repository metadata signer is not an independently approved fingerprint")
    return sorted(observed)[0]


def _debian_control(data: bytes) -> dict[str, str]:
    text = data.decode("utf-8", errors="strict")
    fields: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        if not line:
            continue
        if line[0].isspace() and current:
            continuation = line[1:]
            fields[current] += ("\n" if fields[current] else "") + continuation
            continue
        if ":" not in line:
            raise SupplyChainError("Debian Release metadata contains a malformed field")
        key, value = line.split(":", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key) or key in fields:
            raise SupplyChainError("Debian Release metadata contains duplicate or invalid fields")
        current = key
        fields[key] = value.strip()
    return fields


def _debian_sha256_entries(release: dict[str, str]) -> dict[str, str]:
    section = release.get("SHA256")
    if not section:
        raise SupplyChainError("signed Debian Release metadata has no SHA256 index list")
    entries: dict[str, str] = {}
    for line in section.splitlines():
        fields = line.split()
        if len(fields) != 3 or not HEX256.fullmatch(fields[0]) or not fields[1].isdigit():
            raise SupplyChainError("Debian Release SHA256 index list is malformed")
        name = fields[2]
        if name.startswith("/") or ".." in Path(name).parts or name in entries:
            raise SupplyChainError("Debian Release SHA256 index path is unsafe or duplicated")
        entries[name] = fields[0]
    return entries


def _inrelease_payload(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise SupplyChainError("Debian InRelease is not valid UTF-8") from error
    marker = "-----BEGIN PGP SIGNED MESSAGE-----"
    separator = "\n\n"
    if not text.startswith(marker) or separator not in text:
        raise SupplyChainError("Debian InRelease is not an OpenPGP clear-signed Release file")
    payload = text.split(separator, 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    # RFC 4880 dash-escaped lines are unescaped before the Release control
    # file is parsed. The signature verifier still receives the original file.
    payload = "\n".join(line[2:] if line.startswith("- ") else line for line in payload.splitlines())
    return payload.encode("utf-8")


def _parse_deb_packages(data: bytes) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise SupplyChainError("Debian Packages index is not valid UTF-8") from error
    records, current, previous = [], {}, None
    for line in text.splitlines() + [""]:
        if not line:
            if current:
                records.append(current)
                current = {}
            previous = None
        elif line[0].isspace():
            if previous is None:
                raise SupplyChainError("Debian Packages continuation is malformed")
            current[previous] += "\n" + line[1:]
        elif ":" in line:
            key, value = line.split(":", 1)
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key) or key in current:
                raise SupplyChainError("Debian Packages index has duplicate or invalid fields")
            current[key] = value.strip()
            previous = key
        else:
            raise SupplyChainError("Debian Packages index stanza is malformed")
    return records


def _decompress_index_bytes(path_name: str, raw: bytes) -> bytes:
    try:
        if path_name.endswith(".xz"):
            return lzma.decompress(raw, memlimit=MAX_METADATA_BYTES)
        if path_name.endswith(".gz"):
            return gzip.decompress(raw)
        if path_name.endswith(".bz2"):
            return bz2.decompress(raw)
        if path_name.endswith("/Packages") or path_name == "Packages":
            return raw
    except (OSError, EOFError, lzma.LZMAError) as error:
        raise SupplyChainError("Debian package index compression or contents are invalid") from error
    raise SupplyChainError("Debian package index compression is unsupported")


def verify_debian_repositories(config: dict, expected_packages: list[dict], *, now: dt.datetime, run,
                               expected_snapshot: str, private_mirror_url: str) -> dict:
    if config.get("family") != "debian":
        raise SupplyChainError("repository metadata family does not match Debian package policy")
    keyring = Path(config.get("keyring", ""))
    fingerprints = config.get("approvedFingerprints")
    max_age = config.get("maxAgeSeconds")
    repositories = config.get("repositories")
    if (type(max_age) is not int or not 1 <= max_age <= 604800 or not isinstance(repositories, list)
            or not repositories):
        raise SupplyChainError("Debian repository metadata approval policy is incomplete")
    expected = {item["name"]: item for item in expected_packages}
    found: dict[str, list[dict]] = {name: [] for name in expected}
    keyring_bytes = _regular_bytes(keyring, 16 * 1024 * 1024)
    results = []
    repository_ids: set[str] = set()
    for repo in repositories:
        required = {"id", "root", "baseURL", "snapshotID", "distribution", "origin", "label", "codename",
                    "architectures", "components"}
        if not isinstance(repo, dict) or set(repo) != required:
            raise SupplyChainError("Debian repository identity record is incomplete or has unknown fields")
        if (not isinstance(repo.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", repo["id"])
                or repo["id"] in repository_ids):
            raise SupplyChainError("Debian repository IDs must be unique canonical identifiers")
        repository_ids.add(repo["id"])
        root = Path(repo["root"])
        _safe_directory(root)
        url = repo["baseURL"]
        if (not isinstance(url, str) or not url.startswith("https://") or "@" in url or "?" in url or "#" in url
                or repo["snapshotID"] != expected_snapshot
                or urlsplit(url).hostname != urlsplit(private_mirror_url).hostname):
            raise SupplyChainError("Debian repository identity must bind a credential-free HTTPS base URL")
        inrelease = root / "InRelease"
        release_path = root / "Release"
        detached_sig = root / "Release.gpg"
        has_inrelease = inrelease.exists()
        has_detached = release_path.exists() and detached_sig.exists()
        if not has_inrelease and not (release_path.exists() and detached_sig.exists()):
            raise SupplyChainError("Debian repository requires signed InRelease or Release plus Release.gpg")
        if detached_sig.exists() and not release_path.exists():
            raise SupplyChainError("Debian detached Release signature has no Release file")
        payloads = []
        release_documents = []
        signers = []
        metadata_bytes = []
        signature_bytes = []
        if has_inrelease:
            inrelease = _safe_child(root, "InRelease")
            raw = _regular_bytes(inrelease, 64 * 1024 * 1024)
            signers.append(_verify_gpgv_bytes(keyring_bytes, raw, None, fingerprints, run, inline=True))
            payloads.append(_inrelease_payload(raw))
            release_documents.append(_debian_control(payloads[-1]))
            metadata_bytes.append(raw)
            signature_bytes.append(raw)  # InRelease carries its clearsigned signature inline.
        if has_detached:
            if not release_path.exists() or not detached_sig.exists():
                raise SupplyChainError("Debian detached metadata requires both Release and Release.gpg")
            release_path = _safe_child(root, "Release")
            detached_sig = _safe_child(root, "Release.gpg")
            raw = _regular_bytes(release_path, 64 * 1024 * 1024)
            signature = _regular_bytes(detached_sig, 4 * 1024 * 1024)
            signers.append(_verify_gpgv_bytes(keyring_bytes, signature, raw, fingerprints, run))
            payloads.append(raw)
            release_documents.append(_debian_control(raw))
            metadata_bytes.append(raw)
            signature_bytes.append(signature)
        if any(document != release_documents[0] for document in release_documents[1:]):
            raise SupplyChainError("Debian InRelease and detached Release contents disagree")
        signer = sorted(set(signers))[0]
        release = release_documents[0]
        if any(release.get(k) != repo[v] for k, v in (("Origin", "origin"), ("Label", "label"),
                                                       ("Suite", "distribution"), ("Codename", "codename"))):
            raise SupplyChainError("signed Debian Release identity differs from the approved repository identity")
        if set(release.get("Architectures", "").split()) != set(repo["architectures"]):
            raise SupplyChainError("signed Debian Release architectures differ from the approved repository")
        if set(release.get("Components", "").split()) != set(repo["components"]):
            raise SupplyChainError("signed Debian Release components differ from the approved repository")
        published = _time(release.get("Date"), "Date")
        valid_until = _time(release.get("Valid-Until"), "Valid-Until")
        if published > now + dt.timedelta(minutes=2) or valid_until <= now or now - published > dt.timedelta(seconds=max_age):
            raise SupplyChainError("Debian Release metadata is expired, future-dated, or stale")
        index_hashes = _debian_sha256_entries(release)
        selected = []
        archs = set(repo["architectures"])
        comps = set(repo["components"])
        for relpath, digest in index_hashes.items():
            parts = Path(relpath).parts
            if len(parts) == 3 and parts[0] in comps and parts[1] == "binary-amd64" and parts[2].startswith("Packages"):
                if "amd64" not in archs:
                    raise SupplyChainError("Debian amd64 package index is outside the approved architecture set")
                selected.append((relpath, digest))
        if not selected:
            raise SupplyChainError("signed Debian Release contains no selected amd64 package index")
        index_count = 0
        verified_indexes = []
        for relpath, digest in selected:
            index_path = _safe_child(root, relpath)
            compressed = _regular_bytes(index_path)
            if hashlib.sha256(compressed).hexdigest() != digest:
                raise SupplyChainError("Debian package index differs from the signed Release SHA256")
            verified_indexes.append({"path": relpath, "sha256": digest, "bytes": len(compressed)})
            for record in _parse_deb_packages(_decompress_index_bytes(relpath, compressed)):
                name = record.get("Package")
                if name in expected:
                    sha = record.get("SHA256", "").lower()
                    candidate = {"version": record.get("Version"), "architecture": record.get("Architecture"),
                                 "sha256": sha, "filename": record.get("Filename", "")}
                    found[name].append(candidate)
                index_count += 1
        results.append({"repositoryId": repo["id"], "snapshotID": repo["snapshotID"],
                        "distribution": repo["distribution"], "origin": repo["origin"],
                        "label": repo["label"], "codename": repo["codename"],
                        "architectures": sorted(repo["architectures"]), "components": sorted(repo["components"]),
                        "signerFingerprint": signer, "signerFingerprints": sorted(set(signers)),
                        "releaseSha256": hashlib.sha256(payloads[0]).hexdigest(),
                        "signedMetadataSha256": sorted({hashlib.sha256(payload).hexdigest() for payload in payloads}),
                        "signatureSha256": sorted({hashlib.sha256(signature).hexdigest() for signature in signature_bytes}),
                        "signatureMetadataSha256": [hashlib.sha256(raw).hexdigest() for raw in metadata_bytes],
                        "indexes": verified_indexes,
                        "indexCount": len(selected), "packageRecordCount": index_count,
                        "releaseDate": published.isoformat().replace("+00:00", "Z"),
                        "validUntil": valid_until.isoformat().replace("+00:00", "Z")})
    verified = []
    for name, policy in expected.items():
        candidates = found[name]
        matching = [row for row in candidates if row["version"] == policy["version"]
                    and row["sha256"] == policy["artifactSHA256"]
                    and row["architecture"] in {"amd64", "all"}
                    and row["filename"] and not row["filename"].startswith("/")
                    and ".." not in Path(row["filename"]).parts]
        if len(matching) != 1:
            raise SupplyChainError("signed Debian indexes contain a missing, duplicate, or policy-mismatched package")
        verified.append({"name": name, **matching[0]})
    return {"family": "debian", "keyringSha256": hashlib.sha256(keyring_bytes).hexdigest(),
            "repositories": results, "verifiedPackageCount": len(verified),
            "packages": verified}


def _rpm_primary(xml_bytes: bytes, expected: dict[str, dict]) -> tuple[dict[str, list[dict]], int]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as error:
        raise SupplyChainError("RPM primary metadata XML is malformed") from error
    ns = {"c": "http://linux.duke.edu/metadata/common"}
    found: dict[str, list[dict]] = {name: [] for name in expected}
    count = 0
    for package in root.findall("c:package", ns):
        count += 1
        name = package.findtext("c:name", namespaces=ns)
        if name not in expected:
            continue
        version = package.find("c:version", ns)
        checksum = package.find("c:checksum", ns)
        location = package.find("c:location", ns)
        if version is None or checksum is None or location is None or checksum.get("type") != "sha256":
            raise SupplyChainError("RPM primary metadata package identity is incomplete")
        epoch = version.get("epoch", "0")
        evr = f"{epoch}:{version.get('ver', '')}-{version.get('rel', '')}"
        if evr.startswith("0:"):
            evr = evr[2:]
        row = {"version": evr, "architecture": package.findtext("c:arch", namespaces=ns),
               "sha256": (checksum.text or "").lower(), "filename": location.get("href", "")}
        found[name].append(row)
    return found, count


def verify_rpm_repositories(config: dict, expected_packages: list[dict], *, now: dt.datetime, run,
                            expected_snapshot: str, private_mirror_url: str, os_point_release: str) -> dict:
    if config.get("family") != "rhel":
        raise SupplyChainError("repository metadata family does not match RHEL package policy")
    keyring = Path(config.get("keyring", ""))
    fingerprints = config.get("approvedFingerprints")
    max_age = config.get("maxAgeSeconds")
    repositories = config.get("repositories")
    if (type(max_age) is not int or not 1 <= max_age <= 604800 or not isinstance(repositories, list)
            or not repositories):
        raise SupplyChainError("RPM repository metadata approval policy is incomplete")
    expected = {item["name"]: item for item in expected_packages}
    all_found: dict[str, list[dict]] = {name: [] for name in expected}
    keyring_bytes = _regular_bytes(keyring, 16 * 1024 * 1024)
    results = []
    repository_ids: set[str] = set()
    for repo in repositories:
        required = {"id", "root", "baseURL", "snapshotID", "releasever", "architecture"}
        if not isinstance(repo, dict) or set(repo) != required:
            raise SupplyChainError("RPM repository identity record is incomplete or has unknown fields")
        if (not isinstance(repo.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", repo["id"])
                or repo["id"] in repository_ids):
            raise SupplyChainError("RPM repository IDs must be unique canonical identifiers")
        repository_ids.add(repo["id"])
        root = Path(repo["root"])
        _safe_directory(root)
        repo_url = urlsplit(repo["baseURL"] if isinstance(repo.get("baseURL"), str) else "")
        mirror_url = urlsplit(private_mirror_url if isinstance(private_mirror_url, str) else "")
        if (repo["snapshotID"] != expected_snapshot or repo["releasever"] != os_point_release
                or repo_url.hostname != mirror_url.hostname
                or repo["architecture"] != "x86_64" or not re.fullmatch(r"9\.[0-9]+", repo["releasever"])
                or repo_url.scheme != "https" or not repo_url.path.startswith("/")
                or repo_url.username is not None or repo_url.password is not None
                or repo_url.query or repo_url.fragment):
            raise SupplyChainError("RPM repository identity must bind an exact RHEL minor, x86_64, and private HTTPS URL")
        repomd = _safe_child(root, "repodata/repomd.xml")
        signature = _safe_child(root, "repodata/repomd.xml.asc")
        repomd_bytes = _regular_bytes(repomd, 64 * 1024 * 1024)
        signature_bytes = _regular_bytes(signature, 4 * 1024 * 1024)
        signer = _verify_gpgv_bytes(keyring_bytes, signature_bytes, repomd_bytes, fingerprints, run)
        try:
            doc = ET.fromstring(repomd_bytes)
        except ET.ParseError as error:
            raise SupplyChainError("signed RPM repomd.xml is malformed") from error
        ns = {"r": "http://linux.duke.edu/metadata/repo"}
        revision = doc.findtext("r:revision", namespaces=ns)
        try:
            published = dt.datetime.fromtimestamp(int(revision), tz=dt.timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError) as error:
            raise SupplyChainError("signed RPM repomd revision must be a Unix timestamp") from error
        if published > now + dt.timedelta(minutes=2) or now - published > dt.timedelta(seconds=max_age):
            raise SupplyChainError("RPM repository metadata is future-dated or stale")
        primaries = doc.findall("r:data[@type='primary']", ns)
        if len(primaries) != 1:
            raise SupplyChainError("signed RPM repomd must contain exactly one primary metadata record")
        data = primaries[0]
        location = data.find("r:location", ns)
        checksum = data.find("r:checksum", ns)
        open_checksum = data.find("r:open-checksum", ns)
        if (location is None or checksum is None or open_checksum is None or checksum.get("type") != "sha256"
                or open_checksum.get("type") != "sha256"):
            raise SupplyChainError("RPM primary metadata digest chain is incomplete or not SHA-256")
        href = location.get("href", "")
        if (not href.startswith("repodata/") or href.startswith("/") or ".." in Path(href).parts):
            raise SupplyChainError("RPM primary metadata path is unsafe")
        primary_path = _safe_child(root, href)
        compressed = _regular_bytes(primary_path)
        if hashlib.sha256(compressed).hexdigest() != (checksum.text or "").lower():
            raise SupplyChainError("RPM primary metadata differs from signed repomd checksum")
        try:
            if href.endswith(".gz"):
                opened = gzip.decompress(compressed)
            elif href.endswith(".bz2"):
                opened = bz2.decompress(compressed)
            elif href.endswith(".xz"):
                opened = lzma.decompress(compressed, memlimit=MAX_METADATA_BYTES)
            elif href.endswith(".xml"):
                opened = compressed
            else:
                raise SupplyChainError("RPM primary metadata compression is unsupported")
        except (OSError, EOFError, lzma.LZMAError) as error:
            raise SupplyChainError("RPM primary metadata compression or contents are invalid") from error
        if hashlib.sha256(opened).hexdigest() != (open_checksum.text or "").lower():
            raise SupplyChainError("RPM primary open-checksum differs from signed repomd metadata")
        found, count = _rpm_primary(opened, expected)
        for name, rows in found.items():
            all_found[name].extend(rows)
        results.append({"repositoryId": repo["id"], "snapshotID": repo["snapshotID"],
                        "releasever": repo["releasever"],
                        "architecture": repo["architecture"], "signerFingerprint": signer,
                        "repomdSha256": hashlib.sha256(repomd_bytes).hexdigest(),
                        "signatureSha256": hashlib.sha256(signature_bytes).hexdigest(),
                        "primarySha256": hashlib.sha256(compressed).hexdigest(),
                        "primaryOpenSha256": hashlib.sha256(opened).hexdigest(),
                        "primaryPackageRecordCount": count,
                        "revision": published.isoformat().replace("+00:00", "Z")})
    verified = []
    for name, policy in expected.items():
        rows = all_found[name]
        matches = [row for row in rows if row["version"] == policy["version"]
                   and row["sha256"] == policy["artifactSHA256"] and row["architecture"] in {"x86_64", "noarch"}
                   and row["filename"] and not row["filename"].startswith("/")
                   and ".." not in Path(row["filename"]).parts]
        if len(matches) != 1:
            raise SupplyChainError("signed RPM repositories contain a missing, duplicate, or policy-mismatched package")
        verified.append({"name": name, **matches[0]})
    return {"family": "rhel", "keyringSha256": hashlib.sha256(keyring_bytes).hexdigest(),
            "repositories": results,
            "verifiedPackageCount": len(expected),
            "packages": verified}


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _verified_attestation(output: str, *, image_name: str, digest: str, predicate_type: str,
                          now: dt.datetime, max_age_days: int) -> dict:
    try:
        results = json.loads(output)
    except (json.JSONDecodeError, TypeError) as error:
        raise SupplyChainError("GitHub attestation verifier returned invalid JSON") from error
    if not isinstance(results, list) or len(results) != 1:
        raise SupplyChainError("attestation verification must return exactly one verified result")
    result = results[0].get("verificationResult") if isinstance(results[0], dict) else None
    if not isinstance(result, dict):
        raise SupplyChainError("verified attestation result is incomplete")
    statement = result.get("statement")
    if not isinstance(statement, dict) or statement.get("predicateType") != predicate_type:
        raise SupplyChainError("attestation predicate type is missing or mismatched")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise SupplyChainError("attestation subject is missing")
    if (len(subjects) != 1 or not isinstance(subjects[0], dict)
            or subjects[0].get("name") != image_name
            or not isinstance(subjects[0].get("digest"), dict)
            or subjects[0]["digest"].get("sha256") != digest):
        raise SupplyChainError("attestation subject name or digest does not match the immutable image reference")
    signature = result.get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    if not isinstance(certificate, dict) or certificate.get("issuer") != GH_OIDC_ISSUER:
        raise SupplyChainError("attestation lacks the expected GitHub Actions OIDC certificate identity")
    timestamps = result.get("verifiedTimestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise SupplyChainError("attestation has no cryptographically verified timestamp")
    verified_times = []
    for item in timestamps:
        stamp = item.get("timestamp") if isinstance(item, dict) else None
        verified_times.append(_time(stamp, "attestation timestamp"))
    timestamp = max(verified_times)
    if timestamp > now + dt.timedelta(minutes=2) or now - timestamp > dt.timedelta(days=max_age_days):
        raise SupplyChainError("image attestation is expired under the configured freshness policy")
    return {"statement": statement, "verifiedAt": timestamp}


def _verify_gh_attestation(*, image_ref: str, bundle_bytes: bytes, trust_root_bytes: bytes,
                           trust_root_sha256: str, source_ref: str, source_commit: str,
                           predicate_type: str, now: dt.datetime, max_age_days: int, run) -> dict:
    match = IMAGE_DIGEST.fullmatch(image_ref)
    if not match:
        raise SupplyChainError("container image reference must use an immutable sha256 digest")
    if not re.fullmatch(r"refs/tags/v[0-9]+\.[0-9]+\.[0-9]+", source_ref):
        raise SupplyChainError("attestation source must be an immutable release tag reference")
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", source_commit):
        raise SupplyChainError("attestation source revision must be a full immutable Git commit")
    if not HEX256.fullmatch(trust_root_sha256) or hashlib.sha256(trust_root_bytes).hexdigest() != trust_root_sha256:
        raise SupplyChainError("Sigstore trusted root differs from its independently pinned digest")
    if not bundle_bytes or len(bundle_bytes) > 64 * 1024 * 1024:
        raise SupplyChainError("offline attestation bundle is empty or oversized")
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-image-attestation-") as temporary:
            root = Path(temporary)
            bundle_path = root / "attestation.bundle.jsonl"
            trusted_root_path = root / "sigstore-trusted-root.jsonl"
            _write_private(bundle_path, bundle_bytes)
            _write_private(trusted_root_path, trust_root_bytes)
            cmd = ["gh", "attestation", "verify", f"oci://{image_ref}", "--bundle", str(bundle_path),
                   "--custom-trusted-root", str(trusted_root_path), "--repo", REPOSITORY,
                   "--signer-workflow", WORKFLOW, "--source-ref", source_ref,
                   "--source-digest", source_commit, "--predicate-type", predicate_type, "--format", "json"]
            result = run(cmd, check=True, text=True, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, timeout=180)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SupplyChainError("GitHub/Sigstore attestation signature, identity, or trust verification failed") from error
    verified = _verified_attestation(result.stdout, image_name=image_ref.split("@", 1)[0],
                                     digest=match.group(2), predicate_type=predicate_type,
                                     now=now, max_age_days=max_age_days)
    return {"imageRef": image_ref, "predicateType": predicate_type,
            "bundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
            "trustedRootSha256": trust_root_sha256,
            "attestationTimestamp": verified["verifiedAt"].isoformat().replace("+00:00", "Z"),
            "statement": verified["statement"]}


def verify_image_attestations(config: dict, image_lock: dict[str, str], *, now: dt.datetime, run) -> dict:
    attestations = config.get("imageAttestations")
    trust_root = config.get("sigstoreTrustedRoot")
    trust_root_sha256 = config.get("sigstoreTrustedRootSHA256")
    max_age_days = config.get("maxAgeDays")
    if (not isinstance(attestations, dict) or set(attestations) != set(image_lock)
            or not isinstance(trust_root, str) or not trust_root or type(max_age_days) is not int
            or not 1 <= max_age_days <= 365):
        raise SupplyChainError("six image SBOM/provenance inputs and attestation trust policy are required")
    root_bytes = _regular_bytes(Path(trust_root), 32 * 1024 * 1024)
    if not HEX256.fullmatch(trust_root_sha256) or hashlib.sha256(root_bytes).hexdigest() != trust_root_sha256:
        raise SupplyChainError("Sigstore trusted root differs from its independently pinned digest")
    entries = {}
    for component, image_ref in sorted(image_lock.items()):
        item = attestations[component]
        required = {"sbom", "sbomBundle", "provenanceBundle", "sourceRef", "sourceCommit",
                    "buildMaterials"}
        if not isinstance(item, dict) or set(item) != required:
            raise SupplyChainError("image attestation entry is incomplete or contains unknown fields")
        match = IMAGE_DIGEST.fullmatch(image_ref)
        if not match:
            raise SupplyChainError("signed image lock contains a mutable or malformed image reference")
        entries[component] = (item, image_ref, match)

    # Verify every SBOM before attempting provenance so preflight can report
    # the two independent gates accurately. A missing provenance bundle must
    # not make a verified SBOM appear to have failed (and vice versa).
    sbom_results = {}
    for component, (item, image_ref, match) in entries.items():
        sbom_path = Path(item["sbom"])
        bundle_path = Path(item["sbomBundle"])
        try:
            sbom_bytes = _regular_bytes(sbom_path, 64 * 1024 * 1024)
            count = validate_sbom_bytes(sbom_bytes)
            sbom = json.loads(sbom_bytes.decode("utf-8"))
            sbom_bundle = _regular_bytes(bundle_path, 64 * 1024 * 1024)
            verified = _verify_gh_attestation(
                image_ref=image_ref, bundle_bytes=sbom_bundle, trust_root_bytes=root_bytes,
                trust_root_sha256=trust_root_sha256, source_ref=item["sourceRef"],
                source_commit=item["sourceCommit"], predicate_type=CYCLONEDX_PREDICATE,
                now=now, max_age_days=max_age_days, run=run)
            predicate = verified["statement"].get("predicate")
            if not isinstance(predicate, dict) or _canonical_json(predicate) != _canonical_json(sbom):
                raise SupplyChainError("signed CycloneDX SBOM predicate does not match the supplied SBOM document")
            sbom_results[component] = {
                "imageRef": image_ref, "imageDigest": match.group(2),
                "sbomSha256": hashlib.sha256(sbom_bytes).hexdigest(),
                "sbomComponentCount": count, "sbomBundleSha256": verified["bundleSha256"],
                "sbomAttestationBundleSha256": verified["bundleSha256"],
                "sbomAttestationVerifiedAt": verified["attestationTimestamp"],
                "trustedRootSha256": trust_root_sha256,
            }
        except (SBOMError, OSError, UnicodeError, json.JSONDecodeError, SupplyChainError,
                subprocess.CalledProcessError, subprocess.TimeoutExpired, KeyError, TypeError) as error:
            missing = _path_is_absent(sbom_path) or _path_is_absent(bundle_path)
            raise ImageVerificationError("sbom", component, error, missing=missing) from error

    results = {}
    for component, (item, image_ref, match) in entries.items():
        try:
            provenance_result = _verify_gh_attestation(
                image_ref=image_ref, bundle_bytes=_regular_bytes(Path(item["provenanceBundle"]), 64 * 1024 * 1024),
                trust_root_bytes=root_bytes, trust_root_sha256=trust_root_sha256,
                source_ref=item["sourceRef"], source_commit=item["sourceCommit"],
                predicate_type=SLSA_PREDICATE, now=now, max_age_days=max_age_days, run=run)
        except (OSError, SupplyChainError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
                KeyError, TypeError) as error:
            raise ImageVerificationError(
                "provenance", component, error,
                missing=_path_is_absent(Path(item["provenanceBundle"])),
                sbom_results=sbom_results) from error
        try:
            predicate = provenance_result["statement"].get("predicate")
            if not isinstance(predicate, dict):
                raise SupplyChainError("SLSA provenance predicate is missing")
            build = predicate.get("buildDefinition")
            run_details = predicate.get("runDetails")
            if (not isinstance(build, dict) or build.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1"
                    or not isinstance(run_details, dict) or not isinstance(run_details.get("builder"), dict)
                    or run_details["builder"].get("id") != EXPECTED_BUILDER_ID):
                raise SupplyChainError("SLSA provenance builder identity or build type is not approved")
            params = build.get("externalParameters")
            workflow = params.get("workflow") if isinstance(params, dict) else None
            expected_workflow = {"repository": REPOSITORY, "ref": item["sourceRef"], "path": ".github/workflows/ci.yaml"}
            if (not isinstance(workflow, dict)
                    or any(workflow.get(key) != value for key, value in expected_workflow.items())):
                raise SupplyChainError("SLSA provenance build parameters do not bind the approved source workflow")
            internal = build.get("internalParameters")
            github = internal.get("github") if isinstance(internal, dict) else None
            if (not isinstance(github, dict) or github.get("event_name") != "workflow_dispatch"
                    or github.get("runner_environment") != "github-hosted"
                    or not isinstance(github.get("repository_id"), str)
                    or not github["repository_id"].isdigit()
                    or not isinstance(github.get("repository_owner_id"), str)
                    or not github["repository_owner_id"].isdigit()):
                raise SupplyChainError("SLSA provenance build parameters are incomplete or not from the approved release event")
            materials = build.get("resolvedDependencies")
            if not isinstance(materials, list) or not materials:
                raise SupplyChainError("SLSA provenance has no resolved build materials")
            matched_source = False
            observed_materials = []
            for material in materials:
                if (not isinstance(material, dict) or not isinstance(material.get("uri"), str)
                        or not isinstance(material.get("digest"), dict) or not material["digest"]):
                    raise SupplyChainError("SLSA provenance contains an incomplete material identity")
                for algorithm, value in material["digest"].items():
                    if not isinstance(algorithm, str) or not isinstance(value, str) or not value:
                        raise SupplyChainError("SLSA provenance material digest is malformed")
                observed_materials.append({"uri": material["uri"],
                                           "digest": dict(sorted(material["digest"].items()))})
                uri = material["uri"]
                digest = material["digest"]
                if uri == f"git+https://github.com/{REPOSITORY}@{item['sourceRef']}":
                    matched_source = digest.get("gitCommit") == item["sourceCommit"]
            if not matched_source:
                raise SupplyChainError("SLSA provenance materials do not bind the exact source repository revision")
            expected_materials = item["buildMaterials"]
            source_material = {"uri": f"git+https://github.com/{REPOSITORY}@{item['sourceRef']}",
                               "digest": {"gitCommit": item["sourceCommit"]}}
            normalized_expected = [source_material]
            if (not isinstance(expected_materials, list) or not expected_materials
                    or any(not isinstance(row, dict) or set(row) != {"uri", "digest"}
                           or not isinstance(row.get("uri"), str) or not row["uri"]
                           or not isinstance(row.get("digest"), dict) or not row["digest"]
                           or any(not isinstance(algorithm, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", algorithm)
                                  or not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                                  for algorithm, value in row["digest"].items())
                           for row in expected_materials)):
                raise SupplyChainError("approved build material identities are missing or malformed")
            normalized_expected.extend({"uri": row["uri"], "digest": dict(sorted(row["digest"].items()))}
                                       for row in expected_materials)
            key_material = lambda row: (row["uri"], _canonical_json(row["digest"]))
            if (len({key_material(row) for row in normalized_expected}) != len(normalized_expected)
                    or sorted(map(key_material, observed_materials)) != sorted(map(key_material, normalized_expected))):
                raise SupplyChainError("SLSA provenance build materials differ from the exact approved material identities")
            results[component] = {
                **sbom_results[component],
                "provenanceBundleSha256": provenance_result["bundleSha256"],
                "provenanceAttestationBundleSha256": provenance_result["bundleSha256"],
                "provenanceAttestationVerifiedAt": provenance_result["attestationTimestamp"],
                "sourceRepository": REPOSITORY, "sourceRef": item["sourceRef"],
                "sourceCommit": item["sourceCommit"], "builderId": EXPECTED_BUILDER_ID,
                "workflowIdentity": WORKFLOW_IDENTITY,
                "materials": sorted(observed_materials, key=key_material),
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            }
        except (SupplyChainError, KeyError, TypeError) as error:
            raise ImageVerificationError("provenance", component, error, sbom_results=sbom_results) from error
    return {"imageCount": len(results), "trustedRootSha256": trust_root_sha256, "images": results}
