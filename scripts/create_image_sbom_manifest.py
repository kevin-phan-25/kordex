#!/usr/bin/env python3
"""Bind a CI CycloneDX SBOM to its source revision and built image config."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.validate_image_sbom import MAX_SBOM_BYTES, SBOMError, validate_sbom

COMPONENTS = {"agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres", "agent-relay"}
SHA256 = re.compile(r"sha256:[a-f0-9]{64}\Z")
COMMIT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")


def _read_regular(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SBOMError("SBOM input cannot be a symlink") from exc
        raise SBOMError(f"cannot safely open SBOM input: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SBOMError("SBOM input must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SBOM_BYTES:
            raise SBOMError(f"SBOM input size must be between 1 and {MAX_SBOM_BYTES} bytes")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            contents = stream.read(MAX_SBOM_BYTES + 1)
        if not contents or len(contents) > MAX_SBOM_BYTES:
            raise SBOMError(f"SBOM input size must be between 1 and {MAX_SBOM_BYTES} bytes")
        return contents
    finally:
        if fd >= 0:
            os.close(fd)


def create_manifest(
    component: str,
    source_commit: str,
    image_config_digest: str,
    sbom_path: Path,
    output_path: Path,
) -> dict[str, object]:
    if component not in COMPONENTS:
        raise SBOMError("component is not in the fixed Kordex image catalog")
    if not COMMIT.fullmatch(source_commit):
        raise SBOMError("source commit must be a full lowercase Git SHA-1 or SHA-256")
    if not SHA256.fullmatch(image_config_digest):
        raise SBOMError("image config digest must be sha256 followed by 64 lowercase hex characters")

    component_count = validate_sbom(sbom_path)
    sbom_digest = hashlib.sha256(_read_regular(sbom_path)).hexdigest()
    manifest: dict[str, object] = {
        "schemaVersion": 1,
        "component": component,
        "sourceCommit": source_commit,
        "imageConfigDigest": image_config_digest,
        "sbom": {
            "file": sbom_path.name,
            "sha256": sbom_digest,
            "componentCount": component_count,
            "format": "CycloneDX",
        },
    }

    try:
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o644)
    except OSError as exc:
        raise SBOMError(f"cannot create manifest without overwriting: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(manifest, stream, sort_keys=True, indent=2)
            stream.write("\n")
    finally:
        if fd >= 0:
            os.close(fd)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--image-config-digest", required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest = create_manifest(
            args.component,
            args.source_commit,
            args.image_config_digest,
            args.sbom,
            args.output,
        )
    except SBOMError as exc:
        print(f"invalid SBOM manifest input: {exc}", file=sys.stderr)
        return 1
    print(
        f"bound {manifest['component']} SBOM to {manifest['imageConfigDigest']} "
        f"and source {manifest['sourceCommit']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
