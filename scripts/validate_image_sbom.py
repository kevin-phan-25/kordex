#!/usr/bin/env python3
"""Fail closed when a generated CycloneDX image SBOM is incomplete or unsafe."""

from __future__ import annotations

import errno
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

MAX_SBOM_BYTES = 64 * 1024 * 1024
CYCLONEDX_SPEC_VERSIONS = {"1.4", "1.5", "1.6"}


class SBOMError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SBOMError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def validate_sbom(path: Path) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SBOMError("SBOM must be a regular non-symlink file") from exc
        raise SBOMError(f"cannot safely open SBOM file: {exc}") from exc

    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SBOMError("SBOM must be a regular non-symlink file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SBOM_BYTES:
            raise SBOMError(f"SBOM size must be between 1 and {MAX_SBOM_BYTES} bytes")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_SBOM_BYTES + 1)
        if len(raw) == 0 or len(raw) > MAX_SBOM_BYTES:
            raise SBOMError(f"SBOM size must be between 1 and {MAX_SBOM_BYTES} bytes")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SBOMError(f"SBOM is not valid UTF-8 JSON: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(document, dict):
        raise SBOMError("SBOM root must be an object")
    if document.get("bomFormat") != "CycloneDX":
        raise SBOMError("SBOM bomFormat must be CycloneDX")
    if document.get("specVersion") not in CYCLONEDX_SPEC_VERSIONS:
        raise SBOMError("SBOM specVersion must be a supported CycloneDX 1.4, 1.5, or 1.6 version")
    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise SBOMError("SBOM version must be a positive integer")

    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise SBOMError("SBOM must contain at least one component")
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise SBOMError(f"SBOM component {index} must be an object")
        if not isinstance(component.get("name"), str) or not component["name"].strip():
            raise SBOMError(f"SBOM component {index} must have a nonempty name")
        if not isinstance(component.get("type"), str) or not component["type"].strip():
            raise SBOMError(f"SBOM component {index} must have a nonempty type")
    return len(components)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} SBOM.json", file=sys.stderr)
        return 2
    try:
        count = validate_sbom(Path(argv[1]))
    except SBOMError as exc:
        print(f"invalid SBOM: {exc}", file=sys.stderr)
        return 1
    print(f"validated CycloneDX SBOM with {count} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
