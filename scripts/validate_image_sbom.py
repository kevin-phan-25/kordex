#!/usr/bin/env python3
"""Fail closed when a generated CycloneDX image SBOM is incomplete or unsafe."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

MAX_SBOM_BYTES = 64 * 1024 * 1024
CYCLONEDX_SPEC_VERSIONS = {"1.4", "1.5", "1.6"}
CYCLONEDX_SCHEMA_SHA256 = {
    "1.4": {"bom.schema.json": "51b79463558376e6397802cce4fd792037a941cda89f9a7cc0abd1b5cbeb67b7",
            "spdx.schema.json": "07e151d41d749e81b868634c8b2b39d65798f1db0356fd98c9591e953c9f24ea",
            "jsf-0.82.schema.json": "a517f9e483e2252debd23d5c62edb72805b6d3932935a6ebb8196745052d2dc3"},
    "1.5": {"bom.schema.json": "067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b",
            "spdx.schema.json": "4f6e2b05c05d26a4f2dc5879fbc2fca94b0a28db46289d0c51345621b71cfbfc",
            "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"},
    "1.6": {"bom.schema.json": "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93",
            "spdx.schema.json": "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e",
            "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"},
}


class SBOMError(ValueError):
    pass


def _validate_official_schema(document: dict[str, Any], version: str) -> None:
    try:
        from jsonschema import Draft7Validator, FormatChecker
        from referencing import Registry, Resource
    except ImportError as exc:
        raise SBOMError("pinned JSON Schema validator dependency is unavailable") from exc
    directory = Path(__file__).resolve().parents[1] / "schemas" / "cyclonedx" / version
    schemas = {}
    for name, expected_digest in CYCLONEDX_SCHEMA_SHA256[version].items():
        path = directory / name
        try:
            raw = path.read_bytes()
            schema = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SBOMError("pinned CycloneDX schema bundle is unavailable or invalid") from exc
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            raise SBOMError("pinned CycloneDX schema digest mismatch")
        schemas[name] = schema
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values())
    try:
        errors = list(Draft7Validator(schemas["bom.schema.json"], registry=registry,
                                      format_checker=FormatChecker()).iter_errors(document))
    except Exception as exc:
        raise SBOMError("CycloneDX JSON Schema evaluation failed") from exc
    if errors:
        errors.sort(key=lambda error: (tuple(str(part) for part in error.absolute_path), error.validator or ""))
        raise SBOMError("SBOM does not conform to the pinned official CycloneDX JSON Schema")


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
    except OSError as exc:
        raise SBOMError(f"cannot safely read SBOM file: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    return validate_sbom_bytes(raw)


def validate_sbom_bytes(raw: bytes) -> int:
    """Validate exact SBOM bytes already captured from a safe file descriptor."""
    if len(raw) == 0 or len(raw) > MAX_SBOM_BYTES:
        raise SBOMError(f"SBOM size must be between 1 and {MAX_SBOM_BYTES} bytes")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SBOMError(f"SBOM is not valid UTF-8 JSON: {exc}") from exc
    return validate_sbom_document(document)


def validate_sbom_document(document: Any) -> int:
    """Validate an already safely-read CycloneDX document and return inventory size."""
    if not isinstance(document, dict):
        raise SBOMError("SBOM root must be an object")
    if document.get("bomFormat") != "CycloneDX":
        raise SBOMError("SBOM bomFormat must be CycloneDX")
    if document.get("specVersion") not in CYCLONEDX_SPEC_VERSIONS:
        raise SBOMError("SBOM specVersion must be a supported CycloneDX 1.4, 1.5, or 1.6 version")
    _validate_official_schema(document, document["specVersion"])
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
