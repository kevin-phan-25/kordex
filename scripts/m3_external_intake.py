#!/usr/bin/env python3
"""Read-only intake inventory for the 47 M3 external delivery slots.

This command verifies receipt integrity only. It never verifies signatures,
approves an input, invokes a domain verifier, or advances qualification.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

try:
    import m3_qualification as qualification
except ModuleNotFoundError:
    from scripts import m3_qualification as qualification


ROOT = Path(__file__).resolve().parents[1]
DELIVERY_MANIFEST = ROOT / "docs/m3-external-delivery-manifest.json"
DELIVERY_SCHEMA = ROOT / "schemas/m3-external-delivery-manifest-v1.json"
REPORT_SCHEMA = ROOT / "schemas/m3-external-intake-report-v1.json"
STATUS_VALUES = {"NOT PROVIDED", "RECEIVED", "VERIFIED", "APPROVED", "REJECTED"}


class IntakeError(ValueError):
    pass


def _open_private_dir(path: Path, label: str) -> int:
    dir_fd = None
    try:
        dir_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(dir_fd)
    except OSError as error:
        if dir_fd is not None:
            os.close(dir_fd)
        raise IntakeError(f"{label} is unavailable or unsafe") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(dir_fd)
        raise IntakeError(f"{label} must be private (mode 0700 or stricter)")
    return dir_fd


def _normalize_reference(reference: str) -> tuple[str, tuple[str, ...]]:
    if (not isinstance(reference, str) or not reference or "\\" in reference
            or reference.startswith("/") or reference.endswith("/")
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in reference)):
        raise IntakeError("input reference must be a canonical relative POSIX path")
    parts = reference.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise IntakeError("input reference must be a canonical relative POSIX path")
    return "/".join(parts), tuple(parts)


def _read_json(path: Path, limit: int = 4 * 1024 * 1024, *, dir_fd: int | None = None) -> tuple[dict, bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        if dir_fd is not None:
            target = path.name
            if not target or target in {".", ".."} or "/" in str(path):
                raise IntakeError(f"intake JSON path must name a file: {path}")
            fd = os.open(target, flags, dir_fd=dir_fd)
        else:
            fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise IntakeError(f"intake JSON is unsafe or changed while reading: {path}")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except IntakeError:
        raise
    except OSError as error:
        raise IntakeError(f"cannot read required intake JSON: {path}") from error
    if (not stat.S_ISREG(before.st_mode) or len(raw) != before.st_size or len(raw) > limit
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise IntakeError(f"intake JSON is unsafe or changed while reading: {path}")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=qualification.unique_object)
    except (UnicodeError, json.JSONDecodeError, qualification.QualificationError) as error:
        raise IntakeError(f"intake JSON is malformed: {path}") from error
    if not isinstance(value, dict):
        raise IntakeError(f"intake JSON must be an object: {path}")
    return value, raw, before


def _validate_delivery_contract(path: Path) -> tuple[dict, str]:
    manifest, raw, _ = _read_json(path)
    schema, _, _ = _read_json(DELIVERY_SCHEMA)
    try:
        from jsonschema import Draft202012Validator
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(manifest)
    except Exception as error:
        raise IntakeError("authoritative 47-slot delivery manifest failed schema validation") from error
    ids = [row["inputId"] for row in manifest["inputs"]]
    if len(ids) != len(set(ids)) or set(ids) != set(qualification.INPUTS):
        raise IntakeError("delivery contract must contain every authoritative slot exactly once")
    if set(manifest["statusValues"]) != STATUS_VALUES:
        raise IntakeError("delivery contract state vocabulary is inconsistent")
    return manifest, hashlib.sha256(raw).hexdigest()


def _private_mode(file_stat: os.stat_result) -> bool:
    """Customer-delivered inputs must not grant group/world access."""
    return stat.S_IMODE(file_stat.st_mode) & 0o077 == 0


def _hash_payload(base_fd: int, parts: tuple[str, ...]) -> tuple[str, int, tuple[int, int]]:
    opened_dirs: list[int] = []
    cur_fd = base_fd
    try:
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        for part in parts[:-1]:
            next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
            opened_dirs.append(next_fd)
            dir_info = os.fstat(next_fd)
            if not stat.S_ISDIR(dir_info.st_mode) or stat.S_IMODE(dir_info.st_mode) & 0o077:
                raise IntakeError("delivered input subdirectory must be private (mode 0700 or stricter)")
            cur_fd = next_fd
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(parts[-1], file_flags, dir_fd=cur_fd)
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not _private_mode(before):
                raise IntakeError("delivered input must be a private regular file (mode 0600 or stricter)")
            if before.st_size == 0:
                raise IntakeError("delivered input must not be empty")
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(block)
                if size > qualification.MAX_INPUT:
                    raise IntakeError("delivered input exceeds the supported size limit")
                digest.update(block)
            after = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or size != before.st_size
                or size == 0):
            raise IntakeError("delivered input changed while hashing")
    except IntakeError:
        raise
    except OSError as error:
        raise IntakeError("delivered input is unavailable or unsafe") from error
    finally:
        for dir_fd in reversed(opened_dirs):
            os.close(dir_fd)
    return digest.hexdigest(), size, (before.st_dev, before.st_ino)


def build_report(*, delivery_manifest_path: Path, inputs_path: Path,
                 now: dt.datetime | None = None) -> dict:
    delivery_manifest, delivery_digest = _validate_delivery_contract(delivery_manifest_path)
    if not inputs_path.name or inputs_path.name in {".", ".."}:
        raise IntakeError("customer input manifest path must name a file")
    base_fd = _open_private_dir(inputs_path.parent, "customer input manifest directory")
    try:
        inputs, input_raw, input_stat = _read_json(Path(inputs_path.name), dir_fd=base_fd)
        if not _private_mode(input_stat):
            raise IntakeError("customer input manifest must have mode 0600 or stricter")
        qualification.validate_manifest(inputs)
        if inputs["projectId"] != delivery_manifest["projectId"]:
            raise IntakeError("customer input manifest projectId differs from delivery contract")
        fixture_only = bool(inputs["fixtureOnly"])

        references: dict[str, str] = {}
        normalized_parts: dict[str, tuple[str, ...]] = {}
        for input_id, item in inputs["inputs"].items():
            if item is None:
                continue
            canonical_ref, parts = _normalize_reference(item["reference"])
            if canonical_ref in references:
                raise IntakeError(f"duplicate payload reference used by {references[canonical_ref]} and {input_id}")
            references[canonical_ref] = input_id
            normalized_parts[input_id] = parts

        current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
        contract_entries = {row["inputId"]: row for row in delivery_manifest["inputs"]}
        seen_inodes: dict[tuple[int, int], str] = {}
        entries = []
        for input_id in sorted(qualification.INPUTS):
            declared = inputs["inputs"][input_id]
            contract = contract_entries[input_id]
            digest = None
            size = None
            expected_digest = declared["sha256"] if declared else None
            if declared is None:
                delivery_state = "NOT PROVIDED"
                reason = "required input reference is absent"
            else:
                try:
                    digest, size, inode = _hash_payload(base_fd, normalized_parts[input_id])
                except IntakeError as error:
                    delivery_state = "REJECTED"
                    reason = str(error)
                else:
                    if inode in seen_inodes:
                        raise IntakeError(
                            f"duplicate payload inode used by {seen_inodes[inode]} and {input_id}")
                    seen_inodes[inode] = input_id
                    if fixture_only:
                        delivery_state = "REJECTED"
                        reason = "fixtureOnly input can never be accepted as external delivery"
                    elif digest != expected_digest:
                        delivery_state = "REJECTED"
                        reason = "payload digest differs from the customer input manifest"
                    elif declared["expiresAt"] is not None and qualification.parse_time(declared["expiresAt"]) <= current:
                        delivery_state = "REJECTED"
                        reason = "delivery input is expired"
                    else:
                        delivery_state = "RECEIVED"
                        reason = "payload is safely received and SHA-256 matches; cryptographic/domain verification and approval remain pending"
            entries.append({
                "inputId": input_id,
                "ownerRole": contract["ownerRole"],
                "campaigns": contract["campaigns"],
                "components": contract["components"],
                "blockedGates": contract["blockedGates"],
                "reference": declared["reference"] if declared else None,
                "sha256": digest,
                "expectedSha256": expected_digest,
                "sizeBytes": size,
                "status": delivery_state,
                "domainVerification": "NOT RUN",
                "independentApproval": "NOT RUN",
                "validator": contract["validator"]["domainValidator"],
                "reason": reason,
            })
    finally:
        os.close(base_fd)
    statuses = {entry["status"] for entry in entries}
    rejected = sum(entry["status"] == "REJECTED" for entry in entries)
    received = sum(entry["status"] == "RECEIVED" for entry in entries)
    missing = sum(entry["status"] == "NOT PROVIDED" for entry in entries)
    return {
        "schemaVersion": 1,
        "generatedAt": current.isoformat().replace("+00:00", "Z"),
        "projectId": delivery_manifest["projectId"],
        "inputCount": len(entries),
        "deliveryManifestSha256": delivery_digest,
        "customerInputsManifestSha256": hashlib.sha256(input_raw).hexdigest(),
        "statusValues": sorted(STATUS_VALUES),
        "summary": {"received": received, "notProvided": missing, "rejected": rejected,
                    "verified": 0, "approved": 0,
                    "overall": "REJECTED" if ("REJECTED" in statuses or fixture_only) else
                               "NOT PROVIDED" if missing else "RECEIVED"},
        "entries": entries,
        "qualificationRowsAdvanced": 0,
        "qualificationAccepted": False,
        "limitations": [
            "RECEIVED means file safety, expiry, and declared SHA-256 passed only.",
            "This command does not invoke cryptographic/domain validators or reviewers.",
            "VERIFIED requires the named domain verifier; APPROVED requires distinct authorized signed review.",
            "Original payload files are read only and are not copied or modified.",
            "A local digest is not proof of immutable archive custody or origin.",
        ],
    }


def validate_report(report: dict) -> None:
    """Enforce the published report contract before anything is persisted."""
    schema, _, _ = _read_json(REPORT_SCHEMA)
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    except Exception as error:
        raise IntakeError("intake report does not satisfy its published schema") from error


def write_report(path: Path, report: dict) -> None:
    """Create a private report without replacing a prior intake record."""
    validate_report(report)
    name = path.name
    if not name or name in {".", ".."} or "/" in name:
        raise IntakeError("intake report path must name a file")
    dir_fd = _open_private_dir(path.parent, "intake report directory")
    encoded = qualification.canonical_json(report)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise IntakeError("intake report cannot overwrite an existing record or unsafe path") from error
    finally:
        os.close(dir_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True,
                        help="customer-owned 47-slot inputs manifest; payloads stay in place")
    parser.add_argument("--report", type=Path, required=True,
                        help="new private report path; an existing report is never overwritten")
    args = parser.parse_args(argv)
    try:
        report = build_report(delivery_manifest_path=DELIVERY_MANIFEST, inputs_path=args.inputs)
        write_report(args.report, report)
    except (IntakeError, qualification.QualificationError) as error:
        print(json.dumps({"status": "REJECTED", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 1 if (report["summary"]["rejected"] or report["summary"]["overall"] == "REJECTED") else 0


if __name__ == "__main__":
    raise SystemExit(main())
