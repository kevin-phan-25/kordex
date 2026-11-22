#!/usr/bin/env python3
"""Create and verify signed provenance/reviewer records for M3 evidence archives.

This tool distinguishes structural validity, content hashes, trusted collector
attestation, and an independent review. A signature attests the signer’s
statement; it does not by itself prove that a file came from a physical host.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "tests/integration/host_upgrade_failure_matrix.json"
STRUCTURAL_VERIFIER = ROOT / "scripts/verify-host-upgrade-qualification.py"
SPEC = importlib.util.spec_from_file_location("m3_structural_verifier", STRUCTURAL_VERIFIER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("structural evidence verifier cannot be loaded")
structural = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = structural
SPEC.loader.exec_module(structural)


class ProvenanceError(ValueError):
    pass


SHA256 = re.compile(r"^[a-f0-9]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProvenanceError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ProvenanceError("record cannot be represented as canonical JSON") from error


def read_file(path: Path, limit: int = 64 * 1024 * 1024) -> bytes:
    require(not path.is_symlink(), "evidence and trust inputs must not be symlinks")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise ProvenanceError("evidence or trust file is unavailable") from error
    require(stat.S_ISREG(before.st_mode) and len(raw) == before.st_size and len(raw) <= limit
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "evidence file is not regular, bounded, or stable while reading")
    return raw


def load_json(path: Path, limit: int = 2 * 1024 * 1024) -> tuple[dict, bytes]:
    raw = read_file(path, limit)
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ProvenanceError("record is malformed JSON") from error
    require(isinstance(value, dict), "record must be one JSON object")
    return value, raw


def parse_time(value: object, field: str) -> dt.datetime:
    require(isinstance(value, str), f"{field} must be an RFC3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProvenanceError(f"{field} must be a valid RFC3339 timestamp") from error
    require(parsed.tzinfo is not None, f"{field} must include a timezone")
    return parsed


def _write_snapshot(directory: Path, name: str, content: bytes) -> Path:
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def public_key_fingerprint_bytes(raw: bytes) -> str:
    require(raw and len(raw) <= 64 * 1024, "public verification key is empty or oversized")
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-public-key-") as temporary:
            path = _write_snapshot(Path(temporary), "public.pem", raw)
            key_type = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(path), "-text", "-noout"],
                                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
            require(key_type.splitlines()[:1] == ["ED25519 Public-Key:"],
                    "evidence verification keys must use Ed25519")
            result = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
                                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ProvenanceError("public verification key could not be parsed") from error
    return hashlib.sha256(result.stdout).hexdigest()


def public_key_fingerprint(path: Path) -> str:
    return public_key_fingerprint_bytes(read_file(path, 64 * 1024))


def verify_detached_signature(record: bytes, signature: bytes, public_key: bytes,
                              expected_fingerprint: str) -> str:
    """Verify an immutable in-memory snapshot of all detached-signature inputs."""
    require(SHA256.fullmatch(expected_fingerprint or "") is not None,
            "expected public-key fingerprint must be SHA-256 hex")
    require(record and len(record) <= 8 * 1024 * 1024 and signature and len(signature) <= 4096,
            "signed record or signature is empty or oversized")
    actual = public_key_fingerprint_bytes(public_key)
    require(actual == expected_fingerprint, "public-key fingerprint does not match independent trust input")
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-signature-") as temporary:
            directory = Path(temporary)
            record_path = _write_snapshot(directory, "record.bin", record)
            signature_path = _write_snapshot(directory, "record.sig", signature)
            key_path = _write_snapshot(directory, "public.pem", public_key)
            subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path),
                            "-rawin", "-in", str(record_path), "-sigfile", str(signature_path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ProvenanceError("detached Ed25519 signature verification failed") from error
    return actual


def verify_signature(record_path: Path, signature_path: Path, public_key: Path,
                     expected_fingerprint: str) -> str:
    return verify_detached_signature(read_file(record_path, 8 * 1024 * 1024),
                                     read_file(signature_path, 4096),
                                     read_file(public_key, 64 * 1024), expected_fingerprint)


def file_inventory(directory: Path) -> list[dict]:
    require(directory.is_dir() and not directory.is_symlink(), "evidence directory must be a real directory")
    files = []
    total = 0
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ProvenanceError("evidence directory contains a symlink")
        if path.is_dir():
            continue
        require(path.is_file(), "evidence directory contains a special filesystem entry")
        relative = path.relative_to(directory).as_posix()
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                "evidence path traversal is not allowed")
        raw = read_file(path)
        total += len(raw)
        require(total <= 2 * 1024 * 1024 * 1024, "evidence directory exceeds the 2 GiB safety limit")
        files.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    require(files, "evidence directory is empty")
    return files


def evidence_case_rows(directory: Path, matrix: dict, collector: str, collected_at: str) -> list[dict]:
    families = matrix["osFamilies"]
    rows = []
    seen = set()
    for case in matrix["cases"]:
        for family in families:
            filename = f"{case['id']}-{family}.json"
            evidence, raw = load_json(directory / filename)
            pair = (case["id"], family)
            require(pair not in seen, "duplicate scenario/platform evidence")
            seen.add(pair)
            require(evidence.get("qualificationCase") == case["id"] and evidence.get("osFamily") == family,
                    "evidence scenario or platform conflicts with the canonical matrix")
            require(evidence.get("qualificationScope") != "supplemental",
                    "supplemental evidence cannot be declared canonical real-host evidence")
            require(evidence.get("mode") == "execute" and evidence.get("admissionChecksPassed") is True,
                    "only an executed qualification record with passed admission checks can enter the real-host manifest")
            require(evidence.get("evidenceOrigin") == "real-host"
                    and evidence.get("environmentClaim") == "real-host"
                    and evidence.get("testFixture") is False,
                    "evidence must explicitly identify real-host origin; synthetic or unmarked fixtures are rejected")
            platform = evidence.get("platformEvidence")
            preflight = evidence.get("hostPreflightReceipt")
            node = evidence.get("node")
            require(isinstance(platform, dict) and isinstance(preflight, dict) and isinstance(node, dict),
                    "evidence lacks platform, host identity, or node bindings")
            injection = evidence.get("injection") if case.get("execution") == "manual-injection" else None
            if injection is not None:
                require(isinstance(injection.get("method"), str) and injection["method"]
                        and isinstance(injection.get("operatorIdentity"), str) and injection["operatorIdentity"],
                        "manual fault evidence lacks method or operator identity")
            rows.append({
                "scenario": case["id"], "platform": family,
                "evidenceFile": filename, "evidenceSha256": hashlib.sha256(raw).hexdigest(),
                "operationId": evidence.get("operationId"), "planDigest": evidence.get("planDigest"),
                "profile": platform.get("profile"), "osVersion": platform.get("osVersion"),
                "imageIdentity": platform.get("imageID"), "imageUniqueId": platform.get("imageUniqueID"),
                "imageApprovalReference": platform.get("imageApprovalReference"),
                "imageApprovalSha256": platform.get("imageApprovalSHA256"),
                "artifactPreflightReportSha256": platform.get("artifactPreflightReportSHA256"),
                "packagePolicySha256": platform.get("packagePolicySHA256"),
                "packageArchiveSha256": platform.get("packageArchiveSHA256"),
                "machineIdentity": preflight.get("machineId"), "nodeIdentity": node.get("uid"),
                "collectorIdentity": collector, "collectedAt": collected_at,
                "faultInjectionMethod": injection.get("method") if injection else "not-applicable",
                "faultInjectionOperatorIdentity": injection.get("operatorIdentity") if injection else "not-applicable",
                "environmentClaim": "real-host",
            })
    require(len(seen) == len(matrix["cases"]) * len(families), "canonical evidence matrix is incomplete")
    return sorted(rows, key=lambda row: (row["scenario"], row["platform"]))


def create_manifest(evidence_dir: Path, output: Path, collector: str, collected_at: str) -> dict:
    matrix = json.loads(read_file(MATRIX), object_pairs_hook=unique_object)
    structural.verify_pinned_matrix(MATRIX)
    structural.verify_directory(MATRIX, evidence_dir)
    parse_time(collected_at, "collectedAt")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", collector or "") is not None,
            "collector identity is malformed")
    require(not output.exists() and not output.is_symlink(), "refusing to overwrite evidence manifest")
    try:
        output.resolve().relative_to(evidence_dir.resolve())
    except ValueError:
        pass
    else:
        raise ProvenanceError("manifest and signatures must be stored outside the evidence directory")
    manifest = {
        "schemaVersion": 1,
        "canonicalMatrixSha256": structural.FAILURE_MATRIX_SHA256,
        "environmentClaim": "real-host",
        "collectorIdentity": collector,
        "collectedAt": collected_at,
        "evidenceArtifacts": file_inventory(evidence_dir),
        "cases": evidence_case_rows(evidence_dir, matrix, collector, collected_at),
    }
    validate_manifest_header(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_json(manifest)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ProvenanceError("refusing to overwrite or create an unsafe manifest output") from error
    return manifest


def verify_review(review: dict, manifest_sha: str, collector_identity: str) -> None:
    required = {"schemaVersion", "manifestSha256", "reviewerIdentity", "decision", "reviewedAt", "reason"}
    require(set(review) == required and review.get("schemaVersion") == 1,
            "review record has missing or unsupported fields")
    require(review.get("manifestSha256") == manifest_sha, "review decision is not bound to this manifest")
    require(review.get("decision") in {"accepted", "rejected"}, "review decision must be accepted or rejected")
    require(isinstance(review.get("reviewerIdentity"), str) and review["reviewerIdentity"]
            and review["reviewerIdentity"] != collector_identity,
            "independent reviewer must be identified separately from the collector")
    require(isinstance(review.get("reason"), str) and review["reason"].strip(),
            "review decision requires a reason")
    parse_time(review.get("reviewedAt"), "reviewedAt")


def require_distinct_signers(collector_fingerprint: str, reviewer_fingerprint: str) -> None:
    require(SHA256.fullmatch(collector_fingerprint or "") is not None
            and SHA256.fullmatch(reviewer_fingerprint or "") is not None,
            "collector and reviewer key fingerprints must be SHA-256 hex")
    require(collector_fingerprint != reviewer_fingerprint,
            "collector and reviewer must use distinct independently trusted signing keys")


def validate_manifest_header(manifest: dict) -> None:
    required = {"schemaVersion", "canonicalMatrixSha256", "environmentClaim", "collectorIdentity",
                "collectedAt", "evidenceArtifacts", "cases"}
    require(set(manifest) == required and manifest.get("schemaVersion") == 1,
            "manifest schema has missing or unsupported fields")
    require(manifest.get("canonicalMatrixSha256") == structural.FAILURE_MATRIX_SHA256,
            "manifest canonical matrix digest is not the reviewed matrix")
    require(manifest.get("environmentClaim") == "real-host",
            "synthetic or supplemental evidence cannot be accepted as real-host evidence")
    require(isinstance(manifest.get("collectorIdentity"), str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", manifest["collectorIdentity"]),
            "collector identity is malformed")
    parse_time(manifest.get("collectedAt"), "collectedAt")


def validate_case_index(rows: object, expected_pairs: set[tuple[str, str]]) -> None:
    require(isinstance(rows, list), "manifest cases must be a list")
    observed = []
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("scenario"), str)
                and isinstance(row.get("platform"), str), "manifest case identity is malformed")
        observed.append((row["scenario"], row["platform"]))
    require(len(observed) == len(set(observed)), "manifest contains duplicate or contradictory scenario/platform rows")
    require(set(observed) == expected_pairs and len(observed) == len(expected_pairs),
            "manifest scenario/platform rows do not match the canonical matrix")


def verify_package(args) -> dict:
    structural.verify_pinned_matrix(MATRIX)
    complete = structural.verify_directory(MATRIX, args.evidence_directory)
    manifest, manifest_raw = load_json(args.manifest, 8 * 1024 * 1024)
    require(manifest_raw == canonical_json(manifest), "evidence manifest is not canonical JSON")
    validate_manifest_header(manifest)
    collector = manifest.get("collectorIdentity")
    parse_time(manifest.get("collectedAt"), "collectedAt")
    expected_artifacts = file_inventory(args.evidence_directory)
    require(manifest.get("evidenceArtifacts") == expected_artifacts,
            "evidence artifact inventory or SHA-256 binding differs from the manifest")
    matrix = json.loads(read_file(MATRIX), object_pairs_hook=unique_object)
    expected_cases = evidence_case_rows(args.evidence_directory, matrix, collector, manifest["collectedAt"])
    expected_pairs = {(case["id"], family) for case in matrix["cases"] for family in matrix["osFamilies"]}
    validate_case_index(manifest.get("cases"), expected_pairs)
    require(manifest.get("cases") == expected_cases and len(expected_cases) == 22,
            "scenario evidence has duplicate, contradictory, or incomplete platform bindings")
    collector_fingerprint = verify_detached_signature(
        manifest_raw, read_file(args.manifest_signature, 4096),
        read_file(args.collector_public_key, 64 * 1024), args.collector_fingerprint)
    review, review_raw = load_json(args.review, 64 * 1024)
    require(review_raw == canonical_json(review), "review record is not canonical JSON")
    verify_review(review, hashlib.sha256(manifest_raw).hexdigest(), collector)
    reviewer_fingerprint = verify_detached_signature(
        review_raw, read_file(args.review_signature, 4096),
        read_file(args.reviewer_public_key, 64 * 1024), args.reviewer_fingerprint)
    require_distinct_signers(collector_fingerprint, reviewer_fingerprint)
    return {
        "structurallyValid": True,
        "structuralCases": len(complete),
        "evidenceArtifactHashesVerified": True,
        "canonicalMatrixSha256": structural.FAILURE_MATRIX_SHA256,
        "planPolicyHostOperationScenarioBindingsVerified": True,
        "collectorSignatureVerified": True,
        "collectorIdentity": collector,
        "collectorKeyFingerprint": collector_fingerprint,
        "originAssessment": "trusted collector attestation; signature is not independent proof of physical host origin",
        "reviewerSignatureVerified": True,
        "reviewerIdentity": review["reviewerIdentity"],
        "reviewerKeyFingerprint": reviewer_fingerprint,
        "reviewDecision": review["decision"].upper(),
        "qualificationAccepted": review["decision"] == "accepted",
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="verify structural evidence and write an unsigned canonical manifest")
    prepare.add_argument("--evidence-directory", type=Path, required=True)
    prepare.add_argument("--collector-identity", required=True)
    prepare.add_argument("--collected-at", required=True)
    prepare.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify matrix evidence, collector signature, and independent review")
    verify.add_argument("--evidence-directory", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--manifest-signature", type=Path, required=True)
    verify.add_argument("--collector-public-key", type=Path, required=True)
    verify.add_argument("--collector-fingerprint", required=True)
    verify.add_argument("--review", type=Path, required=True)
    verify.add_argument("--review-signature", type=Path, required=True)
    verify.add_argument("--reviewer-public-key", type=Path, required=True)
    verify.add_argument("--reviewer-fingerprint", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = create_manifest(args.evidence_directory, args.output,
                                     args.collector_identity, args.collected_at)
            print(json.dumps({"manifest": args.output.name,
                              "canonicalMatrixSha256": result["canonicalMatrixSha256"],
                              "caseCount": len(result["cases"]),
                              "artifactCount": len(result["evidenceArtifacts"]),
                              "signatureStatus": "NOT SIGNED"}, sort_keys=True))
            return 0
        result = verify_package(args)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["qualificationAccepted"] else 1
    except (ProvenanceError, structural.EvidenceError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"M3 evidence provenance rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
