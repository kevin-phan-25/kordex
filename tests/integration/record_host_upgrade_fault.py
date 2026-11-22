#!/usr/bin/env python3
"""Attach a case-specific manual injection record to runner evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile


MATRIX = Path(__file__).with_name("host_upgrade_failure_matrix.json")
VERIFIER_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "scripts/verify-host-upgrade-qualification.py",
    Path(__file__).with_name("verify-host-upgrade-qualification.py"),
)
VERIFIER_PATH = next((path for path in VERIFIER_CANDIDATES if path.is_file()), VERIFIER_CANDIDATES[0])
SPEC = importlib.util.spec_from_file_location("host_upgrade_qualification_verifier", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification verifier cannot be loaded")
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class FaultEvidenceError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise FaultEvidenceError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def parse_time(value: str, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise FaultEvidenceError(f"{field} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise FaultEvidenceError(f"{field} must include a timezone")
    return parsed


def attach(evidence_path: Path, method: str, started_at: str, ended_at: str,
           evidence_ref: str, operator_identity: str, log_path: Path, observations: dict) -> Path:
    verifier.verify_pinned_matrix(MATRIX)
    if evidence_path.is_symlink():
        raise FaultEvidenceError("runner evidence file must not be a symlink")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(evidence, dict) or evidence.get("mode") != "execute":
        raise FaultEvidenceError("runner evidence must be a completed execution record")
    case_id = evidence.get("qualificationCase")
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    cases = [case for case in matrix.get("cases", []) if case.get("id") == case_id]
    if len(cases) != 1 or cases[0].get("execution") != "manual-injection":
        raise FaultEvidenceError("runner evidence does not name exactly one manual-injection case")
    requirement = cases[0].get("faultEvidence")
    if not isinstance(requirement, dict):
        raise FaultEvidenceError("reviewed matrix has no case-specific fault evidence contract")
    if evidence.get("outcome") not in cases[0].get("allowedOutcomes", []):
        raise FaultEvidenceError("runner outcome is not an accepted safe outcome for this case")
    if not isinstance(observations, dict):
        raise FaultEvidenceError("observations must be a JSON object")
    start = parse_time(started_at, "startedAt")
    finish = parse_time(ended_at, "endedAt")
    if finish < start:
        raise FaultEvidenceError("endedAt precedes startedAt")
    drill_start = parse_time(evidence.get("startedAt", ""), "runner startedAt")
    drill_finish = parse_time(evidence.get("finishedAt", ""), "runner finishedAt")
    if not drill_start <= start <= finish <= drill_finish:
        raise FaultEvidenceError("fault injection times must fall inside the runner execution interval")
    if (not method.strip() or not evidence_ref.strip() or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", operator_identity or "")):
        raise FaultEvidenceError("method, external evidence reference, and operator identity are required")
    if log_path.is_symlink() or not log_path.is_file():
        raise FaultEvidenceError("injection log must be a regular, non-symlink file")
    evidence_dir = evidence_path.parent.resolve(strict=True)
    artifact_dir = evidence_dir / "injection-logs"
    artifact_dir.mkdir(mode=0o700, exist_ok=True)
    if artifact_dir.is_symlink() or not artifact_dir.is_dir():
        raise FaultEvidenceError("injection-logs must be a real directory")
    artifact_dir.chmod(0o700)
    artifact = artifact_dir / f"{case_id}-{evidence.get('osFamily')}.log"
    if artifact.exists() or artifact.is_symlink():
        raise FaultEvidenceError(f"refusing to overwrite existing injection evidence: {artifact.name}")
    shutil.copyfile(log_path, artifact)
    artifact.chmod(0o600)
    injection = {
        "faultType": requirement.get("faultType"),
        "method": method.strip(),
        "operatorIdentity": operator_identity,
        "startedAt": started_at,
        "endedAt": ended_at,
        "evidenceRef": evidence_ref.strip(),
        "evidenceFile": artifact.relative_to(evidence_dir).as_posix(),
        "evidenceSHA256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "observations": observations,
    }
    try:
        verifier.verify_fault_observations(requirement, injection, evidence, case_id)
    except Exception:
        artifact.unlink(missing_ok=True)
        raise
    evidence["injection"] = injection
    fd, temporary_name = tempfile.mkstemp(prefix=f".{evidence_path.name}.", suffix=".tmp", dir=evidence_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, evidence_path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        artifact.unlink(missing_ok=True)
        raise
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path, help="completed runner evidence JSON")
    parser.add_argument("--method", required=True, help="exact lab fault-injection mechanism")
    parser.add_argument("--started-at", required=True, help="RFC3339 injection start time")
    parser.add_argument("--ended-at", required=True, help="RFC3339 injection end time")
    parser.add_argument("--evidence-ref", required=True, help="lab console, ticket, or external log reference")
    parser.add_argument("--operator-identity", required=True,
                        help="customer identity of the authorized fault operator; never a secret")
    parser.add_argument("--log", required=True, type=Path, help="raw lab log to copy and hash")
    parser.add_argument("--observations", required=True, help="JSON object matching the reviewed case contract")
    args = parser.parse_args()
    try:
        observations = json.loads(args.observations, object_pairs_hook=unique_object)
        artifact = attach(args.evidence, args.method, args.started_at, args.ended_at,
                          args.evidence_ref, args.operator_identity, args.log, observations)
    except (FaultEvidenceError, verifier.EvidenceError, OSError, json.JSONDecodeError, TypeError, KeyError) as error:
        print(f"fault evidence rejected: {error}", file=sys.stderr)
        return 1
    print(f"attached case-specific injection evidence to {args.evidence}; copied log: {artifact}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
