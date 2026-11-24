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
import secrets
import stat
import subprocess
import sys
import tempfile
import uuid
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

try:
    import m3_customer_trust as customer_trust
except ImportError:
    sys.path.insert(0, str(ROOT / "scripts"))
    import m3_customer_trust as customer_trust


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
RUN_VALIDITY = dt.timedelta(days=7)
CLOCK_SKEW = dt.timedelta(minutes=2)
MAX_REGISTRY_RESPONSE = 64 * 1024
REPLAY_CONFORMANCE_REPORT = Path("/etc/kordex/m3/replay-registry-conformance.json")
REPLAY_CONFORMANCE_SIGNATURE = Path("/etc/kordex/m3/replay-registry-conformance.json.sig")
REPLAY_CONFORMANCE_PROTOCOL = "kordex-m3-replay-registry-v1"
REPLAY_CONFORMANCE_SUITE = ROOT / "scripts/m3_replay_registry_conformance.py"


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


def validate_fresh_operation_ids(operation_ids: list[str]) -> None:
    for operation_id in operation_ids:
        try:
            require(str(uuid.UUID(operation_id)) == operation_id,
                    "scenario operation IDs must use canonical UUID format")
        except (ValueError, TypeError, AttributeError) as error:
            raise ProvenanceError("scenario operation ID is not a valid UUID") from error
    require(len(operation_ids) == len(set(operation_ids)),
            "scenario evidence reuses an operation ID; every result requires a fresh operation")


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
            required_platform = (
                "profile", "qualificationOSProfile", "osId", "osMajor", "osMinor", "osPointRelease",
                "imageID", "imageUniqueID", "imageProject", "imageFamilyOrName", "architecture",
                "artifactPreflightReportSHA256", "packagePolicySHA256", "packageArchiveSHA256",
                "packageRepositorySnapshotID", "imageApprovalReference", "imageApprovalSHA256",
            )
            require(platform.get("schemaVersion") == 1
                    and all(isinstance(platform.get(field), str) and platform[field] for field in required_platform),
                    "evidence platform/image approval binding is incomplete")
            boot_disk_check = platform.get("bootDiskImageVerification")
            require(isinstance(boot_disk_check, dict)
                    and boot_disk_check.get("imageSelfLink") == platform.get("imageID")
                    and boot_disk_check.get("imageUniqueId") == platform.get("imageUniqueID")
                    and isinstance(boot_disk_check.get("instances"), list)
                    and len(boot_disk_check["instances"]) == 3,
                    "evidence does not include actual three-node boot-disk image verification")
            expected_profile = "debian-13" if family == "debian" else "rhel-9"
            point_release = platform["osPointRelease"]
            version_matches = (
                family == "debian" and platform["osId"] == "debian" and platform["osMajor"] == "13"
                and re.fullmatch(r"13\.[0-9]+", point_release) is not None
            ) or (
                family == "rhel" and platform["osId"] == "rhel" and platform["osMajor"] == "9"
                and re.fullmatch(r"9\.[0-9]+", point_release) is not None
                and int(point_release.split(".", 1)[1]) >= 8
            )
            require(platform["qualificationOSProfile"] == expected_profile and version_matches,
                    "evidence OS profile or exact Debian/RHEL release is outside the canonical platform policy")
            require(platform["osVersion"] == platform["osMajor"]
                    and platform["profile"].startswith(f"m3-{expected_profile}-k3s-")
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", platform["profile"]),
                    "evidence image profile or base OS version is malformed")
            require(platform["architecture"] == "linux/amd64"
                    and re.fullmatch(r"[1-9][0-9]{0,19}", platform["imageUniqueID"])
                    and all(re.fullmatch(r"[a-f0-9]{64}", platform[field]) for field in (
                        "artifactPreflightReportSHA256", "packagePolicySHA256", "packageArchiveSHA256",
                        "imageApprovalSHA256")),
                    "evidence architecture, image ID, or artifact digest is malformed")
            require(re.fullmatch(
                r"https://www\.googleapis\.com/compute/v1/projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,62}",
                platform["imageID"])
                    and platform["imageProject"] == platform["imageID"].split("/")[6]
                    and platform["imageFamilyOrName"] == platform["imageID"].rsplit("/", 1)[-1],
                    "evidence image self-link and image source identity disagree")
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", platform["packageRepositorySnapshotID"])
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", platform["imageApprovalReference"]),
                    "evidence image approval reference or package repository snapshot is malformed")
            injection = evidence.get("injection") if case.get("execution") == "manual-injection" else None
            if case.get("execution") == "manual-injection":
                require(isinstance(injection, dict)
                        and isinstance(injection.get("method"), str) and injection["method"]
                        and isinstance(injection.get("operatorIdentity"), str) and injection["operatorIdentity"],
                        "manual fault evidence lacks method or operator identity")
            else:
                require(injection is None, "non-injection scenario contains a contradictory fault record")
            operation_id, plan_digest = evidence.get("operationId"), evidence.get("planDigest")
            machine_id, node_uid = preflight.get("machineId"), node.get("uid")
            require(isinstance(operation_id, str) and operation_id
                    and isinstance(plan_digest, str) and SHA256.fullmatch(plan_digest)
                    and isinstance(machine_id, str) and re.fullmatch(r"[a-f0-9]{32}", machine_id)
                    and isinstance(node_uid, str) and node_uid,
                    "evidence operation, plan, host machine, or Kubernetes Node identity is incomplete")
            rows.append({
                "scenario": case["id"], "platform": family,
                "evidenceFile": filename, "evidenceSha256": hashlib.sha256(raw).hexdigest(),
                "operationId": operation_id, "planDigest": plan_digest,
                "profile": platform.get("profile"), "osVersion": platform.get("osVersion"),
                "imageIdentity": platform.get("imageID"), "imageUniqueId": platform.get("imageUniqueID"),
                "imageProject": platform.get("imageProject"), "imageName": platform.get("imageFamilyOrName"),
                "osId": platform.get("osId"), "osMajor": platform.get("osMajor"),
                "osMinor": platform.get("osMinor"), "osPointRelease": point_release,
                "architecture": platform.get("architecture"),
                "imageApprovalReference": platform.get("imageApprovalReference"),
                "imageApprovalSha256": platform.get("imageApprovalSHA256"),
                "artifactPreflightReportSha256": platform.get("artifactPreflightReportSHA256"),
                "packagePolicySha256": platform.get("packagePolicySHA256"),
                "packageArchiveSha256": platform.get("packageArchiveSHA256"),
                "packageRepositorySnapshotId": platform.get("packageRepositorySnapshotID"),
                "machineIdentity": machine_id, "nodeIdentity": node_uid,
                "collectorIdentity": collector, "collectedAt": collected_at,
                "faultInjectionMethod": injection.get("method") if injection else "not-applicable",
                "faultInjectionOperatorIdentity": injection.get("operatorIdentity") if injection else "not-applicable",
                "environmentClaim": "real-host",
            })
    require(len(seen) == len(matrix["cases"]) * len(families), "canonical evidence matrix is incomplete")
    validate_fresh_operation_ids([row["operationId"] for row in rows])
    return sorted(rows, key=lambda row: (row["scenario"], row["platform"]))


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value: str, field: str) -> dt.datetime:
    return parse_time(value, field).astimezone(dt.timezone.utc)


def create_run_context(output: Path, *, now: dt.datetime | None = None,
                       trust_loader=None, registry_register=None) -> dict:
    """Create and, in production, durably reserve the challenge before qualification."""
    current = (now or utc_now()).astimezone(dt.timezone.utc)
    context = {
        "schemaVersion": 1,
        "runId": str(uuid.uuid4()),
        "nonce": secrets.token_hex(32),
        "canonicalMatrixSha256": structural.FAILURE_MATRIX_SHA256,
        "createdAt": current.isoformat().replace("+00:00", "Z"),
        "expiresAt": (current + RUN_VALIDITY).isoformat().replace("+00:00", "Z"),
    }
    require(not output.exists() and not output.is_symlink(), "refusing to overwrite qualification run context")
    output.parent.mkdir(parents=True, exist_ok=True)
    if trust_loader is not None:
        trust, trust_digest = trust_loader()
        register = registry_register or reserve_run_context
        context["trustConfigurationSha256"] = trust_digest
        context["registryReservation"] = register(trust, trust_digest, context, now=current)
        validate_run_context(context, now=current, trust=trust, trust_digest=trust_digest, require_registered=True)
    _write_snapshot(output.parent, output.name, canonical_json(context))
    return context


def validate_run_context(context: dict, *, now: dt.datetime | None = None, trust: dict | None = None,
                         trust_digest: str | None = None, require_registered: bool = False) -> dict:
    base_fields = {"schemaVersion", "runId", "nonce", "canonicalMatrixSha256", "createdAt", "expiresAt"}
    registered_fields = {"trustConfigurationSha256", "registryReservation"}
    allowed = base_fields | registered_fields
    require(set(context) == (allowed if require_registered else (base_fields if set(context) == base_fields else allowed))
            and context.get("schemaVersion") == 1,
            "qualification run context is incomplete or unsupported")
    try:
        run_id = str(uuid.UUID(context["runId"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise ProvenanceError("qualification run ID is invalid") from error
    require(run_id == context["runId"], "qualification run ID is not canonical")
    require(isinstance(context.get("nonce"), str) and re.fullmatch(r"[a-f0-9]{64}", context["nonce"]),
            "qualification run nonce must be 256-bit lowercase hexadecimal")
    require(context.get("canonicalMatrixSha256") == structural.FAILURE_MATRIX_SHA256,
            "qualification run context is bound to a different canonical matrix")
    created = timestamp(context["createdAt"], "run.createdAt")
    expires = timestamp(context["expiresAt"], "run.expiresAt")
    current = (now or utc_now()).astimezone(dt.timezone.utc)
    require(created <= current + CLOCK_SKEW and expires > current and expires > created
            and expires - created <= RUN_VALIDITY,
            "qualification run context is future-dated, expired, or outside its validity window")
    if require_registered or "registryReservation" in context:
        require(trust is not None and trust_digest is not None
                and context.get("trustConfigurationSha256") == trust_digest,
                "qualification run reservation is not bound to the current customer trust configuration")
        validate_run_reservation(context["registryReservation"], trust, context, trust_digest, now=current)
    return context


def _registry_exchange(config: dict, body: bytes) -> dict:
    request = urllib.request.Request(config["url"], data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(MAX_REGISTRY_RESPONSE + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ProvenanceError) as error:
        raise ProvenanceError("customer durable replay registry is unavailable or returned a redirect") from error
    require(len(raw) <= MAX_REGISTRY_RESPONSE, "replay registry response exceeds the size limit")
    try:
        receipt = json.loads(raw, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ProvenanceError("replay registry response is malformed") from error
    require(isinstance(receipt, dict) and raw == canonical_json(receipt),
            "replay registry response is not canonical JSON")
    signature_hex = receipt.pop("signature", None)
    require(isinstance(signature_hex, str) and re.fullmatch(r"(?:[a-f0-9]{2}){64}", signature_hex),
            "replay registry response signature encoding is invalid")
    receipt["_detachedSignature"] = signature_hex
    return receipt


def _verify_registry_receipt(receipt_with_signature: dict, trust: dict, role: str,
                             identity: str, *, now: dt.datetime | None = None) -> dict:
    receipt = dict(receipt_with_signature)
    signature_hex = receipt.pop("_detachedSignature", None)
    public, fingerprint = customer_trust.authorized_key(trust, identity, role, now=now)
    verify_detached_signature(canonical_json(receipt), bytes.fromhex(signature_hex), public, fingerprint)
    return receipt


def verify_replay_registry_conformance(trust: dict, *, report_path: Path = REPLAY_CONFORMANCE_REPORT,
                                       signature_path: Path = REPLAY_CONFORMANCE_SIGNATURE,
                                       now: dt.datetime | None = None) -> str:
    """Require a fresh, reviewer-signed registry conformance report pinned by customer trust."""
    config = trust.get("replayRegistry")
    if not isinstance(config, dict):
        raise ProvenanceError("customer durable replay registry is not configured")
    try:
        raw = customer_trust.read_regular(report_path, 256 * 1024)
        signature = customer_trust.read_regular(signature_path, 4096)
        report = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, json.JSONDecodeError, UnicodeError, customer_trust.TrustError) as error:
        raise ProvenanceError("customer replay registry conformance evidence is unavailable or malformed") from error
    required = {"schemaVersion", "protocolVersion", "registryUrl", "registryIdentity",
                "contractSuiteSha256", "resultsSha256", "decision", "reviewerIdentity",
                "reviewedAt", "expiresAt", "evidenceReference"}
    if (not isinstance(report, dict) or set(report) != required or raw != canonical_json(report)
            or hashlib.sha256(raw).hexdigest() != config.get("conformanceReportSha256")
            or report.get("schemaVersion") != 1 or report.get("protocolVersion") != REPLAY_CONFORMANCE_PROTOCOL
            or report.get("registryUrl") != config.get("url")
            or report.get("registryIdentity") != config.get("identity")
            or report.get("decision") != "accepted"
            or report.get("reviewerIdentity") != config.get("conformanceReviewerIdentity")
            or report.get("reviewedAt") != config.get("conformanceReviewedAt")
            or report.get("expiresAt") != config.get("conformanceExpiresAt")
            or report.get("contractSuiteSha256") != hashlib.sha256(read_file(REPLAY_CONFORMANCE_SUITE)).hexdigest()
            or not SHA256.fullmatch(str(report.get("resultsSha256", "")))
            or not isinstance(report.get("evidenceReference"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", report["evidenceReference"])
            or re.match(r"(?i)^(fixture|synthetic|test)[-_:/.]", report["evidenceReference"])):
        raise ProvenanceError("customer replay registry has no matching independent conformance approval")
    try:
        reviewer, fingerprint = customer_trust.authorized_key(
            trust, report["reviewerIdentity"], "reviewer", now=now)
        registry_key, registry_fingerprint = customer_trust.authorized_key(
            trust, config["identity"], "replay-registry", now=now)
        if report["reviewerIdentity"] == config["identity"] or fingerprint == registry_fingerprint or reviewer == registry_key:
            raise customer_trust.TrustError("conformance reviewer and registry identity must be distinct")
        customer_trust.verify_signature(raw, signature, reviewer)
        reviewed = timestamp(report["reviewedAt"], "conformance.reviewedAt")
        expires = timestamp(report["expiresAt"], "conformance.expiresAt")
        current = (now or utc_now()).astimezone(dt.timezone.utc)
        require(reviewed <= current + CLOCK_SKEW and expires > current and expires > reviewed
                and expires - reviewed <= dt.timedelta(days=30),
                "customer replay-registry conformance approval is stale, future-dated, or expired")
    except customer_trust.TrustError as error:
        raise ProvenanceError("customer replay-registry conformance signature or identity is invalid") from error
    return hashlib.sha256(raw).hexdigest()


def reserve_run_context(trust: dict, trust_digest: str, context: dict,
                        *, now: dt.datetime | None = None) -> dict:
    config = trust.get("replayRegistry")
    if not isinstance(config, dict):
        raise ProvenanceError("qualification run is BLOCKED: customer durable replay registry is not configured")
    verify_replay_registry_conformance(trust, now=now)
    body = canonical_json({"schemaVersion": 1, "action": "reserve-run", "runId": context["runId"],
                           "runNonce": context["nonce"], "canonicalMatrixSha256": context["canonicalMatrixSha256"],
                           "trustConfigurationSha256": trust_digest, "createdAt": context["createdAt"],
                           "expiresAt": context["expiresAt"]})
    response = _registry_exchange(config, body)
    signature = response.pop("_detachedSignature")
    identity = config["identity"]
    receipt = _verify_registry_receipt(dict(response, _detachedSignature=signature), trust,
                                       "replay-registry", identity, now=now)
    required = {"schemaVersion", "action", "registryIdentity", "runId", "runNonce",
                "canonicalMatrixSha256", "trustConfigurationSha256", "sequence", "status", "registeredAt"}
    require(set(receipt) == required and receipt["schemaVersion"] == 1 and receipt["action"] == "reserve-run"
            and receipt["registryIdentity"] == identity and receipt["runId"] == context["runId"]
            and receipt["runNonce"] == context["nonce"]
            and receipt["canonicalMatrixSha256"] == context["canonicalMatrixSha256"]
            and receipt["trustConfigurationSha256"] == trust_digest and type(receipt["sequence"]) is int
            and receipt["sequence"] > 0 and receipt["status"] == "newly-reserved",
            "replay registry did not reserve this new run or returned conflicting bindings")
    registered_at = timestamp(receipt["registeredAt"], "registry.registeredAt")
    current = (now or utc_now()).astimezone(dt.timezone.utc)
    require(timestamp(context["createdAt"], "run.createdAt") <= registered_at <= current + CLOCK_SKEW
            and current - registered_at <= dt.timedelta(minutes=5),
            "replay registry run reservation is stale or future-dated")
    return {**receipt, "signature": signature}


def validate_run_reservation(reservation: dict, trust: dict, context: dict, trust_digest: str,
                             *, now: dt.datetime | None = None) -> None:
    require(isinstance(reservation, dict), "qualification run has no durable customer registry reservation")
    config = trust.get("replayRegistry")
    if not isinstance(config, dict):
        raise ProvenanceError("customer durable replay registry is not configured")
    signed = dict(reservation)
    signature = signed.pop("signature", None)
    require(isinstance(signature, str) and re.fullmatch(r"(?:[a-f0-9]{2}){64}", signature),
            "run reservation signature is malformed")
    receipt = _verify_registry_receipt(dict(signed, _detachedSignature=signature), trust,
                                       "replay-registry", config["identity"], now=now)
    required = {"schemaVersion", "action", "registryIdentity", "runId", "runNonce",
                "canonicalMatrixSha256", "trustConfigurationSha256", "sequence", "status", "registeredAt"}
    require(set(receipt) == required and receipt["schemaVersion"] == 1 and receipt["action"] == "reserve-run"
            and receipt["registryIdentity"] == config["identity"] and receipt["runId"] == context["runId"]
            and receipt["runNonce"] == context["nonce"]
            and receipt["canonicalMatrixSha256"] == context["canonicalMatrixSha256"]
            and receipt["trustConfigurationSha256"] == trust_digest and receipt["status"] == "newly-reserved"
            and type(receipt["sequence"]) is int and receipt["sequence"] > 0,
            "durable run reservation does not match this customer trust and matrix")
    registered_at = timestamp(receipt["registeredAt"], "registry.registeredAt")
    created = timestamp(context["createdAt"], "run.createdAt")
    if registered_at < created or registered_at > timestamp(context["expiresAt"], "run.expiresAt"):
        raise ProvenanceError("durable run reservation is outside the run lifetime")


def create_manifest(evidence_dir: Path, output: Path, collector: str, collected_at: str,
                    run_context_path: Path, *, trust_loader=None, now: dt.datetime | None = None) -> dict:
    matrix = json.loads(read_file(MATRIX), object_pairs_hook=unique_object)
    structural.verify_pinned_matrix(MATRIX)
    structural.verify_directory(MATRIX, evidence_dir)
    collected_time = timestamp(collected_at, "collectedAt")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", collector or "") is not None,
            "collector identity is malformed")
    try:
        context, context_raw = load_json(run_context_path, 16 * 1024)
    except OSError as error:
        raise ProvenanceError("qualification run context is unavailable") from error
    require(context_raw == canonical_json(context), "qualification run context is not canonical")
    loader = trust_loader or customer_trust.load_trust
    trust, trust_digest = loader()
    validate_run_context(context, now=now, trust=trust, trust_digest=trust_digest, require_registered=True)
    customer_trust.authorized_key(trust, collector, "collector", now=now)
    require(timestamp(context["createdAt"], "run.createdAt") <= collected_time <= timestamp(context["expiresAt"], "run.expiresAt"),
            "evidence collection time falls outside the qualification run window")
    require(not output.exists() and not output.is_symlink(), "refusing to overwrite evidence manifest")
    try:
        output.resolve().relative_to(evidence_dir.resolve())
    except ValueError:
        pass
    else:
        raise ProvenanceError("manifest and signatures must be stored outside the evidence directory")
    signed_at = (now or utc_now()).astimezone(dt.timezone.utc)
    manifest = {
        "schemaVersion": 2,
        "canonicalMatrixSha256": structural.FAILURE_MATRIX_SHA256,
        "environmentClaim": "real-host",
        "runId": context["runId"],
        "runNonce": context["nonce"],
        "runCreatedAt": context["createdAt"],
        "runExpiresAt": context["expiresAt"],
        "runReservation": context["registryReservation"],
        "trustConfigurationSha256": trust_digest,
        "collectorIdentity": collector,
        "collectedAt": collected_at,
        "collectorSignedAt": signed_at.isoformat().replace("+00:00", "Z"),
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


def verify_review(review: dict, manifest_sha: str, collector_identity: str,
                  trust_digest: str, corroboration_digest: str) -> None:
    required = {"schemaVersion", "manifestSha256", "trustConfigurationSha256", "corroborationSetSha256",
                "reviewerIdentity", "decision", "reviewedAt", "reason"}
    require(set(review) == required and review.get("schemaVersion") == 1,
            "review record has missing or unsupported fields")
    require(review.get("manifestSha256") == manifest_sha, "review decision is not bound to this manifest")
    require(review.get("trustConfigurationSha256") == trust_digest
            and review.get("corroborationSetSha256") == corroboration_digest,
            "review decision does not bind current customer trust and host corroboration")
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
    required = {"schemaVersion", "canonicalMatrixSha256", "environmentClaim", "runId", "runNonce",
                "runCreatedAt", "runExpiresAt", "trustConfigurationSha256", "runReservation", "collectorIdentity",
                "collectedAt", "collectorSignedAt", "evidenceArtifacts", "cases"}
    require(set(manifest) == required and manifest.get("schemaVersion") == 2,
            "manifest schema has missing or unsupported fields")
    require(manifest.get("canonicalMatrixSha256") == structural.FAILURE_MATRIX_SHA256,
            "manifest canonical matrix digest is not the reviewed matrix")
    require(manifest.get("environmentClaim") == "real-host",
            "synthetic or supplemental evidence cannot be accepted as real-host evidence")
    require(isinstance(manifest.get("collectorIdentity"), str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", manifest["collectorIdentity"]),
            "collector identity is malformed")
    try:
        uuid.UUID(manifest["runId"])
    except (ValueError, TypeError, AttributeError) as error:
        raise ProvenanceError("manifest run ID is invalid") from error
    require(isinstance(manifest.get("runNonce"), str)
            and re.fullmatch(r"[a-f0-9]{64}", manifest["runNonce"]),
            "manifest run nonce is invalid")
    for field in ("trustConfigurationSha256",):
        require(SHA256.fullmatch(manifest.get(field, "")) is not None, f"{field} is invalid")
    created = timestamp(manifest["runCreatedAt"], "runCreatedAt")
    expires = timestamp(manifest["runExpiresAt"], "runExpiresAt")
    collected = timestamp(manifest["collectedAt"], "collectedAt")
    signed = timestamp(manifest["collectorSignedAt"], "collectorSignedAt")
    require(created <= collected <= signed <= expires and expires - created <= RUN_VALIDITY,
            "manifest timestamps are out of order or exceed the run validity window")


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


def validate_freshness(manifest: dict, review: dict, *, now: dt.datetime | None = None) -> None:
    current = (now or utc_now()).astimezone(dt.timezone.utc)
    created = timestamp(manifest["runCreatedAt"], "runCreatedAt")
    expires = timestamp(manifest["runExpiresAt"], "runExpiresAt")
    collected = timestamp(manifest["collectedAt"], "collectedAt")
    signed = timestamp(manifest["collectorSignedAt"], "collectorSignedAt")
    reviewed = timestamp(review["reviewedAt"], "reviewedAt")
    require(created <= collected <= signed <= reviewed <= current + CLOCK_SKEW,
            "run, collection, signature, or review timestamps are out of order or future-dated")
    require(expires > current and current - created <= RUN_VALIDITY,
            "qualification evidence is expired or outside the bounded validity window")


def corroboration_binding(manifest: dict, row: dict) -> dict:
    return {
        "runId": manifest["runId"], "runNonce": manifest["runNonce"],
        "canonicalMatrixSha256": manifest["canonicalMatrixSha256"],
        "scenario": row["scenario"], "platform": row["platform"], "profile": row["profile"],
        "osId": row["osId"], "osMajor": row["osMajor"], "osMinor": row["osMinor"],
        "osPointRelease": row["osPointRelease"], "architecture": row["architecture"],
        "imageSelfLink": row["imageIdentity"], "imageProject": row["imageProject"],
        "imageName": row["imageName"], "imageId": row["imageUniqueId"],
        "imageApprovalReference": row["imageApprovalReference"],
        "imageApprovalSha256": row["imageApprovalSha256"],
        "artifactPreflightReportSha256": row["artifactPreflightReportSha256"],
        "packagePolicySha256": row["packagePolicySha256"],
        "packageArchiveSha256": row["packageArchiveSha256"],
        "packageRepositorySnapshotId": row["packageRepositorySnapshotId"],
        "hostIdentity": row["machineIdentity"], "nodeIdentity": row["nodeIdentity"],
        "operationId": row["operationId"], "planDigest": row["planDigest"],
        "evidenceSha256": row["evidenceSha256"],
        "collectorIdentity": row["collectorIdentity"], "collectedAt": row["collectedAt"],
        "faultInjectionMethod": row["faultInjectionMethod"],
        "faultInjectionOperatorIdentity": row["faultInjectionOperatorIdentity"],
    }


def verify_corroboration(directory: Path, manifest: dict, row: dict, trust: dict,
                         collector_fp: str, *, now: dt.datetime | None = None) -> tuple[dict, str]:
    filename = f"{row['scenario']}-{row['platform']}.json"
    path = directory / filename
    record, raw = load_json(path, 128 * 1024)
    require(raw == canonical_json(record), "customer host corroboration is not canonical JSON")
    required = {"schemaVersion", "bindings", "customerSourceSystem", "evidenceLocation", "collectedAt",
                "corroboratedAt", "corroboratorIdentity", "decision", "rationale"}
    require(set(record) == required and record.get("schemaVersion") == 1,
            "customer host corroboration is incomplete or unsupported")
    require(record.get("bindings") == corroboration_binding(manifest, row),
            "customer host corroboration does not match the signed qualification evidence")
    require(isinstance(record.get("customerSourceSystem"), str) and record["customerSourceSystem"].strip()
            and isinstance(record.get("evidenceLocation"), str) and record["evidenceLocation"].strip(),
            "customer host corroboration lacks an independently reviewable source reference")
    require(not re.match(r"(?i)^(?:fixture|synthetic|test)://", record["evidenceLocation"])
            and not re.match(r"(?i)^(?:fixture|synthetic|test)(?:[-_:]|$)", record["customerSourceSystem"]),
            "synthetic fixture references cannot corroborate production host origin")
    require(record.get("decision") == "confirmed" and isinstance(record.get("rationale"), str)
            and len(record["rationale"].strip()) >= 8,
            "customer host-origin corroboration was not confirmed")
    collected = timestamp(record["collectedAt"], "corroboration.collectedAt")
    corroborated = timestamp(record["corroboratedAt"], "corroboration.corroboratedAt")
    manifest_collected = timestamp(manifest["collectedAt"], "manifest.collectedAt")
    require(record["collectedAt"] == row["collectedAt"] and corroborated >= collected >= manifest_collected
            and corroborated <= (now or utc_now()) + CLOCK_SKEW,
            "customer corroboration timestamps are out of order or future-dated")
    identity = record.get("corroboratorIdentity")
    public, fingerprint = customer_trust.authorized_key(trust, identity, "corroborator", now=now)
    require(identity != manifest["collectorIdentity"] and fingerprint != collector_fp,
            "customer corroborator must be independently authorized from the collector")
    signature = read_file(path.with_name(path.name + ".sig"), 4096)
    verify_detached_signature(raw, signature, public, fingerprint)
    return record, hashlib.sha256(raw).hexdigest(), fingerprint


def validate_corroboration_inventory(directory: Path, expected_pairs: set[tuple[str, str]]) -> None:
    require(directory.is_dir() and not directory.is_symlink(),
            "customer corroboration directory must be a real directory")
    expected = {f"{scenario}-{platform}.json{suffix}"
                for scenario, platform in expected_pairs for suffix in ("", ".sig")}
    observed = set()
    try:
        for path in directory.iterdir():
            require(not path.is_symlink() and path.is_file(),
                    "customer corroboration directory contains an unsafe entry")
            observed.add(path.name)
    except OSError as error:
        raise ProvenanceError("customer corroboration directory is unavailable") from error
    require(observed == expected,
            "customer corroboration directory contains missing, duplicate, or unexpected records")


def claim_durable_replay_registry(trust: dict, trust_digest: str, manifest: dict,
                                  manifest_sha: str, review_sha: str, reviewed_at: str,
                                  *, now: dt.datetime | None = None) -> dict:
    """Atomically consume a run/nonce at the customer-owned durable registry.

    The customer service must reject any previously accepted run ID, nonce, or
    package digest. A signed receipt is returned only for a newly committed
    claim. No local or in-memory replay fallback exists.
    """
    config = trust.get("replayRegistry")
    if not isinstance(config, dict):
        raise ProvenanceError("qualification acceptance is BLOCKED: customer durable replay registry is not configured")
    verify_replay_registry_conformance(trust, now=now)
    identity = config["identity"]
    customer_trust.authorized_key(trust, identity, "replay-registry", now=now)
    challenge = secrets.token_hex(32)
    reservation_sha = hashlib.sha256(canonical_json(manifest["runReservation"])).hexdigest()
    body = canonical_json({
        "schemaVersion": 1, "action": "accept-run", "challenge": challenge, "runId": manifest["runId"],
        "runNonce": manifest["runNonce"], "manifestSha256": manifest_sha,
        "reviewSha256": review_sha, "trustConfigurationSha256": trust_digest,
        "canonicalMatrixSha256": manifest["canonicalMatrixSha256"], "reservationSha256": reservation_sha,
    })
    response = _registry_exchange(config, body)
    signature = response.pop("_detachedSignature")
    receipt = _verify_registry_receipt(dict(response, _detachedSignature=signature), trust,
                                       "replay-registry", identity, now=now)
    required = {"schemaVersion", "action", "registryIdentity", "challenge", "runId", "runNonce", "manifestSha256",
                "reviewSha256", "trustConfigurationSha256", "canonicalMatrixSha256", "reservationSha256",
                "claim", "sequence", "committedAt"}
    require(set(receipt) == required and receipt["schemaVersion"] == 1 and receipt["action"] == "accept-run"
            and receipt["registryIdentity"] == identity and receipt["challenge"] == challenge
            and receipt["runId"] == manifest["runId"] and receipt["runNonce"] == manifest["runNonce"]
            and receipt["manifestSha256"] == manifest_sha and receipt["reviewSha256"] == review_sha
            and receipt["trustConfigurationSha256"] == trust_digest
            and receipt["canonicalMatrixSha256"] == manifest["canonicalMatrixSha256"]
            and receipt["reservationSha256"] == reservation_sha
            and receipt["claim"] == "newly-accepted" and type(receipt["sequence"]) is int
            and receipt["sequence"] > 0,
            "replay registry rejected or returned a conflicting qualification claim")
    committed = timestamp(receipt["committedAt"], "registry.committedAt")
    current = (now or utc_now()).astimezone(dt.timezone.utc)
    require(timestamp(reviewed_at, "reviewedAt") <= committed <= current + CLOCK_SKEW
            and current - committed <= dt.timedelta(minutes=5),
            "durable replay claim is stale, future-dated, or predates independent review")
    return receipt


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProvenanceError("durable replay registry attempted an unapproved redirect")


def verify_package(args) -> dict:
    structural.verify_pinned_matrix(MATRIX)
    complete = structural.verify_directory(MATRIX, args.evidence_directory)
    manifest, manifest_raw = load_json(args.manifest, 8 * 1024 * 1024)
    require(manifest_raw == canonical_json(manifest), "evidence manifest is not canonical JSON")
    validate_manifest_header(manifest)
    # Production verification has no caller-selectable clock or trust loader.
    # Tests may patch the trust module boundary, but the CLI always uses the
    # independently installed, root-anchored customer trust configuration.
    current = utc_now().astimezone(dt.timezone.utc)
    trust, trust_digest = customer_trust.load_trust()
    require(manifest["trustConfigurationSha256"] == trust_digest,
            "qualification manifest was signed under a different customer trust configuration")
    validate_run_context({"schemaVersion": 1, "runId": manifest["runId"], "nonce": manifest["runNonce"],
                          "canonicalMatrixSha256": manifest["canonicalMatrixSha256"],
                          "createdAt": manifest["runCreatedAt"], "expiresAt": manifest["runExpiresAt"],
                          "trustConfigurationSha256": trust_digest, "registryReservation": manifest["runReservation"]},
                         now=current, trust=trust, trust_digest=trust_digest, require_registered=True)
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
    validate_corroboration_inventory(args.corroboration_directory, expected_pairs)
    collector_public, collector_expected_fp = customer_trust.authorized_key(
        trust, collector, "collector", now=current)
    collector_fingerprint = verify_detached_signature(
        manifest_raw, read_file(args.manifest_signature, 4096), collector_public, collector_expected_fp)
    review, review_raw = load_json(args.review, 64 * 1024)
    require(review_raw == canonical_json(review), "review record is not canonical JSON")
    corroboration_digests = []
    corroborator_fingerprints = set()
    for row in expected_cases:
        record, digest, corroborator_fp = verify_corroboration(args.corroboration_directory, manifest, row, trust,
                                                                collector_fingerprint, now=current)
        corroborator_fingerprints.add(corroborator_fp)
        corroboration_digests.append({"path": f"{row['scenario']}-{row['platform']}.json", "sha256": digest})
    corroboration_digest = hashlib.sha256(canonical_json(corroboration_digests)).hexdigest()
    verify_review(review, hashlib.sha256(manifest_raw).hexdigest(), collector, trust_digest, corroboration_digest)
    reviewer_public, reviewer_expected_fp = customer_trust.authorized_key(
        trust, review["reviewerIdentity"], "reviewer", now=current)
    reviewer_fingerprint = verify_detached_signature(
        review_raw, read_file(args.review_signature, 4096), reviewer_public, reviewer_expected_fp)
    require_distinct_signers(collector_fingerprint, reviewer_fingerprint)
    require(reviewer_fingerprint not in corroborator_fingerprints,
            "reviewer and customer corroborator must be independently authorized keys")
    validate_freshness(manifest, review, now=current)
    corroborated_at = max(timestamp(row["corroboratedAt"], "corroboratedAt")
                          for row in [load_json(args.corroboration_directory / f"{case['scenario']}-{case['platform']}.json", 128 * 1024)[0]
                                      for case in expected_cases])
    require(timestamp(review["reviewedAt"], "reviewedAt") >= corroborated_at,
            "review decision predates customer host-origin corroboration")
    accepted = review["decision"] == "accepted"
    registry_receipt = None
    if accepted:
        registry_receipt = claim_durable_replay_registry(
            trust, trust_digest, manifest, hashlib.sha256(manifest_raw).hexdigest(),
            hashlib.sha256(review_raw).hexdigest(), review["reviewedAt"], now=current)
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
        "customerHostOriginCorroborationVerified": True,
        "customerCorroboratedCases": len(expected_cases),
        "freshnessAndRunNonceVerified": True,
        "durableReplayStateVerified": registry_receipt is not None,
        "qualificationAccepted": accepted and registry_receipt is not None,
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    new_run = commands.add_parser("new-run", help="create a unique, time-bounded nonce before qualification begins")
    new_run.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("prepare", help="verify structural evidence and write an unsigned canonical manifest")
    prepare.add_argument("--evidence-directory", type=Path, required=True)
    prepare.add_argument("--collector-identity", required=True)
    prepare.add_argument("--collected-at", required=True)
    prepare.add_argument("--run-context", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify customer-rooted signatures, host corroboration, freshness, and replay state")
    verify.add_argument("--evidence-directory", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--manifest-signature", type=Path, required=True)
    verify.add_argument("--review", type=Path, required=True)
    verify.add_argument("--review-signature", type=Path, required=True)
    verify.add_argument("--corroboration-directory", type=Path, required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "new-run":
            result = create_run_context(args.output, trust_loader=customer_trust.load_trust)
            print(json.dumps({"runId": result["runId"], "createdAt": result["createdAt"],
                              "expiresAt": result["expiresAt"], "canonicalMatrixSha256": result["canonicalMatrixSha256"],
                              "nonceStatus": "created-and-stored-in-protected-run-context"}, sort_keys=True))
            return 0
        if args.command == "prepare":
            result = create_manifest(args.evidence_directory, args.output,
                                     args.collector_identity, args.collected_at, args.run_context)
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
