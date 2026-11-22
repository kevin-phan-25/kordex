"""Customer-pinned Ed25519 trust for M3 approvals and evidence.

The production CLI reads the trust root from a fixed, root-owned system path.
Unit tests may pass synthetic root bytes directly; those fixtures are not
accepted by the production CLI.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit


TRUST_ROOT = Path("/etc/kordex/m3/qualification-root.pub")
TRUST_CONFIG = Path("/etc/kordex/m3/qualification-trust.json")
TRUST_SIGNATURE = Path("/etc/kordex/m3/qualification-trust.json.sig")
FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")


class TrustError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise TrustError("trust record is not canonicalizable") from error


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise TrustError("trust record contains a duplicate field")
        value[key] = item
    return value


def read_regular(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise TrustError("trust input must not be a symlink")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise TrustError("customer trust input is unavailable") from error
    if (not stat.S_ISREG(before.st_mode) or len(data) != before.st_size or len(data) > limit
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise TrustError("customer trust input is unsafe or changed while being read")
    return data


def fingerprint(public_key: bytes) -> str:
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-trust-") as temp:
            key = Path(temp) / "key.pem"
            key.write_bytes(public_key)
            kind = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(key), "-text", "-noout"],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
            if kind.splitlines()[:1] != ["ED25519 Public-Key:"]:
                raise TrustError("customer trust keys must use Ed25519")
            der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(key), "-outform", "DER"],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise TrustError("customer trust key is invalid") from error
    return hashlib.sha256(der).hexdigest()


def verify_signature(payload: bytes, signature: bytes, public_key: bytes) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-trust-verify-") as temp:
            root = Path(temp)
            (root / "payload").write_bytes(payload)
            (root / "signature").write_bytes(signature)
            (root / "key.pem").write_bytes(public_key)
            subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(root / "key.pem"),
                            "-rawin", "-in", str(root / "payload"), "-sigfile", str(root / "signature")],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as error:
        raise TrustError("customer trust signature verification failed") from error


def parse_time(value: object, name: str) -> dt.datetime:
    if not isinstance(value, str):
        raise TrustError(f"{name} must be an RFC3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TrustError(f"{name} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise TrustError(f"{name} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_document(document: dict, now: dt.datetime | None = None) -> dict[str, dict]:
    required = {"schemaVersion", "customerId", "sequence", "issuedAt", "expiresAt", "keys"}
    optional = {"replayRegistry", "trustState"}
    if (not required.issubset(document) or set(document) - required - optional
            or type(document.get("schemaVersion")) is not int or document["schemaVersion"] != 1):
        raise TrustError("customer trust schema is incomplete or unsupported")
    replay = document.get("replayRegistry")
    trust_state = document.get("trustState")
    if replay is not None:
        replay_fields = {"url", "identity", "conformanceReportSha256", "conformanceReviewerIdentity",
                         "conformanceReviewedAt", "conformanceExpiresAt"}
        parsed_replay = urlsplit(replay.get("url", "")) if isinstance(replay, dict) else None
        if (not isinstance(replay, dict) or set(replay) != replay_fields
                or not isinstance(replay.get("url"), str) or parsed_replay is None
                or parsed_replay.scheme != "https" or not parsed_replay.hostname
                or parsed_replay.username is not None or parsed_replay.password is not None
                or parsed_replay.query or parsed_replay.fragment
                or not isinstance(replay.get("identity"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", replay["identity"])
                or not isinstance(replay.get("conformanceReportSha256"), str)
                or not FINGERPRINT.fullmatch(replay["conformanceReportSha256"])
                or not isinstance(replay.get("conformanceReviewerIdentity"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", replay["conformanceReviewerIdentity"])):
            raise TrustError("customer replay-registry configuration is invalid")
    if trust_state is not None:
        trust_fields = {"backendIdentity", "namespace", "endpointReference", "attestorIdentity",
                        "conformanceReportSha256", "conformanceReviewerIdentity",
                        "conformanceReviewedAt", "conformanceExpiresAt"}
        endpoint = urlsplit(trust_state.get("endpointReference", "")) if isinstance(trust_state, dict) else None
        if (not isinstance(trust_state, dict) or set(trust_state) != trust_fields
                or any(not isinstance(trust_state.get(key), str) or not trust_state[key]
                       for key in ("backendIdentity", "namespace", "endpointReference", "attestorIdentity",
                                   "conformanceReviewerIdentity", "conformanceReviewedAt", "conformanceExpiresAt"))
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", trust_state["backendIdentity"])
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", trust_state["namespace"])
                or endpoint is None or endpoint.scheme != "https" or not endpoint.hostname
                or endpoint.username is not None or endpoint.password is not None or endpoint.query or endpoint.fragment
                or not isinstance(trust_state.get("conformanceReportSha256"), str)
                or not FINGERPRINT.fullmatch(trust_state["conformanceReportSha256"])):
            raise TrustError("customer monotonic trust-state configuration is invalid")
    if not isinstance(document["customerId"], str) or not document["customerId"]:
        raise TrustError("customer trust identity is missing")
    if type(document["sequence"]) is not int or document["sequence"] < 1:
        raise TrustError("customer trust sequence is invalid")
    issued, expires = parse_time(document["issuedAt"], "issuedAt"), parse_time(document["expiresAt"], "expiresAt")
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    if issued > current + dt.timedelta(minutes=2) or expires <= current or expires <= issued:
        raise TrustError("customer trust configuration is not current")
    if expires - issued > dt.timedelta(days=30):
        raise TrustError("customer trust configuration validity exceeds 30 days")
    if not isinstance(document["keys"], list) or not document["keys"]:
        raise TrustError("customer trust has no authorized keys")
    by_identity, by_fingerprint = {}, {}
    for item in document["keys"]:
        if not isinstance(item, dict) or set(item) != {
                "identity", "role", "fingerprint", "publicKeyPem", "validFrom", "validUntil", "revokedAt"}:
            raise TrustError("customer trust key record is incomplete")
        identity, role, fp = item["identity"], item["role"], item["fingerprint"]
        if (not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", identity)
                or role not in {"collector", "reviewer", "deployment-approver", "corroborator",
                                "image-approver", "replay-registry", "trust-state-attestor",
                                "terraform-principal-attestor"}
                or not isinstance(fp, str) or not FINGERPRINT.fullmatch(fp)
                or not isinstance(item["publicKeyPem"], str)):
            raise TrustError("customer trust key identity or role is invalid")
        key_bytes = item["publicKeyPem"].encode("ascii", errors="strict")
        if fingerprint(key_bytes) != fp:
            raise TrustError("customer trust key fingerprint mismatch")
        starts, ends = parse_time(item["validFrom"], "key.validFrom"), parse_time(item["validUntil"], "key.validUntil")
        revoked = None if item["revokedAt"] is None else parse_time(item["revokedAt"], "key.revokedAt")
        if starts > current + dt.timedelta(minutes=2) or ends <= current or ends <= starts or (revoked and revoked <= current):
            raise TrustError("customer signing key is expired, not yet valid, or revoked")
        key_record = dict(item)
        if identity in by_identity or fp in by_fingerprint:
            raise TrustError("customer trust contains duplicate identities or key fingerprints")
        by_identity[identity] = key_record
        by_fingerprint[fp] = key_record
    if isinstance(replay, dict):
        reviewer = by_identity.get(replay["conformanceReviewerIdentity"])
        registry = by_identity.get(replay["identity"])
        if (reviewer is None or reviewer["role"] != "reviewer" or registry is None
                or registry["role"] != "replay-registry"
                or reviewer["fingerprint"] == registry["fingerprint"]):
            raise TrustError("replay registry conformance reviewer and registry must be distinct authorized identities")
        reviewed = parse_time(replay["conformanceReviewedAt"], "replayRegistry.conformanceReviewedAt")
        conformance_expires = parse_time(replay["conformanceExpiresAt"], "replayRegistry.conformanceExpiresAt")
        if (reviewed > current + dt.timedelta(minutes=2) or conformance_expires <= current
                or conformance_expires <= reviewed or conformance_expires - reviewed > dt.timedelta(days=30)):
            raise TrustError("replay registry conformance review is stale or expired")
    if isinstance(trust_state, dict):
        if sum(item["role"] == "trust-state-attestor" for item in by_identity.values()) != 1:
            raise TrustError("customer trust must authorize exactly one monotonic-state attestor")
        attestor = by_identity.get(trust_state["attestorIdentity"])
        reviewer = by_identity.get(trust_state["conformanceReviewerIdentity"])
        if (attestor is None or attestor["role"] != "trust-state-attestor"
                or reviewer is None or reviewer["role"] != "reviewer"
                or attestor["fingerprint"] == reviewer["fingerprint"]):
            raise TrustError("trust-state attestor and conformance reviewer must be distinct authorized identities")
        reviewed = parse_time(trust_state["conformanceReviewedAt"], "trustState.conformanceReviewedAt")
        expires = parse_time(trust_state["conformanceExpiresAt"], "trustState.conformanceExpiresAt")
        if (reviewed > current + dt.timedelta(minutes=2) or expires <= current or expires <= reviewed
                or expires - reviewed > dt.timedelta(days=30)):
            raise TrustError("trust-state backend conformance review is stale or expired")
    return by_identity


def load_signed_trust_candidate(config_path: Path = TRUST_CONFIG, signature_path: Path = TRUST_SIGNATURE,
                               root_path: Path = TRUST_ROOT, *, root_public_key: bytes | None = None,
                               now: dt.datetime | None = None, require_root_owned: bool = True) -> tuple[dict, str]:
    """Verify root signature/schema before monotonic-state enforcement."""
    if root_public_key is None:
        if require_root_owned:
            checked_directories = set()
            for path in (root_path, config_path, signature_path):
                for directory in path.parents:
                    if directory in checked_directories:
                        continue
                    checked_directories.add(directory)
                    try:
                        directory_info = directory.lstat()
                    except OSError as error:
                        raise TrustError("customer trust directory is unavailable") from error
                    if (stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode)
                            or directory_info.st_uid != 0 or directory_info.st_mode & 0o022):
                        raise TrustError("customer trust directories must be root-owned and not group/world writable")
                info = path.lstat()
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise TrustError("customer trust files must be root-owned and not group/world writable")
        root_public_key = read_regular(root_path, 64 * 1024)
    raw = read_regular(config_path, 1024 * 1024)
    signature = read_regular(signature_path, 4096)
    try:
        document = json.loads(raw, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise TrustError("customer trust document is malformed") from error
    if not isinstance(document, dict) or raw != canonical_json(document):
        raise TrustError("customer trust document is not canonical")
    verify_signature(raw, signature, root_public_key)
    validate_document(document, now=now)
    digest = hashlib.sha256(raw).hexdigest()
    return document, digest


def load_trust(config_path: Path = TRUST_CONFIG, signature_path: Path = TRUST_SIGNATURE,
               root_path: Path = TRUST_ROOT, *, root_public_key: bytes | None = None,
               now: dt.datetime | None = None, require_root_owned: bool = True,
               monotonic_state_verifier=None) -> tuple[dict, str]:
    document, digest = load_signed_trust_candidate(config_path, signature_path, root_path,
        root_public_key=root_public_key, now=now, require_root_owned=require_root_owned)
    if require_root_owned:
        if not isinstance(document.get("trustState"), dict):
            raise TrustError("root-signed customer trust-state backend configuration is missing; production trust is BLOCKED")
        # A signed positive sequence does not prevent replay of an older,
        # still-valid trust document. Production remains blocked until an
        # independently protected durable verifier is supplied.
        if monotonic_state_verifier is None:
            raise TrustError("durable customer trust rollback state is unavailable; production trust is BLOCKED")
        try:
            state = monotonic_state_verifier(document, digest)
        except Exception as error:
            raise TrustError("durable customer trust rollback state could not be verified") from error
        if (not isinstance(state, dict) or set(state) != {"sequence", "configurationSha256", "durable"}
                or type(state.get("sequence")) is not int or state.get("sequence") != document["sequence"]
                or state.get("configurationSha256") != digest or state.get("durable") is not True):
            raise TrustError("customer trust configuration is stale, rolled back, or not durably recorded")
    return document, digest


def authorized_key(document: dict, identity: str, role: str, *, now: dt.datetime | None = None) -> tuple[bytes, str]:
    by_identity = validate_document(document, now=now)
    item = by_identity.get(identity)
    if item is None or item["role"] != role:
        raise TrustError("signing identity is not authorized for the required role")
    return item["publicKeyPem"].encode("ascii"), item["fingerprint"]
