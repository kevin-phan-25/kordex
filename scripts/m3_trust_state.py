"""Transport-neutral client for a customer-operated monotonic trust-state store.

No storage service or credentials are selected here. A customer adapter must
implement ``read_state`` and ``compare_and_swap`` and return receipts signed by
the independently pinned backend attestation key. The interface deliberately
has no reset or delete operation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
from typing import Callable, Protocol

try:
    import m3_customer_trust as customer_trust
except ImportError:  # importlib-based tests
    from scripts import m3_customer_trust as customer_trust


PROTOCOL_VERSION = "kordex-m3-trust-state-v2"
CONFORMANCE_PROTOCOL = "kordex-m3-trust-state-conformance-v2"
TRUST_STATE_CONFORMANCE_REPORT = Path("/etc/kordex/m3/trust-state-conformance.json")
TRUST_STATE_CONFORMANCE_SIGNATURE = Path("/etc/kordex/m3/trust-state-conformance.json.sig")
TRUST_STATE_CONFORMANCE_SUITE = Path(__file__).resolve().with_name("m3_trust_state_conformance.py")
EMPTY_DIGEST = "0" * 64
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REQUEST_ID = re.compile(r"^[a-f0-9]{64}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}$")
MAX_RECEIPT_AGE = dt.timedelta(minutes=2)
CLOCK_SKEW = dt.timedelta(seconds=30)
ADAPTER_ENTRY_POINT_GROUP = "kordex.m3.trust_state"
ADAPTER_ENTRY_POINT_NAME = "customer"
ENTRY_POINT_VALUE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*):"
    r"([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)$"
)
LOG = logging.getLogger("kordex.m3.trust_state")

# A production process may reload customer trust. Keep the module objects that
# this loader verified so a later load can distinguish its own cached imports
# from a module preloaded by an unrelated caller.
_VERIFIED_ADAPTER_MODULES: dict[tuple[str, str], dict[str, object]] = {}
_ADAPTER_IMPORT_LOCK = threading.RLock()


class TrustStateError(ValueError):
    pass


_VERIFIED_TRUST_TOKEN = object()


class VerifiedCustomerTrust:
    """Opaque immutable result issued after root signature, conformance and CAS checks."""

    __slots__ = ("_document_raw", "_sha256", "_client", "_conformance_sha256", "_state", "_sealed")

    def __init__(self, document: dict, digest: str, client, conformance_digest: str,
                 state: dict, *, _token=None):
        if _token is not _VERIFIED_TRUST_TOKEN:
            raise TrustStateError("verified customer trust snapshots must come from load_customer_trust")
        object.__setattr__(self, "_document_raw", customer_trust.canonical_json(document))
        object.__setattr__(self, "_sha256", digest)
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_conformance_sha256", conformance_digest)
        object.__setattr__(self, "_state", json.loads(canonical_json(state)))
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError("verified customer trust snapshots are immutable")
        object.__setattr__(self, name, value)

    @property
    def document(self) -> dict:
        # Return a fresh value so downstream policy checks cannot mutate the
        # root-verified snapshot held by this opaque object.
        return json.loads(self._document_raw.decode("utf-8"), object_pairs_hook=customer_trust.unique_object)

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def client(self):
        return self._client

    @property
    def conformanceSha256(self) -> str:
        return self._conformance_sha256

    @property
    def state(self) -> dict:
        """Authenticated backend version and audit references used for this snapshot."""
        return json.loads(canonical_json(self._state))


class TrustStateTransport(Protocol):
    """Customer adapter contract; transport authentication is adapter-owned."""

    def identity(self) -> dict: ...

    def read_state(self, customer_id: str, namespace: str, transition_id: str,
                   request_id: str) -> dict: ...

    def compare_and_swap(self, request: dict) -> dict: ...


class CustomerTrustStateAdapter(Protocol):
    """Installed customer adapter entry point; credentials remain adapter-owned.

    The entry-point callable receives only the root-signed ``trustState``
    settings and returns a ``TrustStateTransport``. It must obtain credentials
    from the customer's protected runtime, never from CLI arguments.
    """

    def __call__(self, trust_state_settings: dict) -> TrustStateTransport: ...


def canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise TrustStateError("trust-state record is not canonicalizable") from error


def verify_customer_backend_conformance(trust_document: dict, *,
                                        report_path: Path = TRUST_STATE_CONFORMANCE_REPORT,
                                        signature_path: Path = TRUST_STATE_CONFORMANCE_SIGNATURE,
                                        now: dt.datetime | None = None) -> str:
    """Verify root-pinned independent backend conformance evidence before use."""
    settings = trust_document.get("trustState")
    if not isinstance(settings, dict):
        raise TrustStateError("root-signed customer trust-state backend configuration is missing")
    try:
        raw = customer_trust.read_regular(report_path, 256 * 1024)
        signature = customer_trust.read_regular(signature_path, 4096)
        report = json.loads(raw, object_pairs_hook=customer_trust.unique_object)
    except (OSError, ValueError, json.JSONDecodeError, customer_trust.TrustError) as error:
        raise TrustStateError("customer trust-state conformance report is unavailable or malformed") from error
    required = {"schemaVersion", "protocolVersion", "customerId", "backendIdentity", "endpointReference",
                "conformanceNamespace", "contractSuiteSha256", "resultsSha256", "decision", "reviewerIdentity",
                "reviewedAt", "expiresAt", "evidenceReference"}
    if (not isinstance(report, dict) or set(report) != required or raw != customer_trust.canonical_json(report)
            or hashlib.sha256(raw).hexdigest() != settings["conformanceReportSha256"]
            or type(report.get("schemaVersion")) is not int or report["schemaVersion"] != 2
            or report.get("protocolVersion") != CONFORMANCE_PROTOCOL
            or report.get("customerId") != trust_document.get("customerId")
            or report.get("backendIdentity") != settings.get("backendIdentity")
            or report.get("endpointReference") != settings.get("endpointReference")
            or not isinstance(report.get("conformanceNamespace"), str)
            or not report["conformanceNamespace"].startswith("kordex-conformance-")
            or report.get("contractSuiteSha256") != hashlib.sha256(TRUST_STATE_CONFORMANCE_SUITE.read_bytes()).hexdigest()
            or not SHA256.fullmatch(str(report.get("resultsSha256", "")))
            or report.get("decision") != "accepted"
            or report.get("reviewerIdentity") != settings.get("conformanceReviewerIdentity")
            or report.get("reviewedAt") != settings.get("conformanceReviewedAt")
            or report.get("expiresAt") != settings.get("conformanceExpiresAt")
            or not isinstance(report.get("evidenceReference"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", report["evidenceReference"])
            or re.match(r"(?i)^(fixture|synthetic|test)[-_:/.]", report["evidenceReference"])):
        raise TrustStateError("customer trust-state backend conformance report does not match root-pinned configuration")
    try:
        reviewer_key, _ = customer_trust.authorized_key(
            trust_document, report["reviewerIdentity"], "reviewer", now=now)
        attestor_key, _ = customer_trust.authorized_key(
            trust_document, settings["attestorIdentity"], "trust-state-attestor", now=now)
        if reviewer_key == attestor_key or report["reviewerIdentity"] == settings["attestorIdentity"]:
            raise TrustStateError("trust-state reviewer and attestor must be independent")
        customer_trust.verify_signature(raw, signature, reviewer_key)
        current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
        reviewed = customer_trust.parse_time(report["reviewedAt"], "trustStateConformance.reviewedAt")
        expires = customer_trust.parse_time(report["expiresAt"], "trustStateConformance.expiresAt")
        if (reviewed > current + CLOCK_SKEW or expires <= current or expires <= reviewed
                or expires - reviewed > dt.timedelta(days=30)):
            raise TrustStateError("customer trust-state backend conformance approval is stale or expired")
    except customer_trust.TrustError as error:
        raise TrustStateError("customer trust-state backend conformance signature is invalid") from error
    return hashlib.sha256(raw).hexdigest()


class CustomerTrustStateClient:
    """Enforce consecutive signed trust generations through atomic customer CAS."""

    def __init__(self, transport: TrustStateTransport, *, customer_id: str,
                 backend_identity: str, namespace: str, attestation_public_key: bytes,
                 attestation_fingerprint: str,
                 now: Callable[[], dt.datetime] | None = None):
        if (not IDENTITY.fullmatch(customer_id or "") or not IDENTITY.fullmatch(backend_identity or "")
                or not IDENTITY.fullmatch(namespace or "")):
            raise TrustStateError("customer trust-state identity is malformed")
        if not SHA256.fullmatch(attestation_fingerprint or ""):
            raise TrustStateError("trust-state attestation fingerprint is malformed")
        if customer_trust.fingerprint(attestation_public_key) != attestation_fingerprint:
            raise TrustStateError("trust-state attestation key differs from its independent fingerprint")
        self.transport = transport
        self.customer_id = customer_id
        self.backend_identity = backend_identity
        self.namespace = namespace
        self.attestation_public_key = attestation_public_key
        self.attestation_fingerprint = attestation_fingerprint
        self._now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self._audit_events: list[dict] = []
        self._verify_transport_identity()

    def _record_audit(self, receipt: dict) -> None:
        if any(row["auditId"] == receipt["auditId"] for row in self._audit_events):
            raise TrustStateError("customer trust-state backend replayed a prior audit event identifier")
        event = {"action": receipt["action"], "backendIdentity": self.backend_identity,
                 "customerId": self.customer_id, "namespace": self.namespace,
                 "transitionId": receipt["transitionId"], "sequence": receipt["sequence"],
                 "requestId": receipt["requestId"],
                 "configurationSha256": receipt["configurationSha256"],
                 "auditId": receipt["auditId"], "observedAt": receipt["observedAt"],
                 "recordedAt": receipt["recordedAt"],
                 "attestationFingerprint": self.attestation_fingerprint,
                 "rootFingerprint": receipt["rootFingerprint"],
                 "rootSignatureSha256": receipt["rootSignatureSha256"]}
        self._audit_events.append(event)
        # Only identifiers and digests are emitted; trust documents and
        # credentials are never logged. The backend's signed auditId is the
        # durable audit reference.
        LOG.info("durable trust-state event", extra={"trust_state_event": event})

    @classmethod
    def _from_customer_trust_candidate(cls, transport: TrustStateTransport, trust_document: dict,
                                       *, now: Callable[[], dt.datetime] | None = None):
        """Build authority only from an already root-verified trust document."""
        try:
            settings = trust_document["trustState"]
            identity = settings["attestorIdentity"]
            public_key, fingerprint = customer_trust.authorized_key(
                trust_document, identity, "trust-state-attestor", now=now() if now else None)
            client = cls(transport, customer_id=trust_document["customerId"],
                         backend_identity=settings["backendIdentity"], namespace=settings["namespace"],
                         attestation_public_key=public_key, attestation_fingerprint=fingerprint, now=now)
            if client.transport.identity().get("endpointReference") != settings["endpointReference"]:
                raise TrustStateError("trust-state backend endpoint differs from root-signed customer configuration")
            return client
        except (KeyError, TypeError, customer_trust.TrustError) as error:
            if isinstance(error, TrustStateError):
                raise
            raise TrustStateError("root-signed customer trust-state backend configuration is unavailable") from error

    def _verify_transport_identity(self) -> None:
        try:
            identity = self.transport.identity()
        except Exception as error:
            raise TrustStateError("customer trust-state backend identity is unavailable") from error
        required = {"protocolVersion", "customerId", "backendIdentity", "namespace", "endpointReference"}
        if (not isinstance(identity, dict) or set(identity) != required
                or identity.get("protocolVersion") != PROTOCOL_VERSION
                or identity.get("customerId") != self.customer_id
                or identity.get("backendIdentity") != self.backend_identity
                or identity.get("namespace") != self.namespace
                or not isinstance(identity.get("endpointReference"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", identity["endpointReference"])):
            raise TrustStateError("customer trust-state backend identity or protocol differs from approved configuration")

    def _verify_receipt(self, receipt: object, *, action: str, transition_id: str,
                        request_id: str) -> dict:
        fields = {"schemaVersion", "protocolVersion", "action", "backendIdentity", "customerId", "namespace",
                  "transitionId", "requestId", "sequence", "configurationSha256", "durable", "status",
                  "observedAt", "recordedAt", "auditId", "attestationFingerprint", "rootFingerprint",
                  "rootSignatureSha256", "signature"}
        if not isinstance(receipt, dict) or set(receipt) != fields:
            raise TrustStateError("customer trust-state receipt is incomplete")
        signature_hex = receipt["signature"]
        unsigned = {key: value for key, value in receipt.items() if key != "signature"}
        if (type(unsigned["schemaVersion"]) is not int or unsigned["schemaVersion"] != 1
                or unsigned["protocolVersion"] != PROTOCOL_VERSION or unsigned["action"] != action
                or unsigned["backendIdentity"] != self.backend_identity
                or unsigned["customerId"] != self.customer_id
                or unsigned["namespace"] != self.namespace
                or unsigned["transitionId"] != transition_id
                or not REQUEST_ID.fullmatch(request_id or "")
                or unsigned["requestId"] != request_id
                or type(unsigned["sequence"]) is not int or unsigned["sequence"] < 0
                or not isinstance(unsigned["configurationSha256"], str)
                or not SHA256.fullmatch(unsigned["configurationSha256"])
                or not isinstance(unsigned["rootFingerprint"], str)
                or not SHA256.fullmatch(unsigned["rootFingerprint"])
                or not isinstance(unsigned["rootSignatureSha256"], str)
                or not SHA256.fullmatch(unsigned["rootSignatureSha256"])
                or (unsigned["sequence"] == 0 and (unsigned["rootFingerprint"] != EMPTY_DIGEST
                                                     or unsigned["rootSignatureSha256"] != EMPTY_DIGEST))
                or (unsigned["sequence"] > 0 and (unsigned["rootFingerprint"] == EMPTY_DIGEST
                                                    or unsigned["rootSignatureSha256"] == EMPTY_DIGEST))
                or unsigned["durable"] is not True
                or unsigned["status"] not in {"current", "committed", "conflict"}
                or not isinstance(unsigned["auditId"], str)
                or not IDENTITY.fullmatch(unsigned["auditId"])
                or unsigned["attestationFingerprint"] != self.attestation_fingerprint
                or not isinstance(signature_hex, str) or not re.fullmatch(r"[a-f0-9]{128}", signature_hex)):
            raise TrustStateError("customer trust-state receipt binding or durability assertion is invalid")
        try:
            issued = customer_trust.parse_time(unsigned["observedAt"], "trustState.observedAt")
            recorded = customer_trust.parse_time(unsigned["recordedAt"], "trustState.recordedAt")
            current = self._now().astimezone(dt.timezone.utc)
            if (issued > current + CLOCK_SKEW or recorded > current + CLOCK_SKEW
                    or current - issued > MAX_RECEIPT_AGE or recorded < issued):
                raise TrustStateError("customer trust-state receipt is stale or future-dated")
            customer_trust.verify_signature(canonical_json(unsigned), bytes.fromhex(signature_hex),
                                             self.attestation_public_key)
        except (customer_trust.TrustError, ValueError, TypeError) as error:
            if isinstance(error, TrustStateError):
                raise
            raise TrustStateError("customer trust-state receipt signature or timestamp is invalid") from error
        self._record_audit(unsigned)
        return unsigned

    def _read(self, transition_id: str) -> dict:
        request_id = secrets.token_hex(32)
        try:
            response = self.transport.read_state(self.customer_id, self.namespace, transition_id, request_id)
        except Exception as error:
            raise TrustStateError("customer trust-state backend is unavailable") from error
        receipt = self._verify_receipt(response, action="read-state", transition_id=transition_id,
                                       request_id=request_id)
        if receipt["status"] != "current":
            raise TrustStateError("customer trust-state read returned a non-current state")
        return receipt

    @property
    def audit_events(self) -> list[dict]:
        return json.loads(canonical_json(self._audit_events))

    def verify_and_advance(self, document: dict, configuration_sha256: str, *,
                           root_signature: bytes, root_public_key: bytes,
                           now: dt.datetime | None = None) -> dict:
        """Verify root authorization, then atomically advance one generation.

        A caller cannot update durable trust state with only a document and a
        matching digest. The detached signature is checked over the exact
        canonical bytes before the backend is contacted.
        """
        try:
            raw = customer_trust.canonical_json(document)
            if hashlib.sha256(raw).hexdigest() != configuration_sha256:
                raise TrustStateError("signed trust configuration digest mismatch")
            customer_trust.verify_signature(raw, root_signature, root_public_key)
            customer_trust.validate_document(document, now=now or self._now())
        except (customer_trust.TrustError, TypeError, ValueError) as error:
            if isinstance(error, TrustStateError):
                raise
            raise TrustStateError("trust-state update lacks a valid root-authorized configuration") from error
        if document.get("trustState", {}).get("backendIdentity") != self.backend_identity:
            raise TrustStateError("root-authorized trust update targets another backend")
        if document.get("trustState", {}).get("namespace") != self.namespace:
            raise TrustStateError("root-authorized trust update targets another namespace")
        return self._advance_generation(document, configuration_sha256,
                                        root_signature=root_signature,
                                        root_public_key=root_public_key)

    def _advance_generation(self, document: dict, configuration_sha256: str, *,
                            root_signature: bytes, root_public_key: bytes) -> dict:
        """CAS primitive; both client and backend receive root authorization.

        Ambiguous CAS acknowledgements are resolved by one authenticated read.
        A mismatch, outage, expired receipt, or corrupted state fails closed.
        """
        actual_digest = hashlib.sha256(customer_trust.canonical_json(document)).hexdigest()
        if (document.get("customerId") != self.customer_id
                or type(document.get("sequence")) is not int or document["sequence"] < 1
                or not SHA256.fullmatch(configuration_sha256 or "")
                or actual_digest != configuration_sha256):
            raise TrustStateError("signed trust configuration is not bound to this customer and generation")
        try:
            customer_trust.verify_signature(customer_trust.canonical_json(document),
                                            root_signature, root_public_key)
        except (customer_trust.TrustError, TypeError, ValueError) as error:
            raise TrustStateError("trust-state CAS requires a valid root-authorized configuration") from error
        if (document.get("trustState", {}).get("backendIdentity") != self.backend_identity
                or document.get("trustState", {}).get("namespace") != self.namespace):
            raise TrustStateError("root-authorized trust-state document targets another backend namespace")
        target_sequence = document["sequence"]
        root_fingerprint = customer_trust.fingerprint(root_public_key)
        root_signature_sha256 = hashlib.sha256(root_signature).hexdigest()
        transition_id = hashlib.sha256(canonical_json({
            "protocolVersion": PROTOCOL_VERSION, "customerId": self.customer_id,
            "backendIdentity": self.backend_identity, "namespace": self.namespace, "targetSequence": target_sequence,
            "targetDigest": configuration_sha256,
        })).hexdigest()[:32]
        current = self._read(transition_id)
        current_sequence, current_digest = current["sequence"], current["configurationSha256"]
        if current_sequence > target_sequence:
            raise TrustStateError("customer trust configuration rollback detected")
        if current_sequence == target_sequence:
            if (current_digest != configuration_sha256
                    or current["rootFingerprint"] != root_fingerprint
                    or current["rootSignatureSha256"] != root_signature_sha256):
                raise TrustStateError("customer trust sequence is already bound to a different digest or root signature")
            return self._state_result(target_sequence, configuration_sha256, [current])
        if current_sequence + 1 != target_sequence:
            raise TrustStateError("customer trust generation skipped; explicit customer recovery is required")
        if current_sequence == 0 and current_digest != EMPTY_DIGEST:
            raise TrustStateError("customer trust-state initial generation is inconsistent")
        request = {
            "schemaVersion": 1, "protocolVersion": PROTOCOL_VERSION, "action": "compare-and-swap",
            "customerId": self.customer_id, "backendIdentity": self.backend_identity,
            "namespace": self.namespace,
            "transitionId": transition_id, "requestId": secrets.token_hex(32),
            "expectedSequence": current_sequence,
            "expectedConfigurationSha256": current_digest, "newSequence": target_sequence,
            "newConfigurationSha256": configuration_sha256,
            "configuration": document,
            "rootFingerprint": root_fingerprint,
            "rootSignatureSha256": root_signature_sha256,
            "rootSignature": root_signature.hex(),
        }
        try:
            response = self.transport.compare_and_swap(request)
        except Exception:
            # Never issue a second mutation after a lost acknowledgement. One
            # signed read may prove the exact transition committed.
            observed = self._read(transition_id)
            if (observed["sequence"] == target_sequence and observed["configurationSha256"] == configuration_sha256
                    and observed["rootFingerprint"] == root_fingerprint
                    and observed["rootSignatureSha256"] == root_signature_sha256):
                return self._state_result(target_sequence, configuration_sha256, [current, observed])
            raise TrustStateError("customer trust-state update outcome is ambiguous; customer reconciliation is required")
        receipt = self._verify_receipt(response, action="compare-and-swap", transition_id=transition_id,
                                       request_id=request["requestId"])
        if receipt["status"] == "conflict":
            observed = self._read(transition_id)
            if (observed["sequence"] == target_sequence and observed["configurationSha256"] == configuration_sha256
                    and observed["rootFingerprint"] == root_fingerprint
                    and observed["rootSignatureSha256"] == root_signature_sha256):
                return self._state_result(target_sequence, configuration_sha256, [current, receipt, observed])
            raise TrustStateError("concurrent trust-state change conflicts with this update")
        if (receipt["status"] != "committed" or receipt["sequence"] != target_sequence
                or receipt["configurationSha256"] != configuration_sha256
                or receipt["rootFingerprint"] != root_fingerprint
                or receipt["rootSignatureSha256"] != root_signature_sha256):
            raise TrustStateError("customer trust-state backend did not commit the exact signed configuration")
        return self._state_result(target_sequence, configuration_sha256, [current, receipt])

    def _state_result(self, sequence: int, digest: str, receipts: list[dict]) -> dict:
        return {"sequence": sequence, "configurationSha256": digest, "durable": True,
                "backendIdentity": self.backend_identity, "namespace": self.namespace,
                "attestationFingerprint": self.attestation_fingerprint,
                "rootFingerprint": receipts[-1]["rootFingerprint"],
                "rootSignatureSha256": receipts[-1]["rootSignatureSha256"],
                "auditIds": [row["auditId"] for row in receipts]}


def _load_customer_trust_with_transport(transport: TrustStateTransport, *,
                                        config_path: Path = customer_trust.TRUST_CONFIG,
                                        signature_path: Path = customer_trust.TRUST_SIGNATURE,
                                        root_path: Path = customer_trust.TRUST_ROOT,
                                        now: Callable[[], dt.datetime] | None = None) -> VerifiedCustomerTrust:
    """Internal transport seam; production reaches it only through the pinned adapter loader."""
    current = now() if now else None
    document, signed_digest = customer_trust.load_signed_trust_candidate(
        config_path, signature_path, root_path, now=current, require_root_owned=True)
    conformance_digest = verify_customer_backend_conformance(document, now=current)
    client = CustomerTrustStateClient._from_customer_trust_candidate(transport, document, now=now)
    root_key = customer_trust.read_regular(root_path, 64 * 1024)
    root_signature = customer_trust.read_regular(signature_path, 4096)
    state_result: dict | None = None

    def root_checked_advance(candidate: dict, candidate_digest: str) -> dict:
        nonlocal state_result
        state_result = client.verify_and_advance(candidate, candidate_digest,
                                                 root_signature=root_signature,
                                                 root_public_key=root_key, now=current)
        return state_result

    verified, digest = customer_trust.load_trust(
        config_path, signature_path, root_path, now=current, require_root_owned=True,
        monotonic_state_verifier=root_checked_advance)
    if digest != signed_digest:
        raise TrustStateError("customer trust configuration changed while monotonic state was verified")
    if state_result is None:
        raise TrustStateError("durable trust-state verification did not produce an authenticated state version")
    return VerifiedCustomerTrust(verified, digest, client, conformance_digest,
                                state_result, _token=_VERIFIED_TRUST_TOKEN)


def load_customer_trust(*, config_path: Path = customer_trust.TRUST_CONFIG,
                        signature_path: Path = customer_trust.TRUST_SIGNATURE,
                        root_path: Path = customer_trust.TRUST_ROOT,
                        now: dt.datetime | None = None) -> VerifiedCustomerTrust:
    """Production trust API; the transport is selected only by the pinned package entry point."""
    return load_production_customer_trust(config_path=config_path, signature_path=signature_path,
                                          root_path=root_path, now=now)


def _entry_points():
    discovered = importlib.metadata.entry_points()
    if hasattr(discovered, "select"):
        return list(discovered.select(group=ADAPTER_ENTRY_POINT_GROUP, name=ADAPTER_ENTRY_POINT_NAME))
    return [entry for entry in discovered.get(ADAPTER_ENTRY_POINT_GROUP, [])
            if entry.name == ADAPTER_ENTRY_POINT_NAME]


def adapter_distribution_sha256(distribution, *, owner_uid: int = 0,
                                ancestor_stop: Path | None = None) -> str:
    """Hash every installed distribution file using a deterministic path/hash manifest."""
    files = distribution.files
    if not files:
        raise TrustStateError("installed trust-state adapter has no verifiable package file inventory")
    records = []
    root_path = Path(distribution.locate_file(""))
    root_info = root_path.lstat()
    root = root_path.resolve(strict=True)
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != owner_uid or root_info.st_mode & 0o022):
        raise TrustStateError("trust-state adapter installation root is not protected")
    if owner_uid == 0 or ancestor_stop is not None:
        stop_resolved = ancestor_stop.resolve(strict=True) if ancestor_stop is not None else None
        for ancestor in root_path.parents:
            if stop_resolved is not None and ancestor.resolve(strict=True) == stop_resolved:
                break
            try:
                ancestor_info = ancestor.lstat()
            except OSError as error:
                raise TrustStateError("trust-state adapter installation ancestor directory is unavailable") from error
            if (not stat.S_ISDIR(ancestor_info.st_mode) or stat.S_ISLNK(ancestor_info.st_mode)
                    or ancestor_info.st_uid != owner_uid or ancestor_info.st_mode & 0o022):
                raise TrustStateError("trust-state adapter installation ancestor directory is not protected")
    for package_path in sorted(files, key=lambda value: str(value)):
        relative = Path(str(package_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise TrustStateError("trust-state adapter package inventory contains an unsafe path")
        path = Path(distribution.locate_file(package_path))
        try:
            info = path.lstat()
            resolved = path.resolve(strict=True)
            if (not stat.S_ISREG(info.st_mode) or path.is_symlink()
                    or info.st_uid != owner_uid or info.st_mode & 0o022
                    or not resolved.is_relative_to(root)):
                raise TrustStateError("trust-state adapter package contains a missing or unsafe file")
            parent = path.parent
            while parent != root:
                parent_info = parent.lstat()
                if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
                        or parent_info.st_uid != owner_uid or parent_info.st_mode & 0o022):
                    raise TrustStateError("trust-state adapter package path is not protected")
                parent = parent.parent
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                raw = stream.read(64 * 1024 * 1024 + 1)
                after = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or len(raw) != before.st_size or len(raw) > 64 * 1024 * 1024
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise TrustStateError("trust-state adapter package file changed during integrity verification")
            records.append({"path": relative.as_posix(), "sha256": hashlib.sha256(raw).hexdigest()})
        except OSError as error:
            raise TrustStateError("trust-state adapter package integrity could not be verified") from error
    if len({row["path"] for row in records}) != len(records):
        raise TrustStateError("trust-state adapter package inventory has duplicate paths")
    return hashlib.sha256(canonical_json(records)).hexdigest()


def _adapter_module_name(entry) -> str:
    value = getattr(entry, "value", None)
    match = ENTRY_POINT_VALUE.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        raise TrustStateError("root-authorized adapter entry point has an invalid module reference")
    return match.group(1)


def _adapter_distribution_files(distribution) -> tuple[Path, set[Path]]:
    try:
        root_path = Path(distribution.locate_file(""))
        if root_path.is_symlink():
            raise TrustStateError("root-authorized adapter installation root must not be a symlink")
        root = root_path.resolve(strict=True)
        files = distribution.files
        if not files:
            raise TrustStateError("root-authorized adapter has no verifiable package file inventory")
        allowed = set()
        for item in files:
            relative = Path(str(item))
            if relative.is_absolute() or ".." in relative.parts:
                raise TrustStateError("root-authorized adapter inventory contains an unsafe path")
            candidate = Path(distribution.locate_file(item))
            if candidate.is_symlink():
                raise TrustStateError("root-authorized adapter package contains a symlink")
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(root):
                raise TrustStateError("root-authorized adapter package escapes its protected installation root")
            allowed.add(resolved)
        if len(allowed) != len(files):
            raise TrustStateError("root-authorized adapter inventory contains duplicate paths")
        return root, allowed
    except (AttributeError, OSError, RuntimeError, TypeError) as error:
        if isinstance(error, TrustStateError):
            raise
        raise TrustStateError("root-authorized adapter distribution paths cannot be resolved") from error


def _require_pinned_adapter_origin(origin, allowed: set[Path]) -> Path:
    try:
        if not isinstance(origin, str):
            raise TrustStateError("root-authorized adapter module has no file origin")
        path = Path(origin)
        if path.is_symlink():
            raise TrustStateError("root-authorized adapter module origin must not be a symlink")
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise TrustStateError("root-authorized adapter module origin cannot be resolved") from error
    if resolved not in allowed:
        raise TrustStateError("root-authorized adapter module resolves outside its pinned distribution")
    try:
        cache = Path(importlib.util.cache_from_source(str(resolved)))
    except (NotImplementedError, ValueError):
        pass
    else:
        if cache.is_symlink():
            raise TrustStateError("unpinned adapter bytecode cache shadows the pinned module")
        if cache.exists():
            try:
                cache_resolved = cache.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise TrustStateError("adapter bytecode cache cannot be verified") from error
            if cache_resolved not in allowed:
                raise TrustStateError("unpinned adapter bytecode cache shadows the pinned module")
    return resolved


def _verify_loaded_adapter_origin(module_name: str, allowed: set[Path]) -> dict[str, object]:
    prefixes = module_name.split(".")
    loaded = {}
    for index in range(1, len(prefixes) + 1):
        name = ".".join(prefixes[:index])
        module = sys.modules.get(name)
        if module is None:
            raise TrustStateError("root-authorized adapter import did not load its complete module path")
        _require_pinned_adapter_origin(getattr(module, "__file__", None), allowed)
        loaded[name] = module
    return loaded


def verify_adapter_entry_point_origin(entry, expected_tree_digest: str) -> tuple[str, set[Path], bool]:
    """Resolve an entry point only to files covered by its root-pinned digest.

    The initial lookup is non-executing. Preloaded modules, external package
    paths, unsafe package paths, and unpinned bytecode caches fail closed.
    The boolean reports whether this exact module was previously verified by
    this loader in the current process.
    """
    module_name = _adapter_module_name(entry)
    top_level = module_name.split(".", 1)[0]
    distribution = getattr(entry, "dist", None)
    if distribution is None:
        raise TrustStateError("root-authorized adapter entry point has no distribution")
    dist_root, allowed = _adapter_distribution_files(distribution)
    cache_key = (module_name, expected_tree_digest)
    existing_names = {name for name in sys.modules
                      if name == top_level or name.startswith(top_level + ".")}
    verified_before = cache_key in _VERIFIED_ADAPTER_MODULES
    if existing_names:
        known = _VERIFIED_ADAPTER_MODULES.get(cache_key)
        if known is None or any(sys.modules.get(name) is not known.get(name) for name in existing_names):
            raise TrustStateError("adapter module was imported before its pinned origin could be verified")
        for name in existing_names:
            _require_pinned_adapter_origin(getattr(sys.modules[name], "__file__", None), allowed)
    else:
        try:
            spec = importlib.util.find_spec(top_level)
        except (ImportError, ValueError) as error:
            raise TrustStateError("root-authorized adapter module cannot be located") from error
        if spec is None:
            raise TrustStateError("root-authorized adapter module cannot be located")
        _require_pinned_adapter_origin(spec.origin, allowed)
        for index in range(1, len(module_name.split("."))):
            locations = spec.submodule_search_locations
            if not locations:
                raise TrustStateError("root-authorized adapter package search path is missing")
            verified_locations = []
            for location in locations:
                path = Path(location)
                if path.is_symlink():
                    raise TrustStateError("root-authorized adapter package path must not be a symlink")
                try:
                    resolved = path.resolve(strict=True)
                except (OSError, RuntimeError) as error:
                    raise TrustStateError("root-authorized adapter package path cannot be resolved") from error
                if not resolved.is_relative_to(dist_root):
                    raise TrustStateError("root-authorized adapter package path escapes its distribution")
                verified_locations.append(str(resolved))
            subname = ".".join(module_name.split(".")[:index + 1])
            spec = importlib.machinery.PathFinder.find_spec(subname, verified_locations)
            if spec is None:
                raise TrustStateError("root-authorized adapter submodule cannot be located")
            _require_pinned_adapter_origin(spec.origin, allowed)
    return module_name, allowed, verified_before


def load_production_customer_trust(*, config_path: Path = customer_trust.TRUST_CONFIG,
                                   signature_path: Path = customer_trust.TRUST_SIGNATURE,
                                   root_path: Path = customer_trust.TRUST_ROOT,
                                   now: dt.datetime | None = None) -> VerifiedCustomerTrust:
    """Load production trust through exactly one root-configured installed adapter.

    No environment variable or local file can select a transport. The adapter
    package name/version must be pinned in the root-signed trust configuration;
    the package is expected to be installed by the customer's protected runtime
    supply chain.
    """
    document, expected_digest = customer_trust.load_signed_trust_candidate(
        config_path, signature_path, root_path, now=now, require_root_owned=True)
    settings = document.get("trustState")
    if not isinstance(settings, dict):
        raise TrustStateError("root-signed durable trust-state adapter configuration is missing")
    expected_distribution = settings.get("adapterDistribution")
    expected_version = settings.get("adapterVersion")
    expected_tree_digest = settings.get("adapterTreeSha256")
    if (not isinstance(expected_distribution, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,127}", expected_distribution)
            or not isinstance(expected_version, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!-]{0,127}", expected_version)
            or not SHA256.fullmatch(str(expected_tree_digest or ""))):
        raise TrustStateError("root-signed trust-state adapter package identity is missing")
    # Verify the independently reviewed backend contract before importing its
    # package, since importing an entry point executes adapter code.
    verify_customer_backend_conformance(document, now=now)
    entries = _entry_points()
    if len(entries) != 1:
        raise TrustStateError("exactly one installed customer trust-state adapter entry point is required")
    entry = entries[0]
    distribution = getattr(entry, "dist", None)
    if (distribution is None or distribution.name != expected_distribution
            or distribution.version != expected_version
            or adapter_distribution_sha256(distribution) != expected_tree_digest):
        raise TrustStateError("installed trust-state adapter package differs from root-authorized identity")
    try:
        with _ADAPTER_IMPORT_LOCK:
            module_name, allowed, verified_before = verify_adapter_entry_point_origin(
                entry, expected_tree_digest)
            # Do not create __pycache__ files that are outside the installed-tree
            # digest while loading trusted adapter code.
            old_dont_write_bytecode = sys.dont_write_bytecode
            sys.dont_write_bytecode = True
            try:
                factory = entry.load()
            finally:
                sys.dont_write_bytecode = old_dont_write_bytecode
            loaded = _verify_loaded_adapter_origin(module_name, allowed)
            if adapter_distribution_sha256(distribution) != expected_tree_digest:
                raise TrustStateError("installed trust-state adapter changed while it was being loaded")
            if verified_before:
                known = _VERIFIED_ADAPTER_MODULES[(module_name, expected_tree_digest)]
                if any(known.get(name) is not module for name, module in loaded.items()):
                    raise TrustStateError("cached adapter module identity changed after origin verification")
            else:
                _VERIFIED_ADAPTER_MODULES[(module_name, expected_tree_digest)] = loaded
        if not callable(factory):
            raise TypeError("entry point is not callable")
        transport = factory(dict(settings))
        if adapter_distribution_sha256(distribution) != expected_tree_digest:
            raise TrustStateError("installed trust-state adapter changed during initialization")
    except Exception as error:
        raise TrustStateError("customer trust-state adapter could not be initialized") from error
    snapshot = _load_customer_trust_with_transport(transport, config_path=config_path,
        signature_path=signature_path, root_path=root_path,
        now=lambda: now or dt.datetime.now(dt.timezone.utc))
    if snapshot.sha256 != expected_digest:
        raise TrustStateError("root-authorized trust configuration changed during adapter initialization")
    return snapshot
