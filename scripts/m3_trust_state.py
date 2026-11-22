"""Transport-neutral client for a customer-operated monotonic trust-state store.

No storage service or credentials are selected here. A customer adapter must
implement ``read_state`` and ``compare_and_swap`` and return receipts signed by
the independently pinned backend attestation key. The interface deliberately
has no reset or delete operation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from typing import Callable, Protocol

try:
    import m3_customer_trust as customer_trust
except ImportError:  # importlib-based tests
    from scripts import m3_customer_trust as customer_trust


PROTOCOL_VERSION = "kordex-m3-trust-state-v1"
CONFORMANCE_PROTOCOL = "kordex-m3-trust-state-conformance-v1"
TRUST_STATE_CONFORMANCE_REPORT = Path("/etc/kordex/m3/trust-state-conformance.json")
TRUST_STATE_CONFORMANCE_SIGNATURE = Path("/etc/kordex/m3/trust-state-conformance.json.sig")
TRUST_STATE_CONFORMANCE_SUITE = Path(__file__).resolve().with_name("m3_trust_state_conformance.py")
EMPTY_DIGEST = "0" * 64
SHA256 = re.compile(r"^[a-f0-9]{64}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}$")
MAX_RECEIPT_AGE = dt.timedelta(minutes=2)
CLOCK_SKEW = dt.timedelta(seconds=30)


class TrustStateError(ValueError):
    pass


_VERIFIED_TRUST_TOKEN = object()


class VerifiedCustomerTrust:
    """Opaque immutable result issued after root signature, conformance and CAS checks."""

    __slots__ = ("_document_raw", "_sha256", "_client", "_conformance_sha256", "_sealed")

    def __init__(self, document: dict, digest: str, client, conformance_digest: str, *, _token=None):
        if _token is not _VERIFIED_TRUST_TOKEN:
            raise TrustStateError("verified customer trust snapshots must come from load_customer_trust")
        object.__setattr__(self, "_document_raw", customer_trust.canonical_json(document))
        object.__setattr__(self, "_sha256", digest)
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_conformance_sha256", conformance_digest)
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


class TrustStateTransport(Protocol):
    """Customer adapter contract; transport authentication is adapter-owned."""

    def identity(self) -> dict: ...

    def read_state(self, customer_id: str, namespace: str, transition_id: str) -> dict: ...

    def compare_and_swap(self, request: dict) -> dict: ...


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
            or type(report.get("schemaVersion")) is not int or report["schemaVersion"] != 1
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
        self._verify_transport_identity()

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

    def _verify_receipt(self, receipt: object, *, action: str, transition_id: str) -> dict:
        fields = {"schemaVersion", "protocolVersion", "action", "backendIdentity", "customerId", "namespace",
                  "transitionId", "sequence", "configurationSha256", "durable", "status",
                  "observedAt", "recordedAt", "auditId", "attestationFingerprint", "signature"}
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
                or type(unsigned["sequence"]) is not int or unsigned["sequence"] < 0
                or not isinstance(unsigned["configurationSha256"], str)
                or not SHA256.fullmatch(unsigned["configurationSha256"])
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
        return unsigned

    def _read(self, transition_id: str) -> dict:
        try:
            response = self.transport.read_state(self.customer_id, self.namespace, transition_id)
        except Exception as error:
            raise TrustStateError("customer trust-state backend is unavailable") from error
        receipt = self._verify_receipt(response, action="read-state", transition_id=transition_id)
        if receipt["status"] != "current":
            raise TrustStateError("customer trust-state read returned a non-current state")
        return receipt

    def verify_and_advance(self, document: dict, configuration_sha256: str) -> dict:
        """Verify exact generation or atomically advance one generation.

        Ambiguous CAS acknowledgements are resolved by one authenticated read.
        A mismatch, outage, expired receipt, or corrupted state fails closed.
        """
        actual_digest = hashlib.sha256(customer_trust.canonical_json(document)).hexdigest()
        if (document.get("customerId") != self.customer_id
                or type(document.get("sequence")) is not int or document["sequence"] < 1
                or not SHA256.fullmatch(configuration_sha256 or "")
                or actual_digest != configuration_sha256):
            raise TrustStateError("signed trust configuration is not bound to this customer and generation")
        target_sequence = document["sequence"]
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
            if current_digest != configuration_sha256:
                raise TrustStateError("customer trust sequence is already bound to a different digest")
            return {"sequence": target_sequence, "configurationSha256": configuration_sha256, "durable": True}
        if current_sequence + 1 != target_sequence:
            raise TrustStateError("customer trust generation skipped; explicit customer recovery is required")
        if current_sequence == 0 and current_digest != EMPTY_DIGEST:
            raise TrustStateError("customer trust-state initial generation is inconsistent")
        request = {
            "schemaVersion": 1, "protocolVersion": PROTOCOL_VERSION, "action": "compare-and-swap",
            "customerId": self.customer_id, "backendIdentity": self.backend_identity,
            "namespace": self.namespace,
            "transitionId": transition_id, "expectedSequence": current_sequence,
            "expectedConfigurationSha256": current_digest, "newSequence": target_sequence,
            "newConfigurationSha256": configuration_sha256,
        }
        try:
            response = self.transport.compare_and_swap(request)
        except Exception:
            # Never issue a second mutation after a lost acknowledgement. One
            # signed read may prove the exact transition committed.
            observed = self._read(transition_id)
            if observed["sequence"] == target_sequence and observed["configurationSha256"] == configuration_sha256:
                return {"sequence": target_sequence, "configurationSha256": configuration_sha256, "durable": True}
            raise TrustStateError("customer trust-state update outcome is ambiguous; customer reconciliation is required")
        receipt = self._verify_receipt(response, action="compare-and-swap", transition_id=transition_id)
        if receipt["status"] == "conflict":
            observed = self._read(transition_id)
            if observed["sequence"] == target_sequence and observed["configurationSha256"] == configuration_sha256:
                return {"sequence": target_sequence, "configurationSha256": configuration_sha256, "durable": True}
            raise TrustStateError("concurrent trust-state change conflicts with this update")
        if (receipt["status"] != "committed" or receipt["sequence"] != target_sequence
                or receipt["configurationSha256"] != configuration_sha256):
            raise TrustStateError("customer trust-state backend did not commit the exact signed configuration")
        return {"sequence": target_sequence, "configurationSha256": configuration_sha256, "durable": True}


def load_customer_trust(transport: TrustStateTransport, *,
                        config_path: Path = customer_trust.TRUST_CONFIG,
                        signature_path: Path = customer_trust.TRUST_SIGNATURE,
                        root_path: Path = customer_trust.TRUST_ROOT,
                        now: Callable[[], dt.datetime] | None = None) -> VerifiedCustomerTrust:
    """Production integration: root-verify, attest backend, enforce CAS, return opaque trust."""
    current = now() if now else None
    document, signed_digest = customer_trust.load_signed_trust_candidate(
        config_path, signature_path, root_path, now=current, require_root_owned=True)
    conformance_digest = verify_customer_backend_conformance(document, now=current)
    client = CustomerTrustStateClient._from_customer_trust_candidate(transport, document, now=now)
    verified, digest = customer_trust.load_trust(
        config_path, signature_path, root_path, now=current, require_root_owned=True,
        monotonic_state_verifier=client.verify_and_advance)
    if digest != signed_digest:
        raise TrustStateError("customer trust configuration changed while monotonic state was verified")
    return VerifiedCustomerTrust(verified, digest, client, conformance_digest, _token=_VERIFIED_TRUST_TOKEN)
