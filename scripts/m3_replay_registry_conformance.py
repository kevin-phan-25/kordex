"""Customer adapter contract suite for the M3 durable replay registry.

The suite never discovers or contacts a service. A customer supplies an adapter
for an isolated conformance endpoint. Its returned receipts must be verified
against the customer-rooted replay-registry identity by ``verify_receipt``.
Passing this synthetic/local harness is not production qualification; an
independent reviewer must inspect endpoint and durability evidence.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import secrets
import uuid


PROTOCOL_VERSION = "kordex-m3-replay-registry-v1"
CONCURRENCY = 12


class ConformanceError(ValueError):
    pass


class AmbiguousOutcome(Exception):
    """Adapter reports that the request committed but its acknowledgement was lost."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


def run_conformance(adapter) -> dict:
    """Exercise uniqueness, durability, concurrency and ambiguous-ack behavior.

    Adapter contract:
      - ``identity()`` returns protocolVersion, registryIdentity, endpoint and
        ``isolatedTestEndpoint: true`` (never production).
      - ``reserve(request)`` and ``accept(request)`` return normalized receipts
        with status/claim, reservationId, sequence, runId, runNonce and request
        binding fields.
      - ``verify_receipt(action, receipt)`` cryptographically verifies a
        customer-signed receipt; the harness never trusts a server boolean.
      - ``lookup(request)`` returns the durable state for the exact run.
      - ``restart_and_reopen()`` reconnects after a real service restart.
      - ``lose_next_ack(action)`` causes the next request to commit while the
        adapter raises AmbiguousOutcome before returning its receipt.
    """
    identity = adapter.identity()
    _require(isinstance(identity, dict) and identity.get("protocolVersion") == PROTOCOL_VERSION
             and identity.get("isolatedTestEndpoint") is True
             and isinstance(identity.get("endpoint"), str) and identity["endpoint"].startswith("https://")
             and isinstance(identity.get("registryIdentity"), str),
             "adapter must identify an isolated HTTPS conformance endpoint and protocol v1")
    run_id, nonce = str(uuid.uuid4()), secrets.token_hex(32)
    request = {"schemaVersion": 1, "action": "reserve-run", "runId": run_id,
               "runNonce": nonce, "canonicalMatrixSha256": hashlib.sha256(b"m3-matrix-binding").hexdigest(),
               "trustConfigurationSha256": hashlib.sha256(b"customer-trust-binding").hexdigest(),
               "createdAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
               "expiresAt": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat().replace("+00:00", "Z")}
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        reservations = list(pool.map(lambda _index: adapter.reserve(request), range(CONCURRENCY)))
    for receipt in reservations:
        _require(adapter.verify_receipt("reserve-run", receipt) is True,
                 "reservation response signature or registry identity is not verified")
    winners = [item for item in reservations if item.get("status") == "newly-reserved"]
    _require(len(winners) == 1, "concurrent duplicate reservation must have exactly one winner")
    winner = winners[0]
    _require(all(item.get("status") in {"newly-reserved", "already-reserved"}
                 and item.get("reservationId") == winner.get("reservationId")
                 and item.get("sequence") == winner.get("sequence")
                 and item.get("runId") == run_id and item.get("runNonce") == nonce
                 for item in reservations), "duplicate reservation returned conflicting durable state")

    adapter.restart_and_reopen()
    durable = adapter.lookup(request)
    _require(adapter.verify_receipt("lookup-run", durable) is True
             and durable.get("state") == "reserved"
             and durable.get("reservationId") == winner.get("reservationId"),
             "reservation did not survive service restart with authenticated state")

    changed_nonce = dict(request, runNonce=secrets.token_hex(32))
    changed_run = dict(request, runId=str(uuid.uuid4()))
    changed_nonce_receipt = adapter.reserve(changed_nonce)
    changed_run_receipt = adapter.reserve(changed_run)
    _require(adapter.verify_receipt("reserve-run", changed_nonce_receipt) is True
             and changed_nonce_receipt.get("status") == "conflict",
             "registry must reject one run ID paired with a different nonce")
    _require(adapter.verify_receipt("reserve-run", changed_run_receipt) is True
             and changed_run_receipt.get("status") == "conflict",
             "registry must reject reuse of a nonce with a different run ID")

    adapter.lose_next_ack("reserve-run")
    try:
        adapter.reserve(request)
    except AmbiguousOutcome:
        pass
    else:
        raise ConformanceError("reserve-run lost-ack test did not produce the required ambiguous outcome")
    adapter.restart_and_reopen()
    reserved_after_lost_ack = adapter.lookup(request)
    _require(adapter.verify_receipt("lookup-run", reserved_after_lost_ack) is True
             and reserved_after_lost_ack.get("state") == "reserved"
             and reserved_after_lost_ack.get("reservationId") == winner.get("reservationId"),
             "reservation commit was not durably recoverable after lost acknowledgement")
    reserve_retry = adapter.reserve(request)
    _require(adapter.verify_receipt("reserve-run", reserve_retry) is True
             and reserve_retry.get("reservationId") == winner.get("reservationId")
             and reserve_retry.get("sequence") == winner.get("sequence"),
             "exact reservation retry did not return the same authenticated durable state")

    accept = {"schemaVersion": 1, "action": "accept-run",
              "challenge": secrets.token_hex(32), "runId": run_id, "runNonce": nonce,
              "manifestSha256": hashlib.sha256(b"manifest").hexdigest(),
              "reviewSha256": hashlib.sha256(b"review").hexdigest(),
              "trustConfigurationSha256": request["trustConfigurationSha256"],
              "canonicalMatrixSha256": request["canonicalMatrixSha256"],
              "reservationSha256": winner["reservationSha256"]}
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        accepted = list(pool.map(lambda _index: adapter.accept(accept), range(CONCURRENCY)))
    for receipt in accepted:
        _require(adapter.verify_receipt("accept-run", receipt) is True,
                 "acceptance response signature or registry identity is not verified")
    claims = [item for item in accepted if item.get("claim") == "newly-accepted"]
    _require(len(claims) == 1, "concurrent duplicate acceptance must have exactly one winner")
    accept_winner = claims[0]
    _require(all(item.get("claim") in {"newly-accepted", "already-accepted"}
                 and item.get("sequence") == accept_winner.get("sequence")
                 and item.get("runId") == run_id and item.get("runNonce") == nonce
                 for item in accepted), "duplicate acceptance returned conflicting durable state")

    # A lost acknowledgement is an ambiguous caller outcome, never a fresh run.
    # Exact-request retries must resolve to the same state/receipt; changed
    # challenges or package digests must remain rejected.
    adapter.lose_next_ack("accept-run")
    try:
        adapter.accept(accept)
    except AmbiguousOutcome:
        pass
    else:
        raise ConformanceError("accept-run lost-ack test did not produce the required ambiguous outcome")
    adapter.restart_and_reopen()
    accepted_after_lost_ack = adapter.lookup(accept)
    _require(adapter.verify_receipt("lookup-run", accepted_after_lost_ack) is True
             and accepted_after_lost_ack.get("state") == "accepted",
             "acceptance commit was not durably recoverable after lost acknowledgement")
    retry = adapter.accept(accept)
    _require(adapter.verify_receipt("accept-run", retry) is True
             and retry.get("runId") == run_id and retry.get("runNonce") == nonce,
             "exact acceptance retry did not return authenticated idempotent state")

    changed_accept = dict(accept, challenge=secrets.token_hex(32), manifestSha256=hashlib.sha256(b"other").hexdigest())
    changed_receipt = adapter.accept(changed_accept)
    _require(adapter.verify_receipt("accept-run", changed_receipt) is True
             and changed_receipt.get("claim") == "already-accepted",
             "accepted run must not be accepted again under a changed challenge or package")
    return {"protocolVersion": PROTOCOL_VERSION, "registryIdentity": identity["registryIdentity"],
            "endpoint": identity["endpoint"], "isolatedTestEndpoint": True,
            "tests": ["concurrent-reservation", "durability-after-restart", "run-nonce-uniqueness",
                      "concurrent-acceptance", "lost-ack-retry-reservation", "lost-ack-retry-acceptance",
                      "changed-acceptance-replay"],
            "qualificationAccepted": False}
