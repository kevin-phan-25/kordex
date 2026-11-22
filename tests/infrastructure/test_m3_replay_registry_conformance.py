"""Synthetic adapter tests for the customer replay-registry contract harness."""

import hashlib
import importlib.util
from pathlib import Path
import sys
import threading
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m3_replay_registry_conformance",
    ROOT / "scripts/m3_replay_registry_conformance.py")
contract = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(contract)


def canonical(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class SyntheticRegistryAdapter:
    """In-memory fixture only; it cannot demonstrate production durability or signatures."""

    def __init__(self, isolated=True):
        self.isolated = isolated
        self.lock = threading.Lock()
        self.by_run = {}
        self.by_nonce = {}
        self.accepted = {}
        self.sequence = 0
        self.drop = set()

    def identity(self):
        return {"protocolVersion": contract.PROTOCOL_VERSION, "registryIdentity": "synthetic-registry",
                "endpoint": "https://registry.fixture.invalid/v1/claims", "isolatedTestEndpoint": self.isolated}

    def _receipt(self, action, body, fields):
        result = {"action": action, **fields, "runId": body["runId"], "runNonce": body["runNonce"],
                  "signatureFixture": "synthetic-only"}
        if action == "reserve-run":
            result["reservationSha256"] = hashlib.sha256(canonical(body)).hexdigest()
        return result

    def reserve(self, request):
        with self.lock:
            existing = self.by_run.get(request["runId"])
            nonce_run = self.by_nonce.get(request["runNonce"])
            if (existing and existing["request"]["runNonce"] != request["runNonce"]) or (
                    nonce_run and nonce_run != request["runId"]):
                receipt = self._receipt("reserve-run", request, {"status": "conflict", "sequence": self.sequence,
                                                                    "reservationId": ""})
            elif existing:
                receipt = self._receipt("reserve-run", request, {"status": "already-reserved",
                    "sequence": existing["sequence"], "reservationId": existing["reservationId"]})
                receipt["reservationSha256"] = existing["reservationSha256"]
            else:
                self.sequence += 1
                row = {"request": dict(request), "sequence": self.sequence,
                       "reservationId": f"synthetic-{self.sequence}"}
                row["reservationSha256"] = hashlib.sha256(canonical(request)).hexdigest()
                self.by_run[request["runId"]] = row
                self.by_nonce[request["runNonce"]] = request["runId"]
                receipt = self._receipt("reserve-run", request, {"status": "newly-reserved",
                    "sequence": row["sequence"], "reservationId": row["reservationId"]})
                receipt["reservationSha256"] = row["reservationSha256"]
            if "reserve-run" in self.drop:
                self.drop.remove("reserve-run")
                raise contract.AmbiguousOutcome()
            return receipt

    def accept(self, request):
        with self.lock:
            key = request["runId"]
            current = self.accepted.get(key)
            if key not in self.by_run:
                receipt = self._receipt("accept-run", request, {"claim": "rejected", "sequence": self.sequence})
            elif current is None:
                self.sequence += 1
                self.accepted[key] = {"request": dict(request), "sequence": self.sequence}
                receipt = self._receipt("accept-run", request, {"claim": "newly-accepted", "sequence": self.sequence})
            else:
                receipt = self._receipt("accept-run", request, {"claim": "already-accepted",
                    "sequence": current["sequence"]})
            if "accept-run" in self.drop:
                self.drop.remove("accept-run")
                raise contract.AmbiguousOutcome()
            return receipt

    def lookup(self, request):
        with self.lock:
            row = self.by_run.get(request["runId"])
            state = "accepted" if request["runId"] in self.accepted else "reserved" if row else "unknown"
            return {"state": state, "reservationId": row["reservationId"] if row else "",
                    "signatureFixture": "synthetic-only"}

    def restart_and_reopen(self):
        # Deliberately no process/storage restart: this fixture must not be mistaken for durability evidence.
        return None

    def lose_next_ack(self, action):
        self.drop.add(action)

    def verify_receipt(self, _action, receipt):
        return receipt.get("signatureFixture") == "synthetic-only"


class ReplayRegistryContractTests(unittest.TestCase):
    def test_synthetic_adapter_exercises_concurrency_and_lost_ack_contract(self):
        result = contract.run_conformance(SyntheticRegistryAdapter())
        self.assertEqual(result["protocolVersion"], "kordex-m3-replay-registry-v1")
        self.assertFalse(result["qualificationAccepted"])
        self.assertIn("concurrent-reservation", result["tests"])
        self.assertIn("lost-ack-retry-acceptance", result["tests"])

    def test_harness_rejects_nonisolated_endpoint_before_operations(self):
        with self.assertRaisesRegex(contract.ConformanceError, "isolated HTTPS"):
            contract.run_conformance(SyntheticRegistryAdapter(isolated=False))
