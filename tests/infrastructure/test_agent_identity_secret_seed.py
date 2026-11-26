from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "seed_agent_identity_secret.py"
SPEC = importlib.util.spec_from_file_location("seed_agent_identity_secret", SCRIPT)
assert SPEC and SPEC.loader
seed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed)


def secret(data: dict[str, str] | None = None, *, name: str = "agent-identity") -> dict[str, object]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": "kordex-system", "uid": "uid-1", "resourceVersion": "17"},
        "type": "Opaque",
        "data": data if data is not None else {},
    }


class AgentIdentitySecretSeedTests(unittest.TestCase):
    def test_empty_secret_is_seeded_with_resource_version_cas(self) -> None:
        calls: list[list[str]] = []

        def run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if args[5] == "get":
                return subprocess.CompletedProcess(args, 0, json.dumps(secret()), "")
            patch = json.loads(args[args.index("--patch") + 1])
            self.assertEqual(patch[0], {"op": "test", "path": "/metadata/resourceVersion", "value": "17"})
            self.assertEqual(patch[1], {"op": "add", "path": "/data", "value": {"state.json": "e30="}})
            return subprocess.CompletedProcess(args, 0, json.dumps(secret({"state.json": "e30="})), "")

        self.assertTrue(seed.seed_identity_secret(run, kubectl="kubectl", context="lab", namespace="kordex-system", name="agent-identity"))
        self.assertEqual(len(calls), 2)
        self.assertIn("--context", calls[0])

    def test_present_identity_is_never_overwritten_or_printed(self) -> None:
        calls: list[list[str]] = []
        private_state = "cHJpdmF0ZS1rZXktc2VjcmV0"

        def run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(secret({"state.json": private_state})), "")

        self.assertFalse(seed.seed_identity_secret(run, kubectl="kubectl", context="lab", namespace="kordex-system", name="agent-identity"))
        self.assertEqual(len(calls), 1)
        self.assertNotIn(private_state, " ".join(calls[0]))

    def test_resource_version_conflict_fails_without_retrying_overwrite(self) -> None:
        calls: list[list[str]] = []

        def run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if len(calls) == 1:
                return subprocess.CompletedProcess(args, 0, json.dumps(secret()), "")
            return subprocess.CompletedProcess(args, 1, "", "conflict")

        with self.assertRaisesRegex(RuntimeError, "changed during initialization"):
            seed.seed_identity_secret(run, kubectl="kubectl", context="lab", namespace="kordex-system", name="agent-identity")
        self.assertEqual(len(calls), 2)

    def test_wrong_secret_and_unexpected_data_fail_closed(self) -> None:
        for payload in (secret(name="other"), secret({"unexpected": "eA=="})):
            with self.subTest(payload=payload):
                run = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, json.dumps(payload), "")
                with self.assertRaises(RuntimeError):
                    seed.seed_identity_secret(run, kubectl="kubectl", context="lab", namespace="kordex-system", name="agent-identity")

    def test_empty_or_malformed_state_key_is_not_treated_as_initialized(self) -> None:
        for encoded in ("", "not-base64!"):
            with self.subTest(encoded=encoded):
                run = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, json.dumps(secret({"state.json": encoded})), "")
                with self.assertRaises(RuntimeError):
                    seed.seed_identity_secret(run, kubectl="kubectl", context="lab", namespace="kordex-system", name="agent-identity")

    def test_seed_response_must_preserve_uid_and_only_contain_empty_state(self) -> None:
        responses = [json.dumps(secret()), json.dumps(secret({"state.json": "e30=", "unexpected": "eA=="}))]
        calls = 0

        def run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            response = responses[calls]
            calls += 1
            return subprocess.CompletedProcess(args, 0, response, "")

        with self.assertRaisesRegex(RuntimeError, "did not preserve"):
            seed.seed_identity_secret(run, kubectl="kubectl", context="lab", namespace="kordex-system", name="agent-identity")


if __name__ == "__main__":
    unittest.main()
