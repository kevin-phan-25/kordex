"""Synthetic contract tests; no customer adapter or backend is loaded here."""

from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_m3_trust_state_conformance", ROOT / "scripts/run_m3_trust_state_conformance.py")
runner = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(runner)


class TrustStateConformanceRunnerTests(unittest.TestCase):
    def test_bootstrap_schema_is_well_formed_and_pins_required_fields(self):
        schema = runner.json.loads((ROOT / "schemas/m3-trust-state-conformance-bootstrap-v1.json").read_text())
        Draft202012Validator.check_schema(schema)
        self.assertEqual(set(schema["required"]), runner.BOOTSTRAP_FIELDS)
        self.assertIn("runnerSourceCommit", schema["required"])
        self.assertIn("adapterTreeSha256", schema["required"])

    def test_run_report_v2_requires_request_bound_audit_events(self):
        schema = runner.json.loads(
            (ROOT / "schemas/m3-trust-state-conformance-run-report-v2.json").read_text())
        Draft202012Validator.check_schema(schema)
        execution = schema["$defs"]["execution"]
        audit_event = schema["$defs"]["auditEvent"]
        self.assertEqual(schema["properties"]["schemaVersion"], {"const": 2})
        self.assertEqual(execution["properties"]["protocolVersion"],
                         {"const": "kordex-m3-trust-state-v2"})
        self.assertIn("requestId", audit_event["required"])
        self.assertEqual(audit_event["properties"]["requestId"], {"$ref": "#/$defs/requestId"})

    def test_successful_runner_output_uses_v2_schema_without_accepting_trust(self):
        bootstrap = {
            "schemaVersion": 1, "customerId": "customer-1", "backendIdentity": "backend-1",
            "endpointReference": "https://trust.example.test", "evidenceReference": "ev-run-001",
            "runnerSourceCommit": "a" * 40, "adapterDistribution": "customer-adapter",
            "adapterVersion": "2.4.1", "adapterTreeSha256": "e" * 64,
            "attestationPublicKeyPem": "attestor-key", "attestationFingerprint": "a" * 64,
            "conformanceRootPublicKeyPem": "test-root", "trustPolicyDocument": {},
            "trustPolicySignatureHex": "00" * 64,
        }
        audit = {
            "action": "read-state", "backendIdentity": "backend-1", "customerId": "customer-1",
            "namespace": "kordex-conformance-run-1", "transitionId": "transition-001",
            "requestId": "b" * 64, "sequence": 0, "configurationSha256": "c" * 64,
            "auditId": "audit-001", "observedAt": "2026-11-26T00:00:00Z",
            "recordedAt": "2026-11-26T00:00:00Z", "attestationFingerprint": "a" * 64,
            "rootFingerprint": "0" * 64, "rootSignatureSha256": "0" * 64,
        }
        candidate = {
            "schemaVersion": 2, "protocolVersion": "kordex-m3-trust-state-conformance-v2",
            "customerId": "customer-1", "backendIdentity": "backend-1",
            "endpointReference": "https://trust.example.test",
            "conformanceNamespace": "kordex-conformance-run-1", "contractSuiteSha256": "d" * 64,
            "resultsSha256": "c" * 64, "decision": "pending-independent-review",
            "reviewerIdentity": "pending", "reviewedAt": "2026-11-26T00:00:00Z",
            "expiresAt": "2026-12-26T00:00:00Z", "evidenceReference": "ev-run-001",
        }
        result = {
            "protocolVersion": "kordex-m3-trust-state-v2", "customerId": "customer-1",
            "backendIdentity": "backend-1", "endpointReference": "https://trust.example.test",
            "namespace": "kordex-conformance-run-1", "tests": [f"case-{i}" for i in range(17)],
            "auditEvents": [audit], "trustPolicyTests": [f"policy-{i}" for i in range(8)],
            "resultsSha256": "c" * 64, "conformanceRootFingerprint": "f" * 64,
            "conformanceReportCandidate": candidate, "backendContractChecks": "EXECUTED",
            "customerAdapterConformance": "NOT ESTABLISHED", "unitOrFixtureExecution": False,
            "productionTrustAccepted": False, "requiresIndependentReview": True,
        }
        entry = SimpleNamespace(load=lambda: (lambda _: {
            "transportFactory": lambda _namespace: None,
            "signConformanceConfiguration": lambda _document: b"signature",
        }))
        with tempfile.TemporaryDirectory() as out_dir:
            out_path = Path(out_dir) / "report.json"
            with patch.object(runner, "read_bootstrap", return_value=(bootstrap, b"root")), \
                 patch.object(runner, "source_commit_and_cleanliness", return_value="a" * 40), \
                 patch.object(runner, "select_entry_point", return_value=entry), \
                 patch.object(runner, "verify_entry_module_origin", return_value=("mod", set())), \
                 patch.object(runner, "verify_loaded_module_origin", return_value=None), \
                 patch.object(runner.customer_trust, "fingerprint", return_value="f" * 64), \
                 patch.object(runner.conformance, "run_conformance", return_value=result):
                report = runner.run(Path("bootstrap.json"), Path("bootstrap.sig"), out_path)
            report_mode = out_path.stat().st_mode & 0o777
        self.assertEqual(report["schemaVersion"], 2)
        self.assertFalse(report["productionTrustAccepted"])
        self.assertEqual(report["qualificationRowsAdvanced"], 0)
        self.assertEqual(report_mode, 0o600)

    def test_entrypoint_selection_requires_exactly_one_authorized_distribution(self):
        distribution = SimpleNamespace(name="customer-adapter", version="2.4.1")
        selected = SimpleNamespace(group=runner.ENTRY_POINT_GROUP, name=runner.ENTRY_POINT_NAME,
                                   dist=distribution, load=lambda: self.fail("entry point loaded before pin check"))
        ignored = SimpleNamespace(group="unrelated", name="customer", dist=distribution)
        with patch.object(runner.trust_state, "adapter_distribution_sha256", return_value="a" * 64):
            self.assertIs(runner.select_entry_point([ignored, selected], "customer-adapter", "2.4.1", "a" * 64), selected)
            with self.assertRaisesRegex(runner.RunnerError, "exactly one"):
                runner.select_entry_point([selected, selected], "customer-adapter", "2.4.1", "a" * 64)
            with self.assertRaisesRegex(runner.RunnerError, "distribution/version"):
                runner.select_entry_point([selected], "other-adapter", "2.4.1", "a" * 64)
            with self.assertRaisesRegex(runner.RunnerError, "tree digest"):
                runner.select_entry_point([selected], "customer-adapter", "2.4.1", "b" * 64)

    def test_root_signed_bootstrap_is_required_before_package_lookup(self):
        with patch.object(runner, "read_file", side_effect=[b'{"schemaVersion":1}', b"bad-sig"]), \
             patch.object(runner, "read_trusted_root", return_value=b"public-root"), \
             patch.object(runner.importlib.metadata, "entry_points") as entry_points:
            with self.assertRaisesRegex(runner.RunnerError, "fields are incomplete"):
                runner.read_bootstrap(Path("bootstrap.json"), Path("bootstrap.sig"), Path("root.pub"))
            entry_points.assert_not_called()

    def test_bootstrap_attestor_and_conformance_root_are_bound_to_distinct_trust_roles(self):
        bootstrap = {"customerId": "customer-1", "backendIdentity": "backend-1",
                     "endpointReference": "https://trust.example.test", "attestationPublicKeyPem": "attestor-key",
                     "attestationFingerprint": "a" * 64, "conformanceRootPublicKeyPem": "test-root"}
        policy = {"customerId": "customer-1", "trustState": {
            "backendIdentity": "backend-1", "endpointReference": "https://trust.example.test",
            "attestorIdentity": "backend-attestor", "conformanceReviewerIdentity": "independent-reviewer"}}
        def authorized(document, identity, role):
            if role == "trust-state-attestor":
                return b"attestor-key", "a" * 64
            return b"reviewer-key", "b" * 64
        def fingerprint(key):
            return {b"test-root": "c" * 64, b"qualification-root": "d" * 64}[key]
        with patch.object(runner.customer_trust, "authorized_key", side_effect=authorized), \
             patch.object(runner.customer_trust, "fingerprint", side_effect=fingerprint):
            runner._validate_policy_bindings(bootstrap, policy, b"qualification-root")
            bootstrap["attestationFingerprint"] = "f" * 64
            with self.assertRaisesRegex(runner.RunnerError, "attestor key differs"):
                runner._validate_policy_bindings(bootstrap, policy, b"qualification-root")
            bootstrap["attestationFingerprint"] = "a" * 64
            bootstrap["conformanceRootPublicKeyPem"] = "qualification-root"
            with self.assertRaisesRegex(runner.RunnerError, "isolated conformance root"):
                runner._validate_policy_bindings(bootstrap, policy, b"qualification-root")

    def test_dirty_or_wrong_runner_revision_is_rejected(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            repo = Path(repo_dir)
            resolved = str(repo.resolve())

            def run(args, **kwargs):
                if args[-2:] == ["rev-parse", "--show-toplevel"]:
                    return SimpleNamespace(stdout=resolved + "\n")
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return SimpleNamespace(stdout="a" * 40 + "\n")
                return SimpleNamespace(stdout=" M scripts/untrusted.py\n")

            with patch.object(runner.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(runner.RunnerError, "worktree is dirty"):
                    runner.source_commit_and_cleanliness(repo, "a" * 40)

            def clean_wrong_revision(args, **kwargs):
                if args[-2:] == ["rev-parse", "--show-toplevel"]:
                    return SimpleNamespace(stdout=resolved + "\n")
                return SimpleNamespace(stdout=("b" * 40 + "\n") if args[-2:] == ["rev-parse", "HEAD"] else "")

            with patch.object(runner.subprocess, "run", side_effect=clean_wrong_revision):
                with self.assertRaisesRegex(runner.RunnerError, "source commit differs"):
                    runner.source_commit_and_cleanliness(repo, "a" * 40)

    def test_ignored_files_count_as_dirty_and_git_environment_is_scrubbed(self):
        calls = []
        envs = []
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as other_dir:
            repo = Path(repo_dir)
            resolved = str(repo.resolve())

            def run(args, **kwargs):
                calls.append(args)
                envs.append(kwargs.get("env", {}))
                if args[-2:] == ["rev-parse", "--show-toplevel"]:
                    return SimpleNamespace(stdout=resolved + "\n")
                if args[-2:] == ["rev-parse", "HEAD"]:
                    return SimpleNamespace(stdout="a" * 40 + "\n")
                return SimpleNamespace(stdout="!! scripts/__pycache__/m3_customer_trust.cpython-312.pyc\n")

            with patch.dict(os.environ, {"GIT_DIR": "/tmp/spoof.git", "GIT_WORK_TREE": "/tmp/spoof",
                                         "GIT_CONFIG_GLOBAL": "/tmp/evil.gitconfig"}), \
                 patch.object(runner.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(runner.RunnerError, "worktree is dirty"):
                    runner.source_commit_and_cleanliness(repo, "a" * 40)
            status = next(args for args in calls if "status" in args)
            self.assertIn("--ignored", status)
            self.assertTrue(all("core.fsmonitor=false" in args for args in calls))
            self.assertTrue(all("--no-replace-objects" in args for args in calls))
            for env in envs:
                self.assertNotIn("GIT_DIR", env)
                self.assertNotIn("GIT_WORK_TREE", env)
                self.assertEqual(env.get("GIT_CONFIG_NOSYSTEM"), "1")
                self.assertEqual(env.get("GIT_CONFIG_GLOBAL"), os.devnull)

            def parent_repo(args, **kwargs):
                if args[-2:] == ["rev-parse", "--show-toplevel"]:
                    return SimpleNamespace(stdout=str(Path(other_dir).resolve()) + "\n")
                return SimpleNamespace(stdout=("a" * 40 + "\n") if args[-2:] == ["rev-parse", "HEAD"] else "")

            with patch.object(runner.subprocess, "run", side_effect=parent_repo):
                with self.assertRaisesRegex(runner.RunnerError, "repository root"):
                    runner.source_commit_and_cleanliness(repo, "a" * 40)

    def _fake_entry(self, module: str, distribution_root: Path, files: list[str]):
        distribution = SimpleNamespace(
            name="customer-adapter", version="2.4.1", files=files,
            locate_file=lambda item: distribution_root / str(item))
        return SimpleNamespace(value=f"{module}:factory", dist=distribution)

    def test_entry_module_must_resolve_to_pinned_distribution_files(self):
        module = "kordex_synthetic_conformance_adapter_origin"
        with tempfile.TemporaryDirectory() as pinned, tempfile.TemporaryDirectory() as shadow:
            pinned_root, shadow_root = Path(pinned), Path(shadow)
            (pinned_root / f"{module}.py").write_text("def factory(_):\n    return {}\n")
            (shadow_root / f"{module}.py").write_text("raise SystemExit('shadow executed')\n")
            entry = self._fake_entry(module, pinned_root, [f"{module}.py"])
            with patch.object(sys, "path", [str(shadow_root), *sys.path]):
                with self.assertRaisesRegex(runner.RunnerError, "outside its root-authorized"):
                    runner.verify_entry_module_origin(entry)
            with patch.object(sys, "path", [str(pinned_root), *sys.path]):
                name, allowed = runner.verify_entry_module_origin(entry)
            self.assertEqual(name, module)
            self.assertIn((pinned_root / f"{module}.py").resolve(), allowed)
            self.assertNotIn(module, sys.modules)

    def test_dotted_submodule_and_unpinned_bytecode_are_rejected_without_execution(self):
        pkg = "kordex_synthetic_conformance_pkg"
        with tempfile.TemporaryDirectory() as pinned:
            pinned_root = Path(pinned)
            pkg_dir = pinned_root / pkg
            pkg_dir.mkdir()
            (pkg_dir / "__init__.py").write_text("raise RuntimeError('init must not execute')\n")
            (pkg_dir / "sub.py").write_text("raise RuntimeError('sub must not execute')\n")
            # Pin only __init__.py; leave sub.py unpinned.
            unpinned_sub = self._fake_entry(f"{pkg}.sub", pinned_root, [f"{pkg}/__init__.py"])
            with patch.object(sys, "path", [str(pinned_root), *sys.path]):
                with self.assertRaisesRegex(runner.RunnerError, "outside its root-authorized"):
                    runner.verify_entry_module_origin(unpinned_sub)
                self.assertNotIn(pkg, sys.modules)
                self.assertNotIn(f"{pkg}.sub", sys.modules)

                # Pin both files, then plant an unpinned bytecode cache for sub.py.
                both_pinned = self._fake_entry(f"{pkg}.sub", pinned_root, [f"{pkg}/__init__.py", f"{pkg}/sub.py"])
                cache_file = Path(importlib.util.cache_from_source(str((pkg_dir / "sub.py").resolve())))
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_bytes(b"fake-pyc")
                with self.assertRaisesRegex(runner.RunnerError, "unpinned bytecode cache"):
                    runner.verify_entry_module_origin(both_pinned)
                self.assertNotIn(pkg, sys.modules)

    def test_preloaded_or_malformed_adapter_module_is_rejected(self):
        with tempfile.TemporaryDirectory() as pinned:
            entry = self._fake_entry("json", Path(pinned), [])
            with self.assertRaisesRegex(runner.RunnerError, "imported before"):
                runner.verify_entry_module_origin(entry)
            bad = self._fake_entry("os; import evil", Path(pinned), [])
            with self.assertRaisesRegex(runner.RunnerError, "invalid module reference"):
                runner.verify_entry_module_origin(bad)
            no_attr = SimpleNamespace(value="only_module", dist=SimpleNamespace())
            with self.assertRaisesRegex(runner.RunnerError, "invalid module reference"):
                runner.verify_entry_module_origin(no_attr)

    def test_loaded_module_origin_is_rechecked_after_import(self):
        with tempfile.TemporaryDirectory() as pinned:
            with self.assertRaisesRegex(runner.RunnerError, "outside its root-authorized"):
                runner.verify_loaded_module_origin("json", {Path(pinned).resolve()})

    def test_read_trusted_root_rejects_relative_path(self):
        with self.assertRaisesRegex(runner.RunnerError, "must be absolute"):
            runner.read_trusted_root(Path("relative/root.pub"))

    def test_bootstrap_schema_validation_error_fails_closed_as_runner_error(self):
        invalid_bootstrap = {key: "bad" for key in runner.BOOTSTRAP_FIELDS}
        raw = runner.customer_trust.canonical_json(invalid_bootstrap)
        with patch.object(runner, "read_file", side_effect=[raw, b"x" * 64]), \
             patch.object(runner, "read_trusted_root", return_value=b"public-root"), \
             patch.object(runner.customer_trust, "verify_signature", return_value=None):
            with self.assertRaisesRegex(runner.RunnerError, "schema validation"):
                runner.read_bootstrap(Path("bootstrap.json"), Path("bootstrap.sig"), Path("/etc/kordex/m3/root.pub"))

    def test_policy_binding_rejects_adapter_mismatch_and_any_policy_key_collision(self):
        bootstrap = {
            "customerId": "customer-1", "backendIdentity": "backend-1",
            "endpointReference": "https://trust.example.test",
            "adapterDistribution": "customer-adapter", "adapterVersion": "2.4.1",
            "adapterTreeSha256": "e" * 64,
            "attestationPublicKeyPem": "attestor-key", "attestationFingerprint": "a" * 64,
            "conformanceRootPublicKeyPem": "collector-key",
        }
        policy = {
            "customerId": "customer-1",
            "keys": [{"identity": "collector-1", "role": "collector", "fingerprint": "c" * 64}],
            "trustState": {
                "backendIdentity": "backend-1", "endpointReference": "https://trust.example.test",
                "attestorIdentity": "backend-attestor", "conformanceReviewerIdentity": "independent-reviewer",
                "adapterDistribution": "customer-adapter", "adapterVersion": "2.4.1",
                "adapterTreeSha256": "e" * 64,
            },
        }
        def authorized(document, identity, role):
            return (b"attestor-key", "a" * 64) if role == "trust-state-attestor" else (b"reviewer-key", "b" * 64)
        def fingerprint(key):
            return {b"collector-key": "c" * 64, b"unique-test-root": "f" * 64, b"qualification-root": "d" * 64}[key]
        with patch.object(runner.customer_trust, "authorized_key", side_effect=authorized), \
             patch.object(runner.customer_trust, "fingerprint", side_effect=fingerprint):
            with self.assertRaisesRegex(runner.RunnerError, "all policy keys"):
                runner._validate_policy_bindings(bootstrap, policy, b"qualification-root")
            bootstrap["conformanceRootPublicKeyPem"] = "unique-test-root"
            runner._validate_policy_bindings(bootstrap, policy, b"qualification-root")
            policy["trustState"]["adapterTreeSha256"] = "9" * 64
            with self.assertRaisesRegex(runner.RunnerError, "bootstrap adapter package"):
                runner._validate_policy_bindings(bootstrap, policy, b"qualification-root")

    def test_main_fails_closed_without_python_isolated_mode(self):
        stderr = io.StringIO()
        with patch.object(sys, "stderr", stderr):
            rc = runner.main(["--bootstrap", "b.json", "--signature", "b.sig", "--output", "out.json"])
        if not sys.flags.isolated:
            self.assertEqual(rc, 2)
            self.assertIn("isolated mode (-I)", stderr.getvalue())

    def test_run_wraps_conformance_errors_and_rejects_mismatched_result_identity(self):
        bootstrap = {
            "schemaVersion": 1, "customerId": "customer-1", "backendIdentity": "backend-1",
            "endpointReference": "https://trust.example.test", "evidenceReference": "ev-run-001",
            "runnerSourceCommit": "a" * 40, "adapterDistribution": "customer-adapter",
            "adapterVersion": "2.4.1", "adapterTreeSha256": "e" * 64,
            "attestationPublicKeyPem": "attestor-key", "attestationFingerprint": "a" * 64,
            "conformanceRootPublicKeyPem": "test-root", "trustPolicyDocument": {},
            "trustPolicySignatureHex": "00" * 64,
        }
        entry = SimpleNamespace(load=lambda: (lambda _: {
            "transportFactory": lambda ns: None, "signConformanceConfiguration": lambda doc: b"x" * 64}))
        with tempfile.TemporaryDirectory() as out_dir:
            out_path = Path(out_dir) / "report.json"
            with patch.object(runner, "read_bootstrap", return_value=(bootstrap, b"root")), \
                 patch.object(runner, "source_commit_and_cleanliness", return_value="a" * 40), \
                 patch.object(runner, "select_entry_point", return_value=entry), \
                 patch.object(runner, "verify_entry_module_origin", return_value=("mod", set())), \
                 patch.object(runner, "verify_loaded_module_origin", return_value=None), \
                 patch.object(runner.conformance, "run_conformance", side_effect=RuntimeError("backend boom")):
                with self.assertRaisesRegex(runner.RunnerError, "conformance execution failed"):
                    runner.run(Path("b.json"), Path("b.sig"), out_path)

            mismatched = {
                "backendContractChecks": "EXECUTED", "unitOrFixtureExecution": False,
                "customerAdapterConformance": "NOT ESTABLISHED", "productionTrustAccepted": False,
                "requiresIndependentReview": True, "customerId": "wrong-customer",
                "backendIdentity": "backend-1", "endpointReference": "https://trust.example.test",
                "conformanceRootFingerprint": "c" * 64,
                "conformanceReportCandidate": {
                    "customerId": "customer-1", "backendIdentity": "backend-1",
                    "endpointReference": "https://trust.example.test", "evidenceReference": "ev-run-001",
                },
            }
            with patch.object(runner, "read_bootstrap", return_value=(bootstrap, b"root")), \
                 patch.object(runner, "source_commit_and_cleanliness", return_value="a" * 40), \
                 patch.object(runner, "select_entry_point", return_value=entry), \
                 patch.object(runner, "verify_entry_module_origin", return_value=("mod", set())), \
                 patch.object(runner, "verify_loaded_module_origin", return_value=None), \
                 patch.object(runner.customer_trust, "fingerprint", return_value="c" * 64), \
                 patch.object(runner.conformance, "run_conformance", return_value=mismatched):
                with self.assertRaisesRegex(runner.RunnerError, "mismatched"):
                    runner.run(Path("b.json"), Path("b.sig"), out_path)


if __name__ == "__main__":
    unittest.main()
