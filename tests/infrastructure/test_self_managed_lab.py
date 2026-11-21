import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import self_managed_lab as lab  # noqa: E402


PROJECT = "kordex-qualification-test"


class SelfManagedLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.module = self.root / "module"
        self.module.mkdir()
        self.tfvars = self.module / "terraform.tfvars"
        self.write_tfvars()
        self.artifact_paths = {
            "artifact_binary": self.root / "k3s-fixture",
            "artifact_lock": self.root / "artifact.lock",
            "artifact_signature": self.root / "artifact.lock.sig",
            "artifact_trust": self.root / "artifact.trust",
        }
        for key, path in self.artifact_paths.items():
            path.write_bytes(("synthetic " + key).encode())
        self.module_patch = patch.object(lab, "MODULE", self.module)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.addCleanup(self.temp.cleanup)

    def write_tfvars(self, *, project=PROJECT, confirmation=PROJECT, allowed=None, mode=0o600):
        if allowed is None:
            allowed = [PROJECT]
        values = [f'project_id = "{project}"', f'project_id_confirmation = "{confirmation}"',
                  "allowed_project_ids = [" + ", ".join(f'"{value}"' for value in allowed) + "]",
                  'k3s_binary_sha256 = "' + "a" * 64 + '"',
                  'k3s_binary_mirror_url = "https://mirror.example.test/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s"']
        self.tfvars.write_text("\n".join(values) + "\n")
        self.tfvars.chmod(mode)

    def test_private_tfvars_requires_exact_project_allowlist_and_restrictive_mode(self):
        self.assertEqual(lab.private_tfvars(PROJECT), self.tfvars)
        self.write_tfvars(allowed=[PROJECT, "shared-project"])
        with self.assertRaisesRegex(lab.LabError, "exactly the reviewed"):
            lab.private_tfvars(PROJECT)
        self.write_tfvars(mode=0o644)
        with self.assertRaisesRegex(lab.LabError, "no group/other permissions"):
            lab.private_tfvars(PROJECT)
        self.tfvars.unlink()
        target = self.module / "vars-source"
        target.write_text(f'project_id = "{PROJECT}"\n')
        target.chmod(0o600)
        self.tfvars.symlink_to(target)
        with self.assertRaisesRegex(lab.LabError, "regular file"):
            lab.private_tfvars(PROJECT)
        with self.assertRaisesRegex(lab.LabError, "permanently prohibited"):
            lab.validate_project_id("kordex-fleet-platform")

    def test_artifact_tfvars_reject_duplicates_and_malformed_values(self):
        digest = "a" * 64
        mirror = "https://mirror.example.test/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s"
        parsed = lab.terraform_artifact_values(f'k3s_binary_sha256 = "{digest}"\nk3s_binary_mirror_url = "{mirror}"\n')
        self.assertEqual(parsed, (digest, mirror))
        with self.assertRaisesRegex(lab.LabError, "exactly once"):
            lab.terraform_artifact_values(f'k3s_binary_sha256 = "{digest}"\nk3s_binary_sha256 = "{"b" * 64}"\nk3s_binary_mirror_url = "{mirror}"\n')
        with self.assertRaisesRegex(lab.LabError, "malformed"):
            lab.terraform_artifact_values(f'k3s_binary_sha256 = "short"\nk3s_binary_mirror_url = "{mirror}"\n')
        nonstandard_port = mirror.replace("https://mirror.example.test", "https://mirror.example.test:8443")
        with self.assertRaisesRegex(lab.LabError, "malformed"):
            lab.terraform_artifact_values(
                f'k3s_binary_sha256 = "{digest}"\nk3s_binary_mirror_url = "{nonstandard_port}"\n'
            )

    def test_approval_verifier_receives_exact_terraform_digest_and_mirror(self):
        calls = []
        snapshots = {}

        def run(args, **kwargs):
            calls.append((args, kwargs))
            for option, key in (("--lock", "artifact_lock"), ("--signature", "artifact_signature"),
                                ("--trust-bundle", "artifact_trust")):
                snapshot = Path(args[args.index(option) + 1])
                snapshots[key] = (snapshot.read_bytes(), snapshot.stat().st_mode & 0o777,
                                  snapshot.parent.stat().st_mode & 0o777)
            return "Verified synthetic fixture\n"

        digest = "a" * 64
        mirror = "https://mirror.example.test/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s"
        fingerprints = lab.verify_customer_artifact(
            self.artifact_paths["artifact_binary"], self.artifact_paths["artifact_lock"],
            self.artifact_paths["artifact_signature"], self.artifact_paths["artifact_trust"],
            digest, mirror, run=run)
        self.assertEqual(set(fingerprints), {"lock", "signature", "trust"})
        args, kwargs = calls[0]
        self.assertIn("--expected-digest", args)
        self.assertEqual(args[args.index("--expected-digest") + 1], digest)
        self.assertEqual(args[args.index("--expected-mirror-url") + 1], mirror)
        for key, (content, mode, directory_mode) in snapshots.items():
            self.assertEqual(content, self.artifact_paths[key].read_bytes())
            self.assertEqual(mode, 0o600)
            self.assertEqual(directory_mode, 0o700)
            self.assertNotEqual(Path(args[args.index({"artifact_lock": "--lock", "artifact_signature": "--signature", "artifact_trust": "--trust-bundle"}[key]) + 1]), self.artifact_paths[key])
        self.assertEqual(kwargs["cwd"], lab.ROOT / "api")
        self.assertTrue(kwargs["capture"])

    def test_plan_passes_only_lock_bound_artifact_inputs_to_terraform(self):
        calls = []

        def run(args, **kwargs):
            calls.append((args, kwargs))
            return ""

        approval = {"lock": "l", "signature": "s", "trust": "t"}
        with patch.object(lab, "terraform_init"), patch.object(lab, "verify_customer_artifact", return_value=approval), patch.object(lab, "require_approval_unchanged"):
            lab.terraform_plan(PROJECT, **self.artifact_paths, run=run)
        plan_args, kwargs = calls[-1]
        self.assertEqual(plan_args[1], "plan")
        self.assertIn("-var=k3s_binary_sha256=" + "a" * 64, plan_args)
        self.assertIn("-var=k3s_binary_mirror_url=https://mirror.example.test/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s", plan_args)
        self.assertNotIn("TF_CLI_ARGS_plan", kwargs["env"])
        self.assertFalse(any(name.startswith("TF_VAR_") for name in kwargs["env"]))

    def test_apply_stops_if_verified_lock_is_replaced_after_preflight(self):
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            return ""

        def confirm(_phrase):
            self.artifact_paths["artifact_lock"].write_text("substituted lock\n")

        def verify(*args, **_kwargs):
            return lab.artifact_approval_fingerprints(
                self.artifact_paths["artifact_lock"], self.artifact_paths["artifact_signature"],
                self.artifact_paths["artifact_trust"])

        with patch.object(lab, "terraform_init"), patch.object(lab, "verify_customer_artifact", side_effect=verify), \
                self.assertRaisesRegex(lab.LabError, "changed after preflight"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, run=run, confirm=confirm,
                                verify_project=lambda _project_id, **_kwargs: None)
        self.assertTrue(any(args[1] == "plan" for args in calls))
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_automatic_tfvars_are_rejected(self):
        (self.module / "override.auto.tfvars").write_text('k3s_binary_sha256 = "' + "b" * 64 + '"\n')
        with self.assertRaisesRegex(lab.LabError, "automatic Terraform variable file"):
            lab.reject_auto_tfvars()

    def test_validate_formats_tracked_and_unignored_tf_sources_not_ignored_tfvars(self):
        repository = self.root / "checkout"
        module = repository / "infrastructure/terraform/gcp/self-managed-lab"
        module.mkdir(parents=True)
        subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
        (repository / ".gitignore").write_text("**/terraform.tfvars\n")
        tracked_source = module / "main.tf"
        tracked_source.write_text('terraform {\n required_version = ">= 1.0"\n}\n')
        untracked_source = module / "additional.tf"
        untracked_source.write_text('variable "x" { type = string }\n')
        ignored_tfvars = module / "terraform.tfvars"
        ignored_tfvars.write_text("SENSITIVE_SENTINEL = \"must not be read or printed\"\n")
        ignored_tfvars.chmod(0o600)
        subprocess.run(
            ["git", "-C", str(repository), "add", ".gitignore", str(tracked_source)],
            check=True,
        )

        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            if args[:3] == ["git", "ls-files", "--cached"]:
                return lab.run_command(args, **kwargs)
            return ""

        before = ignored_tfvars.stat()
        with patch.object(lab, "ROOT", repository), patch.object(lab, "MODULE", module):
            lab.terraform_validate(run=fake_run)
        after = ignored_tfvars.stat()

        fmt_args = next(args for args, _ in calls if args[:2] == ["terraform", "fmt"])
        self.assertEqual(fmt_args[:3], ["terraform", "fmt", "-check"])
        self.assertIn("main.tf", fmt_args)
        self.assertIn("additional.tf", fmt_args)
        self.assertFalse(any("terraform.tfvars" in arg for arg in fmt_args))
        self.assertNotIn("-recursive", fmt_args)
        self.assertTrue(any(args[:2] == ["terraform", "init"] and "-backend=false" in args
                            and "-lockfile=readonly" in args for args, _ in calls))
        self.assertTrue(any(args == ["terraform", "validate"] for args, _ in calls))
        self.assertEqual(before.st_mode, after.st_mode)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)

    def test_validate_fails_if_no_terraform_source_is_discovered(self):
        repository = self.root / "empty-checkout"
        module = repository / "infrastructure/terraform/gcp/self-managed-lab"
        module.mkdir(parents=True)
        subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
        (module / "terraform.tfvars").write_text("ignored = true\n")
        with patch.object(lab, "ROOT", repository), patch.object(lab, "MODULE", module):
            with self.assertRaisesRegex(lab.LabError, "no tracked or non-ignored Terraform source"):
                lab.terraform_source_files()

    def test_validate_reports_format_failure_and_does_not_continue_to_init(self):
        repository = self.root / "format-checkout"
        module = repository / "infrastructure/terraform/gcp/self-managed-lab"
        module.mkdir(parents=True)
        subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
        source = module / "main.tf"
        source.write_text('variable "x" { type = string }\n')
        subprocess.run(["git", "-C", str(repository), "add", str(source)], check=True)
        commands = []

        def fake_run(args, **kwargs):
            if args[:3] == ["git", "ls-files", "--cached"]:
                return lab.run_command(args, **kwargs)
            commands.append(args)
            if args[:2] == ["terraform", "fmt"]:
                raise lab.LabError("terraform fmt returned non-zero")
            return ""

        with patch.object(lab, "ROOT", repository), patch.object(lab, "MODULE", module):
            with self.assertRaisesRegex(lab.LabError, "source formatting check failed"):
                lab.terraform_validate(run=fake_run)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][:3], ["terraform", "fmt", "-check"])

    def test_apply_never_reaches_mutation_without_exact_post_plan_confirmation(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return ""

        def reject_confirmation(_):
            raise lab.LabError("confirmation did not match; no Terraform apply was run")

        with patch.object(lab, "terraform_init"), patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), patch.object(lab, "require_approval_unchanged"), self.assertRaisesRegex(lab.LabError, "no Terraform apply"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, run=run, confirm=reject_confirmation)
        self.assertTrue(any(args[1] == "plan" and any(arg.startswith("-out=") for arg in args) for args in calls))
        self.assertTrue(any(args[1] == "show" for args in calls))
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_apply_uses_saved_reviewed_plan_after_exact_confirmation(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return ""

        confirmations = []
        with patch.object(lab, "terraform_init"), patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), patch.object(lab, "require_approval_unchanged"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, run=run, confirm=confirmations.append,
                                verify_project=lambda _project_id, **_kwargs: None)
        self.assertEqual(confirmations, [f"APPLY {PROJECT}"])
        apply_call = next(args for args in calls if args[1] == "apply")
        plan_call = next(args for args in calls if args[1] == "plan")
        self.assertIn(next(arg.removeprefix("-out=") for arg in plan_call if arg.startswith("-out=")), apply_call)

    def test_destroy_refuses_state_from_another_project_before_destroy_plan(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return "another-project\n" if args[1:3] == ["output", "-raw"] else ""

        with patch.object(lab, "terraform_init"), self.assertRaisesRegex(lab.LabError, "state project_id"):
            lab.terraform_destroy(PROJECT, run=run)
        self.assertFalse(any(args[1] == "plan" for args in calls))

    def test_destroy_confirmation_is_exact_and_no_automatic_cleanup_is_requested(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return f"{PROJECT}\n" if args[1:3] == ["output", "-raw"] else ""

        confirmations = []
        with patch.object(lab, "terraform_init"):
            lab.terraform_destroy(PROJECT, run=run, confirm=confirmations.append,
                                  verify_project=lambda _project_id, **_kwargs: None)
        self.assertEqual(confirmations, [f"DESTROY {PROJECT}"])
        self.assertTrue(any(args[1] == "plan" and "-destroy" in args for args in calls))
        self.assertTrue(any(args[1] == "apply" for args in calls))
        self.assertFalse(any(args[1] == "destroy" for args in calls))

    def test_destroy_does_not_apply_after_wrong_confirmation(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return f"{PROJECT}\n" if args[1:3] == ["output", "-raw"] else ""

        def reject_confirmation(_):
            raise lab.LabError("confirmation did not match; no Terraform apply was run")

        with patch.object(lab, "terraform_init"), self.assertRaisesRegex(lab.LabError, "no Terraform apply"):
            lab.terraform_destroy(PROJECT, run=run, confirm=reject_confirmation)
        self.assertTrue(any(args[1] == "plan" and "-destroy" in args for args in calls))
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_destroy_rechecks_live_designation_and_stops_if_it_was_revoked(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return f"{PROJECT}\n" if args[1:3] == ["output", "-raw"] else ""

        def revoked(project_id, **_kwargs):
            self.assertEqual(project_id, PROJECT)
            raise lab.LabError("live disposable label is missing")

        with patch.object(lab, "terraform_init"), self.assertRaisesRegex(lab.LabError, "label is missing"):
            lab.terraform_destroy(PROJECT, run=run, confirm=lambda _phrase: None, verify_project=revoked)
        self.assertTrue(any(args[1] == "plan" and "-destroy" in args for args in calls))
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_confirmation_requires_interactive_exact_phrase(self):
        class NonTerminal:
            def isatty(self):
                return False

        with patch.object(lab.sys, "stdin", NonTerminal()):
            with self.assertRaisesRegex(lab.LabError, "interactive terminal"):
                lab.ask_confirmation("DESTROY " + PROJECT)
        with patch.object(lab.sys, "stdin", type("Terminal", (), {"isatty": lambda self: True})()):
            with self.assertRaisesRegex(lab.LabError, "did not match"):
                lab.ask_confirmation("DESTROY " + PROJECT, input_fn=lambda _: "yes")

    def test_execute_requires_the_runner_disposable_confirmation(self):
        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": "other-target"}):
            with self.assertRaisesRegex(lab.LabError, "must exactly equal"):
                lab.runner_command(True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT)

    def test_execute_requires_correct_cancellation_phase_and_positive_timeout(self):
        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": PROJECT}):
            with self.assertRaisesRegex(lab.LabError, "requires --cancel-on-phase Draining"):
                lab.runner_command(True, self.root / "case.json", "cancel-before-apply",
                                   target_confirmation=PROJECT, run=lambda *_args, **_kwargs: "")
            with self.assertRaisesRegex(lab.LabError, "must be positive"):
                lab.runner_command(True, self.root / "case.json", "clean-upgrade", timeout=0,
                                   target_confirmation=PROJECT, run=lambda *_args, **_kwargs: "")
            calls = []
            lab.runner_command(True, self.root / "case.json", "cancel-before-apply",
                               cancel_phase="Draining", target_confirmation=PROJECT,
                               run=lambda args, **_kwargs: calls.append(args),
                               project_id=PROJECT,
                               confirm_project=lambda _expected: None,
                               verify_project=lambda _project_id, **_kwargs: None)
        cancel_index = calls[0].index("--cancel-on-phase")
        self.assertEqual(calls[0][cancel_index + 1], "Draining")

    def test_project_designation_is_verified_from_live_gcloud_metadata(self):
        calls = []

        def describe(args, **_):
            calls.append(args)
            return json.dumps({
                "projectId": PROJECT,
                "projectNumber": "1234567890",
                "lifecycleState": "ACTIVE",
                "labels": {"kordex-disposable": "qualification"},
            })

        lab.verify_disposable_project(PROJECT, run=describe)
        self.assertEqual(calls[0][0:3], ["gcloud", "projects", "describe"])
        self.assertIn(PROJECT, calls[0])
        self.assertIn(f"--project={PROJECT}", calls[0])
        self.assertIn("--format=json(projectId,projectNumber,lifecycleState,labels)", calls[0])

    def test_project_designation_rejects_identity_state_and_label_mismatch(self):
        invalid_responses = [
            ({"projectId": "another-project", "projectNumber": "123", "lifecycleState": "ACTIVE",
              "labels": {"kordex-disposable": "qualification"}}, "identity"),
            ({"projectId": PROJECT, "projectNumber": "123", "lifecycleState": "DELETE_REQUESTED",
              "labels": {"kordex-disposable": "qualification"}}, "not ACTIVE"),
            ({"projectId": PROJECT, "projectNumber": "123", "lifecycleState": "ACTIVE",
              "labels": {"kordex-disposable": "shared"}}, "missing label"),
            ({"projectId": PROJECT, "projectNumber": "123", "lifecycleState": "ACTIVE",
              "labels": []}, "missing label"),
        ]
        for response, reason in invalid_responses:
            with self.subTest(reason=reason), self.assertRaisesRegex(lab.LabError, reason):
                lab.verify_disposable_project(PROJECT, run=lambda *_args, **_kwargs: json.dumps(response))

    def test_apply_rechecks_live_disposable_designation_after_confirmation(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return ""

        def verify(project_id, **_kwargs):
            self.assertEqual(project_id, PROJECT)
            calls.append(["verify-disposable-project"])

        with patch.object(lab, "terraform_init"), patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), patch.object(lab, "require_approval_unchanged"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, run=run, confirm=lambda _phrase: None, verify_project=verify)
        apply_index = next(index for index, args in enumerate(calls) if args[1:2] == ["apply"])
        verify_index = next(index for index, args in enumerate(calls) if args[0] == "verify-disposable-project")
        self.assertLess(verify_index, apply_index)

    def test_execute_requires_live_project_check_and_second_confirmation(self):
        events = []
        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": PROJECT}):
            lab.runner_command(
                True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT,
                project_id=PROJECT,
                verify_project=lambda project_id, **_kwargs: events.append(("verify", project_id)),
                confirm_project=lambda expected: events.append(("confirm", expected)),
                run=lambda args, **_kwargs: events.append(("runner", args)),
            )
        self.assertEqual(events[0], ("verify", PROJECT))
        self.assertEqual(events[1], ("confirm", f"EXECUTE IN DISPOSABLE PROJECT {PROJECT}"))
        self.assertEqual(events[2][0], "runner")

    def test_execute_never_launches_runner_when_live_project_check_fails(self):
        def revoked(*_args, **_kwargs):
            raise lab.LabError("disposable label was revoked")

        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": PROJECT}):
            with self.assertRaisesRegex(lab.LabError, "label was revoked"):
                lab.runner_command(
                    True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT,
                    project_id=PROJECT,
                    verify_project=revoked,
                    confirm_project=lambda _expected: None,
                    run=lambda *_args, **_kwargs: self.fail("runner must not launch"),
                )

    def test_execute_cli_requires_a_project_id(self):
        with self.assertRaises(SystemExit):
            lab.parser().parse_args([
                "execute", "--target-confirmation", PROJECT,
                "--qualification-case", "clean-upgrade", "--evidence", "case.json",
            ])

    def test_wrapper_case_allowlist_matches_qualification_runner_cli(self):
        result = subprocess.run([sys.executable, str(lab.RUNNER), "--help"], check=True,
                                capture_output=True, text=True)
        for case in lab.CASES:
            self.assertIn(case, result.stdout)
        for phase in lab.PHASES:
            self.assertIn(phase, result.stdout)

    def test_diagnostics_check_exact_context_and_redact_log_credentials(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return "wrong-context\n"

        out = self.root / "diagnostics"
        with patch.dict(os.environ, {"KORDEX_EXPECTED_CONTEXT": "disposable"}):
            with self.assertRaisesRegex(lab.LabError, "context mismatch"):
                lab.collect_diagnostics(out, run=run)
        self.assertFalse(out.exists())
        self.assertEqual(len(calls), 1)
        sample = 'Authorization: Bearer abc123 {"token":"secret-value","password":"hidden"}'
        for pattern, replacement in lab.LOG_REDACTIONS:
            sample = pattern.sub(replacement, sample)
        self.assertNotIn("abc123", sample)
        self.assertNotIn("secret-value", sample)
        self.assertNotIn("hidden", sample)

    def test_diagnostics_keep_restricted_partial_and_complete_outputs(self):
        output = self.root / "diagnostics"

        def collect(args, **_):
            if args[1:] == ["config", "current-context"]:
                return "disposable-context\n"
            if "logs" in args:
                return 'Authorization: Bearer opaque {"token":"private-value"}\n'
            return "read-only diagnostic\n"

        with patch.dict(os.environ, {"KORDEX_EXPECTED_CONTEXT": "disposable-context"}):
            lab.collect_diagnostics(output, run=collect)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        for name in ("nodes.txt", "pods.txt", "pdbs.txt", "events.txt", "maintenance-resources.yaml",
                     "operator.log", "agent.log", "collection-manifest.json"):
            path = output / name
            self.assertTrue(path.is_file(), name)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("opaque", (output / "operator.log").read_text())
        self.assertNotIn("private-value", (output / "agent.log").read_text())

    def test_diagnostics_retain_partial_files_after_command_failure(self):
        output = self.root / "partial-diagnostics"
        count = 0

        def collect(args, **_):
            nonlocal count
            count += 1
            if args[1:] == ["config", "current-context"]:
                return "disposable-context\n"
            if args[1:3] == ["get", "nodes"]:
                return "node/worker Ready\n"
            raise lab.LabError("simulated API failure")

        with patch.dict(os.environ, {"KORDEX_EXPECTED_CONTEXT": "disposable-context"}):
            with self.assertRaisesRegex(lab.LabError, "partial evidence was kept"):
                lab.collect_diagnostics(output, run=collect)
        self.assertTrue((output / "nodes.txt").is_file())
        self.assertTrue((output / "collection-manifest.json").is_file())
        self.assertTrue((output / "pods.txt").is_file())
        self.assertIn("simulated API failure", (output / "pods.txt").read_text())
        manifest = json.loads((output / "collection-manifest.json").read_text())
        self.assertEqual(manifest["artifacts"][-1]["exitCode"], 1)

    def test_command_timeout_is_reported_as_a_fail_closed_error(self):
        with patch.object(lab.subprocess, "run", side_effect=lab.subprocess.TimeoutExpired("kubectl", 20)):
            with self.assertRaisesRegex(lab.LabError, "command timed out: kubectl"):
                lab.run_command(["kubectl", "get", "nodes"], capture=True, timeout=20)

    def test_archive_writes_hash_manifest_and_refuses_secret_named_inputs(self):
        source = self.root / "evidence"
        source.mkdir()
        (source / "clean-upgrade.json").write_text('{"result":"recorded"}\n')
        archive = self.root / "off-cluster" / "qualification.tar.gz"
        paths = lab.archive_evidence(source, archive)
        self.assertEqual(paths, (archive, Path(str(archive) + ".sha256"), Path(str(archive) + ".manifest.json")))
        with tarfile.open(archive, "r:gz") as bundle:
            self.assertIn("qualification-manifest.json", bundle.getnames())
            self.assertIn("clean-upgrade.json", bundle.getnames())
        manifest = json.loads(paths[2].read_text())
        self.assertEqual(manifest["archiveSHA256"], lab.sha256_file(archive))
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        (source / "terraform.tfstate.backup").write_text("secret state")
        with self.assertRaisesRegex(lab.LabError, "secret-bearing"):
            lab.archive_evidence(source, self.root / "off-cluster" / "another.tar.gz")

    def test_archive_rejects_destination_reached_through_source_directory_symlink(self):
        source = self.root / "evidence"
        source.mkdir()
        (source / "clean-upgrade.json").write_text('{"result":"recorded"}\n')
        alias = self.root / "evidence-alias"
        alias.symlink_to(source, target_is_directory=True)
        with self.assertRaisesRegex(lab.LabError, "outside the evidence source"):
            lab.archive_evidence(source, alias / "inside.tar.gz")


if __name__ == "__main__":
    unittest.main()
