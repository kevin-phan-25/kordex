import hashlib
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
import self_managed_lab_recovery as recovery  # noqa: E402


PROJECT = "kordex-qualification-test"


def system_image_inventory():
    return [
        {"SourceReference": f"docker.io/rancher/test-{index}:v1", "MirrorReference": f"registry.example.test/rancher/test-{index}:v1",
         "Digest": "sha256:" + f"{index:064x}"}
        for index in range(8)
    ]


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
        self.system_image_paths = {
            "system_images_bundle": self.root / "system-images.tar",
            "system_images_lock": self.root / "system-images.lock",
            "system_images_signature": self.root / "system-images.lock.sig",
            "system_images_trust": self.root / "system-images.trust",
        }
        for key, path in self.system_image_paths.items():
            path.write_bytes(("synthetic " + key).encode())
        self.readiness_paths = {}
        for name in ("readiness", "terraform-inputs", "network-inputs", "artifact-inputs", "artifact-report",
                     "principal-attestation", "image-approval"):
            path = self.root / f"{name}.json"
            path.write_text("{}", encoding="utf-8")
            self.readiness_paths[name] = path
        self.plan_args = {
            "readiness_report_path": self.readiness_paths["readiness"],
            "terraform_inputs_path": self.readiness_paths["terraform-inputs"],
            "network_inputs_path": self.readiness_paths["network-inputs"],
            "artifact_inputs_path": self.readiness_paths["artifact-inputs"],
            "artifact_report_path": self.readiness_paths["artifact-report"],
            "principal_attestation_path": self.readiness_paths["principal-attestation"],
            "image_approval_path": self.readiness_paths["image-approval"],
        }
        self.fake_plan_values = {"project_id": PROJECT, "k3s_binary_sha256": "a" * 64,
                                 "k3s_binary_mirror_url": "https://mirror.example.test/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s",
                                 "qualification_os_profile": "ubuntu-24.04", "qualification_os_minor": "",
                                 "qualification_os_point_release": "", "os_family": "debian",
                                 "k3s_system_images_manifest_version": "1",
                                 "k3s_system_images_k3s_version": "v1.36.6+k3s1",
                                 "k3s_system_images_architecture": "linux/amd64",
                                 "k3s_system_images_bundle_sha256": "b" * 64,
                                 "k3s_system_images_bundle_mirror_url": "https://mirror.example.test/k3s/v1.36.6+k3s1/linux-amd64/" + "b" * 64 + "/k3s-airgap-images-amd64.tar",
                                 "k3s_system_images_mirror_host": "registry.example.test",
                                 "terraform_principal_email": "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"}
        self.credential_env_patch = patch.dict(os.environ, {
            "GOOGLE_APPLICATION_CREDENTIALS": "/synthetic-only/credential-config.json",
        }, clear=False)
        self.credential_env_patch.start()
        self.addCleanup(self.credential_env_patch.stop)
        self.gcloud_context_patch = patch.object(lab.terraform_context.m3_gcloud_context, "describe",
            return_value={"executablePath": "/usr/bin/gcloud", "executableSha256": "a" * 64,
                          "version": "1.2.3", "configurationDirectory": "/etc/kordex/gcloud",
                          "configurationName": "kordex-m3", "homePath": "/nonexistent",
                          "environmentPolicy": "fixed-gcloud-system-path-and-dedicated-config"})
        self.gcloud_context_patch.start()
        self.addCleanup(self.gcloud_context_patch.stop)
        self.gcloud_command_patch = patch.object(lab.gcloud_context, "command", side_effect=lambda args: (
            ["/usr/bin/gcloud", *args], {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                "CLOUDSDK_CONFIG": "/etc/kordex/gcloud", "CLOUDSDK_ACTIVE_CONFIG_NAME": "kordex-m3",
                "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}, {"executablePath": "/usr/bin/gcloud"}))
        self.gcloud_command_patch.start()
        self.addCleanup(self.gcloud_command_patch.stop)
        self.operation_context_patch = patch.object(lab, "_bound_operation_context",
            return_value=({"terraformVersion": "1.9.0", "providerPrincipal": "fixture"}, "f" * 64))
        self.operation_context_patch.start()
        self.addCleanup(self.operation_context_patch.stop)
        self.readiness_binding_patch = patch.object(lab, "verify_readiness_plan_binding", return_value=(
            self.fake_plan_values, lab.readiness_binding.canonical_sha256(self.fake_plan_values)))
        self.readiness_binding_patch.start()
        self.addCleanup(self.readiness_binding_patch.stop)
        self.system_images_patch = patch.object(
            lab, "verify_customer_system_images", side_effect=self.fake_system_images_verification
        )
        self.system_images_patch.start()
        self.addCleanup(self.system_images_patch.stop)
        self.image_approval_patch = patch.object(
            lab.readiness_binding, "validate_image_approval",
            return_value=({"imageUniqueId": "1234567890123456789"}, "f" * 64))
        self.image_approval_patch.start()
        self.addCleanup(self.image_approval_patch.stop)
        self.live_image_patch = patch.object(lab, "verify_live_image_identity")
        self.live_image_patch.start()
        self.addCleanup(self.live_image_patch.stop)
        self.module_patch = patch.object(lab, "MODULE", self.module)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.addCleanup(self.temp.cleanup)

    def write_tfvars(self, *, project=PROJECT, confirmation=PROJECT, allowed=None, mode=0o600):
        if allowed is None:
            allowed = [PROJECT]
        values = [f'project_id = "{project}"', f'project_id_confirmation = "{confirmation}"',
                  "allowed_project_ids = [" + ", ".join(f'"{value}"' for value in allowed) + "]",
                  'terraform_principal_email = "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"',
                  'k3s_binary_sha256 = "' + "a" * 64 + '"',
                  'k3s_binary_mirror_url = "https://mirror.example.test/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s"']
        self.tfvars.write_text("\n".join(values) + "\n")
        self.tfvars.chmod(mode)

    def fake_system_images_verification(self, bundle, lock, signature, trust, run=lab.run_command):
        self.assertEqual((bundle, lock, signature, trust), tuple(self.system_image_paths.values()))
        return ({
            "manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1", "architecture": "linux/amd64",
            "bundleSha256": "b" * 64,
            "bundleMirrorReference": "https://mirror.example.test/k3s/v1.36.6+k3s1/linux-amd64/" + "b" * 64 + "/k3s-airgap-images-amd64.tar",
            "mirrorHost": "registry.example.test", "signerKeyId": "a" * 64, "approvedAt": "2026-11-21T12:00:00Z", "images": system_image_inventory(),
        }, lab.system_images_approval_fingerprints(*self.system_image_paths.values()))

    def terraform_state_output(self, name):
        values = {
            "project_id": PROJECT,
            "qualification_os_profile": "debian-13",
            "qualification_os_minor": "",
            "qualification_os_point_release": "13.8",
            "k3s_system_images_manifest_version": "1",
            "k3s_system_images_k3s_version": "v1.36.6+k3s1",
            "k3s_system_images_architecture": "linux/amd64",
            "k3s_system_images_bundle_sha256": "b" * 64,
            "k3s_system_images_bundle_mirror_url": "https://mirror.example.test/k3s/v1.36.6+k3s1/linux-amd64/" + "b" * 64 + "/k3s-airgap-images-amd64.tar",
            "k3s_system_images_mirror_host": "registry.example.test",
        }
        return values[name] + "\n"

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
        self.assertEqual((kwargs["env"]["GOPROXY"], kwargs["env"]["GOSUMDB"], kwargs["env"]["GOTOOLCHAIN"]),
                         ("off", "off", "local"))

    def test_system_image_verifier_uses_private_snapshots_and_returns_lock_bound_values(self):
        self.system_images_patch.stop()
        calls = []
        result = {
            "manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1", "architecture": "linux/amd64",
            "bundleSha256": "b" * 64,
            "bundleMirrorReference": "https://mirror.example.test/k3s/v1.36.6+k3s1/linux-amd64/" + "b" * 64 + "/k3s-airgap-images-amd64.tar",
            "mirrorHost": "registry.example.test", "signerKeyId": "a" * 64, "approvedAt": "2026-11-21T12:00:00Z", "images": system_image_inventory(),
        }

        def run(args, **kwargs):
            calls.append((args, kwargs))
            for option, path in (("--bundle", "system_images_bundle"), ("--lock", "system_images_lock"),
                                 ("--signature", "system_images_signature"), ("--trust-bundle", "system_images_trust")):
                snapshot = Path(args[args.index(option) + 1])
                self.assertEqual(snapshot.read_bytes(), self.system_image_paths[path].read_bytes())
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                self.assertEqual(snapshot.parent.stat().st_mode & 0o777, 0o700)
                self.assertNotEqual(snapshot, self.system_image_paths[path])
            return json.dumps(result)

        verified, fingerprints = lab.verify_customer_system_images(*self.system_image_paths.values(), run=run)
        self.assertEqual(verified, result)
        self.assertEqual(set(fingerprints), {"bundle", "lock", "signature", "trust"})
        args, kwargs = calls[0]
        self.assertIn("system-images", args)
        self.assertIn("verify", args)
        self.assertIn("--json", args)
        self.assertEqual(kwargs["cwd"], lab.ROOT / "api")
        self.assertTrue(kwargs["capture"])
        self.assertEqual((kwargs["env"]["GOPROXY"], kwargs["env"]["GOSUMDB"], kwargs["env"]["GOTOOLCHAIN"]),
                         ("off", "off", "local"))

    def test_system_image_verifier_rejects_unsupported_version_and_bad_result(self):
        self.system_images_patch.stop()
        valid = {
            "manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1", "architecture": "linux/amd64",
            "bundleSha256": "b" * 64,
            "bundleMirrorReference": "https://mirror.example.test/k3s/v1.36.6+k3s1/linux-amd64/" + "b" * 64 + "/k3s-airgap-images-amd64.tar",
            "mirrorHost": "registry.example.test", "signerKeyId": "a" * 64, "approvedAt": "2026-11-21T12:00:00Z", "images": system_image_inventory(),
        }
        wrong = dict(valid, architecture="linux/arm64")
        with self.assertRaisesRegex(lab.LabError, "unsupported"):
            lab.verify_customer_system_images(*self.system_image_paths.values(), run=lambda *_args, **_kwargs: json.dumps(wrong))
        malformed = dict(valid, bundleSha256="not-a-digest")
        with self.assertRaisesRegex(lab.LabError, "digest is malformed"):
            lab.verify_customer_system_images(*self.system_image_paths.values(), run=lambda *_args, **_kwargs: json.dumps(malformed))
        unbound_url = dict(valid, bundleMirrorReference="https://mirror.example.test/k3s/images.tar")
        with self.assertRaisesRegex(lab.LabError, "not bound to its content-addressed"):
            lab.verify_customer_system_images(*self.system_image_paths.values(), run=lambda *_args, **_kwargs: json.dumps(unbound_url))

    def test_recovery_terraform_inputs_are_mode_restricted_and_bound_to_all_roles(self):
        state = lab.recovery_vars_file()
        snapshots = {role: f"{recovery.LAB_ID}-{role}-snap-" + "a" * 12
                     for role in recovery.NODE_ROLES}
        addresses = {"server": "10.76.0.10", "worker-1": "10.76.0.11", "worker-2": "10.76.0.12"}
        with self.assertRaisesRegex(lab.LabError, "exact three-node lab"):
            lab.write_recovery_vars(state, recovery.PROJECT_ID, "kordex-lab", "us-east1-b", snapshots, addresses, "b" * 12)
        lab.write_recovery_vars(state, recovery.PROJECT_ID, recovery.LAB_ID, "us-east1-b", snapshots, addresses, "b" * 12)
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(lab.recovery_var_args(), [f"-var-file={state}"])
        values = json.loads(state.read_text())
        values["recovery_lab_id"] = "kordex-lab"
        state.write_text(json.dumps(values))
        state.chmod(0o600)
        with self.assertRaisesRegex(lab.LabError, "exact supported variables|fail closed"):
            lab.recovery_var_args()

    def test_restore_requires_reviewed_plan_and_persists_exact_snapshot_inputs(self):
        restore_project = recovery.PROJECT_ID
        self.write_tfvars(project=restore_project, confirmation=restore_project, allowed=[restore_project])
        outputs = {
            "project_id": restore_project, "lab_id": recovery.LAB_ID, "zone": "us-east1-b",
            "qualification_os_profile": "debian-13",
            "qualification_os_minor": "",
            "qualification_os_point_release": "13.8",
            "k3s_system_images_manifest_version": "1", "k3s_system_images_k3s_version": "v1.36.6+k3s1",
            "k3s_system_images_architecture": "linux/amd64", "k3s_system_images_bundle_sha256": "b" * 64,
            "k3s_system_images_bundle_mirror_url": "https://mirror.example.test/k3s/v1.36.6+k3s1/linux-amd64/" + "b" * 64 + "/k3s-airgap-images-amd64.tar",
            "k3s_system_images_mirror_host": "registry.example.test",
        }
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            if args[:2] == ["terraform", "output"]:
                return outputs[args[-1]] + "\n"
            return "reviewed plan output\n"

        snapshots = {role: f"{recovery.LAB_ID}-{role}-snap-" + "a" * 12
                     for role in recovery.NODE_ROLES}
        addresses = {"server": "10.76.0.10", "worker-1": "10.76.0.11", "worker-2": "10.76.0.12"}
        with patch.object(lab, "terraform_init"):
            lab.terraform_restore_apply(restore_project, recovery.LAB_ID, "us-east1-b", snapshots, addresses, "c" * 12,
                run=run, confirm=lambda phrase: self.assertEqual(phrase,
                    f"RESTORE-APPLY {restore_project}/{recovery.LAB_ID}/" + "c" * 12 +
                    " PLAN-SHA256 " + hashlib.sha256(b"").hexdigest()),
                verify_project=lambda _project, **_kwargs: None)
        restore_plans = [args for args in calls if args[1] == "plan" and
                         any("restore.tfvars.json" in arg for arg in args)]
        self.assertEqual(len(restore_plans), 1)
        self.assertIn("-var=qualification_os_profile=debian-13", restore_plans[0])
        self.assertTrue(any(args[1] == "show" for args in calls))
        self.assertTrue(any(args[1] == "apply" for args in calls))
        active = lab.recovery_vars_file()
        self.assertEqual(active.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(active.read_text())["recovery_project_id"], restore_project)

    def test_restore_refuses_saved_plan_changed_after_confirmation(self):
        self.write_tfvars(project=recovery.PROJECT_ID, confirmation=recovery.PROJECT_ID,
                          allowed=[recovery.PROJECT_ID])
        outputs = {"project_id": recovery.PROJECT_ID, "lab_id": recovery.LAB_ID, "zone": "us-east1-b",
            "qualification_os_profile": "debian-13", "qualification_os_minor": "",
            "qualification_os_point_release": "13.8", "k3s_system_images_manifest_version": "1",
            "k3s_system_images_k3s_version": "v1.36.6+k3s1", "k3s_system_images_architecture": "linux/amd64",
            "k3s_system_images_bundle_sha256": "b" * 64,
            "k3s_system_images_bundle_mirror_url": "https://mirror.example.test/k3s/v1.36.6+k3s1/linux-amd64/" + "b" * 64 + "/k3s-airgap-images-amd64.tar",
            "k3s_system_images_mirror_host": "registry.example.test"}
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            if args[:2] == ["terraform", "output"]:
                return outputs[args[-1]] + "\n"
            if args[1] == "plan":
                plan = Path(next(arg.removeprefix("-out=") for arg in args if arg.startswith("-out=")))
                plan.write_bytes(b"reviewed restore plan")
            return ""

        def drift_after_confirmation(_project, **_kwargs):
            plan = next(Path(args[2]) for args in calls if args[1] == "show")
            plan.write_bytes(b"substituted restore plan")

        snapshots = {role: f"{recovery.LAB_ID}-{role}-snap-" + "a" * 12 for role in recovery.NODE_ROLES}
        addresses = {"server": "10.76.0.10", "worker-1": "10.76.0.11", "worker-2": "10.76.0.12"}
        with patch.object(lab, "terraform_init"), self.assertRaisesRegex(lab.LabError, "changed after review"):
            lab.terraform_restore_apply(recovery.PROJECT_ID, recovery.LAB_ID, "us-east1-b", snapshots, addresses, "c" * 12,
                run=run, confirm=lambda _phrase: None, verify_project=drift_after_confirmation)
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_plan_passes_only_lock_bound_artifact_inputs_to_terraform(self):
        calls = []

        def run(args, **kwargs):
            calls.append((args, kwargs))
            return ""

        approval = {"lock": "l", "signature": "s", "trust": "t"}
        with patch.object(lab, "terraform_init"), patch.object(lab, "verify_customer_artifact", return_value=approval), patch.object(lab, "require_approval_unchanged"):
            lab.terraform_plan(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                               os_profile="ubuntu-24.04",
                               recheck_artifact_preflight=lambda: None, run=run)
        plan_args, kwargs = calls[-1]
        self.assertEqual(plan_args[1], "plan")
        self.assertIn("-var=k3s_binary_sha256=" + "a" * 64, plan_args)
        self.assertIn("-var=k3s_binary_mirror_url=https://mirror.example.test/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s", plan_args)
        self.assertNotIn("TF_CLI_ARGS_plan", kwargs["env"])
        self.assertFalse(any(name.startswith("TF_VAR_") for name in kwargs["env"]))

    def test_plan_rejects_cli_artifact_overrides_that_conflict_with_reviewed_inputs(self):
        calls = []
        with patch.object(lab, "terraform_init"):
            with self.assertRaisesRegex(lab.LabError, "CLI artifact overrides differ"):
                lab.terraform_plan(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                                   os_profile="debian-13", os_point_release="13.8",
                                   recheck_artifact_preflight=lambda: None,
                                   run=lambda args, **_kwargs: calls.append(args))
        self.assertFalse(any(args[1] == "plan" for args in calls))

    def test_ubuntu_and_debian_profiles_are_bound_as_explicit_terraform_inputs(self):
        images = {
            "manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1", "architecture": "linux/amd64",
            "bundleSha256": "b" * 64,
            "bundleMirrorReference": "https://mirror.example.test/k3s/v1.36.6+k3s1/images.tar",
            "mirrorHost": "mirror.example.test",
        }
        for profile in ("ubuntu-24.04", "debian-13"):
            with self.subTest(profile=profile):
                point_release = "13.8" if profile == "debian-13" else ""
                values = lab.terraform_artifact_vars("a" * 64, "https://mirror.example.test/k3s", images,
                                                     profile, os_point_release=point_release)
                self.assertIn(f"-var=qualification_os_profile={profile}", values)
                self.assertIn("-var=os_family=debian", values)

    def test_plan_and_apply_functions_require_the_consolidated_preflight_callback(self):
        with patch.object(lab, "terraform_init") as init:
            with self.assertRaisesRegex(lab.LabError, "consolidated M3 artifact preflight"):
                lab.terraform_plan(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                                   os_profile="ubuntu-24.04")
            with self.assertRaisesRegex(lab.LabError, "consolidated M3 artifact preflight"):
                lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths,
                                    os_profile="ubuntu-24.04")
        init.assert_not_called()

    def test_consolidated_preflight_binding_rejects_substituted_k3s_inputs(self):
        report = self.root / "m3-report.json"
        expected = {
            "k3sBinary.binary": self.artifact_paths["artifact_binary"],
            "k3sBinary.lock": self.artifact_paths["artifact_lock"],
            "k3sBinary.signature": self.artifact_paths["artifact_signature"],
            "k3sBinary.trustBundle": self.artifact_paths["artifact_trust"],
            "k3sSystemImages.bundle": self.system_image_paths["system_images_bundle"],
            "k3sSystemImages.lock": self.system_image_paths["system_images_lock"],
            "k3sSystemImages.signature": self.system_image_paths["system_images_signature"],
            "k3sSystemImages.trustBundle": self.system_image_paths["system_images_trust"],
        }
        report_bytes = json.dumps({"inputSha256": {key: lab.sha256_file(path) for key, path in expected.items()}}).encode()
        report.write_bytes(report_bytes)
        report_hash = hashlib.sha256(report_bytes).hexdigest()
        lab.require_preflight_binds_k3s(report, artifact_binary=expected["k3sBinary.binary"],
            artifact_lock=expected["k3sBinary.lock"], artifact_signature=expected["k3sBinary.signature"],
            artifact_trust=expected["k3sBinary.trustBundle"], system_images_bundle=expected["k3sSystemImages.bundle"],
            system_images_lock=expected["k3sSystemImages.lock"], system_images_signature=expected["k3sSystemImages.signature"],
            system_images_trust=expected["k3sSystemImages.trustBundle"], expected_report_sha256=report_hash)
        report.write_text(json.dumps({"schemaVersion": 1, "overallStatus": "PASS", "inputSha256": {
            key: lab.sha256_file(path) for key, path in expected.items()}}))
        with self.assertRaisesRegex(lab.LabError, "report changed"):
            lab.require_preflight_binds_k3s(report, artifact_binary=expected["k3sBinary.binary"],
                artifact_lock=expected["k3sBinary.lock"], artifact_signature=expected["k3sBinary.signature"],
                artifact_trust=expected["k3sBinary.trustBundle"], system_images_bundle=expected["k3sSystemImages.bundle"],
                system_images_lock=expected["k3sSystemImages.lock"], system_images_signature=expected["k3sSystemImages.signature"],
                system_images_trust=expected["k3sSystemImages.trustBundle"], expected_report_sha256=report_hash)
        report.write_bytes(report_bytes)
        self.artifact_paths["artifact_lock"].write_bytes(b"substituted after the preflight report")
        with self.assertRaisesRegex(lab.LabError, "do not match"):
            lab.require_preflight_binds_k3s(report, artifact_binary=expected["k3sBinary.binary"],
                artifact_lock=expected["k3sBinary.lock"], artifact_signature=expected["k3sBinary.signature"],
                artifact_trust=expected["k3sBinary.trustBundle"], system_images_bundle=expected["k3sSystemImages.bundle"],
                system_images_lock=expected["k3sSystemImages.lock"], system_images_signature=expected["k3sSystemImages.signature"],
                system_images_trust=expected["k3sSystemImages.trustBundle"])

    def test_preflight_rejects_report_tampering_between_writer_and_reader(self):
        inputs = self.root / "inputs.json"
        report = self.root / "report.json"
        inputs.write_text('{"schemaVersion":1}')
        report.write_text('{"overallStatus":"PASS"}')
        claimed_hash = hashlib.sha256(b'{"overallStatus":"PASS"}').hexdigest()
        report.write_text('{"overallStatus":"PASS","tampered":true}')

        def run(_args, **_kwargs):
            return f"M3 artifact preflight: PASS; report-sha256={claimed_hash}\n"

        with self.assertRaisesRegex(lab.LabError, "digest does not match"):
            lab.run_m3_artifact_preflight(inputs, report, run=run)

    def test_debian_preflight_selects_debian_bootstrap_and_binds_report_bytes(self):
        inputs = self.root / "inputs.json"
        report = self.root / "report.json"
        inputs.write_text('{"schemaVersion":1}')
        rows = {name: {"status": "PASS"} for name in (
            "maintenancePublicTrust", "artifactApprovalTrust", "releasePublicTrust", "toolProvenancePublicTrust",
            "signedReleaseBundle", "signedImageDigestLock", "k3sBinaryApproval", "k3sSystemImageApproval",
            "privateRegistryImages", "hostPackageArtifacts", "helmSignerAllowlist", "requiredKordexImages",
        )}
        profile = "m3-debian-13-k3s-v1.36.6+k3s1-linux-amd64"
        rows["hostPackageArtifacts"].update({
            "profile": profile,
            "osFamily": "debian", "osId": "debian", "osMajor": "13", "osMinor": "",
            "osPointRelease": "13.8",
        })
        body = json.dumps({"schemaVersion": 1, "overallStatus": "PASS",
                           "profile": profile, "artifacts": rows},
                          sort_keys=True, separators=(",", ":")) + "\n"
        body_bytes = body.encode()

        def run(_args, **_kwargs):
            report.write_bytes(body_bytes)
            return f"M3 artifact preflight: PASS; report-sha256={hashlib.sha256(body_bytes).hexdigest()}\n"

        report_hash = lab.run_m3_artifact_preflight(inputs, report, run=run)
        self.assertEqual(report_hash, hashlib.sha256(body_bytes).hexdigest())
        self.assertEqual(lab.qualification_os_profile(report, report_hash), "debian-13")
        self.assertIn("-var=qualification_os_profile=debian-13",
                      lab.terraform_artifact_vars("a" * 64, "https://mirror.example.test/k3s",
                                                  {"manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1",
                                                   "architecture": "linux/amd64", "bundleSha256": "b" * 64,
                                                   "bundleMirrorReference": "https://mirror.example.test/image.tar",
                                                   "mirrorHost": "mirror.example.test"}, "debian-13", "", "13.8"))
        wrong_release = json.loads(body)
        wrong_release["artifacts"]["hostPackageArtifacts"]["osPointRelease"] = "13.9"
        report.write_text(json.dumps(wrong_release, sort_keys=True, separators=(",", ":")) + "\n")
        wrong_hash = hashlib.sha256(report.read_bytes()).hexdigest()
        with self.assertRaisesRegex(lab.LabError, "approved Debian 13.8"):
            lab.qualification_os_point_release(report, wrong_hash)
        report.write_text(body + " ")
        with self.assertRaisesRegex(lab.LabError, "report changed after verification"):
            lab.qualification_os_profile(report, report_hash)

    def test_rhel98_artifact_profile_selects_exact_customer_image_profile(self):
        inputs = self.root / "inputs.json"
        report = self.root / "report.json"
        inputs.write_text('{"schemaVersion":1}')
        rows = {name: {"status": "PASS"} for name in (
            "maintenancePublicTrust", "artifactApprovalTrust", "releasePublicTrust", "toolProvenancePublicTrust",
            "signedReleaseBundle", "signedImageDigestLock", "k3sBinaryApproval", "k3sSystemImageApproval",
            "privateRegistryImages", "hostPackageArtifacts", "helmSignerAllowlist", "requiredKordexImages",
        )}
        profile = "m3-rhel-9.8-k3s-v1.36.6+k3s1-linux-amd64"
        rows["hostPackageArtifacts"].update({
            "profile": profile, "osFamily": "rhel", "osId": "rhel", "osMajor": "9", "osMinor": "8",
            "osPointRelease": "9.8",
        })
        body_bytes = (json.dumps({"schemaVersion": 1, "overallStatus": "PASS", "profile": profile,
                                  "artifacts": rows}, sort_keys=True, separators=(",", ":")) + "\n").encode()

        def run(_args, **_kwargs):
            report.write_bytes(body_bytes)
            return f"M3 artifact preflight: PASS; report-sha256={hashlib.sha256(body_bytes).hexdigest()}\n"

        report_hash = lab.run_m3_artifact_preflight(inputs, report, run=run)
        self.assertEqual(lab.qualification_os_profile(report, report_hash), "rhel-9")
        self.assertEqual(lab.qualification_os_minor(report, report_hash), "8")
        self.assertEqual(lab.qualification_os_point_release(report, report_hash), "9.8")
        image_inputs = {"manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1", "architecture": "linux/amd64",
                        "bundleSha256": "b" * 64,
                        "bundleMirrorReference": "https://mirror.example.test/k3s/image.tar",
                        "mirrorHost": "mirror.example.test"}
        self.assertIn("-var=qualification_os_minor=8", lab.terraform_artifact_vars(
            "a" * 64, "https://mirror.example.test/k3s", image_inputs, "rhel-9", "8", "9.8"))

    def test_terraform_artifact_vars_rejects_blocked_or_unknown_os_profiles(self):
        for profile in ("rhel-9.7", "rocky-9", "debian-12"):
            with self.subTest(profile=profile), self.assertRaisesRegex(lab.LabError, "unsupported or blocked"):
                lab.terraform_artifact_vars("a" * 64, "https://mirror.example.test/k3s", {
                    "manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1", "architecture": "linux/amd64",
                    "bundleSha256": "b" * 64, "bundleMirrorReference": "https://mirror.example.test/image.tar",
                    "mirrorHost": "mirror.example.test",
                }, profile)

    def test_terraform_artifact_vars_rejects_debian_point_release_other_than_138(self):
        with self.assertRaisesRegex(lab.LabError, "point release"):
            lab.terraform_artifact_vars("a" * 64, "https://mirror.example.test/k3s", {
                "manifestVersion": "1", "k3sVersion": "v1.36.6+k3s1", "architecture": "linux/amd64",
                "bundleSha256": "b" * 64, "bundleMirrorReference": "https://mirror.example.test/image.tar",
                "mirrorHost": "mirror.example.test",
            }, "debian-13", os_point_release="13.9")

    def test_plan_cli_requires_consolidated_artifact_inputs_and_report(self):
        with self.assertRaises(SystemExit):
            lab.parser().parse_args(["plan", "--project-id", PROJECT,
                "--k3s-binary", str(self.artifact_paths["artifact_binary"]),
                "--k3s-artifact-lock", str(self.artifact_paths["artifact_lock"]),
                "--k3s-artifact-signature", str(self.artifact_paths["artifact_signature"]),
                "--k3s-artifact-trust", str(self.artifact_paths["artifact_trust"]),
                "--k3s-system-images-bundle", str(self.system_image_paths["system_images_bundle"]),
                "--k3s-system-images-lock", str(self.system_image_paths["system_images_lock"]),
                "--k3s-system-images-signature", str(self.system_image_paths["system_images_signature"]),
                "--k3s-system-images-trust", str(self.system_image_paths["system_images_trust"])] )

    def test_plan_stops_before_terraform_when_system_image_approval_fails(self):
        calls = []
        with patch.object(lab, "terraform_init") as init, \
                patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), \
                patch.object(lab, "verify_customer_system_images", side_effect=lab.LabError("bad image signature")), \
                self.assertRaisesRegex(lab.LabError, "bad image signature"):
            lab.terraform_plan(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                               os_profile="ubuntu-24.04",
                               recheck_artifact_preflight=lambda: None,
                               run=lambda args, **_kwargs: calls.append(args))
        init.assert_not_called()
        self.assertEqual(calls, [])

    def test_apply_stops_if_system_image_approval_changes_after_plan_review(self):
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            return ""

        def confirm(_phrase):
            self.system_image_paths["system_images_bundle"].write_bytes(b"substituted bundle")

        with patch.object(lab, "terraform_init"), \
                patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), \
                patch.object(lab, "require_approval_unchanged"), \
                self.assertRaisesRegex(lab.LabError, "system-image approval inputs changed"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args, run=run,
                                os_profile="ubuntu-24.04",
                                recheck_artifact_preflight=lambda: None, confirm=confirm,
                                verify_project=lambda _project_id, **_kwargs: None)
        self.assertTrue(any(args[1] == "plan" for args in calls))
        self.assertTrue(any(args[1] == "show" for args in calls))
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_apply_stops_when_image_id_changes_after_plan_review(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            if args[1:3] == ["compute", "images"]:
                return json.dumps({"name": "approved-image", "selfLink": self.fake_plan_values.get("imageSelfLink"),
                                   "id": "999999999999", "architecture": "X86_64"})
            return ""

        self.fake_plan_values.update({"qualification_os_profile": "debian-13",
                                      "qualification_os_point_release": "13.8",
                                      "os_family": "debian",
                                      "debian_image_self_link": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/approved-image",
                                      "qualification_image_unique_id": "1234567890123456789"})
        lab.verify_readiness_plan_binding.return_value = (
            self.fake_plan_values, lab.readiness_binding.canonical_sha256(self.fake_plan_values))
        self.live_image_patch.stop()
        self.addCleanup(self.live_image_patch.start)
        with patch.object(lab, "verify_live_image_identity", side_effect=lab.LabError("image identity changed")), \
                patch.object(lab, "terraform_init"), \
                patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), \
                patch.object(lab, "require_approval_unchanged"), \
                self.assertRaisesRegex(lab.LabError, "image identity changed"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                                os_profile="debian-13", os_point_release="13.8", recheck_artifact_preflight=lambda: None,
                                run=run, confirm=lambda _value: None,
                                verify_project=lambda *_args, **_kwargs: None)
        self.assertTrue(any(args[1] == "plan" for args in calls))
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_saved_plan_modification_after_review_blocks_apply(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            if args[1] == "show":
                Path(args[2]).write_bytes(b"changed-after-review")
            return ""

        self.fake_plan_values.update({"qualification_os_profile": "debian-13",
                                      "qualification_os_point_release": "13.8",
                                      "os_family": "debian",
                                      "debian_image_self_link": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/approved-image",
                                      "qualification_image_unique_id": "1234567890123456789"})
        lab.verify_readiness_plan_binding.return_value = (
            self.fake_plan_values, lab.readiness_binding.canonical_sha256(self.fake_plan_values))
        with patch.object(lab, "terraform_init"), \
                patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), \
                patch.object(lab, "require_approval_unchanged"), \
                self.assertRaisesRegex(lab.LabError, "saved Terraform plan changed"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                                os_profile="debian-13", os_point_release="13.8", recheck_artifact_preflight=lambda: None,
                                run=run, confirm=lambda _value: None,
                                verify_project=lambda *_args, **_kwargs: None)
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_apply_refuses_plan_replaced_after_confirmation(self):
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            if args[1] == "plan":
                Path(next(arg.removeprefix("-out=") for arg in args if arg.startswith("-out="))).write_bytes(
                    b"reviewed plan")
            return ""

        def replace_after_confirmation(_project, **_kwargs):
            plan = next(Path(args[2]) for args in calls if args[1] == "show")
            plan.write_bytes(b"replacement after confirmation")

        with patch.object(lab, "terraform_init"), \
                patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), \
                patch.object(lab, "require_approval_unchanged"), \
                self.assertRaisesRegex(lab.LabError, "saved Terraform plan changed"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                run=run, os_profile="ubuntu-24.04", recheck_artifact_preflight=lambda: None,
                confirm=lambda _phrase: None, verify_project=replace_after_confirmation)
        self.assertTrue(any(args[1] == "show" for args in calls))
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_live_image_identity_check_rejects_recreated_image(self):
        self.live_image_patch.stop()
        self.addCleanup(self.live_image_patch.start)
        values = {"qualification_os_profile": "debian-13",
                  "debian_image_self_link": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/approved-image",
                  "qualification_image_unique_id": "1234567890123456789",
                  "project_id": PROJECT,
                  "terraform_principal_email": "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"}
        approval = {"imageUniqueId": "1234567890123456789", "projectId": PROJECT}
        def fake_run(_args, **_kwargs):
            return json.dumps({"name": "approved-image", "selfLink": values["debian_image_self_link"],
                               "id": "999999999999", "architecture": "X86_64"})
        with self.assertRaisesRegex(lab.LabError, "identity or architecture changed"):
            lab.verify_live_image_identity(values, approval, run=fake_run)

    def test_rhel_image_identity_requires_payg_and_eus_license_uris(self):
        self.live_image_patch.stop()
        self.addCleanup(self.live_image_patch.start)
        values = {"qualification_os_profile": "rhel-9",
                  "rhel_image_self_link": "https://www.googleapis.com/compute/v1/projects/rhel-cloud/global/images/rhel-9-8-eus-v20261113",
                  "qualification_image_unique_id": "1234567890123456789",
                  "project_id": PROJECT,
                  "terraform_principal_email": "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"}
        approval = {"imageUniqueId": "1234567890123456789", "projectId": PROJECT}

        def fake_run(licenses):
            return lambda _args, **_kwargs: json.dumps({
                "name": "rhel-9-8-eus-v20261113", "selfLink": values["rhel_image_self_link"],
                "id": "1234567890123456789", "architecture": "X86_64", "licenses": licenses,
            })

        with self.assertRaisesRegex(lab.LabError, "PAYG/EUS licenses"):
            lab.verify_live_image_identity(values, approval, run=fake_run([]))
        lab.verify_live_image_identity(values, approval, run=fake_run(list(lab.RHEL_PAYG_LICENSES)))

    def test_rhel_boot_disk_evidence_requires_payg_license_identity(self):
        project = recovery.PROJECT_ID
        zone = "us-east1-b"
        lab_id = recovery.LAB_ID
        principal = "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"
        image = "https://www.googleapis.com/compute/v1/projects/rhel-cloud/global/images/rhel-9-8-eus-v20261113"

        def run_with_disk_licenses(licenses):
            def run(args, **_kwargs):
                if args[1:4] == ["compute", "instances", "describe"]:
                    name = args[4]
                    role = "server" if name.endswith("server") else "worker-1" if name.endswith("worker") else "worker-2"
                    return json.dumps({"name": name, "id": "100",
                        "zone": f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}",
                        "status": "RUNNING", "labels": {"application": "kordex",
                            "purpose": "disposable-qualification", "managed-by": "terraform",
                            "lab-id": lab_id, "node-role": role},
                        "disks": [{"boot": True,
                            "source": f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/disks/{name}"}]})
                name = args[4]
                return json.dumps({"name": name, "id": "200", "selfLink":
                    f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/disks/{name}",
                    "sourceImage": image, "sourceImageId": "1234567890123456789", "licenses": licenses})
            return run

        with self.assertRaisesRegex(lab.LabError, "boot-disk verification context is malformed"):
            lab.verify_created_boot_disk_images(project, zone, "kordex-lab", principal, image, "1234567890123456789",
                                                require_rhel_payg=True, run=run_with_disk_licenses(list(lab.RHEL_PAYG_LICENSES)))
        with self.assertRaisesRegex(lab.LabError, "does not carry the approved RHEL PAYG/EUS licenses"):
            lab.verify_created_boot_disk_images(project, zone, lab_id, principal, image, "1234567890123456789",
                                                require_rhel_payg=True, run=run_with_disk_licenses([]))
        result = lab.verify_created_boot_disk_images(project, zone, lab_id, principal, image, "1234567890123456789",
                                                     require_rhel_payg=True,
                                                     run=run_with_disk_licenses(list(lab.RHEL_PAYG_LICENSES)))
        self.assertEqual(result["instances"][0]["licenses"], list(lab.RHEL_PAYG_LICENSES))

    def test_created_boot_disks_are_independently_bound_to_exact_image_identity(self):
        project = recovery.PROJECT_ID
        zone = "us-east1-b"
        lab_id = recovery.LAB_ID
        principal = "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"
        image = "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-approved"
        image_id = "1234567890123456789"
        roles = {f"{lab_id}-server": "server", f"{lab_id}-worker": "worker-1",
                 f"{lab_id}-worker-2": "worker-2"}
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            if args[1:4] == ["compute", "instances", "describe"]:
                name = args[4]
                role = roles[name]
                return json.dumps({"name": name, "id": str(100 + len(calls)),
                    "zone": f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}",
                    "status": "RUNNING", "labels": {"application": "kordex",
                        "purpose": "disposable-qualification", "managed-by": "terraform",
                        "lab-id": lab_id, "node-role": role},
                    "disks": [{"boot": True,
                        "source": f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/disks/{name}"}]})
            name = args[4]
            return json.dumps({"name": name, "id": "200", "selfLink":
                f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/disks/{name}",
                "sourceImage": image, "sourceImageId": image_id})

        result = lab.verify_created_boot_disk_images(project, zone, lab_id, principal, image, image_id, run=run)
        self.assertEqual(len(result["instances"]), 3)
        self.assertEqual([item["role"] for item in result["instances"]], ["server", "worker-1", "worker-2"])
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(call[0] == "/usr/bin/gcloud" for call in calls))

        def replaced_disk(args, **kwargs):
            output = json.loads(run(args, **kwargs))
            if args[1:4] == ["compute", "disks", "describe"] and args[4] == f"{lab_id}-worker":
                output["sourceImageId"] = "987654321"
            return json.dumps(output)

        with self.assertRaisesRegex(lab.LabError, "does not identify the approved image"):
            lab.verify_created_boot_disk_images(project, zone, lab_id, principal, image, image_id,
                                                run=replaced_disk)

        def wrong_project_zone(args, **kwargs):
            output = json.loads(run(args, **kwargs))
            if args[1:4] == ["compute", "instances", "describe"]:
                output["zone"] = f"https://www.googleapis.com/compute/v1/projects/other-project/zones/{zone}"
            return json.dumps(output)

        with self.assertRaisesRegex(lab.LabError, "does not match the approved disposable lab identity"):
            lab.verify_created_boot_disk_images(project, zone, lab_id, principal, image, image_id,
                                                run=wrong_project_zone)

    def test_debian_apply_requires_post_creation_boot_disk_image_verification(self):
        events = []
        self.fake_plan_values.update({
            "qualification_os_profile": "debian-13", "qualification_os_point_release": "13.8",
            "os_family": "debian", "name_prefix": recovery.LAB_ID, "zone": "us-east1-b",
            "debian_image_self_link": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-approved",
            "qualification_image_unique_id": "1234567890123456789",
        })
        self.readiness_binding_patch.stop()
        self.readiness_binding_patch = patch.object(lab, "verify_readiness_plan_binding", return_value=(
            self.fake_plan_values, lab.readiness_binding.canonical_sha256(self.fake_plan_values)))
        self.readiness_binding_patch.start()
        self.addCleanup(self.readiness_binding_patch.stop)

        def run(args, **_kwargs):
            events.append(args[1] if len(args) > 1 else args[0])
            return ""

        def reject_disk_mismatch(*_args, **_kwargs):
            events.append("boot-disk-verification")
            raise lab.LabError("created boot disk image identity mismatch")

        with patch.object(lab, "terraform_init"), \
                patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), \
                patch.object(lab, "require_approval_unchanged"), \
                patch.object(lab, "verify_live_image_identity"), \
                patch.object(lab, "verify_disposable_project"), \
                patch.object(lab, "verify_created_boot_disk_images", side_effect=reject_disk_mismatch), \
                self.assertRaisesRegex(lab.LabError, "created boot disk image identity mismatch"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args,
                os_profile="debian-13", os_point_release="13.8", recheck_artifact_preflight=lambda: None,
                run=run, confirm=lambda _phrase: None,
                verify_project=lambda _project_id, **_kwargs: None)
        self.assertIn("apply", events)
        self.assertEqual(events[-1], "boot-disk-verification")

    def test_security_sensitive_gcloud_checks_ignore_gcoud_home_path_and_cloudsdk_overrides(self):
        values = {"qualification_os_profile": "debian-13",
                  "debian_image_self_link": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/approved-image",
                  "qualification_image_unique_id": "1234567890123456789", "project_id": PROJECT,
                  "terraform_principal_email": "kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com"}
        approval = {"imageUniqueId": values["qualification_image_unique_id"], "projectId": PROJECT}
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs["env"]))
            if "images" in args:
                return json.dumps({"name": "approved-image", "selfLink": values["debian_image_self_link"],
                                   "id": values["qualification_image_unique_id"], "architecture": "X86_64"})
            return json.dumps({"projectId": PROJECT, "projectNumber": "1234567890", "lifecycleState": "ACTIVE",
                               "labels": {"kordex-disposable": "qualification"}})
        controlled_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "CLOUDSDK_CONFIG": "/etc/kordex/gcloud",
                          "CLOUDSDK_ACTIVE_CONFIG_NAME": "kordex-m3", "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}
        self.live_image_patch.stop()
        self.addCleanup(self.live_image_patch.start)
        with patch.object(lab.gcloud_context, "describe", return_value={"executablePath": "/usr/lib64/google-cloud-sdk/bin/gcloud"}), \
             patch.object(lab.gcloud_context, "environment", return_value=controlled_env), \
             patch.dict(os.environ, {"GCLOUD": "/tmp/attacker-gcloud", "HOME": "/tmp/attacker-home",
                 "PATH": "/tmp/attacker-bin", "CLOUDSDK_CONFIG": "/tmp/attacker-config",
                 "CLOUDSDK_ACTIVE_CONFIG_NAME": "attacker", "CLOUDSDK_CORE_PROJECT": "attacker-project"}, clear=False):
            lab.verify_live_image_identity(values, approval, run=run)
            self.assertEqual(len(calls), 1)
            self.assertIn("images", calls[0][0])
            self.assertEqual(calls[0][0][0], "/usr/bin/gcloud")
            calls.clear()
            lab.verify_disposable_project(PROJECT, run=run, principal_email=values["terraform_principal_email"])
        self.assertEqual(len(calls), 1)
        self.assertIn("projects", calls[0][0])
        self.assertEqual(calls[0][0][0], "/usr/bin/gcloud")
        for _args, env in calls:
            self.assertEqual(env, controlled_env)

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
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args, run=run,
                                os_profile="ubuntu-24.04",
                                recheck_artifact_preflight=lambda: None, confirm=confirm,
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
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args, run=run,
                                os_profile="ubuntu-24.04",
                                recheck_artifact_preflight=lambda: None, confirm=reject_confirmation)
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
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args, run=run,
                                os_profile="ubuntu-24.04",
                                recheck_artifact_preflight=lambda: None, confirm=confirmations.append,
                                verify_project=lambda _project_id, **_kwargs: None)
        self.assertEqual(confirmations, [f"APPLY {PROJECT} PLAN-SHA256 " + hashlib.sha256(b"").hexdigest()])
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
            return self.terraform_state_output(args[3]) if args[1:3] == ["output", "-raw"] else ""

        confirmations = []
        with patch.object(lab, "terraform_init"):
            lab.terraform_destroy(PROJECT, run=run, confirm=confirmations.append,
                                  verify_project=lambda _project_id, **_kwargs: None)
        self.assertEqual(confirmations, [f"DESTROY {PROJECT} PLAN-SHA256 " + hashlib.sha256(b"").hexdigest()])
        self.assertTrue(any(args[1] == "plan" and "-destroy" in args for args in calls))
        self.assertTrue(any(args[1] == "apply" for args in calls))
        destroy_plan = next(args for args in calls if args[1] == "plan")
        self.assertIn("-var=k3s_system_images_manifest_version=1", destroy_plan)
        self.assertIn("-var=k3s_system_images_mirror_host=registry.example.test", destroy_plan)
        self.assertFalse(any(args[1] == "destroy" for args in calls))

    def test_destroy_refuses_saved_plan_changed_after_confirmation(self):
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            if args[1:3] == ["output", "-raw"]:
                return self.terraform_state_output(args[3])
            if args[1] == "plan":
                plan = Path(next(arg.removeprefix("-out=") for arg in args if arg.startswith("-out=")))
                plan.write_bytes(b"reviewed destroy plan")
            return ""

        def drift_after_confirmation(_project, **_kwargs):
            plan = next(Path(args[2]) for args in calls if args[1] == "show")
            plan.write_bytes(b"substituted destroy plan")

        with patch.object(lab, "terraform_init"), self.assertRaisesRegex(lab.LabError, "changed after review"):
            lab.terraform_destroy(PROJECT, run=run, confirm=lambda _phrase: None, verify_project=drift_after_confirmation)
        self.assertFalse(any(args[1] == "apply" for args in calls))

    def test_destroy_does_not_apply_after_wrong_confirmation(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return self.terraform_state_output(args[3]) if args[1:3] == ["output", "-raw"] else ""

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
            return self.terraform_state_output(args[3]) if args[1:3] == ["output", "-raw"] else ""

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
                lab.runner_command(True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT,
                                   platform_binding={"schemaVersion": 1},
                                   recheck_artifact_preflight=lambda: None)

    def test_execute_requires_correct_cancellation_phase_and_positive_timeout(self):
        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": PROJECT}):
            with self.assertRaisesRegex(lab.LabError, "requires --cancel-on-phase Draining"):
                lab.runner_command(True, self.root / "case.json", "cancel-before-apply",
                                   target_confirmation=PROJECT, recheck_artifact_preflight=lambda: None,
                                   platform_binding={"schemaVersion": 1},
                                   run=lambda *_args, **_kwargs: "")
            with self.assertRaisesRegex(lab.LabError, "must be positive"):
                lab.runner_command(True, self.root / "case.json", "clean-upgrade", timeout=0,
                                   target_confirmation=PROJECT, recheck_artifact_preflight=lambda: None,
                                   platform_binding={"schemaVersion": 1},
                                   run=lambda *_args, **_kwargs: "")
            calls = []
            lab.runner_command(True, self.root / "case.json", "cancel-before-apply",
                               cancel_phase="Draining", target_confirmation=PROJECT,
                               platform_binding={"schemaVersion": 1},
                               run=lambda args, **_kwargs: calls.append(args),
                               project_id=PROJECT,
                               confirm_project=lambda _expected: None,
                               verify_project=lambda _project_id, **_kwargs: None,
                               recheck_artifact_preflight=lambda: None)
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

        lab.verify_disposable_project(PROJECT, run=describe,
            principal_email="kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com")
        self.assertEqual(calls[0][0:3], ["/usr/bin/gcloud", "projects", "describe"])
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
                lab.verify_disposable_project(PROJECT, run=lambda *_args, **_kwargs: json.dumps(response),
                    principal_email="kordex-m3-plan@kordex-fleet-platform-515416.iam.gserviceaccount.com")

    def test_apply_rechecks_live_disposable_designation_after_confirmation(self):
        calls = []

        def run(args, **_):
            calls.append(args)
            return ""

        def verify(project_id, **_kwargs):
            self.assertEqual(project_id, PROJECT)
            calls.append(["verify-disposable-project"])

        with patch.object(lab, "terraform_init"), patch.object(lab, "verify_customer_artifact", return_value={"lock": "l", "signature": "s", "trust": "t"}), patch.object(lab, "require_approval_unchanged"):
            lab.terraform_apply(PROJECT, **self.artifact_paths, **self.system_image_paths, **self.plan_args, run=run,
                                os_profile="ubuntu-24.04",
                                recheck_artifact_preflight=lambda: None, confirm=lambda _phrase: None,
                                verify_project=verify)
        apply_index = next(index for index, args in enumerate(calls) if args[1:2] == ["apply"])
        verify_index = next(index for index, args in enumerate(calls) if args[0] == "verify-disposable-project")
        self.assertLess(verify_index, apply_index)

    def test_execute_requires_live_project_check_and_second_confirmation(self):
        events = []
        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": PROJECT}):
            lab.runner_command(
                True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT,
                project_id=PROJECT,
                platform_binding={"schemaVersion": 1},
                verify_project=lambda project_id, **_kwargs: events.append(("verify", project_id)),
                confirm_project=lambda expected: events.append(("confirm", expected)),
                recheck_artifact_preflight=lambda: events.append(("artifact-preflight",)),
                run=lambda args, **_kwargs: events.append(("runner", args)),
            )
        self.assertEqual(events[0], ("verify", PROJECT))
        self.assertEqual(events[1], ("confirm", f"EXECUTE IN DISPOSABLE PROJECT {PROJECT}"))
        self.assertEqual(events[2], ("artifact-preflight",))
        self.assertEqual(events[3][0], "runner")

    def test_execute_never_launches_runner_when_live_project_check_fails(self):
        def revoked(*_args, **_kwargs):
            raise lab.LabError("disposable label was revoked")

        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": PROJECT}):
            with self.assertRaisesRegex(lab.LabError, "label was revoked"):
                lab.runner_command(
                    True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT,
                    project_id=PROJECT,
                    platform_binding={"schemaVersion": 1},
                    verify_project=revoked,
                    confirm_project=lambda _expected: None,
                    recheck_artifact_preflight=lambda: None,
                    run=lambda *_args, **_kwargs: self.fail("runner must not launch"),
                )

    def test_execute_requires_consolidated_artifact_preflight_before_project_access(self):
        with self.assertRaisesRegex(lab.LabError, "passing consolidated M3 artifact preflight"):
            lab.runner_command(
                True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT,
                project_id=PROJECT,
                verify_project=lambda *_args, **_kwargs: self.fail("project must not be checked"),
                run=lambda *_args, **_kwargs: self.fail("runner must not launch"),
            )

    def test_execute_does_not_start_runner_when_second_artifact_preflight_fails(self):
        def reject_preflight():
            raise lab.LabError("artifact input changed after approval")

        with patch.dict(os.environ, {"KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM": PROJECT}):
            with self.assertRaisesRegex(lab.LabError, "artifact input changed"):
                lab.runner_command(
                    True, self.root / "case.json", "clean-upgrade", target_confirmation=PROJECT,
                    project_id=PROJECT,
                    platform_binding={"schemaVersion": 1},
                    verify_project=lambda *_args, **_kwargs: None,
                    confirm_project=lambda _expected: None,
                    recheck_artifact_preflight=reject_preflight,
                    run=lambda *_args, **_kwargs: self.fail("runner must not launch"),
                )

    def test_execute_cli_requires_a_project_id(self):
        with self.assertRaises(SystemExit):
            lab.parser().parse_args([
                "execute", "--target-confirmation", PROJECT,
                "--qualification-case", "clean-upgrade", "--evidence", "case.json",
            ])

    def test_execute_cli_requires_customer_artifact_preflight_inputs(self):
        with self.assertRaises(SystemExit):
            lab.parser().parse_args([
                "execute", "--project-id", PROJECT, "--target-confirmation", PROJECT,
                "--qualification-case", "clean-upgrade", "--evidence", "case.json",
            ])

    def test_cost_cli_requires_explicit_machine_and_rhel_license_hours(self):
        with self.assertRaises(SystemExit):
            lab.parser().parse_args(["lab", "cost"])
        args = lab.parser().parse_args([
            "lab", "cost", "--machine-type", "e2-medium", "--boot-disk-size-gib", "40",
            "--debian-scenario-hours-per-vm", "40",
            "--debian-cleanup-restore-hours-per-vm", "8",
            "--rhel-scenario-hours-per-vm", "40",
            "--rhel-cleanup-restore-hours-per-vm", "8",
            "--wrong-machine-id-extra-host-hours-per-os", "1",
            "--rhel-license-mode", "payg",
            "--rhel-license-hours-per-vm", "48",
            "--debian-boot-disk-gib-hours", "1000",
            "--rhel-boot-disk-gib-hours", "1000",
            "--wrong-machine-id-extra-host-disk-gib-hours-per-os", "100",
            "--snapshot-stored-gib-hours", "100",
            "--private-dns-query-bound", "1000",
            "--monthly-logging-gib", "1", "1", "1",
            "--logging-retention-cost-bound-usd", "1",
            "--network-bound-usd", "1",
            "--artifact-storage-bound-usd", "1",
            "--registry-storage-bound-usd", "1",
            "--rhel-subscription-bound-usd", "1",
            "--other-bound-usd", "1",
        ])
        self.assertEqual(args.machine_type, "e2-medium")
        self.assertEqual(args.debian_scenario_hours_per_vm, 40)
        self.assertEqual(args.debian_cleanup_restore_hours_per_vm, 8)
        self.assertEqual(args.rhel_scenario_hours_per_vm, 40)
        self.assertEqual(args.rhel_cleanup_restore_hours_per_vm, 8)
        self.assertEqual(args.rhel_license_hours_per_vm, 48)

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
