import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


builder = load_module("kordex_package_artifact_builder", ROOT / "scripts/build-offline-package-artifacts.py")
stager = load_module("kordex_package_artifact_stager", ROOT / "scripts/install-offline-package-artifacts.py")


def make_policy(directory: Path, artifact: bytes) -> tuple[Path, Path, str]:
    digest = hashlib.sha256(artifact).hexdigest()
    policy = {
        "apiVersion": "operations.kordex.local/v1alpha1",
        "kind": "MaintenancePolicy",
        "metadata": {"name": "offline-test"},
        "spec": {"upgrade": {
            "schemaVersion": 2,
            "id": "offline-test",
            "osFamily": "debian",
            "executionBackend": "ansible-ee",
            "playbookCatalogId": "kordex.os-upgrade.debian.v2",
            "executionEnvironment": "registry.example/kordex/ee@sha256:" + "a" * 64,
            "playbookDigest": "b" * 64,
            "collectionsDigest": "c" * 64,
            "actionMarkerVersion": 1,
            "artifactMode": "OfflineArtifacts",
            "packages": [{"name": "openssl", "version": "3.0.2-1", "artifactSHA256": digest}],
            "channel": "stable",
            "reboot": "Never",
            "executionTimeout": 60_000_000_000,
            "rebootTimeout": 60_000_000_000,
            "verificationTimeout": 60_000_000_000,
            "maxAttempts": 1,
        }},
    }
    policy_path = directory / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    artifact_path = directory / "openssl.deb"
    artifact_path.write_bytes(artifact)
    return policy_path, artifact_path, digest


class OfflinePackageArtifactsTest(unittest.TestCase):
    def test_build_and_stage_policy_bound_artifact_and_repeat_idempotently(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            artifact = b"controlled offline package fixture\n"
            policy, package, digest = make_policy(directory, artifact)
            archive = directory / "packages.tar"
            builder.build(policy, [f"openssl={package}"], archive)
            archive_again = directory / "packages-again.tar"
            builder.build(policy, [f"openssl={package}"], archive_again)
            self.assertEqual(archive.read_bytes(), archive_again.read_bytes())
            with tarfile.open(archive, "r:") as tar:
                names = tar.getnames()
                self.assertEqual(names, ["manifest.json", f"artifacts/{digest}.deb"])
                manifest = json.load(tar.extractfile("manifest.json"))
                self.assertEqual(manifest["planDigest"], stager.read_policy(policy)[1])
            destination = directory / "worker-cache"
            staged = stager.stage(archive, policy, destination)
            self.assertEqual(Path(staged[0]).name, f"{digest}.deb")
            self.assertEqual(Path(staged[0]).read_bytes(), artifact)
            self.assertEqual(Path(staged[0]).stat().st_mode & 0o777, 0o644)
            self.assertEqual(stager.stage(archive, policy, destination), staged)

    def test_rhel_policy_uses_rpm_artifact_path(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            policy, package, digest = make_policy(directory, b"controlled rpm fixture\n")
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["spec"]["upgrade"].update({
                "id": "offline-rhel-test",
                "osFamily": "rhel",
                "playbookCatalogId": "kordex.os-upgrade.rhel.v1",
                "packages": [{"name": "openssl", "version": "3.0.2-1.el9", "artifactSHA256": digest}],
            })
            policy.write_text(json.dumps(document), encoding="utf-8")
            package = package.with_suffix(".rpm")
            package.write_bytes(b"controlled rpm fixture\n")
            archive = directory / "packages.tar"
            builder.build(policy, [f"openssl={package}"], archive)
            with tarfile.open(archive, "r:") as tar:
                self.assertEqual(tar.getnames(), ["manifest.json", f"artifacts/{digest}.rpm"])
            destination = directory / "worker-cache"
            staged = stager.stage(archive, policy, destination)
            self.assertEqual(Path(staged[0]).name, f"{digest}.rpm")
            self.assertEqual(Path(staged[0]).read_bytes(), b"controlled rpm fixture\n")

    def test_wrong_source_digest_and_incomplete_mapping_reject(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            policy, package, _ = make_policy(directory, b"correct")
            package.write_bytes(b"tampered")
            with self.assertRaises(builder.BundleError):
                builder.build(policy, [f"openssl={package}"], directory / "bad.tar")
            package.write_bytes(b"correct")
            with self.assertRaises(builder.BundleError):
                builder.build(policy, [], directory / "missing.tar")

    def test_builder_rejects_symlinked_policy_and_package_inputs(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            policy, package, _digest = make_policy(directory, b"valid artifact")
            output = directory / "bundle.tar"
            linked_policy = directory / "linked-policy.json"
            linked_policy.symlink_to(policy)
            with self.assertRaisesRegex(builder.BundleError, "cannot read policy JSON"):
                builder.build(linked_policy, [f"openssl={package}"], output)
            self.assertFalse(output.exists())

            linked_package = directory / "linked-openssl.deb"
            linked_package.symlink_to(package)
            with self.assertRaisesRegex(builder.BundleError, "safely opened regular file"):
                builder.build(policy, [f"openssl={linked_package}"], output)
            self.assertFalse(output.exists())

    def test_corrupt_archive_is_rejected_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            artifact = b"valid artifact"
            policy, package, digest = make_policy(directory, artifact)
            archive = directory / "valid.tar"
            builder.build(policy, [f"openssl={package}"], archive)
            bad_archive = directory / "bad.tar"
            with tarfile.open(archive, "r:") as source, tarfile.open(bad_archive, "w", format=tarfile.USTAR_FORMAT) as target:
                for member in source.getmembers():
                    data = source.extractfile(member).read()
                    if member.name == f"artifacts/{digest}.deb":
                        data = b"corrupt artifact"
                    info = tarfile.TarInfo(member.name)
                    info.size = len(data)
                    info.mode = 0o644
                    import io
                    target.addfile(info, io.BytesIO(data))
            destination = directory / "must-not-exist"
            with self.assertRaises(stager.BundleError):
                stager.stage(bad_archive, policy, destination)
            self.assertFalse(destination.exists())

    def test_archive_rejects_unexpected_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            artifact = b"valid artifact"
            policy, package, _ = make_policy(directory, artifact)
            archive = directory / "valid.tar"
            builder.build(policy, [f"openssl={package}"], archive)
            malicious = directory / "malicious.tar"
            with tarfile.open(archive, "r:") as source, tarfile.open(malicious, "w", format=tarfile.USTAR_FORMAT) as target:
                for member in source.getmembers():
                    data = source.extractfile(member).read()
                    info = tarfile.TarInfo("../outside" if member.name == "manifest.json" else member.name)
                    info.size = len(data)
                    info.mode = 0o644
                    import io
                    target.addfile(info, io.BytesIO(data))
            with self.assertRaises(stager.BundleError):
                stager.stage(malicious, policy, directory / "destination")

    def test_archive_entry_limit_is_enforced_while_reading_headers(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            policy, _package, _digest = make_policy(directory, b"valid artifact")
            oversized = directory / "too-many-entries.tar"
            import io
            with tarfile.open(oversized, "w", format=tarfile.USTAR_FORMAT) as archive:
                for index in range(130):
                    info = tarfile.TarInfo("manifest.json" if index == 0 else f"artifacts/{index:064x}.deb")
                    data = b"{}" if index == 0 else b""
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(stager.BundleError, "too many entries"):
                stager.stage(oversized, policy, directory / "destination")
            self.assertFalse((directory / "destination").exists())

    def test_staging_rejects_symlinked_destination_components_and_targets(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            policy, package, digest = make_policy(directory, b"valid artifact")
            archive = directory / "valid.tar"
            builder.build(policy, [f"openssl={package}"], archive)

            real_parent = directory / "real-parent"
            real_parent.mkdir(mode=0o755)
            linked_parent = directory / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(stager.BundleError, "unsafe or unowned directory"):
                stager.stage(archive, policy, linked_parent / "artifacts")
            self.assertFalse((real_parent / "artifacts").exists())

            destination = directory / "safe-cache"
            destination.mkdir(mode=0o700)
            outside = directory / "outside-package"
            outside.write_bytes(b"valid artifact")
            (destination / f"{digest}.deb").symlink_to(outside)
            with self.assertRaisesRegex(stager.BundleError, "existing staged artifact"):
                stager.stage(archive, policy, destination)
            self.assertEqual(outside.read_bytes(), b"valid artifact")

    def test_staging_rejects_symlinked_policy_and_archive_inputs(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            policy, package, _digest = make_policy(directory, b"valid artifact")
            archive = directory / "valid.tar"
            builder.build(policy, [f"openssl={package}"], archive)

            linked_policy = directory / "linked-policy.json"
            linked_policy.symlink_to(policy)
            with self.assertRaisesRegex(stager.BundleError, "safely opened regular file"):
                stager.stage(archive, linked_policy, directory / "policy-destination")
            self.assertFalse((directory / "policy-destination").exists())

            linked_archive = directory / "linked-archive.tar"
            linked_archive.symlink_to(archive)
            with self.assertRaisesRegex(stager.BundleError, "safely opened regular file"):
                stager.stage(linked_archive, policy, directory / "archive-destination")
            self.assertFalse((directory / "archive-destination").exists())


if __name__ == "__main__":
    unittest.main()
