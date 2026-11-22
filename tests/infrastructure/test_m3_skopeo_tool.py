"""Synthetic local tests for the pinned Skopeo tool verifier; not customer evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import m3_skopeo_tool as tool


class PinnedSkopeoToolTest(unittest.TestCase):
    def test_committed_rocky_pin_has_exact_architecture_specific_artifacts(self):
        pin = tool.load_pin()
        self.assertEqual(pin["rockySigningKey"]["fingerprint"], "FC226859C0860BF0DDB95B085B106C736FEDFC85")
        self.assertEqual(pin["profiles"]["linux-amd64"]["rpmArchitecture"], "x86_64")
        self.assertEqual(pin["profiles"]["linux-arm64"]["rpmArchitecture"], "aarch64")
        self.assertNotEqual(pin["profiles"]["linux-amd64"]["rpmSha256"],
                            pin["profiles"]["linux-arm64"]["rpmSha256"])

    def test_lock_row_accepts_exact_pin_and_rejects_unpinned_version_or_hash(self):
        pin = tool.load_pin()
        p = pin["profiles"]["linux-amd64"]
        k = pin["rockySigningKey"]
        tool.verify_lock_row(f"v{p['version']}", "linux-amd64", p["binarySha256"],
                             p["rpmSha256"], p["rpmUrl"], "rocky-rpm-signature", k["fingerprint"], pin=pin)
        for values in (
            ("v9.9.9", "linux-amd64", p["binarySha256"], p["rpmSha256"], p["rpmUrl"], "rocky-rpm-signature", k["fingerprint"]),
            (f"v{p['version']}", "linux-amd64", "0" * 64, p["rpmSha256"], p["rpmUrl"], "rocky-rpm-signature", k["fingerprint"]),
        ):
            with self.assertRaises(tool.SkopeoError):
                tool.verify_lock_row(*values, pin=pin)

    def _runtime_case(self, *, binary=b"synthetic skopeo executable", version="1.24.0",
                      package="skopeo-3:1.24.0-2.el10.x86_64", path_override=None):
        temp = tempfile.TemporaryDirectory(prefix="synthetic-skopeo-")
        root = Path(temp.name)
        executable = root / "skopeo"
        executable.write_bytes(binary)
        executable.chmod(0o755)
        release = root / "os-release"
        release.write_text('ID=rocky\nVERSION_ID="10.2"\n', encoding="utf-8")
        profile = {"version": "1.24.0", "binarySha256": hashlib.sha256(binary).hexdigest(),
                   "binaryPath": str(executable), "nevra": "skopeo-3:1.24.0-2.el10.x86_64"}
        pin = {"schemaVersion": 1, "distribution": "Rocky Linux", "distributionMajor": 10,
               "profiles": {"linux-amd64": profile, "linux-arm64": profile},
               "rockySigningKey": {"fingerprint": "A" * 40, "sha256": "0" * 64, "rpmKeyId": "aaaaaaaa"}}

        def runner(args, **kwargs):
            if args[0] == str(executable):
                return SimpleNamespace(returncode=0, stdout=f"skopeo version {version}\n", stderr="")
            if args[0] == "rpm":
                return SimpleNamespace(returncode=0, stdout=package, stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="unexpected command")
        return temp, executable, release, pin, runner

    def test_runtime_accepts_matching_digest_version_identity_and_package(self):
        temp, executable, release, pin, runner = self._runtime_case()
        with temp:
            result = tool.verify_runtime(executable=executable, os_release=release, runner=runner,
                                         require_root_owner=False, pin=pin)
        self.assertEqual(result["status"], "PASS")

    def test_missing_replaced_and_unpinned_executables_fail(self):
        temp, executable, release, pin, runner = self._runtime_case()
        with temp:
            executable.unlink()
            with self.assertRaises(tool.SkopeoMissing):
                tool.verify_runtime(executable=executable, os_release=release, runner=runner,
                                    require_root_owner=False, pin=pin)

        temp, executable, release, pin, runner = self._runtime_case(binary=b"changed executable")
        with temp:
            pin["profiles"]["linux-amd64"]["binarySha256"] = hashlib.sha256(
                b"synthetic skopeo executable").hexdigest()
            with self.assertRaisesRegex(tool.SkopeoError, "digest"):
                tool.verify_runtime(executable=executable, os_release=release, runner=runner,
                                    require_root_owner=False, pin=pin)

        temp, executable, release, pin, runner = self._runtime_case(version="9.9.9")
        with temp:
            with self.assertRaisesRegex(tool.SkopeoError, "version"):
                tool.verify_runtime(executable=executable, os_release=release, runner=runner,
                                    require_root_owner=False, pin=pin)

    def test_wrong_installed_package_identity_is_rejected(self):
        temp, executable, release, pin, runner = self._runtime_case(package="skopeo-3:1.24.1-1.el10.x86_64")
        with temp:
            with self.assertRaisesRegex(tool.SkopeoError, "package identity"):
                tool.verify_runtime(executable=executable, os_release=release, runner=runner,
                                    require_root_owner=False, pin=pin)

    def test_wrong_os_architecture_path_and_symlink_are_rejected(self):
        temp, executable, release, pin, runner = self._runtime_case()
        with temp:
            release.write_text('ID=rocky\nVERSION_ID="9.6"\n', encoding="utf-8")
            with self.assertRaisesRegex(tool.SkopeoError, "Rocky Linux 10"):
                tool.verify_runtime(executable=executable, os_release=release, runner=runner,
                                    require_root_owner=False, pin=pin)
            with self.assertRaises(tool.SkopeoError):
                tool.architecture_key("ppc64le")
            release.write_text('ID=rocky\nVERSION_ID="10.2"\n', encoding="utf-8")
            with self.assertRaisesRegex(tool.SkopeoError, "path"):
                tool.verify_runtime(executable=Path("/tmp/untrusted-skopeo"), os_release=release,
                                    runner=runner, require_root_owner=False, pin=pin)
            link = Path(temp.name) / "link"
            link.symlink_to(executable)
            with self.assertRaises(tool.SkopeoError):
                tool._regular_file(link)

            Path(temp.name).chmod(0o777)
            with self.assertRaisesRegex(tool.SkopeoError, "installation directory"):
                tool.verify_runtime(executable=executable, os_release=release, runner=runner,
                                    require_root_owner=False, pin=pin)

    def test_rpm_verification_rejects_missing_corrupt_and_bad_signature_artifacts(self):
        tempdir = tempfile.TemporaryDirectory(prefix="synthetic-skopeo-rpm-")
        with tempdir:
            root = Path(tempdir.name)
            package = root / "skopeo.rpm"
            keyfile = root / "rocky-key"
            package.write_bytes(b"synthetic-rpm")
            package.chmod(0o600)
            keyfile.write_bytes(b"synthetic-public-key")
            keyfile.chmod(0o600)
            fp = "A" * 40
            profile = {"version": "1.24.0",
                       "rpmSha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                       "nevra": "skopeo-3:1.24.0-2.el10.x86_64"}
            pin = {"schemaVersion": 1, "distribution": "Rocky Linux", "distributionMajor": 10,
                   "profiles": {"linux-amd64": profile, "linux-arm64": profile},
                   "rockySigningKey": {"fingerprint": fp, "sha256": hashlib.sha256(keyfile.read_bytes()).hexdigest(),
                                        "rpmKeyId": "aaaaaaaa"}}

            def runner(args, **kwargs):
                if args[0] == "gpg":
                    return SimpleNamespace(returncode=0, stdout=f"fpr:::::::::{fp}:\n", stderr="")
                if args[0] == "rpmkeys":
                    output = ("Header V4 RSA/SHA256 Signature, key ID aaaaaaaa: OK\n"
                              "Header SHA256 digest: OK\nPayload SHA256 digest: OK\n")
                    return SimpleNamespace(returncode=0, stdout=output, stderr="")
                if args[0] == "rpm" and "-qp" in args:
                    return SimpleNamespace(returncode=0, stdout=profile["nevra"], stderr="")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            result = tool.verify_rpm(package, "linux-amd64", pin=pin, runner=runner, key_path=keyfile)
            self.assertEqual(result["status"], "PASS")
            bad_signature_runner = lambda args, **kwargs: (
                SimpleNamespace(returncode=0, stdout=f"fpr:::::::::{fp}:\n", stderr="")
                if args[0] == "gpg" else
                SimpleNamespace(returncode=0, stdout="Header V4 RSA/SHA256 Signature, key ID aaaaaaaa: NOT OK\n",
                                 stderr="")
                if args[0] == "rpmkeys" else
                SimpleNamespace(returncode=0, stdout=profile["nevra"], stderr="")
            )
            with self.assertRaisesRegex(tool.SkopeoError, "signature or payload digest"):
                tool.verify_rpm(package, "linux-amd64", pin=pin, runner=bad_signature_runner,
                                key_path=keyfile)
            package.write_bytes(b"corrupt")
            with self.assertRaisesRegex(tool.SkopeoError, "SHA-256"):
                tool.verify_rpm(package, "linux-amd64", pin=pin, runner=runner, key_path=keyfile)


if __name__ == "__main__":
    unittest.main()
