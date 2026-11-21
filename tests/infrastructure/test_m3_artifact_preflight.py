import hashlib
import importlib.util
import json
import datetime as dt
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


preflight = load("m3_artifact_preflight", "m3_artifact_preflight.py")
registry = load("verify_private_registry", "verify-private-registry.py")
builder = load("package_artifact_builder", "build-offline-package-artifacts.py")


class ArtifactPreflightTests(unittest.TestCase):
    def test_missing_inputs_are_not_provided_and_report_is_deterministic(self):
        first = preflight.build_report({"schemaVersion": 1})
        second = preflight.build_report({"schemaVersion": 1})
        self.assertEqual(first, second)
        self.assertEqual(first["overallStatus"], "NOT PROVIDED")
        self.assertEqual({row["status"] for row in first["artifacts"].values()}, {"NOT PROVIDED"})
        self.assertNotIn("path", json.dumps(first).lower())

    def test_report_serialization_is_repeatable_and_private(self):
        report = preflight.build_report({"schemaVersion": 1})
        with tempfile.TemporaryDirectory() as temp:
            first_path = Path(temp) / "first.json"
            second_path = Path(temp) / "second.json"
            first_hash = preflight.write_report(first_path, report)
            second_hash = preflight.write_report(second_path, report)
            self.assertEqual(first_hash, second_hash)
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            self.assertEqual(first_path.stat().st_mode & 0o777, 0o600)

    def test_cli_reports_missing_inputs_as_not_provided_and_repeatable(self):
        with tempfile.TemporaryDirectory() as temp:
            inputs = Path(temp) / "inputs.json"
            report = Path(temp) / "report.json"
            inputs.write_text('{"schemaVersion":1}', encoding="utf-8")
            reports = []
            for _ in range(2):
                result = subprocess.run([sys.executable, str(ROOT / "scripts/m3_artifact_preflight.py"),
                                         "--inputs", str(inputs), "--report", str(report)],
                                        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(str(inputs), result.stdout + result.stderr)
                self.assertNotIn("auth", result.stdout.lower())
                reports.append(report.read_bytes())
                self.assertIn(hashlib.sha256(reports[-1]).hexdigest(), result.stdout)
            self.assertEqual(reports[0], reports[1])
            self.assertEqual(json.loads(reports[0])["overallStatus"], "NOT PROVIDED")

    def test_maintenance_public_trust_checks_key_id_and_fingerprint(self):
        import base64

        raw = hashlib.sha256(b"synthetic public-key fixture only").digest()
        key_id = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "maintenance-public.json"
            bundle.write_text(json.dumps({key_id: base64.b64encode(raw).decode().rstrip("=")}), encoding="utf-8")
            result = preflight.verify_public_ed25519_bundle(bundle, [key_id])
            self.assertEqual(result["keyIds"], [key_id])
            with self.assertRaises(preflight.PreflightError):
                preflight.verify_public_ed25519_bundle(bundle, ["0" * 64])

    def test_customer_artifact_trust_checks_canonical_sorted_ids(self):
        key_a = b"a" * 32
        key_b = b"b" * 32
        id_a, id_b = hashlib.sha256(key_a).hexdigest(), hashlib.sha256(key_b).hexdigest()
        records = sorted(((id_a, key_a), (id_b, key_b)))
        with tempfile.TemporaryDirectory() as temp:
            trust = Path(temp) / "artifact.trust"
            trust.write_text("KORDEX-CUSTOMER-ARTIFACT-TRUST-V1\n" + "".join(
                f"{key_id} {__import__('base64').b64encode(key).decode().rstrip('=')}\n" for key_id, key in records), encoding="ascii")
            self.assertEqual(preflight.verify_artifact_trust(trust, [item[0] for item in records])["keyIds"], [item[0] for item in records])
            trust.write_text("KORDEX-CUSTOMER-ARTIFACT-TRUST-V1\n" + "".join(
                f"{key_id} {__import__('base64').b64encode(key).decode().rstrip('=')}\n" for key_id, key in reversed(records)), encoding="ascii")
            with self.assertRaises(preflight.PreflightError):
                preflight.verify_artifact_trust(trust, [item[0] for item in records])

    def test_private_endpoint_requires_https_and_private_allowed_dns(self):
        def resolver(host, port, type):
            return [(None, None, None, None, ("10.20.0.7", port))]

        ips = preflight.validate_private_https("https://mirror.customer.test/ubuntu/", ["10.20.0.0/24"], resolver)
        self.assertEqual(ips, ["10.20.0.7"])
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_private_https("http://mirror.customer.test/", ["10.20.0.0/24"], resolver)
        for ambiguous in ("https://mirror.customer.test/a/../packages.tar",
                          "https://mirror.customer.test/a/%2f../packages.tar",
                          "https://mirror.customer.test/a/%252e%252e/packages.tar"):
            with self.assertRaises(preflight.PreflightError):
                preflight.validate_private_https(ambiguous, ["10.20.0.0/24"], resolver)
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_private_https("https://mirror.customer.test/", ["10.20.0.0/24"],
                                             lambda *_args, **_kwargs: [(None, None, None, None, ("8.8.8.8", 443))])

    def test_private_https_download_checks_digest_and_removes_mismatched_file(self):
        payload = b"synthetic private archive fixture"

        class Response:
            status = 200

            def __init__(self):
                self.body = payload

            def getheader(self, _name):
                return str(len(payload))

            def read(self, _limit):
                body, self.body = self.body, b""
                return body

        class Connection:
            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "bundle.tar"
            expected = hashlib.sha256(payload).hexdigest()
            result = preflight.request_private_https(
                "https://mirror.customer.test/bundle.tar", ["10.20.0.7"],
                expected_sha256=expected, destination=destination,
                connection_factory=lambda *_args, **_kwargs: Connection())
            self.assertEqual(result["sha256"], expected)
            self.assertEqual(destination.read_bytes(), payload)
            destination.unlink()
            with self.assertRaisesRegex(preflight.PreflightError, "digest differs"):
                preflight.request_private_https(
                    "https://mirror.customer.test/bundle.tar", ["10.20.0.7"],
                    expected_sha256="0" * 64, destination=destination,
                    connection_factory=lambda *_args, **_kwargs: Connection())
            self.assertFalse(destination.exists())

    def test_registry_verifies_digest_architecture_and_uses_external_authfile(self):
        with tempfile.TemporaryDirectory() as temp:
            auth = Path(temp) / "auth.json"
            auth.write_text("synthetic external auth fixture", encoding="utf-8")
            auth.chmod(0o600)
            raw = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}'
            expected = hashlib.sha256(raw).hexdigest()
            calls = []

            def run(args, **kwargs):
                calls.append((args, kwargs))
                stdout = raw.decode() if "--raw" in args else '{"os":"linux","architecture":"amd64"}'
                return subprocess.CompletedProcess(args, 0, stdout, "")

            report = registry.verify_images([{"name": "k3s-01", "mirrorReference": "registry.private.test/rancher/x:v1",
                                              "digest": "sha256:" + expected}],
                                            "registry.private.test", auth, run=run)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(len(calls), 3)
            self.assertTrue(all(any(part.startswith("--authfile=") for part in c[0]) for c in calls))
            self.assertTrue(all(c[1]["stderr"] == subprocess.DEVNULL for c in calls))
            self.assertFalse(any("synthetic external auth fixture" in str(item) for item in calls))
            self.assertTrue(any(c[0][1] == "copy" and c[0][-2].endswith("@sha256:" + expected) for c in calls))
            self.assertNotIn("synthetic external auth fixture", json.dumps(report))

    def test_registry_rejects_missing_or_insecure_authfile(self):
        with tempfile.TemporaryDirectory() as temp:
            auth = Path(temp) / "auth.json"
            with self.assertRaises(registry.RegistryError):
                registry.safe_auth_file(auth)
            auth.write_text("fixture", encoding="utf-8")
            auth.chmod(0o644)
            with self.assertRaises(registry.RegistryError):
                registry.safe_auth_file(auth)

    def test_registry_rejects_digest_arch_auth_and_public_reference_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            auth = Path(temp) / "auth.json"
            auth.write_text("fixture", encoding="utf-8")
            auth.chmod(0o600)
            raw = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}'

            def result(architecture="amd64", fail=False, fail_copy=False):
                def run(args, **kwargs):
                    if fail or (fail_copy and args[1] == "copy"):
                        raise subprocess.CalledProcessError(1, args, stderr="credential must not leak")
                    stdout = raw.decode() if "--raw" in args else json.dumps({"os": "linux", "architecture": architecture})
                    return subprocess.CompletedProcess(args, 0, stdout, "")
                return run

            base = {"name": "node", "mirrorReference": "registry.private.test/rancher/x:v1", "digest": hashlib.sha256(raw).hexdigest()}
            self.assertEqual(registry.verify_images([dict(base, digest="f" * 64)], "registry.private.test", auth,
                                                   run=result())["images"][0]["code"], "DigestMismatch")
            self.assertEqual(registry.verify_images([base], "registry.private.test", auth,
                                                   run=result(architecture="arm64"))["images"][0]["code"], "ArchitectureMismatch")
            self.assertEqual(registry.verify_images([base], "registry.private.test", auth,
                                                   run=result(fail=True))["images"][0]["code"], "RegistryUnavailableOrUnauthorized")
            self.assertEqual(registry.verify_images([base], "registry.private.test", auth,
                                                   run=result(fail_copy=True))["images"][0]["code"], "RegistryImageContentUnavailable")
            public = registry.verify_images([dict(base, mirrorReference="docker.io/rancher/x:v1")], "registry.private.test", auth)
            self.assertEqual(public["status"], "FAIL")
            with self.assertRaises(registry.RegistryError):
                registry.verify_images([], "registry.private.test", auth)

    def test_image_lock_rejects_mutable_public_and_path_traversal_refs(self):
        with tempfile.TemporaryDirectory() as temp:
            lock = Path(temp) / "images.tsv"
            refs = {name: f"registry.private.test/kordex/{name}@sha256:" + "a" * 64 for name in registry.KORDEX_IMAGES}
            lock.write_text("".join(f"{name}\t{refs[name]}\n" for name in registry.KORDEX_IMAGES), encoding="utf-8")
            self.assertEqual(len(registry.parse_image_lock(lock, "registry.private.test")), 6)
            refs["agent"] = "docker.io/kordex/agent@sha256:" + "a" * 64
            lock.write_text("".join(f"{name}\t{refs[name]}\n" for name in registry.KORDEX_IMAGES), encoding="utf-8")
            with self.assertRaises(registry.RegistryError):
                registry.parse_image_lock(lock, "registry.private.test")
            refs["agent"] = "registry.private.test/kordex/../kordex/agent@sha256:" + "a" * 64
            lock.write_text("".join(f"{name}\t{refs[name]}\n" for name in registry.KORDEX_IMAGES), encoding="utf-8")
            with self.assertRaises(registry.RegistryError):
                registry.parse_image_lock(lock, "registry.private.test")

    def test_input_schema_rejects_unknown_fields(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_input_schema({"schemaVersion": 1, "registryPassword": "do-not-accept"})
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_input_schema({"schemaVersion": 1, "privateRegistry": {"skopeo": "/tmp/untrusted-executable"}})
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_input_schema({"schemaVersion": 1, "k3sBinary": {"binary": 123}})
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_input_schema({"schemaVersion": 1, "trust": {"artifactApprovalMaxAgeDays": True}})

    def test_registry_report_must_match_exact_signed_inventory(self):
        system = {"images": [{"MirrorReference": f"registry.private.test/rancher/image-{n}:v1",
                               "Digest": "sha256:" + f"{n:064x}"} for n in range(8)]}
        kordex = [{"name": name, "reference": f"registry.private.test/kordex/{name}@sha256:" + "a" * 64}
                  for name in preflight.REQUIRED_KORDEX_IMAGES]
        rows = []
        for index, image in enumerate(system["images"], start=1):
            digest = image["Digest"].removeprefix("sha256:")
            rows.append({"name": f"k3s-{index:02d}", "reference": image["MirrorReference"],
                         "expectedDigest": digest, "observedDigest": digest, "architecture": "linux/amd64", "status": "PASS"})
        for image in kordex:
            digest = image["reference"].rsplit("@sha256:", 1)[1]
            rows.append({"name": image["name"], "reference": image["reference"], "expectedDigest": digest,
                         "observedDigest": digest, "architecture": "linux/amd64", "status": "PASS"})
        report = {"schemaVersion": 1, "registryHost": "registry.private.test", "architecture": "linux/amd64",
                  "images": rows, "status": "PASS"}
        self.assertEqual(preflight.validate_registry_report(report, system, kordex, "registry.private.test"), 14)
        with self.assertRaisesRegex(preflight.PreflightError, "missing or unexpected"):
            preflight.validate_registry_report(dict(report, images=rows[:-1]), system, kordex, "registry.private.test")
        changed = [dict(row) for row in rows]
        changed[0]["observedDigest"] = "b" * 64
        with self.assertRaisesRegex(preflight.PreflightError, "differs from the signed"):
            preflight.validate_registry_report(dict(report, images=changed), system, kordex, "registry.private.test")

    def test_customer_approval_expiry_is_explicit_and_fail_closed(self):
        now = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.timezone.utc)
        preflight.require_fresh_approval("2026-11-20T12:00:00Z", 30, now)
        for approved, days in (("2026-10-01T12:00:00Z", 30), ("2026-11-22T12:00:00Z", 30),
                               ("2026-11-20T12:00:00Z", None)):
            with self.assertRaises(preflight.PreflightError):
                preflight.require_fresh_approval(approved, days, now)

    def test_ubuntu_package_preflight_binds_policy_manifest_versions_arch_and_real_delta(self):
        package_bytes = b"synthetic .deb bytes for isolated validator test"
        digest = hashlib.sha256(package_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy_path = root / "policy.json"
            policy = {
                "apiVersion": "operations.kordex.local/v1alpha1", "kind": "MaintenancePolicy",
                "metadata": {"name": "fixture"}, "spec": {"upgrade": {
                    "schemaVersion": 2, "id": "fixture", "osFamily": "debian", "osId": "ubuntu",
                    "osMajor": "24", "osMinor": "04", "executionBackend": "ansible-ee",
                    "playbookCatalogId": "kordex.os-upgrade.debian.v2", "executionEnvironment": "registry.example/kordex/ee@sha256:" + "a" * 64,
                    "playbookDigest": "b" * 64, "collectionsDigest": "c" * 64, "actionMarkerVersion": 1,
                    "artifactMode": "OfflineArtifacts", "packages": [{"name": "openssl", "version": "3.0.2-1", "artifactSHA256": digest}],
                    "channel": "stable", "reboot": "Never", "executionTimeout": 60_000_000_000,
                    "rebootTimeout": 60_000_000_000, "verificationTimeout": 60_000_000_000, "maxAttempts": 1,
                }}}
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            package_path = root / "openssl.deb"
            package_path.write_bytes(package_bytes)
            archive = root / "packages.tar"
            builder.build(policy_path, [f"openssl={package_path}"], archive)
            config = {"ubuntuPackages": {"policy": str(policy_path), "archive": str(archive),
                       "approvedPolicySHA256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                       "baselineVersions": {"openssl": "3.0.1-1"},
                       "privateMirrorURL": "https://mirror.customer.test/ubuntu/",
                       "privateMirrorCIDRs": ["10.80.0.0/24"]}}
            def download(_url, _addresses, *, destination, expected_sha256, **_kwargs):
                destination.write_bytes(archive.read_bytes())
                return {"status": 200, "sha256": expected_sha256, "size": archive.stat().st_size}

            with patch.object(preflight, "validate_private_https", return_value=["10.80.0.7"]), \
                 patch.object(preflight, "request_private_https", side_effect=download):
                result = preflight.verify_package_inputs(config, run=lambda *_args, **_kwargs:
                    subprocess.CompletedProcess([], 0, "openssl\n3.0.2-1\namd64\n", ""))
            self.assertEqual(result["architecture"], "linux/amd64")
            self.assertEqual(result["packages"][0]["baselineVersion"], "3.0.1-1")
            self.assertEqual(result["packages"][0]["sha256"], digest)
            self.assertEqual(result["packageArchiveSha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            config["ubuntuPackages"]["baselineVersions"]["openssl"] = "3.0.2-1"
            with patch.object(preflight, "validate_private_https", return_value=["10.80.0.7"]), \
                 patch.object(preflight, "request_private_https", side_effect=download), \
                 self.assertRaisesRegex(preflight.PreflightError, "no real package version change"):
                preflight.verify_package_inputs(config, run=lambda *_args, **_kwargs:
                    subprocess.CompletedProcess([], 0, "openssl\n3.0.2-1\namd64\n", ""))


if __name__ == "__main__":
    unittest.main()
