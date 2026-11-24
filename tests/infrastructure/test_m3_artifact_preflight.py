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
    def test_image_lock_accepts_the_exact_release_workflow_repository_names(self):
        with tempfile.TemporaryDirectory(prefix="kordex-test-only-image-lock-") as temporary:
            lock = Path(temporary) / "images.tsv"
            rows = [f"{name}\tghcr.io/kevin-phan-25/kordex-{name}@sha256:{index:064x}"
                    for index, name in enumerate(preflight.REQUIRED_KORDEX_IMAGES, start=1)]
            lock.write_text("\n".join(rows) + "\n", encoding="utf-8")
            parsed = preflight.strict_image_lock(lock)
            self.assertEqual([item["name"] for item in parsed], list(preflight.REQUIRED_KORDEX_IMAGES))
            self.assertEqual([item["reference"] for item in parsed], [row.split("\t", 1)[1] for row in rows])

    def test_image_lock_rejects_unrelated_repository_suffix_even_when_digest_is_immutable(self):
        with tempfile.TemporaryDirectory(prefix="kordex-test-only-image-lock-") as temporary:
            lock = Path(temporary) / "images.tsv"
            rows = [f"{name}\tregistry.private.test/kordex/{name}@sha256:{index:064x}"
                    for index, name in enumerate(preflight.REQUIRED_KORDEX_IMAGES, start=1)]
            rows[0] = rows[0].replace("/agent@", "/different-agent@")
            lock.write_text("\n".join(rows) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(preflight.PreflightError, "mutable or invalid"):
                preflight.strict_image_lock(lock)

    def test_preflight_rollup_requires_all_mandatory_rows_and_is_deterministic(self):
        passing = {name: {"status": "PASS"} for name in preflight.REQUIRED_ARTIFACTS}
        failing = dict(passing, privateRegistryImages={"status": "FAIL"})
        incomplete = dict(passing)
        incomplete.pop("toolProvenancePublicTrust")
        incomplete["signedReleaseBundle"] = {"status": "NOT PROVIDED"}

        self.assertEqual(preflight.overall_status(passing), "PASS")
        self.assertEqual(preflight.overall_status(failing), "FAIL")
        self.assertEqual(preflight.overall_status(incomplete), "NOT PROVIDED")
        self.assertEqual(preflight.overall_status(incomplete), preflight.overall_status(incomplete))
        report = preflight.build_report({"schemaVersion": 1})
        self.assertEqual(report["overallStatus"], "NOT PROVIDED")
        self.assertEqual(report["profile"], "unselected")

    def test_go_verification_disables_public_module_and_toolchain_downloads(self):
        observed = {}

        def run(command, **kwargs):
            observed.update(kwargs["env"])
            return subprocess.CompletedProcess(command, 0, "verified fixture", "")

        result = preflight.run_checked(["go", "run", "./cmd/kordex-artifact-lock"],
                                       env={"GOPROXY": "https://public.example", "GOSUMDB": "public",
                                            "GOTOOLCHAIN": "auto"}, run=run)
        self.assertEqual(result, "verified fixture")
        self.assertEqual(observed["GOPROXY"], "off")
        self.assertEqual(observed["GOSUMDB"], "off")
        self.assertEqual(observed["GOTOOLCHAIN"], "local")

    def test_missing_inputs_are_not_provided_and_report_is_deterministic(self):
        first = preflight.build_report({"schemaVersion": 1})
        second = preflight.build_report({"schemaVersion": 1})
        self.assertEqual(first, second)
        self.assertEqual(first["overallStatus"], "NOT PROVIDED")
        self.assertEqual({row["status"] for row in first["artifacts"].values()}, {"NOT PROVIDED"})
        self.assertNotIn("path", json.dumps(first).lower())

    def test_absent_signed_artifact_review_remains_not_provided(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = {"schemaVersion": 1, "release": {
                "campaignId": "m3-debian-test-campaign",
                "artifactOwners": {"image:ansible-ee": "designated-build-owner"},
                "artifactReview": {"record": str(root / "review.json"),
                                   "signature": str(root / "review.json.sig")}}}
            report = preflight.build_report(config)
            self.assertEqual(report["artifacts"]["independentApproval"]["status"], "NOT PROVIDED")
            self.assertEqual(report["overallStatus"], "NOT PROVIDED")

    def test_supplied_invalid_trust_is_fail_not_not_provided(self):
        with tempfile.TemporaryDirectory() as temp:
            trust = Path(temp) / "maintenance-public.json"
            trust.write_text('{"bad-key-id":"not-a-public-key"}', encoding="utf-8")
            config = {"schemaVersion": 1, "trust": {
                "maintenanceBundle": str(trust), "maintenanceExpectedKeyIds": ["a" * 64]}}
            first = preflight.build_report(config)
            second = preflight.build_report(config)
            self.assertEqual(first, second)
            self.assertEqual(first["overallStatus"], "FAIL")
            self.assertEqual(first["artifacts"]["maintenancePublicTrust"]["status"], "FAIL")
            self.assertEqual(first["artifacts"]["releasePublicTrust"]["status"], "NOT PROVIDED")

    def test_synthetic_manifest_cannot_claim_full_artifact_readiness(self):
        """Synthetic command doubles never satisfy the new signed metadata/attestation gates."""
        import base64

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def file(name, data=b"synthetic fixture only"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                return str(path)

            maintenance_key = b"m" * 32
            maintenance_id = hashlib.sha256(maintenance_key).hexdigest()
            maintenance = file("trust/maintenance.json", json.dumps({
                maintenance_id: base64.b64encode(maintenance_key).decode().rstrip("=")}).encode())
            artifact_key = b"a" * 32
            artifact_id = hashlib.sha256(artifact_key).hexdigest()
            artifact_trust = file("trust/artifact.trust", (
                "KORDEX-CUSTOMER-ARTIFACT-TRUST-V1\n" + artifact_id + " "
                + base64.b64encode(artifact_key).decode().rstrip("=") + "\n").encode())
            release_key = file("trust/release.pub")
            tool_key = file("trust/tool.pub")
            helm = file("trust/helm-signers.txt", b"synthetic signer allowlist\n")
            bundle_dir = root / "release-bundle"
            bundle_dir.mkdir()
            (bundle_dir / "SHA256SUMS").write_text("synthetic bundle manifest\n", encoding="utf-8")
            image_lock = root / "release-images.tsv"
            image_lock.write_text("".join(
                f"{name}\tregistry.private.test/platform/kordex/{name}@sha256:{index:064x}\n"
                for index, name in enumerate(preflight.REQUIRED_KORDEX_IMAGES, start=1)), encoding="utf-8")
            image_signature = file("release-images.tsv.sig")
            k3s_binary = file("k3s")
            k3s_lock = file("k3s.lock")
            k3s_signature = file("k3s.lock.sig")
            system_bundle = file("k3s-airgap-images-amd64.tar")
            system_lock = file("k3s-system-images.lock")
            system_signature = file("k3s-system-images.lock.sig")
            auth_file = file("secrets/registry-auth.json")
            Path(auth_file).chmod(0o600)
            package_policy = file("ubuntu/policy.json")
            package_archive = file("ubuntu/packages.tar")
            release_fingerprint, tool_fingerprint = "1" * 64, "2" * 64
            system_images = [{
                "SourceReference": f"docker.io/rancher/image-{index}:v1",
                "MirrorReference": f"registry.private.test/rancher/image-{index}:v1",
                "Digest": f"sha256:{index:064x}",
            } for index in range(1, 9)]
            verified_k3s = {
                "version": preflight.EXPECTED_K3S, "architecture": preflight.EXPECTED_ARCH,
                "approvedAt": "2026-11-21T12:00:00Z", "digest": "3" * 64,
                "mirrorReference": "https://mirror.private.test/k3s/v1.36.6+k3s1/linux-amd64/k3s",
                "signerKeyId": artifact_id,
            }
            verified_system = {
                "manifestVersion": "1", "k3sVersion": preflight.EXPECTED_K3S,
                "architecture": preflight.EXPECTED_ARCH, "bundleSha256": "4" * 64,
                "bundleMirrorReference": "https://mirror.private.test/k3s/v1.36.6+k3s1/linux-amd64/"
                    + "4" * 64 + "/k3s-airgap-images-amd64.tar",
                "mirrorHost": "registry.private.test", "signerKeyId": artifact_id,
                "approvedAt": "2026-11-21T12:00:00Z", "images": system_images,
            }
            config = {
                "schemaVersion": 1,
                "trust": {
                    "maintenanceBundle": maintenance, "maintenanceExpectedKeyIds": [maintenance_id],
                    "artifactApprovalBundle": artifact_trust, "artifactApprovalExpectedKeyIds": [artifact_id],
                    "artifactApprovalMaxAgeDays": 30, "releasePublicKey": release_key,
                    "releaseExpectedFingerprint": release_fingerprint, "toolProvenancePublicKey": tool_key,
                    "toolProvenanceExpectedFingerprint": tool_fingerprint, "helmSignerAllowlist": helm,
                },
                "release": {"bundleDirectory": str(bundle_dir), "imageDigestLock": str(image_lock),
                            "imageDigestSignature": str(image_signature)},
                "k3sBinary": {"binary": k3s_binary, "lock": k3s_lock, "signature": k3s_signature,
                              "trustBundle": artifact_trust},
                "k3sSystemImages": {"bundle": system_bundle, "lock": system_lock,
                                    "signature": system_signature, "trustBundle": artifact_trust},
                "network": {"privateMirrorCIDRs": ["10.80.0.0/24"]},
                "privateRegistry": {"host": "registry.private.test", "privateCIDRs": ["10.81.0.0/24"],
                                    "authFile": auth_file},
                "packageArtifacts": {"policy": package_policy, "archive": package_archive},
            }

            def fake_run_checked(command, **_kwargs):
                if command[0] == "go" and "system-images" in command:
                    return json.dumps(verified_system)
                if command[0] == "go":
                    return json.dumps(verified_k3s)
                if command[0] == "python3" and command[1].endswith("verify-private-registry.py"):
                    system_rows = [{
                        "name": f"k3s-{index:02d}", "reference": image["MirrorReference"],
                        "expectedDigest": image["Digest"].removeprefix("sha256:"),
                        "observedDigest": image["Digest"].removeprefix("sha256:"),
                        "architecture": "linux/amd64", "status": "PASS",
                    } for index, image in enumerate(system_images, start=1)]
                    kordex_rows = [{
                        "name": item["name"], "reference": item["reference"],
                        "expectedDigest": item["reference"].rsplit("@sha256:", 1)[1],
                        "observedDigest": item["reference"].rsplit("@sha256:", 1)[1],
                        "architecture": "linux/amd64", "status": "PASS",
                    } for item in preflight.strict_image_lock(image_lock)]
                    report_path = Path(command[command.index("--output") + 1])
                    report_path.write_text(json.dumps({
                        "schemaVersion": 1, "registryHost": "registry.private.test",
                        "architecture": "linux/amd64", "images": system_rows + kordex_rows,
                        "status": "PASS",
                    }), encoding="utf-8")
                return ""

            with patch.object(preflight, "public_key_fingerprint", side_effect=lambda _path, expected, _run: {"fingerprint": expected}), \
                    patch.object(preflight, "run_checked", side_effect=fake_run_checked), \
                    patch.object(preflight, "validate_private_https", return_value=["10.80.0.5"]), \
                    patch.object(preflight, "request_private_https", side_effect=lambda _url, _addresses, *, expected_sha256, **_kwargs: {"sha256": expected_sha256}), \
                    patch.object(preflight, "verify_package_inputs", return_value={
                        "architecture": "linux/amd64", "packages": [],
                        "policySha256": "5" * 64, "packageArchiveSha256": "6" * 64,
                    }):
                now = dt.datetime(2026, 11, 21, 13, tzinfo=dt.timezone.utc)
                first = preflight.build_report(config, now=now)
                second = preflight.build_report(config, now=now)

            self.assertEqual(first, second)
            self.assertEqual(first["overallStatus"], "NOT PROVIDED")
            self.assertEqual(first["artifacts"]["privateRegistryImages"]["imageCount"], 14)
            self.assertEqual(first["checks"]["structuralManifestValidation"]["status"], "PASS")
            self.assertEqual(first["checks"]["repositoryMetadataVerification"]["status"], "NOT PROVIDED")
            self.assertEqual(first["checks"]["imageSBOMVerification"]["status"], "NOT PROVIDED")
            self.assertEqual(first["checks"]["imageProvenanceVerification"]["status"], "NOT PROVIDED")
            self.assertEqual(first["checks"]["independentApproval"]["status"], "NOT PROVIDED")
            self.assertNotIn(auth_file, json.dumps(first))

    def test_basic_structural_input_does_not_imply_cryptographic_artifact_readiness(self):
        report = preflight.build_report({"schemaVersion": 1})
        self.assertEqual(report["checks"]["structuralManifestValidation"]["status"], "PASS")
        self.assertEqual(report["checks"]["repositoryMetadataVerification"]["status"], "NOT PROVIDED")
        self.assertEqual(report["checks"]["imageSBOMVerification"]["status"], "NOT PROVIDED")
        self.assertEqual(report["checks"]["imageProvenanceVerification"]["status"], "NOT PROVIDED")
        self.assertEqual(report["overallStatus"], "NOT PROVIDED")

    def test_package_preflight_reports_repository_metadata_as_distinct_cryptographic_check(self):
        config = {"schemaVersion": 1, "packageArtifacts": {
            "policy": "/unused/policy.json", "archive": "/unused/packages.tar",
            "privateMirrorURL": "https://mirror.customer.test/debian/",
            "repositoryMetadata": {"family": "debian", "keyring": "/unused/repo.gpg",
                "approvedFingerprints": ["A" * 40], "maxAgeSeconds": 3600,
                "repositories": [{}]}}}
        details = {"policySha256": "1" * 64, "packageArchiveSha256": "2" * 64,
                   "repositorySnapshotID": "snapshot-1", "osFamily": "debian", "packages": []}
        verified = {"family": "debian", "keyringSha256": "3" * 64,
                    "repositories": [], "verifiedPackageCount": 0, "packages": []}
        with patch.object(preflight, "verify_package_inputs", return_value=details), \
             patch.object(preflight.m3_supply_chain_verify, "verify_debian_repositories", return_value=verified), \
             patch.object(preflight, "hash_file", return_value="3" * 64):
            report = preflight.build_report(config)
        self.assertEqual(report["artifacts"]["hostPackageArtifacts"]["status"], "PASS")
        self.assertEqual(report["checks"]["repositoryMetadataVerification"]["status"], "PASS")
        self.assertNotEqual(report["overallStatus"], "PASS")

    def test_signed_image_lock_flows_into_separate_sbom_and_provenance_report_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image_lock = root / "images.tsv"
            image_lock.write_text("test-only lock fixture\n", encoding="utf-8")
            image_sig = root / "images.tsv.sig"
            image_sig.write_bytes(b"test-only signature fixture")
            release_key = root / "release.pub"
            release_key.write_bytes(b"test-only public-key fixture")
            trust_root = root / "sigstore-trusted-root.jsonl"
            trust_root.write_bytes(b"test-only trust-root fixture\n")
            locked = [{"name": name,
                       "reference": f"ghcr.io/kevin-phan-25/kordex/{name}@sha256:{index:064x}"}
                      for index, name in enumerate(preflight.REQUIRED_KORDEX_IMAGES, start=1)]
            entries = {}
            image_results = {}
            for row in locked:
                name = row["name"]
                sbom = root / f"{name}.cdx.json"
                sbom_bundle = root / f"{name}.sbom.bundle.jsonl"
                provenance_bundle = root / f"{name}.provenance.bundle.jsonl"
                for path in (sbom, sbom_bundle, provenance_bundle):
                    path.write_bytes(b"test-only fixture; never qualification evidence")
                entries[name] = {"sbom": str(sbom), "sbomBundle": str(sbom_bundle),
                                 "provenanceBundle": str(provenance_bundle),
                                 "sourceRef": "refs/tags/v1.2.3", "sourceCommit": "a" * 40,
                                 "buildMaterials": [{"uri": "pkg:docker/base@sha256:" + "f" * 64,
                                                     "digest": {"sha256": "f" * 64}}]}
                image_results[name] = {"imageRef": row["reference"], "imageDigest": "a" * 64,
                    "sbomSha256": "b" * 64, "sbomComponentCount": 1,
                    "trustedRootSha256": hashlib.sha256(trust_root.read_bytes()).hexdigest(),
                    "sbomBundleSha256": "c" * 64,
                    "sbomAttestationBundleSha256": "c" * 64,
                    "sbomAttestationVerifiedAt": "2026-11-23T11:00:00Z",
                    "provenanceBundleSha256": "d" * 64,
                    "provenanceAttestationBundleSha256": "d" * 64,
                    "provenanceAttestationVerifiedAt": "2026-11-23T11:00:00Z",
                    "sourceRepository": "kevin-phan-25/kordex", "sourceRef": "refs/tags/v1.2.3",
                    "sourceCommit": "a" * 40,
                    "builderId": preflight.m3_supply_chain_verify.EXPECTED_BUILDER_ID,
                    "workflowIdentity": preflight.m3_supply_chain_verify.WORKFLOW_IDENTITY,
                    "materials": [{"uri": "pkg:docker/base@sha256:" + "f" * 64,
                                   "digest": {"sha256": "f" * 64}}],
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1"}
            config = {"schemaVersion": 1,
                "trust": {"releasePublicKey": str(release_key),
                          "releaseExpectedFingerprint": "1" * 64},
                "release": {
                "imageDigestLock": str(image_lock), "imageDigestSignature": str(image_sig),
                "sigstoreTrustedRoot": str(trust_root),
                "sigstoreTrustedRootSHA256": hashlib.sha256(trust_root.read_bytes()).hexdigest(),
                "imageAttestationMaxAgeDays": 30, "imageAttestations": entries}}
            attestation_result = {"imageCount": 6, "trustedRootSha256": hashlib.sha256(trust_root.read_bytes()).hexdigest(),
                                  "images": image_results}
            with patch.object(preflight, "public_key_fingerprint", return_value={"fingerprint": "1" * 64}), \
                 patch.object(preflight, "run_checked", return_value="verified test fixture"), \
                 patch.object(preflight, "strict_image_lock", return_value=locked), \
                 patch.object(preflight.m3_supply_chain_verify, "verify_image_attestations",
                              return_value=attestation_result):
                report = preflight.build_report(config, now=dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc))
            self.assertEqual(report["artifacts"]["signedImageDigestLock"]["status"], "PASS")
            self.assertEqual(report["checks"]["imageSBOMVerification"]["status"], "PASS")
            self.assertEqual(report["checks"]["imageProvenanceVerification"]["status"], "PASS")
            self.assertEqual(report["checks"]["independentApproval"]["status"], "NOT PROVIDED")
            self.assertEqual(report["overallStatus"], "NOT PROVIDED")

            sbom_rows = {name: {key: row[key] for key in (
                "imageRef", "imageDigest", "sbomSha256", "sbomComponentCount",
                "sbomBundleSha256", "sbomAttestationVerifiedAt", "trustedRootSha256")}
                for name, row in image_results.items()}
            for phase_error, expected_sbom, expected_provenance in (
                    (preflight.m3_supply_chain_verify.ImageVerificationError(
                        "sbom", "agent", FileNotFoundError(), missing=True), "NOT PROVIDED", "NOT PROVIDED"),
                    (preflight.m3_supply_chain_verify.ImageVerificationError(
                        "sbom", "agent", ValueError(), missing=False), "FAIL", "NOT PROVIDED"),
                    (preflight.m3_supply_chain_verify.ImageVerificationError(
                        "provenance", "agent", FileNotFoundError(), missing=True,
                        sbom_results=sbom_rows), "PASS", "NOT PROVIDED"),
                    (preflight.m3_supply_chain_verify.ImageVerificationError(
                        "provenance", "agent", ValueError(), missing=False,
                        sbom_results=sbom_rows), "PASS", "FAIL")):
                with patch.object(preflight, "public_key_fingerprint", return_value={"fingerprint": "1" * 64}), \
                     patch.object(preflight, "run_checked", return_value="verified test fixture"), \
                     patch.object(preflight, "strict_image_lock", return_value=locked), \
                     patch.object(preflight.m3_supply_chain_verify, "verify_image_attestations",
                                  side_effect=phase_error):
                    partial = preflight.build_report(
                        config, now=dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc))
                self.assertEqual(partial["checks"]["imageSBOMVerification"]["status"], expected_sbom)
                self.assertEqual(partial["checks"]["imageProvenanceVerification"]["status"],
                                 expected_provenance)
                self.assertNotEqual(partial["overallStatus"], "PASS")

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
            unicode_path = Path(temp) / "unicode.json"
            unicode_report = {"reviewText": "Trixie café"}
            report_digest = preflight.write_report(unicode_path, unicode_report)
            self.assertEqual(unicode_path.read_bytes(), preflight.m3_artifact_review.canonical_json(unicode_report))
            self.assertEqual(report_digest, hashlib.sha256(unicode_path.read_bytes()).hexdigest())

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
            self.assertTrue(all(not any(key.lower().endswith("_proxy") or key.lower() == "no_proxy"
                                        for key in c[1]["env"]) for c in calls))
            self.assertTrue(any(c[0][1] == "copy" and c[0][-1].startswith("oci:") for c in calls))
            docker_references = [part.removeprefix("docker://") for c in calls for part in c[0]
                                 if part.startswith("docker://")]
            self.assertTrue(docker_references)
            self.assertTrue(all(reference.startswith("registry.private.test/") for reference in docker_references))
            go_env = registry.offline_go_environment()
            self.assertEqual((go_env["GOPROXY"], go_env["GOSUMDB"], go_env["GOTOOLCHAIN"]),
                             ("off", "off", "local"))
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
            config = {"packageArtifacts": {"policy": str(policy_path), "archive": str(archive),
                       "approvedPolicySHA256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                       "baselineVersions": {"openssl": "3.0.1-1"},
                       "repositorySnapshotID": "ubuntu-noble-snapshot-2026-11-21",
                       "osPointRelease": "",
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
            config["packageArtifacts"]["baselineVersions"]["openssl"] = "3.0.2-1"
            with patch.object(preflight, "validate_private_https", return_value=["10.80.0.7"]), \
                 patch.object(preflight, "request_private_https", side_effect=download), \
                 self.assertRaisesRegex(preflight.PreflightError, "no real package version change"):
                preflight.verify_package_inputs(config, run=lambda *_args, **_kwargs:
                    subprocess.CompletedProcess([], 0, "openssl\n3.0.2-1\namd64\n", ""))

    def test_debian13_package_preflight_binds_deb_metadata_arch_and_real_delta(self):
        """Synthetic .deb fixture confirms Debian 13 Trixie identity, not a customer artifact."""
        package_bytes = b"synthetic Debian 13 Trixie .deb fixture; not a customer artifact"
        digest = hashlib.sha256(package_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy_path = root / "policy.json"
            policy = {
                "apiVersion": "operations.kordex.local/v1alpha1", "kind": "MaintenancePolicy",
                    "metadata": {"name": "debian-fixture"}, "spec": {"upgrade": {
                    "schemaVersion": 2, "id": "debian-fixture", "osFamily": "debian", "osId": "debian",
                    "osMajor": "13", "osMinor": "", "osPointRelease": "13.8", "executionBackend": "ansible-ee",
                    "playbookCatalogId": "kordex.os-upgrade.debian.v2",
                    "executionEnvironment": "registry.example/kordex/ee@sha256:" + "a" * 64,
                    "playbookDigest": "b" * 64, "collectionsDigest": "c" * 64, "actionMarkerVersion": 1,
                    "artifactMode": "OfflineArtifacts",
                    "packages": [{"name": "openssl", "version": "3.0.2-1", "artifactSHA256": digest}],
                    "channel": "stable", "reboot": "Never", "executionTimeout": 60_000_000_000,
                    "rebootTimeout": 60_000_000_000, "verificationTimeout": 60_000_000_000, "maxAttempts": 1,
                }}}
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            package_path = root / "openssl.deb"
            package_path.write_bytes(package_bytes)
            archive = root / "packages.tar"
            builder.build(policy_path, [f"openssl={package_path}"], archive)
            config = {"packageArtifacts": {
                "policy": str(policy_path), "archive": str(archive),
                "approvedPolicySHA256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                "baselineVersions": {"openssl": "3.0.1-1"},
                "repositorySnapshotID": "debian-trixie-snapshot-2026-11-21T00:00Z",
                "osPointRelease": "13.8",
                "privateMirrorURL": "https://mirror.customer.test/debian/",
                "privateMirrorCIDRs": ["10.80.0.0/24"],
            }}

            def download(_url, _addresses, *, destination, expected_sha256, **_kwargs):
                destination.write_bytes(archive.read_bytes())
                return {"status": 200, "sha256": expected_sha256, "size": archive.stat().st_size}

            with patch.object(preflight, "validate_private_https", return_value=["10.80.0.7"]), \
                    patch.object(preflight, "request_private_https", side_effect=download):
                result = preflight.verify_package_inputs(config, run=lambda *_args, **_kwargs:
                    subprocess.CompletedProcess([], 0, "openssl\n3.0.2-1\namd64\n", ""))
            self.assertEqual(result["profile"], "m3-debian-13-k3s-v1.36.6+k3s1-linux-amd64")
            self.assertEqual(result["osId"], "debian")
            self.assertEqual(result["osMajor"], "13")
            self.assertEqual(result["osMinor"], "")
            self.assertEqual(result["osPointRelease"], "13.8")
            self.assertEqual(result["architecture"], "linux/amd64")
            self.assertEqual(result["packages"][0]["sha256"], digest)
            self.assertEqual(result["packages"][0]["baselineVersion"], "3.0.1-1")
            self.assertEqual(result["repositorySnapshotID"], "debian-trixie-snapshot-2026-11-21T00:00Z")

    def test_rhel_package_preflight_verifies_signed_policy_bound_rpm_metadata(self):
        """Synthetic RPM bytes and metadata exercise the RHEL verifier only."""
        package_bytes = b"synthetic RPM bytes; not a customer artifact"
        digest = hashlib.sha256(package_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy_path = root / "policy.json"
            policy = {
                "apiVersion": "operations.kordex.local/v1alpha1", "kind": "MaintenancePolicy",
                "metadata": {"name": "fixture"}, "spec": {"upgrade": {
                    "schemaVersion": 2, "id": "fixture-rhel", "osFamily": "rhel", "osId": "rhel",
                    "osMajor": "9", "osMinor": "8", "osPointRelease": "9.8", "executionBackend": "ansible-ee",
                    "playbookCatalogId": "kordex.os-upgrade.rhel.v1",
                    "executionEnvironment": "registry.example/kordex/ee@sha256:" + "a" * 64,
                    "playbookDigest": "b" * 64, "collectionsDigest": "c" * 64, "actionMarkerVersion": 1,
                    "artifactMode": "OfflineArtifacts",
                    "packages": [{"name": "openssl", "version": "3.0.2-1.el9", "artifactSHA256": digest}],
                    "channel": "stable", "reboot": "Never", "executionTimeout": 60_000_000_000,
                    "rebootTimeout": 60_000_000_000, "verificationTimeout": 60_000_000_000, "maxAttempts": 1,
                }}}
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            package_path = root / "openssl.rpm"
            package_path.write_bytes(package_bytes)
            archive = root / "packages.tar"
            builder.build(policy_path, [f"openssl={package_path}"], archive)
            config = {"packageArtifacts": {
                "policy": str(policy_path), "archive": str(archive),
                "approvedPolicySHA256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                "baselineVersions": {"openssl": "3.0.1-1.el9"},
                "repositorySnapshotID": "rhel9-snapshot-9.8-customer-17",
                "osPointRelease": "9.8",
                "privateMirrorURL": "https://mirror.customer.test/rhel/9.8/",
                "privateMirrorCIDRs": ["10.80.0.0/24"],
            }}

            def download(_url, _addresses, *, destination, expected_sha256, **_kwargs):
                destination.write_bytes(archive.read_bytes())
                return {"status": 200, "sha256": expected_sha256, "size": archive.stat().st_size}

            def rpm_metadata(command, **_kwargs):
                self.assertEqual(command[0:2], ["rpm", "-qp"])
                return subprocess.CompletedProcess(command, 0, "openssl\n0:3.0.2-1.el9\nx86_64\n", "")

            with patch.object(preflight, "validate_private_https", return_value=["10.80.0.7"]), \
                 patch.object(preflight, "request_private_https", side_effect=download):
                result = preflight.verify_package_inputs(config, run=rpm_metadata)
                with self.assertRaisesRegex(preflight.PreflightError, "architecture differs"):
                    preflight.verify_package_inputs(config, run=lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, "openssl\n0:3.0.2-1.el9\namd64\n", ""))
            self.assertEqual(result["osId"], "rhel")
            self.assertEqual(result["profile"], "m3-rhel-9.8-k3s-v1.36.6+k3s1-linux-amd64")
            self.assertEqual(result["packages"][0]["architecture"], "x86_64")

    def test_debian12_rhel97_and_compatible_derivatives_are_not_canonical_package_profiles(self):
        for identity in (("debian", "12", ""), ("rhel", "9", "7"),
                         ("rocky", "9", "9"), ("almalinux", "9", "9")):
            with self.subTest(identity=identity):
                self.assertIsNone(preflight.supported_package_os(*identity))
        self.assertEqual(preflight.supported_package_os("debian", "13", ""), "debian")
        self.assertEqual(preflight.supported_package_os("rhel", "9", "8"), "rhel")
        self.assertEqual(preflight.supported_package_os("rhel", "9", "9"), "rhel")


if __name__ == "__main__":
    unittest.main()
