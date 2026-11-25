"""Unit-only contract checks for the M3 offline lock ceremony; no keys/signatures are created."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import jsonschema

from scripts import m3_customer_trust as trust
from scripts import m3_offline_release_lock as ceremony
from scripts import m3_supply_chain_verify as supply


NOW = dt.datetime(2026, 11, 23, 12, 0, tzinfo=dt.timezone.utc)
FUTURE = "2026-12-20T00:00:00Z"
COMMIT = "a" * 40
TAG = "v1.2.3"


class KIQTReleaseSignerRoleTests(unittest.TestCase):
    def setUp(self):
        self.fingerprints = {}
        for identity in ("release-signer", "release-verifier", "security-custodian", "artifact-owner", "artifact-signer", "reviewer"):
            self.fingerprints[identity] = hashlib.sha256(identity.encode()).hexdigest()
        self.document = {"schemaVersion": 1, "customerId": "internal-lab-test-only", "sequence": 7,
                         "issuedAt": "2026-11-23T00:00:00Z", "expiresAt": FUTURE, "keys": []}
        roles = {"release-signer": "release-lock-signer", "release-verifier": "release-lock-verifier",
                 "security-custodian": "security-custodian",
                 "artifact-owner": "artifact-owner", "artifact-signer": "artifact-signer",
                 "reviewer": "reviewer"}
        for identity, role in roles.items():
            self.document["keys"].append({"identity": identity, "role": role,
                "fingerprint": self.fingerprints[identity], "publicKeyPem": f"fixture-public-{identity}",
                "validFrom": "2026-11-22T00:00:00Z", "validUntil": FUTURE, "revokedAt": None})
        self.document["releaseLockSigning"] = {
            "signerIdentity": "release-signer", "signerFingerprint": self.fingerprints["release-signer"],
            "signerSourceCommit": COMMIT, "verifierSourceCommit": "b" * 40,
        }
        self.document["releaseLockVerification"] = {
            "verifierIdentity": "release-verifier", "verifierFingerprint": self.fingerprints["release-verifier"],
            "sourceCommit": "b" * 40,
        }
        original = trust.fingerprint
        self.fingerprint_patch = patch.object(
            trust, "fingerprint", side_effect=lambda value: next(
                fp for identity, fp in self.fingerprints.items() if value == f"fixture-public-{identity}".encode()))
        self.fingerprint_patch.start()
        self.addCleanup(self.fingerprint_patch.stop)
        self.original_fingerprint = original

    def test_authorized_release_lock_signer_is_role_and_fingerprint_bound(self):
        result = trust.authorized_release_lock_signer(self.document, now=NOW)
        self.assertEqual(result["identity"], "release-signer")
        self.assertEqual(result["fingerprint"], self.fingerprints["release-signer"])
        self.assertEqual(result["sourceCommit"], COMMIT)
        self.assertEqual(result["verifierSourceCommit"], "b" * 40)
        verifier = trust.authorized_release_lock_verifier(self.document, now=NOW)
        self.assertEqual(verifier["identity"], "release-verifier")
        self.assertEqual(verifier["sourceCommit"], "b" * 40)

    def test_missing_or_unauthorized_release_signer_fails_closed(self):
        del self.document["releaseLockSigning"]
        del self.document["releaseLockVerification"]
        self.document["keys"] = [row for row in self.document["keys"] if row["role"] != "release-lock-signer"]
        self.document["keys"] = [row for row in self.document["keys"] if row["role"] != "release-lock-verifier"]
        with self.assertRaisesRegex(trust.TrustError, "designation is missing"):
            trust.authorized_release_lock_signer(self.document, now=NOW)

    def test_duplicate_release_signer_designation_is_rejected(self):
        self.document["keys"].append({"identity": "second-release-signer", "role": "release-lock-signer",
            "fingerprint": "e" * 64, "publicKeyPem": "fixture-public-second", "validFrom": "2026-11-22T00:00:00Z",
            "validUntil": FUTURE, "revokedAt": None})
        with patch.object(trust, "fingerprint", side_effect=lambda value: self.fingerprints[
                value.decode().removeprefix("fixture-public-")] if value != b"fixture-public-second" else "e" * 64):
            with self.assertRaisesRegex(trust.TrustError, "exactly one configured"):
                trust.validate_document(self.document, now=NOW)

    def test_expired_and_revoked_signer_are_rejected(self):
        signer = self.document["keys"][0]
        signer["validUntil"] = "2026-11-23T11:00:00Z"
        with self.assertRaisesRegex(trust.TrustError, "expired"):
            trust.authorized_release_lock_signer(self.document, now=NOW)
        signer["validUntil"] = FUTURE
        signer["revokedAt"] = "2026-11-23T11:00:00Z"
        with self.assertRaisesRegex(trust.TrustError, "revoked"):
            trust.authorized_release_lock_signer(self.document, now=NOW)

    def test_release_verifier_must_be_root_authorized_current_and_separate(self):
        result = trust.authorized_release_lock_verifier(self.document, now=NOW)
        self.assertEqual(result["identity"], "release-verifier")
        verifier = next(row for row in self.document["keys"] if row["role"] == "release-lock-verifier")
        verifier["validUntil"] = "2026-11-23T11:00:00Z"
        with self.assertRaisesRegex(trust.TrustError, "expired"):
            trust.authorized_release_lock_verifier(self.document, now=NOW)
        verifier["validUntil"] = FUTURE
        verifier["revokedAt"] = "2026-11-23T11:00:00Z"
        with self.assertRaisesRegex(trust.TrustError, "revoked"):
            trust.authorized_release_lock_verifier(self.document, now=NOW)
        verifier["revokedAt"] = None
        self.document["releaseLockVerification"]["sourceCommit"] = "c" * 40
        with self.assertRaisesRegex(trust.TrustError, "source revision"):
            trust.validate_document(self.document, now=NOW)

    def test_signing_requires_a_distinct_verifier_designation(self):
        del self.document["releaseLockVerification"]
        with self.assertRaisesRegex(trust.TrustError, "configured release-lock verifier designation"):
            trust.validate_document(self.document, now=NOW)
        self.document["releaseLockVerification"] = {
            "verifierIdentity": "release-verifier", "verifierFingerprint": "f" * 64,
            "sourceCommit": "b" * 40,
        }
        with self.assertRaisesRegex(trust.TrustError, "not root-authorized"):
            trust.validate_document(self.document, now=NOW)

    def test_release_signer_cannot_share_identity_or_key_with_reviewer_or_owner_roles(self):
        reviewer = next(row for row in self.document["keys"] if row["role"] == "reviewer")
        signer = next(row for row in self.document["keys"] if row["role"] == "release-lock-signer")
        self.fingerprints["release-signer"] = reviewer["fingerprint"]
        signer["fingerprint"] = reviewer["fingerprint"]
        self.document["releaseLockSigning"]["signerFingerprint"] = reviewer["fingerprint"]
        with self.assertRaisesRegex(trust.TrustError, "duplicate identities or key fingerprints"):
            trust.validate_document(self.document, now=NOW)


def verification_fixture():
    components = {}
    rows = []
    for name in ceremony.COMPONENTS:
        digest = hashlib.sha256(name.encode()).hexdigest()
        image = f"ghcr.io/kevin-phan-25/kordex-{name}@sha256:{digest}"
        rows.append(f"{name}\t{image}")
        components[name] = {
            "imageReference": image, "imageDigest": digest, "sbomSha256": "1" * 64,
            "sbomBundleSha256": "2" * 64, "provenanceBundleSha256": "3" * 64,
            "provenanceSubjectDigest": digest, "sourceRepository": "kevin-phan-25/kordex",
            "sourceRef": f"refs/tags/{TAG}", "sourceCommit": COMMIT,
            "builderId": "https://github.com/actions/runner/github-hosted",
            "workflowIdentity": "https://github.com/kevin-phan-25/kordex/.github/workflows/ci.yaml",
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "buildParameters": {"workflow": {"repository": "kevin-phan-25/kordex"}},
            "materials": [{"uri": "pkg:docker/base@sha256:" + "4" * 64,
                           "digest": {"sha256": "4" * 64}}],
            "sbomVerifiedAt": "2026-11-23T11:55:00Z", "provenanceVerifiedAt": "2026-11-23T11:55:00Z",
        }
    lock = ("\n".join(rows) + "\n").encode()
    repository_result = {"family": "debian", "keyringSha256": "d" * 64,
        "verifiedPackageCount": 1, "packages": [{"name": "fixture", "version": "1.0",
                                                    "sha256": "e" * 64}],
        "repositories": [{"repositoryId": "debian-main", "releaseSha256": "5" * 64,
            "signedMetadataSha256": ["6" * 64], "signatureSha256": ["7" * 64],
            "signatureMetadataSha256": ["8" * 64], "signerFingerprints": ["A" * 40],
            "indexes": [{"path": "main/binary-amd64/Packages", "sha256": "9" * 64, "bytes": 10}]}]}
    manifest = {
        "schemaVersion": 1, "kind": "kordex-m3-release-lock-verification", "status": "PASS",
        "campaign": "debian-13", "releaseTag": TAG, "sourceCommit": COMMIT,
        "workflowRun": {"id": "123456", "attempt": "1"},
        "verifier": {"sourceCommit": "b" * 40, "sourceTreeClean": True, "scriptSha256": "6" * 64},
        "trust": {"configurationSha256": "7" * 64, "rootFingerprint": "8" * 64,
                  "releaseLockSignerIdentity": "fixture-release-lock-signer", "releaseLockSignerFingerprint": "9" * 64,
                  "releaseLockVerifierIdentity": "fixture-release-lock-verifier",
                  "releaseLockVerifierFingerprint": "c" * 64,
                  "releaseLockVerifierSourceCommit": "b" * 40,
                  "signerSourceCommit": COMMIT, "verifierSourceCommit": "b" * 40},
        "trustState": {"sequence": 7, "configurationSha256": "7" * 64,
                       "backendIdentity": "fixture-trust-backend", "namespace": "fixture-production",
                       "attestationFingerprint": "e" * 64, "conformanceSha256": "f" * 64,
                       "rootFingerprint": "1" * 64, "rootSignatureSha256": "2" * 64,
                       "auditIds": ["fixture-audit-001"]},
        "sigstoreTrustedRootSha256": "a" * 64,
        "repositoryMetadata": {"resultSha256": hashlib.sha256(ceremony.canonical_json(repository_result)).hexdigest(),
                               "result": repository_result},
        "lockCandidateSha256": hashlib.sha256(lock).hexdigest(), "components": components,
        "inputSha256": {"verification-input-map": "a" * 64, "verification-input-map-file": "b" * 64,
                        "packagePolicy": "c" * 64, "sigstoreTrustedRoot": "d" * 64,
                        "repository-keyring": "e" * 64},
        "verifiedAt": "2026-11-23T12:00:00Z",
    }
    return lock, manifest


class OfflineLockManifestTests(unittest.TestCase):
    def test_valid_exact_six_component_manifest_matches_schema(self):
        lock, manifest = verification_fixture()
        ceremony._validate_manifest(manifest, lock, now=NOW)
        schema = json.loads(ceremony.SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(manifest)

    def test_incomplete_component_set_and_supplemental_relay_are_rejected(self):
        lock, manifest = verification_fixture()
        del manifest["components"]["postgres"]
        with self.assertRaisesRegex(ceremony.CeremonyError, "schema|exactly the six"):
            ceremony._validate_manifest(manifest, lock, now=NOW)
        lock, manifest = verification_fixture()
        manifest["components"]["agent-relay"] = {}
        with self.assertRaisesRegex(ceremony.CeremonyError, "schema|exactly the six"):
            ceremony._validate_manifest(manifest, lock, now=NOW)

    def test_mutable_or_changed_lock_candidate_is_rejected(self):
        lock, manifest = verification_fixture()
        mutable = lock.replace(b"@sha256:", b":latest@sha256:", 1)
        with self.assertRaises(ceremony.CeremonyError):
            ceremony._validate_manifest(manifest, mutable, now=NOW)
        with self.assertRaisesRegex(ceremony.CeremonyError, "digest is invalid"):
            ceremony._validate_manifest(manifest, lock + b"\n", now=NOW)

    def test_wrong_digest_source_or_component_identity_is_rejected(self):
        lock, manifest = verification_fixture()
        manifest["components"]["agent"]["imageDigest"] = "f" * 64
        with self.assertRaisesRegex(ceremony.CeremonyError, "component identity"):
            ceremony._validate_manifest(manifest, lock, now=NOW)
        lock, manifest = verification_fixture()
        manifest["components"]["agent"]["sourceCommit"] = "d" * 40
        with self.assertRaisesRegex(ceremony.CeremonyError, "component identity"):
            ceremony._validate_manifest(manifest, lock, now=NOW)

    def test_changed_verification_manifest_trust_binding_is_rejected(self):
        lock, manifest = verification_fixture()
        signer = {"identity": "fixture-release-lock-signer", "fingerprint": "9" * 64,
                  "sourceCommit": COMMIT, "verifierSourceCommit": "b" * 40}
        verifier = {"identity": "fixture-release-lock-verifier", "fingerprint": "c" * 64,
                    "sourceCommit": "b" * 40}
        state = {key: value for key, value in manifest["trustState"].items()}
        ceremony._validate_manifest_trust(manifest, "7" * 64, "8" * 64, signer, verifier, state)
        with self.assertRaisesRegex(ceremony.CeremonyError, "trust configuration digest changed"):
            ceremony._validate_manifest_trust(manifest, "0" * 64, "8" * 64, signer, verifier, state)
        manifest["verifier"]["scriptSha256"] = "f" * 64
        ceremony._validate_manifest(manifest, lock, now=NOW)

    def test_stale_manifest_and_unsigned_or_mismatched_signature_fail_closed(self):
        lock, manifest = verification_fixture()
        with self.assertRaisesRegex(ceremony.CeremonyError, "stale"):
            ceremony._validate_manifest(manifest, lock, now=NOW + dt.timedelta(hours=25))
        with patch.object(ceremony.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "openssl")):
            with self.assertRaisesRegex(ceremony.CeremonyError, "does not verify"):
                ceremony.verify_detached_signature(Path("lock"), Path("wrong.sig"), b"public fixture")

    def test_trusted_signing_source_requires_exact_clean_immutable_commit(self):
        signer = {"sourceCommit": COMMIT}
        with patch.object(ceremony, "git_source_state", return_value=(COMMIT, False)):
            with self.assertRaisesRegex(ceremony.CeremonyError, "exact clean"):
                ceremony._trusted_signing_source(signer)
        with patch.object(ceremony, "git_source_state", return_value=("b" * 40, True)):
            with self.assertRaisesRegex(ceremony.CeremonyError, "exact clean"):
                ceremony._trusted_signing_source(signer)

    def test_protected_key_path_rejects_relative_and_parent_traversal_paths(self):
        checkout = Path(__file__).resolve().parents[2]
        with self.assertRaisesRegex(ceremony.CeremonyError, "absolute"):
            ceremony._private_key_fd(Path("relative-key.pem"), checkout)
        with self.assertRaisesRegex(ceremony.CeremonyError, "traversal"):
            ceremony._private_key_fd(Path("/secure/../key.pem"), checkout)

    def test_signer_treats_candidate_release_content_as_data_only(self):
        lock, manifest = verification_fixture()
        with tempfile.TemporaryDirectory(prefix="kordex-test-only-candidate-code-") as temp:
            root = Path(temp)
            sentinel = root / "candidate-code-ran"
            (root / "candidate-release.py").write_text(
                f"from pathlib import Path; Path({str(sentinel)!r}).touch()\n", encoding="utf-8")
            candidate = root / "kordex-images.tsv"
            candidate.write_bytes(lock + b"# candidate release code: import candidate-release.py\n")
            manifest_path = root / "verification-manifest.json"
            manifest_path.write_bytes(ceremony.canonical_json(manifest))
            manifest_signature = root / "verification-manifest.json.sig"
            manifest_signature.write_bytes(b"test-only unsigned manifest-signature placeholder")
            args = type("Args", (), {"lock_candidate": candidate,
                "verification_manifest": manifest_path, "output_dir": root / "signed",
                "verification_manifest_signature": manifest_signature,
                "private_key": root / "must-not-be-opened.pem"})()
            signer = {"identity": "fixture-release-lock-signer", "fingerprint": "9" * 64,
                      "sourceCommit": COMMIT, "verifierSourceCommit": "b" * 40}
            with patch.object(ceremony, "_trusted_signing_source", return_value=root), \
                    patch.object(ceremony.subprocess, "run") as process:
                with self.assertRaisesRegex(ceremony.CeremonyError, "candidate digest"):
                    ceremony._sign_candidate(args, {}, "7" * 64, signer,
                                             {"identity": "fixture-release-lock-verifier",
                                              "fingerprint": "c" * 64,
                                              "sourceCommit": "b" * 40}, "8" * 64,
                                             manifest["trustState"], now=NOW)
            self.assertFalse(sentinel.exists())
            process.assert_not_called()
            self.assertFalse(args.output_dir.exists())

    def test_invalid_verification_manifest_signature_blocks_before_lock_key_access(self):
        lock, manifest = verification_fixture()
        with tempfile.TemporaryDirectory(prefix="kordex-test-only-manifest-signature-") as temp:
            root = Path(temp)
            lock_path = root / "kordex-images.tsv"
            manifest_path = root / "verification-manifest.json"
            sig_path = root / "verification-manifest.json.sig"
            lock_path.write_bytes(lock)
            manifest_path.write_bytes(ceremony.canonical_json(manifest))
            sig_path.write_bytes(b"test-only invalid signature fixture")
            args = type("Args", (), {"lock_candidate": lock_path,
                "verification_manifest": manifest_path, "verification_manifest_signature": sig_path,
                "output_dir": root / "signed", "private_key": root / "never-open.pem"})()
            signer = {"identity": "fixture-release-lock-signer", "fingerprint": "9" * 64,
                      "sourceCommit": COMMIT, "verifierSourceCommit": "b" * 40}
            verifier = {"identity": "fixture-release-lock-verifier", "fingerprint": "c" * 64,
                        "sourceCommit": "b" * 40,
                        "publicKeyPem": "fixture verifier public key"}
            with patch.object(ceremony, "_trusted_signing_source", return_value=root), \
                    patch.object(ceremony.subprocess, "run",
                                 side_effect=subprocess.CalledProcessError(1, "openssl")), \
                    patch.object(ceremony, "_private_key_fd") as private_key:
                with self.assertRaisesRegex(ceremony.CeremonyError, "does not verify"):
                    ceremony._sign_candidate(args, {}, "7" * 64, signer, verifier, "8" * 64,
                                             manifest["trustState"], now=NOW)
            private_key.assert_not_called()
            self.assertFalse(args.output_dir.exists())

    def test_sign_candidate_enforces_manifest_freshness_and_future_skew_before_signature_or_key_access(self):
        lock, manifest = verification_fixture()
        with tempfile.TemporaryDirectory(prefix="kordex-test-only-manifest-freshness-") as temp:
            root = Path(temp)
            lock_path = root / "kordex-images.tsv"
            manifest_path = root / "verification-manifest.json"
            sig_path = root / "verification-manifest.json.sig"
            lock_path.write_bytes(lock)
            manifest_path.write_bytes(ceremony.canonical_json(manifest))
            sig_path.write_bytes(b"test-only signature fixture")
            args = type("Args", (), {"lock_candidate": lock_path,
                "verification_manifest": manifest_path, "verification_manifest_signature": sig_path,
                "output_dir": root / "signed", "private_key": root / "never-open.pem"})()
            signer = {"identity": "fixture-release-lock-signer", "fingerprint": "9" * 64,
                      "sourceCommit": COMMIT, "verifierSourceCommit": "b" * 40}
            verifier = {"identity": "fixture-release-lock-verifier", "fingerprint": "c" * 64,
                        "sourceCommit": "b" * 40,
                        "publicKeyPem": "fixture verifier public key"}
            for label, check_now in (
                ("stale_beyond_24h", NOW + dt.timedelta(hours=24, seconds=1)),
                ("future_beyond_2m", NOW - dt.timedelta(minutes=2, seconds=1)),
            ):
                with self.subTest(case=label), \
                        patch.object(ceremony, "_trusted_signing_source", return_value=root), \
                        patch.object(ceremony, "verify_detached_signature_bytes") as verify_sig, \
                        patch.object(ceremony, "_private_key_fd") as private_key:
                    with self.assertRaisesRegex(ceremony.CeremonyError, "future-dated or stale"):
                        ceremony._sign_candidate(args, {}, "7" * 64, signer, verifier, "8" * 64,
                                                 manifest["trustState"], now=check_now)
                    verify_sig.assert_not_called()
                    private_key.assert_not_called()
            self.assertFalse(args.output_dir.exists())

    def test_pre_sign_pipeline_calls_existing_image_and_repository_verifiers(self):
        with tempfile.TemporaryDirectory(prefix="kordex-test-only-offline-candidate-") as temp:
            root = Path(temp)
            components_root = root / "components"
            components_root.mkdir()
            package_policy = root / "policy.json"
            package_policy.write_bytes(b"test-only approved package-policy fixture")
            trusted_root = root / "sigstore-root.jsonl"
            trusted_root.write_bytes(b"test-only independently supplied root fixture")
            keyring = root / "repository-keyring.gpg"
            keyring.write_bytes(b"test-only repository trust fixture")
            repository_root = root / "repository"
            repository_root.mkdir()
            (repository_root / "signed-metadata.fixture").write_bytes(b"test-only metadata snapshot")
            repo_result = {"family": "debian", "keyringSha256": "d" * 64,
                "verifiedPackageCount": 1, "packages": [{"name": "fixture", "version": "1.0",
                                                              "sha256": "e" * 64}],
                "repositories": [{"repositoryId": "debian-main", "releaseSha256": "5" * 64,
                    "signedMetadataSha256": ["6" * 64], "signatureSha256": ["7" * 64],
                    "signatureMetadataSha256": ["8" * 64], "signerFingerprints": ["A" * 40],
                    "indexes": [{"path": "Packages", "sha256": "9" * 64, "bytes": 10}]}]}
            policy = {"spec": {"upgrade": {"osPointRelease": "13.8"}}}
            config = {"schemaVersion": 1, "campaign": "debian-13", "releaseTag": TAG,
                "sourceCommit": COMMIT, "workflowRun": {"id": "123", "attempt": "1"},
                "componentsRoot": str(components_root), "sigstoreTrustedRoot": str(trusted_root),
                "sigstoreTrustedRootSHA256": hashlib.sha256(trusted_root.read_bytes()).hexdigest(),
                "imageAttestationMaxAgeDays": 30, "packagePolicy": str(package_policy),
                "packagePolicySHA256": hashlib.sha256(package_policy.read_bytes()).hexdigest(),
                "repositorySnapshotID": "snapshot-fixture", "privateMirrorURL": "https://mirror.invalid/packages",
                "repositoryMetadata": {"family": "debian", "keyring": str(keyring),
                    "approvedFingerprints": ["A" * 40], "maxAgeSeconds": 86400,
                    "repositories": [{"id": "debian-main", "root": str(repository_root)}]}}
            component_records = {}
            images = {}
            for component in ceremony.COMPONENTS:
                folder = components_root / component
                folder.mkdir()
                (folder / "component.json").write_text(json.dumps({"component": component}), encoding="utf-8")
                (folder / "evidence.fixture").write_bytes(f"test-only-{component}".encode())
                digest = hashlib.sha256(component.encode()).hexdigest()
                image = f"ghcr.io/kevin-phan-25/kordex-{component}@sha256:{digest}"
                component_records[component] = {"manifest": {"sourceRef": f"refs/tags/{TAG}",
                    "sourceCommit": COMMIT, "buildMaterials": [{"uri": "pkg:fixture/base",
                    "digest": {"sha256": "f" * 64}}], "buildParameters": {"fixture": True}},
                    "imageReference": image, "files": {}}
                images[component] = {"imageRef": image, "imageDigest": digest, "sbomSha256": "1" * 64,
                    "sbomAttestationBundleSha256": "2" * 64, "provenanceAttestationBundleSha256": "3" * 64,
                    "sourceRepository": supply.REPOSITORY, "sourceRef": f"refs/tags/{TAG}",
                    "sourceCommit": COMMIT, "builderId": supply.EXPECTED_BUILDER_ID,
                    "workflowIdentity": supply.WORKFLOW_IDENTITY,
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "materials": [{"uri": "pkg:fixture/base", "digest": {"sha256": "f" * 64}}],
                    "sbomAttestationVerifiedAt": "2026-11-23T11:55:00Z",
                    "provenanceAttestationVerifiedAt": "2026-11-23T11:55:00Z"}
            image_result = {"imageCount": 6, "trustedRootSha256": config["sigstoreTrustedRootSHA256"],
                            "images": images}
            signer = {"identity": "fixture-release-lock-signer", "fingerprint": "a" * 64,
                      "sourceCommit": COMMIT, "verifierSourceCommit": "b" * 40}
            verifier = {"identity": "fixture-release-lock-verifier", "fingerprint": "b" * 64,
                        "sourceCommit": "b" * 40}
            with patch.object(ceremony, "_package_policy", return_value=(policy, [{"name": "fixture"}], "c" * 64)), \
                 patch.object(ceremony.release_evidence, "_parse_component_evidence",
                              side_effect=lambda component, *_args, **_kwargs: component_records[component]), \
                 patch.object(ceremony.supply, "verify_image_attestations", return_value=image_result) as image_verify, \
                 patch.object(ceremony, "_repo_result", return_value=repo_result) as repository_verify:
                lock, manifest_raw = ceremony._build_candidate(config, trust_digest="a" * 64,
                    trust_root_fingerprint="b" * 64, signer=signer, verifier=verifier, now=NOW,
                    trust_state_binding={"sequence": 7, "configurationSha256": "a" * 64,
                        "backendIdentity": "fixture-trust-backend", "namespace": "fixture-production",
                        "attestationFingerprint": "d" * 64, "conformanceSha256": "e" * 64,
                        "rootFingerprint": "1" * 64, "rootSignatureSha256": "2" * 64,
                        "auditIds": ["fixture-audit-001"]},
                    source_state=("b" * 40, True), input_map_sha256="c" * 64)
            manifest = json.loads(manifest_raw)
            self.assertEqual(len(lock.splitlines()), 6)
            self.assertEqual(set(manifest["components"]), set(ceremony.COMPONENTS))
            self.assertEqual(image_verify.call_args.args[1].keys(), images.keys())
            self.assertEqual(repository_verify.call_args.args[2], "debian-13")
            self.assertIn("verification-input-map-file", manifest["inputSha256"])

    def test_signing_receipt_must_bind_exact_signature_lock_manifest_and_signer(self):
        lock, manifest = verification_fixture()
        manifest_raw = ceremony.canonical_json(manifest)
        signature_bytes = b"test-only signature digest fixture; never cryptographic evidence"
        manifest_signature = b"test-only verifier signature digest fixture; never cryptographic evidence"
        signer = {"identity": "fixture-release-lock-signer", "fingerprint": "9" * 64,
                  "sourceCommit": COMMIT}
        receipt = {"schemaVersion": 1, "kind": "kordex-m3-offline-release-lock-signing-receipt",
            "lockSha256": hashlib.sha256(lock).hexdigest(),
            "verificationManifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
            "verificationManifestSignatureSha256": hashlib.sha256(manifest_signature).hexdigest(),
            "signerIdentity": signer["identity"], "signerFingerprint": signer["fingerprint"],
            "signerSourceCommit": signer["sourceCommit"], "signedAt": "2026-11-23T12:00:00Z",
            "signatureSha256": hashlib.sha256(signature_bytes).hexdigest(),
            "trustState": manifest["trustState"], "signatureVerified": True}
        ceremony._validate_receipt(receipt, lock, manifest_raw, signature_bytes, manifest_signature, signer,
                                   manifest["trustState"], now=NOW)
        future_receipt = dict(receipt, signedAt="2026-12-01T12:00:00Z")
        with self.assertRaisesRegex(ceremony.CeremonyError, "future-dated"):
            ceremony._validate_receipt(future_receipt, lock, manifest_raw, signature_bytes,
                                       manifest_signature, signer, manifest["trustState"], now=NOW)
        receipt["lockSha256"] = "0" * 64
        with self.assertRaisesRegex(ceremony.CeremonyError, "does not bind"):
            ceremony._validate_receipt(receipt, lock, manifest_raw, signature_bytes, manifest_signature, signer,
                                       manifest["trustState"], now=NOW)
        receipt["lockSha256"] = hashlib.sha256(lock).hexdigest()
        receipt["verificationManifestSignatureSha256"] = "0" * 64
        with self.assertRaisesRegex(ceremony.CeremonyError, "does not bind"):
            ceremony._validate_receipt(receipt, lock, manifest_raw, signature_bytes, manifest_signature, signer,
                                       manifest["trustState"], now=NOW)
        with patch.object(ceremony, "git_source_state", return_value=("b" * 40, True)):
            with self.assertRaisesRegex(ceremony.CeremonyError, "exact clean"):
                ceremony._trusted_signing_source(signer)


if __name__ == "__main__":
    unittest.main()
