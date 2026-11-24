"""Test-only signatures and trust roots; these fixtures never approve artifacts."""

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

from scripts import m3_artifact_review as review
from scripts import m3_customer_trust as trust
from scripts.m3_artifact_preflight import REQUIRED_ARTIFACTS


NOW = dt.datetime(2026, 11, 23, 12, 0, tzinfo=dt.timezone.utc)


class ArtifactReviewContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="kordex-m3-review-test-only-")
        cls.root = Path(cls.temp.name)
        cls.owner_private, cls.owner_public = cls._keypair("owner")
        cls.reviewer_private, cls.reviewer_public = cls._keypair("reviewer")
        cls.owner_fp = trust.fingerprint(cls.owner_public.read_bytes())
        cls.reviewer_fp = trust.fingerprint(cls.reviewer_public.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def _keypair(cls, name):
        private = cls.root / f"{name}.test-only.pem"
        public = cls.root / f"{name}.test-only.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return private, public

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="kordex-m3-review-case-test-only-")
        self.dir = Path(self.tmp.name)
        self.root_public = self.dir / "qualification-root.test-only.pub"
        self.root_public.write_bytes(self.reviewer_public.read_bytes())
        self.trust_doc = self._trust_document()
        self.trust_digest = "c" * 64
        self.config = self._config()
        self.report = self._report()
        self.record_path = self.dir / "artifact-review.json"
        self.signature_path = self.dir / "artifact-review.json.sig"
        self._write_record()

    def tearDown(self):
        self.tmp.cleanup()

    def _trust_document(self):
        keys = []
        for identity, role, fp, public in (
                ("lab-owner", "artifact-owner", self.owner_fp, self.owner_public),
                ("independent-reviewer", "reviewer", self.reviewer_fp, self.reviewer_public)):
            keys.append({"identity": identity, "role": role, "fingerprint": fp,
                         "publicKeyPem": public.read_text(encoding="ascii"),
                         "validFrom": "2026-11-23T00:00:00Z", "validUntil": "2026-12-23T00:00:00Z",
                         "revokedAt": None})
        return {"schemaVersion": 1, "customerId": "test-only-qualification-lab", "sequence": 1,
                "issuedAt": "2026-11-23T00:00:00Z", "expiresAt": "2026-12-23T00:00:00Z", "keys": keys}

    def _config(self):
        owners = {key: "lab-owner" for key in (
            "release-bundle", "release-image-lock", "k3s-binary", "k3s-system-images",
            "image:agent", "image:operator", "image:control-plane", "image:dashboard",
            "image:ansible-ee", "image:postgres", "repository:debian-main")}
        return {"schemaVersion": 1, "packageArtifacts": {"repositoryMetadata": {
            "repositories": [{"id": "debian-main"}]}},
            "release": {"campaignId": "m3-debian-nov23-run-01", "artifactOwners": owners}}

    def _report(self):
        artifacts = {name: {"status": "PASS"} for name in REQUIRED_ARTIFACTS}
        artifacts["independentApproval"] = {"status": "NOT PROVIDED", "code": "IndependentApprovalPending"}
        artifacts["hostPackageArtifacts"] = {"status": "PASS", "osFamily": "debian", "osId": "debian",
            "osMajor": "13", "osMinor": "", "osPointRelease": "13.8", "profile": "debian-13"}
        artifacts["artifactApprovalTrust"] = {"status": "PASS", "keyIds": ["a" * 64]}
        artifacts["releasePublicTrust"] = {"status": "PASS", "fingerprint": "b" * 64}
        artifacts["toolProvenancePublicTrust"] = {"status": "PASS", "fingerprint": "d" * 64}
        artifacts["repositoryMetadataVerification"] = {"status": "PASS", "repositories": [{
            "repositoryId": "debian-main", "snapshotID": "snapshot-20261123",
            "distribution": "trixie", "origin": "Debian", "label": "Debian",
            "codename": "trixie", "architectures": ["amd64"], "components": ["main"],
            "signerFingerprint": "1234567890abcdef1234567890abcdef12345678",
            "signerFingerprints": ["1234567890abcdef1234567890abcdef12345678"],
            "releaseSha256": "a" * 64, "signedMetadataSha256": ["a" * 64],
            "signatureSha256": ["b" * 64], "signatureMetadataSha256": ["b" * 64],
            "indexes": [{"path": "main/binary-amd64/Packages", "sha256": "c" * 64, "bytes": 100}],
            "indexCount": 1, "packageRecordCount": 4,
            "releaseDate": "2026-11-23T11:00:00Z", "validUntil": "2026-11-24T11:00:00Z"}]}
        artifacts["k3sBinaryApproval"] = {"status": "PASS", "signerKeyId": "e" * 64}
        artifacts["k3sSystemImageApproval"] = {"status": "PASS", "signerKeyId": "f" * 64}
        images = {}
        for component in ("agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres"):
            images[component] = {"imageRef": f"registry.test/kordex/{component}@sha256:" + "9" * 64,
                "imageDigest": "9" * 64, "sourceRepository": "kevin-phan-25/kordex",
                "sourceRef": "refs/tags/v1.2.3", "sourceCommit": "1" * 40,
                "builderId": "https://github.com/actions/runner/github-hosted",
                "workflowIdentity": "https://github.com/kevin-phan-25/kordex/.github/workflows/ci.yaml",
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "materials": [{"uri": "git+https://github.com/kevin-phan-25/kordex@refs/tags/v1.2.3",
                               "digest": {"gitCommit": "1" * 40}}],
                "sbomSha256": "2" * 64, "provenanceBundleSha256": "3" * 64}
        artifacts["imageSBOMVerification"] = {"status": "PASS", "images": {
            name: {"imageRef": row["imageRef"], "imageDigest": row["imageDigest"],
                   "sbomSha256": "2" * 64, "sbomBundleSha256": "6" * 64,
                   "sbomAttestationVerifiedAt": "2026-11-23T11:00:00Z"}
            for name, row in images.items()}}
        artifacts["imageProvenanceVerification"] = {"status": "PASS", "images": images}
        return {"schemaVersion": 1, "campaignId": self.config["release"]["campaignId"],
            "profile": "debian-13", "osProfile": "debian-13",
            "osIdentity": {"osId": "debian", "osMajor": "13", "osMinor": "",
                           "pointRelease": "13.8", "architecture": "linux/amd64"},
            "artifactOwners": self.config["release"]["artifactOwners"],
            "signerIdentities": {}, "checks": {"independentApproval": artifacts["independentApproval"]},
            "overallStatus": "NOT PROVIDED", "artifacts": artifacts,
            "inputSha256": {"sigstoreTrustedRoot": "4" * 64,
                            "repositoryMetadataKeyring": "5" * 64}}

    def _record(self):
        self.report["signerIdentities"] = review.signer_identities(self.report)
        return {"schemaVersion": 1, "campaignId": self.config["release"]["campaignId"],
            "osProfile": "debian-13", "osIdentity": self.report["osIdentity"],
            "decision": "accepted", "reportSha256": hashlib.sha256(review.canonical_json(self.report)).hexdigest(),
            "verificationSha256": review.verification_digest(self.report),
            "artifactBindings": review.artifact_bindings(self.report),
            "artifactOwners": self.config["release"]["artifactOwners"],
            "signerIdentities": self.report["signerIdentities"],
            "trustConfigurationSha256": self.trust_digest,
            "trustRootFingerprint": trust.fingerprint(self.root_public.read_bytes()),
            "reviewerIdentity": "independent-reviewer", "signatureIdentity": "independent-reviewer",
            "reviewedAt": "2026-11-23T11:30:00Z", "expiresAt": "2026-12-01T00:00:00Z",
            "reviewReference": "review-ticket-123", "rationale": "Verified every signed artifact and source binding."}

    def _write_record(self, record=None, signer=None):
        record = record or self._record()
        raw = review.canonical_json(record)
        self.record_path.write_bytes(raw)
        signer = signer or self.reviewer_private
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(signer), "-rawin",
                        "-in", str(self.record_path), "-out", str(self.signature_path)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return record

    def _validate(self, *, config=None, report=None, trust_doc=None, signature=True):
        if not signature:
            self.signature_path.unlink(missing_ok=True)
        loader = lambda: (trust_doc or self.trust_doc, self.trust_digest)
        with patch.object(review.trust, "TRUST_ROOT", self.root_public):
            return review.validate_review(record_path=self.record_path, signature_path=self.signature_path,
                config=config or self.config, pre_review_report=report or self.report, now=NOW,
                trust_loader=loader)

    def test_accepts_valid_report_bound_independent_review(self):
        result = self._validate()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reviewedReportSha256"], hashlib.sha256(review.canonical_json(self.report)).hexdigest())
        self.assertEqual(result["reviewerIdentity"], "independent-reviewer")
        schema = json.loads((Path(__file__).resolve().parents[2] / "schemas/m3-artifact-review-v1.json").read_text())
        self.assertEqual(set(schema["required"]), review.REVIEW_FIELDS)
        jsonschema.validate(self._record(), schema)

    def test_rejects_wrong_or_unauthorized_reviewer_and_owner_self_review(self):
        record = self._record()
        record["reviewerIdentity"] = "lab-owner"
        record["signatureIdentity"] = "lab-owner"
        self._write_record(record, self.owner_private)
        with self.assertRaisesRegex(review.ArtifactReviewError, "not currently authorized"):
            self._validate()
        record = self._record()
        record["reviewerIdentity"] = "not-designated"
        record["signatureIdentity"] = "not-designated"
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "not currently authorized"):
            self._validate()

    def test_rejects_reviewer_key_equal_to_verified_artifact_signer(self):
        self.report["artifacts"]["artifactApprovalTrust"]["keyIds"] = [self.reviewer_fp]
        self._write_record()
        with self.assertRaisesRegex(review.ArtifactReviewError, "aliases a verified artifact signer"):
            self._validate()

    def test_rejects_missing_invalid_expired_or_revoked_signature_trust(self):
        with self.assertRaisesRegex(review.ArtifactReviewError, "signature.*unavailable"):
            self._validate(signature=False)
        self.signature_path.write_bytes(b"bad signature")
        with self.assertRaisesRegex(review.ArtifactReviewError, "signature verification"):
            self._validate()
        expired = json.loads(json.dumps(self.trust_doc))
        expired["keys"][1]["validUntil"] = "2026-11-22T00:00:00Z"
        self._write_record()
        with self.assertRaisesRegex(review.ArtifactReviewError, "not currently authorized"):
            self._validate(trust_doc=expired)
        revoked = json.loads(json.dumps(self.trust_doc))
        revoked["keys"][1]["revokedAt"] = "2026-11-23T11:00:00Z"
        with self.assertRaisesRegex(review.ArtifactReviewError, "not currently authorized"):
            self._validate(trust_doc=revoked)

    def test_rejects_wrong_campaign_os_or_component_set(self):
        record = self._record()
        record["osProfile"] = "rhel-9"
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "different OS campaign"):
            self._validate()
        owners = dict(self.config["release"]["artifactOwners"])
        owners.pop("image:postgres")
        config = json.loads(json.dumps(self.config))
        config["release"]["artifactOwners"] = owners
        record = self._record()
        record["artifactOwners"] = owners
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "owner designation"):
            self._validate(config=config)
        config = json.loads(json.dumps(self.config))
        config["release"]["campaignId"] = "m3-debian-another-run"
        with self.assertRaisesRegex(review.ArtifactReviewError, "different OS campaign"):
            self._validate(config=config)

    def test_each_locked_component_requires_its_own_designated_owner(self):
        for component in ("ansible-ee", "postgres"):
            with self.subTest(component=component):
                config = json.loads(json.dumps(self.config))
                config["release"]["artifactOwners"].pop(f"image:{component}")
                record = self._record()
                record["artifactOwners"] = config["release"]["artifactOwners"]
                self._write_record(record)
                with self.assertRaisesRegex(review.ArtifactReviewError, "owner designation"):
                    self._validate(config=config)

    def test_rejects_changed_report_image_repository_sbom_provenance_or_trust_digest(self):
        record = self._record()
        self._write_record(record)
        for mutation in (
            lambda report: report["artifacts"]["imageProvenanceVerification"]["images"]["postgres"].update(imageDigest="8" * 64),
            lambda report: report["artifacts"]["repositoryMetadataVerification"]["repositories"][0].update(signerFingerprint="8" * 40),
            lambda report: report["artifacts"]["imageProvenanceVerification"]["images"]["agent"].update(sbomSha256="8" * 64),
            lambda report: report["artifacts"]["imageProvenanceVerification"]["images"]["agent"].update(provenanceBundleSha256="8" * 64),
            lambda report: report["inputSha256"].update(sigstoreTrustedRoot="8" * 64),
        ):
            changed = json.loads(json.dumps(self.report))
            mutation(changed)
            with self.subTest(changed=changed["inputSha256"]):
                with self.assertRaisesRegex(review.ArtifactReviewError, "exact preflight report"):
                    self._validate(report=changed)

    def test_record_explicit_image_bindings_must_match_verified_report(self):
        record = self._record()
        record["artifactBindings"]["images"]["postgres"]["imageDigest"] = "8" * 64
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "artifact bindings differ"):
            self._validate()

    def test_rejects_changed_trust_root_report_digest_and_incomplete_or_stale_record(self):
        record = self._record()
        record["trustRootFingerprint"] = "8" * 64
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "trust identities"):
            self._validate()
        record = self._record()
        record["trustConfigurationSha256"] = "7" * 64
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "trust identities"):
            self._validate()
        record = self._record()
        record["reportSha256"] = "8" * 64
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "exact preflight report"):
            self._validate()
        record = self._record()
        record.pop("rationale")
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "incomplete"):
            self._validate()
        record = self._record()
        record["expiresAt"] = "2026-11-23T11:59:00Z"
        self._write_record(record)
        with self.assertRaisesRegex(review.ArtifactReviewError, "stale, expired"):
            self._validate()

    def test_record_cannot_approve_partial_verification(self):
        changed = json.loads(json.dumps(self.report))
        changed["artifacts"]["repositoryMetadataVerification"]["status"] = "NOT PROVIDED"
        self.report = changed
        self._write_record()
        with self.assertRaisesRegex(review.ArtifactReviewError, "incomplete verification"):
            self._validate(report=changed)


if __name__ == "__main__":
    unittest.main()
