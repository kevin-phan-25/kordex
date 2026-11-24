"""Supply-chain verifier tests use ephemeral test-only OpenPGP keys and fake GH attestations.

These fixtures test verifier behavior only. They are never accepted by the M3
preflight as owner approvals, release artifacts, or qualification evidence.
"""

import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import m3_supply_chain_verify as verify


class SignedRepositoryMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="kordex-test-only-gpg-")
        cls.root = Path(cls.temp.name)
        cls.home = cls.root / "gnupg"
        cls.home.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(cls.home)}
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                        "Kordex unit-test-only repository verifier", "ed25519", "sign", "0"],
                       check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        listing = subprocess.run(["gpg", "--batch", "--with-colons", "--list-keys"], check=True,
                                 env=env, text=True, capture_output=True).stdout
        cls.fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        cls.keyring = cls.root / "test-only-keyring.gpg"
        cls.keyring.write_bytes(subprocess.run(["gpg", "--batch", "--export", cls.fingerprint],
                                               check=True, env=env, capture_output=True).stdout)
        cls.env = env

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kordex-test-only-repository-")
        self.root = Path(self.temp.name)
        self.now = dt.datetime(2026, 11, 23, 12, tzinfo=dt.timezone.utc)
        self.digest = hashlib.sha256(b"test package payload").hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def sign(self, payload: Path, output: Path, *, clear=False):
        cmd = ["gpg", "--batch", "--yes", "--local-user", self.fingerprint]
        cmd += ["--clearsign", "--output", str(output), str(payload)] if clear else [
            "--armor", "--detach-sign", "--output", str(output), str(payload)]
        subprocess.run(cmd, check=True, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def debian_fixture(self, *, expiry="Tue, 24 Nov 2026 12:00:00 UTC", wrong_index=False):
        repo = self.root / "debian"
        index = repo / "main/binary-amd64/Packages"
        index.parent.mkdir(parents=True, exist_ok=True)
        index_bytes = (f"Package: fixture\nVersion: 2.0-1\nArchitecture: amd64\n"
                       f"Filename: pool/main/f/fixture.deb\nSHA256: {self.digest}\n\n").encode()
        index.write_bytes(index_bytes)
        index_digest = hashlib.sha256(index_bytes).hexdigest()
        release = repo / "Release"
        date = "Mon, 23 Nov 2026 11:00:00 UTC"
        release.write_text(
            f"Origin: Debian\nLabel: Debian\nSuite: trixie\nCodename: trixie\n"
            f"Architectures: amd64\nComponents: main\nDate: {date}\nValid-Until: {expiry}\n"
            f"SHA256:\n {'0' * 64 if wrong_index else index_digest} {len(index_bytes)} main/binary-amd64/Packages\n",
            encoding="utf-8")
        inrelease = repo / "InRelease"
        self.sign(release, inrelease, clear=True)
        return repo, inrelease

    def deb_config(self, repo, *, fingerprint=None, max_age=86400):
        return {"family": "debian", "keyring": str(self.keyring),
                "approvedFingerprints": [fingerprint or self.fingerprint], "maxAgeSeconds": max_age,
                "repositories": [{"id": "debian-trixie", "root": str(repo),
                    "baseURL": "https://mirror.test/debian", "snapshotID": "snapshot-1",
                    "distribution": "trixie", "origin": "Debian", "label": "Debian",
                    "codename": "trixie", "architectures": ["amd64"], "components": ["main"]}]}

    def package_policy(self):
        return [{"name": "fixture", "version": "2.0-1", "artifactSHA256": self.digest}]

    def test_valid_signed_debian_inrelease_binds_identity_freshness_and_index_package(self):
        repo, _ = self.debian_fixture()
        result = verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(),
            now=self.now, run=subprocess.run, expected_snapshot="snapshot-1",
            private_mirror_url="https://mirror.test/package-archive")
        self.assertEqual(result["verifiedPackageCount"], 1)
        self.assertEqual(result["repositories"][0]["signerFingerprint"], self.fingerprint)
        self.assertEqual(result["repositories"][0]["signatureSha256"],
                         [hashlib.sha256((repo / "InRelease").read_bytes()).hexdigest()])
        self.assertEqual(result["repositories"][0]["signedMetadataSha256"],
                         [hashlib.sha256(verify._inrelease_payload((repo / "InRelease").read_bytes())).hexdigest()])

    def test_valid_detached_release_signature_and_rejects_disagreement_with_inrelease(self):
        repo, inrelease = self.debian_fixture()
        release = repo / "Release"
        detached = repo / "Release.gpg"
        self.sign(release, detached)
        result = verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(),
            now=self.now, run=subprocess.run, expected_snapshot="snapshot-1",
            private_mirror_url="https://mirror.test/package-archive")
        self.assertEqual(result["repositories"][0]["signerFingerprint"], self.fingerprint)
        release.write_text(release.read_text(encoding="utf-8").replace("Suite: trixie", "Suite: bookworm"),
                           encoding="utf-8")
        self.sign(release, detached)
        with self.assertRaisesRegex(verify.SupplyChainError, "contents disagree"):
            verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(),
                now=self.now, run=subprocess.run, expected_snapshot="snapshot-1",
                private_mirror_url="https://mirror.test/package-archive")

    def test_rejects_expired_invalid_unapproved_and_substituted_debian_metadata(self):
        repo, inrelease = self.debian_fixture(expiry="Mon, 23 Nov 2026 11:00:00 UTC")
        with self.assertRaisesRegex(verify.SupplyChainError, "expired"):
            verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(), now=self.now,
                run=subprocess.run, expected_snapshot="snapshot-1", private_mirror_url="https://mirror.test/archive")
        repo, inrelease = self.debian_fixture()
        inrelease.write_bytes(inrelease.read_bytes().replace(b"Codename: trixie", b"Codename: forged"))
        with self.assertRaisesRegex(verify.SupplyChainError, "signature"):
            verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(), now=self.now,
                run=subprocess.run, expected_snapshot="snapshot-1", private_mirror_url="https://mirror.test/archive")
        repo, _ = self.debian_fixture()
        with self.assertRaisesRegex(verify.SupplyChainError, "approved fingerprint"):
            verify.verify_debian_repositories(self.deb_config(repo, fingerprint="A" * 40), self.package_policy(),
                now=self.now, run=subprocess.run, expected_snapshot="snapshot-1",
                private_mirror_url="https://mirror.test/archive")
        repo, _ = self.debian_fixture(wrong_index=True)
        with self.assertRaisesRegex(verify.SupplyChainError, "index differs"):
            verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(), now=self.now,
                run=subprocess.run, expected_snapshot="snapshot-1", private_mirror_url="https://mirror.test/archive")

    def test_rejects_signed_but_wrong_debian_distribution_or_snapshot_identity(self):
        repo, inrelease = self.debian_fixture()
        release = repo / "Release"
        release.write_text(release.read_text(encoding="utf-8").replace("Suite: trixie", "Suite: bookworm"),
                           encoding="utf-8")
        self.sign(release, inrelease, clear=True)
        with self.assertRaisesRegex(verify.SupplyChainError, "identity differs"):
            verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(), now=self.now,
                run=subprocess.run, expected_snapshot="snapshot-1", private_mirror_url="https://mirror.test/archive")
        repo, _ = self.debian_fixture()
        with self.assertRaisesRegex(verify.SupplyChainError, "identity must bind"):
            verify.verify_debian_repositories(self.deb_config(repo), self.package_policy(), now=self.now,
                run=subprocess.run, expected_snapshot="another-snapshot", private_mirror_url="https://mirror.test/archive")

    def rpm_fixture(self, *, corrupt_signature=False):
        repo = self.root / "rpm"
        repodata = repo / "repodata"
        repodata.mkdir(parents=True, exist_ok=True)
        primary = (f"<?xml version='1.0'?><metadata xmlns='http://linux.duke.edu/metadata/common' packages='1'>"
                   f"<package type='rpm'><name>fixture</name><arch>x86_64</arch><version epoch='0' ver='2.0' rel='1.el9'/>"
                   f"<checksum type='sha256' pkgid='YES'>{self.digest}</checksum>"
                   f"<location href='Packages/f.rpm'/></package></metadata>").encode()
        compressed = gzip.compress(primary, mtime=0)
        (repodata / "primary.xml.gz").write_bytes(compressed)
        repomd = repodata / "repomd.xml"
        repomd.write_text(
            f"<?xml version='1.0'?><repomd xmlns='http://linux.duke.edu/metadata/repo'>"
            f"<revision>{int(self.now.timestamp())}</revision><data type='primary'>"
            f"<checksum type='sha256'>{hashlib.sha256(compressed).hexdigest()}</checksum>"
            f"<open-checksum type='sha256'>{hashlib.sha256(primary).hexdigest()}</open-checksum>"
            f"<location href='repodata/primary.xml.gz'/></data></repomd>", encoding="utf-8")
        signature = repodata / "repomd.xml.asc"
        self.sign(repomd, signature)
        if corrupt_signature:
            repomd.write_bytes(repomd.read_bytes().replace(b"<revision>", b"<revision>9"))
        return repo

    def rpm_config(self, repo, *, fingerprint=None, max_age=86400):
        return {"family": "rhel", "keyring": str(self.keyring),
                "approvedFingerprints": [fingerprint or self.fingerprint], "maxAgeSeconds": max_age,
                "repositories": [{"id": "rhel-9-baseos", "root": str(repo),
                    "baseURL": "https://mirror.test/rhel/9.8/BaseOS", "snapshotID": "snapshot-1",
                    "releasever": "9.8", "architecture": "x86_64"}]}

    def test_valid_rpm_metadata_signature_authenticates_key_and_primary_package_index(self):
        repo = self.rpm_fixture()
        result = verify.verify_rpm_repositories(self.rpm_config(repo),
            [{"name": "fixture", "version": "2.0-1.el9", "artifactSHA256": self.digest}],
            now=self.now, run=subprocess.run, expected_snapshot="snapshot-1",
            private_mirror_url="https://mirror.test/package-archive", os_point_release="9.8")
        self.assertEqual(result["verifiedPackageCount"], 1)
        self.assertEqual(result["repositories"][0]["signerFingerprint"], self.fingerprint)
        self.assertEqual(result["repositories"][0]["signatureSha256"],
                         hashlib.sha256((repo / "repodata/repomd.xml.asc").read_bytes()).hexdigest())

    def test_rejects_invalid_untrusted_expired_or_changed_rpm_metadata(self):
        repo = self.rpm_fixture(corrupt_signature=True)
        packages = [{"name": "fixture", "version": "2.0-1.el9", "artifactSHA256": self.digest}]
        with self.assertRaisesRegex(verify.SupplyChainError, "signature"):
            verify.verify_rpm_repositories(self.rpm_config(repo), packages, now=self.now, run=subprocess.run,
                expected_snapshot="snapshot-1", private_mirror_url="https://mirror.test/archive", os_point_release="9.8")
        repo = self.rpm_fixture()
        with self.assertRaisesRegex(verify.SupplyChainError, "approved fingerprint"):
            verify.verify_rpm_repositories(self.rpm_config(repo, fingerprint="A" * 40), packages,
                now=self.now, run=subprocess.run, expected_snapshot="snapshot-1",
                private_mirror_url="https://mirror.test/archive", os_point_release="9.8")
        with self.assertRaisesRegex(verify.SupplyChainError, "stale"):
            verify.verify_rpm_repositories(self.rpm_config(repo, max_age=1), packages,
                now=self.now + dt.timedelta(seconds=2),
                run=subprocess.run, expected_snapshot="snapshot-1", private_mirror_url="https://mirror.test/archive",
                os_point_release="9.8")
        (repo / "repodata/primary.xml.gz").write_bytes(b"substituted")
        with self.assertRaisesRegex(verify.SupplyChainError, "primary metadata differs"):
            verify.verify_rpm_repositories(self.rpm_config(repo), packages, now=self.now,
                run=subprocess.run, expected_snapshot="snapshot-1", private_mirror_url="https://mirror.test/archive",
                os_point_release="9.8")


class ImageAttestationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kordex-test-only-attestation-")
        self.root = Path(self.temp.name)
        self.now = dt.datetime(2026, 11, 23, 12, tzinfo=dt.timezone.utc)
        self.components = ("agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres")
        # Correct component-keyed image references are test-only immutable fixtures.
        self.images = {name: f"ghcr.io/kevin-phan-25/kordex/{name}@sha256:{index:064x}"
                       for index, name in enumerate(self.components, start=1)}
        self.sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                     "components": [{"type": "library", "name": "fixture", "version": "1.0"}]}
        self.sbom_path = self.root / "image.cdx.json"
        self.sbom_path.write_text(json.dumps(self.sbom), encoding="utf-8")
        self.root_file = self.root / "trusted_root.jsonl"
        self.root_file.write_text('{"fixture":"test-only"}\n', encoding="utf-8")
        self.root_sha = hashlib.sha256(self.root_file.read_bytes()).hexdigest()
        self.entries = {}
        for component in self.components:
            sbom_bundle = self.root / f"{component}.sbom.bundle.jsonl"
            prov_bundle = self.root / f"{component}.prov.bundle.jsonl"
            sbom_bundle.write_text('{"fixture":"test-only"}\n', encoding="utf-8")
            prov_bundle.write_text('{"fixture":"test-only"}\n', encoding="utf-8")
            self.entries[component] = {"sbom": str(self.sbom_path), "sbomBundle": str(sbom_bundle),
                "provenanceBundle": str(prov_bundle), "sourceRef": "refs/tags/v1.2.3",
                "sourceCommit": "a" * 40,
                "buildMaterials": [{"uri": "pkg:docker/golang@sha256:" + "f" * 64,
                                    "digest": {"sha256": "f" * 64}}]}

    def tearDown(self):
        self.temp.cleanup()

    def attestation(self, image_ref, predicate_type):
        digest = image_ref.rsplit("sha256:", 1)[1]
        if predicate_type == verify.CYCLONEDX_PREDICATE:
            predicate = self.sbom
        else:
            predicate = {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"repository": verify.REPOSITORY,
                    "ref": "refs/tags/v1.2.3", "path": ".github/workflows/ci.yaml"}},
                "internalParameters": {"github": {"event_name": "workflow_dispatch",
                    "runner_environment": "github-hosted", "repository_id": "123", "repository_owner_id": "456"}},
                "resolvedDependencies": [{"uri": "git+https://github.com/kevin-phan-25/kordex@refs/tags/v1.2.3",
                    "digest": {"gitCommit": "a" * 40}},
                    {"uri": "pkg:docker/golang@sha256:" + "f" * 64,
                     "digest": {"sha256": "f" * 64}}]},
                "runDetails": {"builder": {"id": verify.EXPECTED_BUILDER_ID}}}
        return json.dumps([{"verificationResult": {"statement": {"predicateType": predicate_type,
            "subject": [{"name": image_ref.split("@", 1)[0], "digest": {"sha256": digest}}],
            "predicate": predicate}, "signature": {"certificate": {"issuer": verify.GH_OIDC_ISSUER}},
            "verifiedTimestamps": [{"timestamp": "2026-11-23T11:00:00Z"}]}}])

    def runner(self, *, bad_mode=None):
        def run(command, **kwargs):
            self.assertEqual(command[0:3], ["gh", "attestation", "verify"])
            self.assertIn("--bundle", command)
            self.assertIn("--custom-trusted-root", command)
            self.assertIn("--signer-workflow", command)
            predicate_type = command[command.index("--predicate-type") + 1]
            image_ref = command[3].removeprefix("oci://")
            if bad_mode == "signature":
                raise subprocess.CalledProcessError(1, command)
            output = json.loads(self.attestation(image_ref, predicate_type))
            verified = output[0]["verificationResult"]
            if bad_mode == "subject":
                verified["statement"]["subject"][0]["digest"]["sha256"] = "f" * 64
            elif bad_mode == "subject-name":
                verified["statement"]["subject"][0]["name"] = "ghcr.io/attacker/image"
            elif bad_mode == "builder" and predicate_type == verify.SLSA_PREDICATE:
                verified["statement"]["predicate"]["runDetails"]["builder"]["id"] = "https://evil.invalid"
            elif bad_mode == "source" and predicate_type == verify.SLSA_PREDICATE:
                verified["statement"]["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["repository"] = "evil/repo"
            elif bad_mode == "commit" and predicate_type == verify.SLSA_PREDICATE:
                verified["statement"]["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "b" * 40
            elif bad_mode == "expired":
                verified["verifiedTimestamps"][0]["timestamp"] = "2026-10-01T11:00:00Z"
            elif bad_mode == "incomplete" and predicate_type == verify.SLSA_PREDICATE:
                verified["statement"]["predicate"]["buildDefinition"]["resolvedDependencies"] = []
            elif bad_mode == "material" and predicate_type == verify.SLSA_PREDICATE:
                verified["statement"]["predicate"]["buildDefinition"]["resolvedDependencies"][1]["digest"]["sha256"] = "e" * 64
            return subprocess.CompletedProcess(command, 0, json.dumps(output), "")
        return run

    def verify(self, run, entries=None):
        return verify.verify_image_attestations({"imageAttestations": entries or self.entries,
            "sigstoreTrustedRoot": str(self.root_file), "sigstoreTrustedRootSHA256": self.root_sha,
            "maxAgeDays": 30}, self.images, now=self.now, run=run)

    def test_valid_test_only_signed_attestation_results_bind_each_sbom_digest_and_provenance(self):
        result = self.verify(self.runner())
        self.assertEqual(result["imageCount"], 6)
        for component in self.components:
            self.assertEqual(result["images"][component]["imageDigest"], f"{self.components.index(component)+1:064x}")
            self.assertEqual(result["images"][component]["sbomSha256"], hashlib.sha256(self.sbom_path.read_bytes()).hexdigest())

    def test_rejects_subject_mismatch_wrong_builder_wrong_source_expired_and_incomplete_provenance(self):
        for mode, message in (("subject", "subject name or digest"), ("subject-name", "subject name or digest"),
                              ("builder", "builder identity"),
                              ("source", "build parameters"), ("commit", "exact source repository revision"),
                              ("expired", "expired"),
                              ("incomplete", "no resolved build materials"),
                              ("material", "exact approved material identities"),
                              ("signature", "signature, identity")):
            with self.subTest(mode=mode), self.assertRaisesRegex(verify.SupplyChainError, message):
                self.verify(self.runner(bad_mode=mode))

    def test_rejects_missing_sbom_bundle_tag_only_images_and_trust_root_mismatch(self):
        entries = dict(self.entries)
        entries["agent"] = {**entries["agent"], "sbom": str(self.root / "missing.cdx.json")}
        with self.assertRaisesRegex(verify.SupplyChainError, "unavailable or unsafe"):
            self.verify(self.runner(), entries)
        changed = dict(self.images)
        changed["agent"] = "ghcr.io/kevin-phan-25/kordex/agent:v1.2.3"
        with self.assertRaisesRegex(verify.SupplyChainError, "mutable or malformed"):
            verify.verify_image_attestations({"imageAttestations": self.entries,
                "sigstoreTrustedRoot": str(self.root_file), "sigstoreTrustedRootSHA256": self.root_sha,
                "maxAgeDays": 30}, changed, now=self.now, run=self.runner())
        with self.assertRaisesRegex(verify.SupplyChainError, "trusted root differs"):
            verify.verify_image_attestations({"imageAttestations": self.entries,
                "sigstoreTrustedRoot": str(self.root_file), "sigstoreTrustedRootSHA256": "0" * 64,
                "maxAgeDays": 30}, self.images, now=self.now, run=self.runner())

    def test_every_locked_component_requires_its_own_sbom_and_provenance_bundle(self):
        for component in self.components:
            with self.subTest(component=component, artifact="SBOM"):
                entries = {name: dict(row) for name, row in self.entries.items()}
                entries[component]["sbom"] = str(self.root / f"missing-{component}.cdx.json")
                with self.assertRaises(verify.ImageVerificationError) as raised:
                    self.verify(self.runner(), entries)
                self.assertEqual(raised.exception.phase, "sbom")
                self.assertEqual(raised.exception.component, component)
                self.assertTrue(raised.exception.missing)
            with self.subTest(component=component, artifact="provenance"):
                entries = {name: dict(row) for name, row in self.entries.items()}
                entries[component]["provenanceBundle"] = str(self.root / f"missing-{component}.bundle.jsonl")
                with self.assertRaises(verify.ImageVerificationError) as raised:
                    self.verify(self.runner(), entries)
                self.assertEqual(raised.exception.phase, "provenance")
                self.assertEqual(raised.exception.component, component)
                self.assertTrue(raised.exception.missing)

    def test_unsigned_fallback_is_rejected_when_attestation_bundle_is_absent(self):
        entries = dict(self.entries)
        entries["agent"] = {key: value for key, value in entries["agent"].items() if key != "provenanceBundle"}
        with self.assertRaisesRegex(verify.SupplyChainError, "incomplete or contains unknown fields"):
            self.verify(self.runner(), entries)

    def test_rejects_missing_or_mismatched_attestation_predicate_sbom(self):
        bad = self.runner()
        original = bad
        def mismatch(command, **kwargs):
            result = original(command, **kwargs)
            data = json.loads(result.stdout)
            if command[command.index("--predicate-type") + 1] == verify.CYCLONEDX_PREDICATE:
                data[0]["verificationResult"]["statement"]["predicate"]["components"][0]["name"] = "different"
            return subprocess.CompletedProcess(command, 0, json.dumps(data), "")
        with self.assertRaisesRegex(verify.SupplyChainError, "predicate does not match"):
            self.verify(mismatch)


if __name__ == "__main__":
    unittest.main()
