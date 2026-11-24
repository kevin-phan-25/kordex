"""Test-only structural fixtures for the M3 release evidence packager.

These unsigned bundles are synthetic parser fixtures. They are not accepted by
the cryptographic supply-chain verifier and are never release or qualification
evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import assemble_m3_release_evidence as evidence
import m3_supply_chain_verify as supply


COMPONENTS = evidence.COMPONENTS
TAG = "v1.2.3"
COMMIT = "a" * 40
RUN_ID = "123456"
RUN_ATTEMPT = "1"
SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{"type": "library", "name": "fixture-only", "version": "1.0.0"}]}


def bundle(statement: dict) -> bytes:
    payload = base64.b64encode(json.dumps(statement, separators=(",", ":")).encode()).decode()
    # Test-only unsigned parser fixture; intentionally lacks a signature.
    return json.dumps({"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": payload,
                                         "signatures": []}}).encode()


def statements(component: str) -> tuple[dict, dict]:
    image = f"ghcr.io/kevin-phan-25/kordex-{component}"
    digest = hashlib.sha256(component.encode()).hexdigest()
    sbom_statement = {"_type": "https://in-toto.io/Statement/v1",
                      "subject": [{"name": image, "digest": {"sha256": digest}}],
                      "predicateType": supply.CYCLONEDX_PREDICATE, "predicate": SBOM}
    provenance = {"_type": "https://in-toto.io/Statement/v1",
                  "subject": [{"name": image, "digest": {"sha256": digest}}],
                  "predicateType": supply.SLSA_PREDICATE,
                  "predicate": {"buildDefinition": {
                      "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                      "externalParameters": {"workflow": {"repository": supply.REPOSITORY,
                          "ref": f"refs/tags/{TAG}", "path": ".github/workflows/ci.yaml"}},
                      "internalParameters": {"github": {"event_name": "workflow_dispatch",
                          "runner_environment": "github-hosted", "repository_id": "123",
                          "repository_owner_id": "456"}},
                      "resolvedDependencies": [
                          {"uri": f"git+https://github.com/{supply.REPOSITORY}@refs/tags/{TAG}",
                           "digest": {"gitCommit": COMMIT}},
                          {"uri": f"pkg:docker/fixture-base-{component}@sha256:{'b' * 64}",
                           "digest": {"sha256": "b" * 64}},
                      ]}, "runDetails": {"builder": {"id": supply.EXPECTED_BUILDER_ID}}}}
    return sbom_statement, provenance


class ReleaseImageEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kordex-test-only-release-evidence-")
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.components_root = self.root / "downloaded"
        self.components_root.mkdir()
        self.old_env = {key: os.environ.get(key) for key in (
            "KORDEX_RELEASE_PRIVATE_KEY", "KORDEX_RELEASE_PUBLIC_KEY",
            "KORDEX_RELEASE_PUBLIC_KEY_SHA256")}
        for key in self.old_env:
            os.environ.pop(key, None)
        for component in (*COMPONENTS, evidence.SUPPLEMENTAL):
            self.make_component(component)

    def reset_components(self):
        shutil.rmtree(self.components_root)
        self.components_root.mkdir()
        for component in (*COMPONENTS, evidence.SUPPLEMENTAL):
            self.make_component(component)

    def tearDown(self):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp.cleanup()

    def make_component(self, component: str, *, image_ref: str | None = None,
                       sbom_doc: dict | None = None, sbom_predicate: dict | None = None,
                       prov_statement: dict | None = None, commit: str = COMMIT) -> Path:
        name = component
        directory = self.components_root / f"artifact-{component}"
        directory.mkdir(exist_ok=True)
        image = image_ref or f"ghcr.io/kevin-phan-25/kordex-{component}@sha256:{hashlib.sha256(component.encode()).hexdigest()}"
        sbom = sbom_doc or SBOM
        sbom_statement, provenance = statements(component)
        if sbom_predicate is not None:
            sbom_statement["predicate"] = sbom_predicate
        if prov_statement is not None:
            provenance = prov_statement
        files = {
            "image-reference.txt": (image + "\n").encode(),
            f"{name}.cdx.json": json.dumps(sbom, separators=(",", ":")).encode(),
            f"{name}.sbom.bundle.jsonl": bundle(sbom_statement),
            f"{name}.provenance.bundle.jsonl": bundle(provenance),
        }
        for path in directory.iterdir():
            if path.is_file():
                path.unlink()
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        manifest = {"schemaVersion": 1, "kind": "kordex-m3-release-image-evidence", "component": name,
                    "buildResult": "PASS",
                    "imageReference": image, "sourceRef": f"refs/tags/{TAG}", "sourceCommit": commit,
                    "repository": supply.REPOSITORY, "workflow": supply.WORKFLOW,
                    "builderId": supply.EXPECTED_BUILDER_ID,
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "buildParameters": {"workflow": {"repository": supply.REPOSITORY,
                        "ref": f"refs/tags/{TAG}", "path": ".github/workflows/ci.yaml"},
                        "github": {"event_name": "workflow_dispatch", "runner_environment": "github-hosted",
                            "repository_id": "123", "repository_owner_id": "456"}},
                    "buildMaterials": [{"uri": f"pkg:docker/fixture-base-{component}@sha256:{'b' * 64}",
                                        "digest": {"sha256": "b" * 64}}],
                    "releaseTag": TAG, "runId": RUN_ID, "runAttempt": RUN_ATTEMPT,
                    "files": {filename: hashlib.sha256(data).hexdigest() for filename, data in files.items()}}
        (directory / "component.json").write_text(json.dumps(manifest, separators=(",", ":")))
        names = sorted((*files.keys(), "component.json"))
        (directory / "SHA256SUMS").write_text("\n".join(
            f"{hashlib.sha256((directory / filename).read_bytes()).hexdigest()}  {filename}" for filename in names) + "\n")
        return directory

    def assemble(self, *, output: Path | None = None) -> int:
        args = ["assemble", "--components-root", str(self.components_root), "--release-tag", TAG,
                "--source-commit", COMMIT, "--run-id", RUN_ID, "--run-attempt", RUN_ATTEMPT,
                "--output-dir", str(output or self.root / "assembled")]
        with patch.object(sys, "argv", ["assemble_m3_release_evidence.py", *args]):
            return evidence.main()

    def package_component(self, component: str, *, output: Path | None = None, image: str | None = None) -> int:
        sbom = self.root / f"input-{component}.cdx.json"
        sbom.write_text(json.dumps(SBOM, separators=(",", ":")))
        sbom_statement, provenance = statements(component)
        sbom_bundle = self.root / f"input-{component}.sbom.bundle"
        provenance_bundle = self.root / f"input-{component}.provenance.bundle"
        sbom_bundle.write_bytes(bundle(sbom_statement))
        provenance_bundle.write_bytes(bundle(provenance))
        args = ["component", "--component", component, "--image-reference", image or
                f"ghcr.io/kevin-phan-25/kordex-{component}@sha256:{hashlib.sha256(component.encode()).hexdigest()}",
                "--sbom", str(sbom), "--sbom-bundle", str(sbom_bundle),
                "--provenance-bundle", str(provenance_bundle), "--source-ref", f"refs/tags/{TAG}",
                "--source-commit", COMMIT, "--release-tag", TAG, "--run-id", RUN_ID,
                "--run-attempt", RUN_ATTEMPT, "--output-dir", str(output or self.root / f"packaged-{component}")]
        with patch.object(sys, "argv", ["assemble_m3_release_evidence.py", *args]):
            return evidence.main()

    def test_component_command_packages_action_attestation_bundles_in_intake_paths(self):
        output = self.root / "packaged-agent"
        self.assertEqual(self.package_component("agent", output=output), 0)
        self.assertTrue((output / "agent.cdx.json").is_file())
        self.assertTrue((output / "agent.sbom.bundle.jsonl").is_file())
        self.assertTrue((output / "agent.provenance.bundle.jsonl").is_file())
        manifest = json.loads((output / "component.json").read_text())
        self.assertEqual(manifest["sourceCommit"], COMMIT)
        self.assertEqual(manifest["buildParameters"]["workflow"]["path"], ".github/workflows/ci.yaml")
        self.assertTrue((output / "SHA256SUMS").is_file())

    def test_component_command_rejects_wrong_digest_and_missing_attestation_input(self):
        wrong = "ghcr.io/kevin-phan-25/kordex-agent:v1.2.3"
        self.assertEqual(self.package_component("agent", output=self.root / "mutable", image=wrong), 2)
        args = ["component", "--component", "agent", "--image-reference",
                f"ghcr.io/kevin-phan-25/kordex-agent@sha256:{'a' * 64}",
                "--sbom", str(self.root / "absent.cdx.json"), "--sbom-bundle", str(self.root / "absent.sbom"),
                "--provenance-bundle", str(self.root / "absent.provenance"), "--source-ref", f"refs/tags/{TAG}",
                "--source-commit", COMMIT, "--release-tag", TAG, "--run-id", RUN_ID,
                "--run-attempt", RUN_ATTEMPT, "--output-dir", str(self.root / "missing-inputs")]
        with patch.object(sys, "argv", ["assemble_m3_release_evidence.py", *args]):
            self.assertEqual(evidence.main(), 2)

    def test_six_component_evidence_sets_are_required_and_relay_is_excluded(self):
        verified = {component: evidence._parse_component_evidence(
            component, self.components_root / f"artifact-{component}", tag=TAG, commit=COMMIT,
            run_id=RUN_ID, run_attempt=RUN_ATTEMPT) for component in COMPONENTS}
        self.assertEqual(set(verified), set(COMPONENTS))
        self.assertNotIn(evidence.SUPPLEMENTAL, verified)
        code = self.assemble()
        self.assertEqual(code, 2)  # Missing protected signer: no synthetic signature is made.
        self.assertFalse((self.root / "assembled").exists())

    def test_each_missing_m3_component_fails_before_signing(self):
        for component in COMPONENTS:
            with self.subTest(component=component):
                self.reset_components()
                for path in self.components_root.rglob("component.json"):
                    data = json.loads(path.read_text())
                    if data["component"] == component:
                        component_dir = path.parent
                        for item in component_dir.iterdir():
                            item.unlink()
                        component_dir.rmdir()
                        break
                output = self.root / f"missing-{component}"
                result = self.assemble(output=output)
                self.assertEqual(result, 2)
                self.assertFalse(output.exists())

    def test_mutable_image_reference_is_rejected(self):
        self.make_component("agent", image_ref="ghcr.io/kevin-phan-25/kordex-agent:v1.2.3")
        self.assertEqual(self.assemble(), 2)

    def test_wrong_sbom_subject_digest_is_rejected(self):
        statement, _ = statements("agent")
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
        self.make_component("agent", sbom_predicate=SBOM)
        directory = self.components_root / "artifact-agent"
        (directory / "agent.sbom.bundle.jsonl").write_bytes(bundle(statement))
        self._rehash_component(directory)
        self.assertEqual(self.assemble(), 2)

    def test_wrong_provenance_subject_digest_is_rejected(self):
        _, statement = statements("agent")
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
        self.make_component("agent", prov_statement=statement)
        self.assertEqual(self.assemble(), 2)

    def test_wrong_source_commit_is_rejected(self):
        self.make_component("agent", commit="c" * 40)
        self.assertEqual(self.assemble(), 2)

    def test_wrong_builder_and_workflow_are_rejected(self):
        for mutate in ("builder", "workflow"):
            with self.subTest(mutate=mutate):
                self.reset_components()
                _, statement = statements("agent")
                predicate = statement["predicate"]
                if mutate == "builder":
                    statement["predicate"]["runDetails"]["builder"]["id"] = "unknown-builder"
                else:
                    predicate["buildDefinition"]["externalParameters"]["workflow"]["path"] = "other.yml"
                self.make_component("agent", prov_statement=statement)
                self.assertEqual(self.assemble(output=self.root / f"bad-{mutate}"), 2)

    def test_malformed_attestation_bundle_is_rejected(self):
        (self.components_root / "artifact-agent/agent.provenance.bundle.jsonl").write_text("not json\n")
        self._rehash_component(self.components_root / "artifact-agent")
        self.assertEqual(self.assemble(), 2)

    def test_each_required_sbom_and_attestation_file_is_required(self):
        for filename in ("agent.cdx.json", "agent.sbom.bundle.jsonl", "agent.provenance.bundle.jsonl"):
            with self.subTest(filename=filename):
                self.reset_components()
                path = self.components_root / "artifact-agent" / filename
                path.unlink()
                self.assertEqual(self.assemble(output=self.root / f"missing-{filename}"), 2)

    def test_component_checksum_manifest_mismatch_is_rejected(self):
        path = self.components_root / "artifact-agent/SHA256SUMS"
        path.write_text(path.read_text().replace("agent.cdx.json", "agent-other.cdx.json"))
        self.assertEqual(self.assemble(), 2)

    def test_component_checksum_mismatch_is_rejected(self):
        path = self.components_root / "artifact-agent/agent.cdx.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.assertEqual(self.assemble(), 2)

    def test_missing_protected_signing_identity_fails_closed(self):
        self.assertEqual(self.assemble(), 2)
        self.assertFalse((self.root / "assembled").exists())

    def test_failed_lock_signature_verification_fails_closed(self):
        private_key = self.root / "invalid-private.pem"
        public_key = self.root / "invalid-public.pem"
        private_key.write_text("not a private key")
        private_key.chmod(0o600)
        public_key.write_text("not a public key")
        os.environ["KORDEX_RELEASE_PRIVATE_KEY"] = str(private_key)
        os.environ["KORDEX_RELEASE_PUBLIC_KEY"] = str(public_key)
        os.environ["KORDEX_RELEASE_PUBLIC_KEY_SHA256"] = "0" * 64
        self.assertEqual(self.assemble(), 2)
        self.assertFalse((self.root / "assembled").exists())

    def test_lock_verifier_rejection_leaves_no_combined_artifact(self):
        # Test-only command doubles. These bytes are not keys or signatures.
        private_key = self.root / "protected-key-fixture"
        public_key = self.root / "public-key-fixture"
        private_key.write_bytes(b"test-only protected key path fixture")
        private_key.chmod(0o600)
        public_key.write_bytes(b"test-only public key path fixture")
        der = bytes.fromhex("302a300506032b6570032100") + b"p" * 32
        os.environ["KORDEX_RELEASE_PRIVATE_KEY"] = str(private_key)
        os.environ["KORDEX_RELEASE_PUBLIC_KEY"] = str(public_key)
        os.environ["KORDEX_RELEASE_PUBLIC_KEY_SHA256"] = hashlib.sha256(der).hexdigest()

        def fake_openssl(command, **kwargs):
            if command[:2] == ["openssl", "pkey"] and "-pubout" in command:
                Path(command[command.index("-out") + 1]).write_text("test-only derived public-key fixture")
            elif command[:2] == ["openssl", "pkey"] and "-outform" in command:
                Path(command[command.index("-out") + 1]).write_bytes(der)
            elif command[:2] == ["openssl", "pkeyutl"]:
                Path(command[command.index("-out") + 1]).write_bytes(b"test-only signature fixture")
            elif command[:2] == ["bash", str(ROOT / "scripts/verify-image-lock.sh")]:
                raise subprocess.CalledProcessError(1, command)
            else:
                raise AssertionError(f"unexpected verifier command: {command}")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(evidence.subprocess, "run", side_effect=fake_openssl):
            self.assertEqual(self.assemble(), 2)
        self.assertFalse((self.root / "assembled").exists())

    def test_global_manifest_checksums_and_component_names_are_bound(self):
        # No unsigned or partially assembled output may survive the signer gate.
        result = self.assemble()
        self.assertEqual(result, 2)
        self.assertFalse((self.root / "assembled").exists())

    def _rehash_component(self, directory: Path):
        manifest_path = directory / "component.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"] = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                              for name in manifest["files"]}
        manifest_path.write_text(json.dumps(manifest, separators=(",", ":")))
        names = sorted((*manifest["files"].keys(), "component.json"))
        (directory / "SHA256SUMS").write_text("\n".join(
            f"{hashlib.sha256((directory / filename).read_bytes()).hexdigest()}  {filename}" for filename in names) + "\n")


if __name__ == "__main__":
    unittest.main()
