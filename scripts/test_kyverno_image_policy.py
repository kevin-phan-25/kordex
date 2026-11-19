from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT / "deployments/policies/kyverno/kordex-release-images.yaml"
KUSTOMIZATION_PATH = ROOT / "deployments/policies/kyverno/kustomization.yaml"
EXPECTED_IMAGES = {
    "ghcr.io/kevin-phan-25/kordex-control-plane*",
    "ghcr.io/kevin-phan-25/kordex-agent*",
    "ghcr.io/kevin-phan-25/kordex-operator*",
    "ghcr.io/kevin-phan-25/kordex-dashboard*",
}
EXPECTED_SUBJECT = (
    r"^https://github\.com/kevin-phan-25/kordex/\.github/workflows/ci\.yaml"
    r"@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$"
)


class KyvernoImagePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
        cls.kustomization = yaml.safe_load(KUSTOMIZATION_PATH.read_text(encoding="utf-8"))
        cls.rule = cls.policy["spec"]["rules"][0]
        cls.verifier = cls.rule["verifyImages"][0]

    def test_policy_is_cluster_scoped_and_fails_closed(self) -> None:
        self.assertEqual(self.policy["apiVersion"], "kyverno.io/v1")
        self.assertEqual(self.policy["kind"], "ClusterPolicy")
        self.assertEqual(self.policy["metadata"]["name"], "kordex-release-images")
        self.assertEqual(self.policy["spec"]["webhookConfiguration"]["failurePolicy"], "Fail")
        self.assertFalse(self.policy["spec"]["background"])
        self.assertEqual(self.rule["match"]["any"][0]["resources"]["kinds"], ["Pod"])
        self.assertEqual(self.verifier["failureAction"], "Enforce")
        self.assertIs(self.verifier["required"], True)

    def test_only_release_workflow_signed_digest_pinned_images_match(self) -> None:
        self.assertEqual(set(self.verifier["imageReferences"]), EXPECTED_IMAGES)
        self.assertIs(self.verifier["verifyDigest"], True)
        self.assertIs(self.verifier["mutateDigest"], False)
        self.assertEqual(len(self.verifier["attestors"]), 1)
        attestor = self.verifier["attestors"][0]
        self.assertEqual(attestor["count"], 1)
        self.assertEqual(len(attestor["entries"]), 1)
        keyless = attestor["entries"][0]["keyless"]
        self.assertEqual(keyless["issuer"], "https://token.actions.githubusercontent.com")
        self.assertEqual(keyless["subjectRegExp"], EXPECTED_SUBJECT)
        identity = re.compile(keyless["subjectRegExp"])
        self.assertIsNotNone(identity.fullmatch("https://github.com/kevin-phan-25/kordex/.github/workflows/ci.yaml@refs/tags/v1.2.3"))
        for rejected in (
            "https://github.com/kevin-phan-25/kordex/.github/workflows/ci.yaml@refs/heads/main",
            "https://github.com/attacker/kordex/.github/workflows/ci.yaml@refs/tags/v1.2.3",
            "https://github.com/kevin-phan-25/kordex/.github/workflows/other.yaml@refs/tags/v1.2.3",
            "https://github.com/kevin-phan-25/kordex/.github/workflows/ci.yaml@refs/tags/v1.2.3-rc.1",
        ):
            with self.subTest(identity=rejected):
                self.assertIsNone(identity.fullmatch(rejected))

    def test_kustomize_overlay_renders_the_policy(self) -> None:
        self.assertEqual(self.kustomization["resources"], ["kordex-release-images.yaml"])
        kubectl = shutil.which("kubectl")
        if not kubectl:
            self.skipTest("kubectl is unavailable; CI installs it for this contract test")
        rendered = subprocess.run(
            [kubectl, "kustomize", str(KUSTOMIZATION_PATH.parent)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        document = yaml.safe_load(rendered)
        self.assertEqual(document["kind"], "ClusterPolicy")
        self.assertEqual(document["metadata"]["name"], self.policy["metadata"]["name"])
        self.assertEqual(document["spec"], self.policy["spec"])


if __name__ == "__main__":
    unittest.main()
