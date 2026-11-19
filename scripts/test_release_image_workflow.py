from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yaml"
RELEASE_JOB = "  release-images:\n"
ACTION_REF = re.compile(r"^\s+uses:\s+([^\s]+)\s*$", re.MULTILINE)
SHA_PIN = re.compile(r"^[^@]+@[0-9a-f]{40}$")


class ReleaseImageWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        if RELEASE_JOB not in workflow:
            raise AssertionError("release-images job is missing")
        cls.workflow = workflow
        cls.release = workflow.split(RELEASE_JOB, maxsplit=1)[1]

    def test_release_is_manual_tag_dispatch_with_second_explicit_gate(self) -> None:
        self.assertIn("  workflow_dispatch:\n", self.workflow)
        self.assertIn("      publish_images:\n", self.workflow)
        self.assertIn("        type: boolean\n", self.workflow)
        self.assertIn("        default: false\n", self.workflow)
        self.assertRegex(
            self.release.split("    needs:\n", maxsplit=1)[0],
            r"if: github\.event_name == 'workflow_dispatch' && inputs\.publish_images == true && startsWith\(github\.ref, 'refs/tags/v'\)",
        )
        self.assertIn('[[ "$GITHUB_REF" == "refs/tags/$RELEASE_TAG" ]]', self.release)
        self.assertIn('[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]', self.release)
        self.assertIn(r"^v[0-9]+\.[0-9]+\.[0-9]+$", self.release)

    def test_release_waits_for_all_current_ci_jobs(self) -> None:
        required = (
            "terraform-self-managed-lab",
            "ansible-ee-contract",
            "offline-oci-podman",
            "go",
            "container",
            "dashboard",
            "envtest",
            "helm",
            "kustomize",
            "kind-registration",
        )
        needs = self.release.split("    runs-on:", maxsplit=1)[0]
        for job in required:
            with self.subTest(job=job):
                self.assertRegex(needs, rf"(?m)^      - {re.escape(job)}$")

    def test_release_scans_and_attests_the_candidate_digest_before_tagging(self) -> None:
        digest_ref = "${{ env.IMAGE }}@${{ steps.build.outputs.digest }}"
        self.assertGreaterEqual(self.release.count(digest_ref), 2)
        self.assertGreaterEqual(self.release.count("subject-digest: ${{ steps.build.outputs.digest }}"), 2)
        self.assertIn("severity: HIGH,CRITICAL", self.release)
        self.assertIn("sbom-path: kordex-${{ matrix.component }}-${{ inputs.release_tag }}.cdx.json", self.release)
        self.assertIn('cosign sign --yes "$IMAGE@${{ steps.build.outputs.digest }}"', self.release)
        self.assertIn('docker buildx imagetools create \\\n', self.release)
        self.assertIn("published version tag does not resolve to the scanned and signed manifest digest", self.release)
        self.assertGreaterEqual(self.release.count("could not safely determine"), 2)
        self.assertLess(self.release.index("Scan exact candidate digest"), self.release.index("Publish the release version tag by verified digest"))
        self.assertLess(self.release.index("Sign exact release image digest"), self.release.index("Publish the release version tag by verified digest"))

    def test_release_actions_are_pinned_to_full_commit_shas(self) -> None:
        for action in ACTION_REF.findall(self.release):
            with self.subTest(action=action):
                self.assertRegex(action, SHA_PIN)


if __name__ == "__main__":
    unittest.main()
