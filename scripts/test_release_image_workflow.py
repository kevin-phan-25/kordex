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
        self.assertIn(
            "        description: Explicitly authorize publishing six M3 images plus supplemental agent-relay\n",
            self.workflow,
        )
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
        self.assertIn("component: [control-plane, agent, operator, dashboard, ansible-ee, postgres, agent-relay]", self.release)
        self.assertIn("integrations/Containerfile.agent-relay", self.release)
        self.assertIn("integrations/ansible-ee/Containerfile", self.release)
        self.assertIn("integrations/postgres/Containerfile", self.release)
        self.assertIn("scripts/prepare-release-image-build-args.sh", self.release)
        self.assertIn("KORDEX_ANSIBLE_EE_BASE", self.release)
        self.assertIn("KORDEX_POSTGRES_BASE", self.release)
        self.assertLess(self.release.index("Scan exact candidate digest"), self.release.index("Publish the release version tag by verified digest"))
        self.assertLess(self.release.index("Sign exact release image digest"), self.release.index("Publish the release version tag by verified digest"))

    def test_each_component_retains_the_exact_preflight_attestation_bundle_format(self) -> None:
        self.assertIn("id: provenance-attestation", self.release)
        self.assertIn("id: sbom-attestation", self.release)
        self.assertIn("steps.sbom-attestation.outputs.bundle-path", self.release)
        self.assertIn("steps.provenance-attestation.outputs.bundle-path", self.release)
        self.assertIn("scripts/assemble_m3_release_evidence.py component", self.release)
        self.assertIn("{component}.sbom.bundle.jsonl", (ROOT / "scripts/assemble_m3_release_evidence.py").read_text())
        self.assertIn("{component}.provenance.bundle.jsonl", (ROOT / "scripts/assemble_m3_release_evidence.py").read_text())
        self.assertIn("image-reference.txt", (ROOT / "scripts/assemble_m3_release_evidence.py").read_text())
        intake = (ROOT / "docs/m3-artifact-intake.md").read_text()
        self.assertIn("/artifacts/kordex-m3-six-image/components/agent/agent.cdx.json", intake)
        self.assertIn("/artifacts/kordex-m3-six-image/components/postgres/postgres.provenance.bundle.jsonl", intake)
        self.assertIn("retention-days: 90", self.release)
        self.assertIn("if-no-files-found: error", self.release)

    def test_hosted_release_only_packages_verification_inputs_and_never_signs_lock(self) -> None:
        self.assertIn("  assemble-m3-release-evidence:\n", self.release)
        signer = self.release.split("  assemble-m3-release-evidence:\n", maxsplit=1)[1]
        self.assertRegex(
            signer.split("    needs:", maxsplit=1)[0],
            r"if: github\.event_name == 'workflow_dispatch' && inputs\.publish_images == true && startsWith\(github\.ref, 'refs/tags/v'\)",
        )
        self.assertIn("needs: [release-images]", signer)
        self.assertIn("      actions: read\n      contents: read", signer)
        self.assertNotIn("packages: write", signer)
        self.assertNotIn("id-token: write", signer)
        self.assertNotIn("attestations: write", signer)
        self.assertNotIn("KORDEX_RELEASE_PRIVATE_KEY", self.release)
        self.assertNotIn("KORDEX_RELEASE_PUBLIC_KEY", self.release)
        self.assertNotIn("kordex-m3-release-signing", self.release)
        self.assertNotIn("assemble_m3_release_evidence.py assemble", signer)
        self.assertIn("Package verification-ready evidence without signing", signer)
        self.assertIn('"cryptographicVerification": "NOT RUN"', signer)
        self.assertIn('"releaseLockCandidate": "NOT PRODUCED"', signer)
        self.assertIn('"signature": "NOT PRODUCED"', signer)
        self.assertNotIn("actions/checkout", signer)
        normal_ci = self.workflow.split("  container:\n", maxsplit=1)[1].split("\n  dashboard:", maxsplit=1)[0]
        self.assertNotIn("kordex-m3-release-signing", normal_ci)
        self.assertNotIn("KORDEX_RELEASE_PRIVATE_KEY", normal_ci)
        self.assertIn("actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333", self.release)
        self.assertIn("exact six M3 component evidence sets are required", signer)
        self.assertIn("component evidence contains a symbolic link", signer)
        self.assertIn("component evidence must contain only regular files", signer)
        self.assertIn("SHA256SUMS", signer)
        self.assertGreaterEqual(self.release.count("retention-days: 90"), 2)
        self.assertIn("kordex-m3-six-image-release-${{ inputs.release_tag }}-${{ github.run_id }}-${{ github.run_attempt }}", self.release)

    def test_release_actions_are_pinned_to_full_commit_shas(self) -> None:
        for action in ACTION_REF.findall(self.release):
            with self.subTest(action=action):
                self.assertRegex(action, SHA_PIN)

    def test_exact_six_m3_images_are_in_the_attested_release_matrix(self) -> None:
        required = {"control-plane", "agent", "operator", "dashboard", "ansible-ee", "postgres"}
        matrix = re.search(r"(?m)^\s+component: \[([^]]+)\]$", self.release)
        self.assertIsNotNone(matrix)
        components = set(matrix.group(1).replace(" ", "").split(","))
        self.assertTrue(required.issubset(components))
        self.assertEqual(components - required, {"agent-relay"})

    def test_ci_container_job_builds_each_locked_component_with_its_real_context(self) -> None:
        container = self.workflow.split("  container:\n", maxsplit=1)[1].split("\n  dashboard:", maxsplit=1)[0]
        self.assertIn("component: [control-plane, agent, operator, dashboard, ansible-ee, postgres, agent-relay]", container)
        self.assertIn("scripts/prepare-release-image-build-args.sh", container)
        self.assertIn("vars.KORDEX_ANSIBLE_EE_BASE", container)
        self.assertIn("vars.KORDEX_POSTGRES_BASE", container)
        self.assertIn("ansible-ee) file=integrations/ansible-ee/Containerfile; context=integrations/ansible-ee", container)
        self.assertIn("postgres) file=integrations/postgres/Containerfile; context=integrations/postgres", container)
        self.assertIn('docker build "${build_args[@]}"', container)


if __name__ == "__main__":
    unittest.main()
