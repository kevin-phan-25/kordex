"""Render the self-managed overlay without creating production trust material.

The fixture is deliberately malformed as an Ed25519 key and exists only in a
temporary sibling of the overlay. Kustomize treats keys.json as opaque data;
this test checks packaging/rendering contracts, not cryptographic trust.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
OVERLAY = ROOT / "deployments/kustomize/overlays/self-managed"
FIXTURE = '{"TEST_ONLY_SYNTHETIC_NOT_TRUSTED":"NOT_A_REAL_PUBLIC_KEY"}\n'
OVERLAY_INPUTS = (
    "kustomization.yaml",
    "agent-pull-secret.patch.yaml",
    "agent-settings.patch.yaml",
    "operator-pull-secret.patch.yaml",
    "operator-settings.patch.yaml",
    "agent-mtls.patch.yaml",
)


class SelfManagedTrustRenderTests(unittest.TestCase):
    def test_overlay_renders_with_temporary_non_trust_fixture(self):
        with tempfile.TemporaryDirectory(
            prefix=".m3-self-managed-render-", dir=OVERLAY.parent
        ) as temporary:
            render_dir = Path(temporary)
            # Copy only known non-secret overlay inputs. In particular, never
            # copy or read a possible customer-provided ignored keys.json.
            for name in OVERLAY_INPUTS:
                shutil.copy2(OVERLAY / name, render_dir / name)
            (render_dir / "keys.json").write_text(FIXTURE, encoding="utf-8")

            result = subprocess.run(
                [
                    "kubectl",
                    "kustomize",
                    "--load-restrictor=LoadRestrictionsNone",
                    str(render_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = result.stdout
        self.assertIn("name: kordex-hub-trust", rendered)
        self.assertIn("TEST_ONLY_SYNTHETIC_NOT_TRUSTED", rendered)
        self.assertIn("NOT_A_REAL_PUBLIC_KEY", rendered)
        self.assertIn("name: kordex-agent", rendered)
        self.assertIn("name: kordex-operator", rendered)
        self.assertIn('upgradeEnabled: "false"', rendered)
        self.assertIn('gkeUpgradeEnabled: "false"', rendered)
        self.assertIn("registry.example.invalid/platform/kordex/agent", rendered)
        self.assertIn("registry.example.invalid/platform/kordex/operator", rendered)
        self.assertIn('mtlsEnabled: "false"', rendered)
        self.assertNotIn("kordex-agent-mtls-client", rendered)

    def test_opt_in_mtls_patch_mounts_external_secrets_without_rendering_values(self):
        with tempfile.TemporaryDirectory(
            prefix=".m3-self-managed-mtls-render-", dir=OVERLAY.parent
        ) as temporary:
            render_dir = Path(temporary)
            for name in OVERLAY_INPUTS:
                shutil.copy2(OVERLAY / name, render_dir / name)
            (render_dir / "keys.json").write_text(FIXTURE, encoding="utf-8")
            kustomization = render_dir / "kustomization.yaml"
            source = kustomization.read_text(encoding="utf-8")
            self.assertIn("  - path: operator-pull-secret.patch.yaml\n", source)
            kustomization.write_text(
                source.replace(
                    "  - path: operator-pull-secret.patch.yaml\n",
                    "  - path: operator-pull-secret.patch.yaml\n  - path: agent-mtls.patch.yaml\n",
                    1,
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "kubectl",
                    "kustomize",
                    "--load-restrictor=LoadRestrictionsNone",
                    str(render_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('mtlsEnabled: "true"', result.stdout)
        self.assertIn('gatewayAuthRequired: "false"', result.stdout)
        self.assertIn("kordex-agent-mtls-client", result.stdout)
        self.assertIn("kordex-agent-mtls-ca", result.stdout)
        self.assertIn("/var/run/kordex/mtls-client/tls.key", result.stdout)
        self.assertIn("REPLACE_WITH_PRIVATE_RELAY_DNS_NAME", result.stdout)
        self.assertNotIn("name: KORDEX_GATEWAY_CLIENT_SECRET", result.stdout)
        self.assertNotIn("-----BEGIN", result.stdout)


if __name__ == "__main__":
    unittest.main()
