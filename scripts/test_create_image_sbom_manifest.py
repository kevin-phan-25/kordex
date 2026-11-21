from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.create_image_sbom_manifest import create_manifest
from scripts.validate_image_sbom import SBOMError


class ImageSBOMManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.sbom = self.root / "agent.cdx.json"
        self.output = self.root / "manifest.json"
        self.sbom.write_text(
            json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [{"type": "library", "name": "openssl"}],
            }),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def create(self, **overrides: str) -> dict[str, object]:
        values = {
            "component": "agent",
            "source_commit": "a" * 40,
            "image_config_digest": "sha256:" + "b" * 64,
            "sbom_path": self.sbom,
            "output_path": self.output,
        }
        values.update(overrides)
        return create_manifest(**values)

    def test_binds_component_source_image_and_sbom_hash(self) -> None:
        result = self.create()
        self.assertEqual(result["component"], "agent")
        self.assertEqual(result["imageConfigDigest"], "sha256:" + "b" * 64)
        self.assertEqual(result["sourceCommit"], "a" * 40)
        self.assertEqual(result["sbom"]["sha256"], hashlib.sha256(self.sbom.read_bytes()).hexdigest())

    def test_accepts_agent_relay_release_component(self) -> None:
        result = self.create(component="agent-relay")
        self.assertEqual(result["component"], "agent-relay")

    def test_rejects_unlisted_component_and_malformed_digests(self) -> None:
        with self.assertRaisesRegex(SBOMError, "fixed Kordex image catalog"):
            self.create(component="postgres")
        with self.assertRaisesRegex(SBOMError, "source commit"):
            self.create(source_commit="not-a-commit")
        with self.assertRaisesRegex(SBOMError, "image config digest"):
            self.create(image_config_digest="sha256:bad")

    def test_refuses_to_overwrite_manifest(self) -> None:
        self.output.write_text("retained evidence", encoding="utf-8")
        with self.assertRaisesRegex(SBOMError, "without overwriting"):
            self.create()
        self.assertEqual(self.output.read_text(encoding="utf-8"), "retained evidence")

    def test_cli_writes_manifest_for_a_bound_sbom(self) -> None:
        script = Path(__file__).with_name("create_image_sbom_manifest.py")
        subprocess.run(
            [
                sys.executable,
                str(script),
                "--component", "agent",
                "--source-commit", "a" * 40,
                "--image-config-digest", "sha256:" + "b" * 64,
                "--sbom", str(self.sbom),
                "--output", str(self.output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        document = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(document["sbom"]["sha256"], hashlib.sha256(self.sbom.read_bytes()).hexdigest())

    def test_rejects_symlinked_sbom_input(self) -> None:
        target = self.root / "target.json"
        target.write_bytes(self.sbom.read_bytes())
        self.sbom.unlink()
        self.sbom.symlink_to(target)
        with self.assertRaisesRegex(SBOMError, "regular non-symlink"):
            self.create()


if __name__ == "__main__":
    unittest.main()
