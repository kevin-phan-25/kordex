from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_image_sbom import SBOMError, validate_sbom


def valid_sbom() -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"type": "library", "name": "openssl", "version": "3.0.2"}],
    }


class ImageSBOMValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "sbom.json"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_document(self, document: object) -> None:
        self.path.write_text(json.dumps(document), encoding="utf-8")

    def test_accepts_nonempty_cyclonedx_inventory(self) -> None:
        self.write_document(valid_sbom())
        self.assertEqual(validate_sbom(self.path), 1)

    def test_rejects_non_cyclonedx_or_empty_inventory(self) -> None:
        document = valid_sbom()
        document["bomFormat"] = "SPDX"
        self.write_document(document)
        with self.assertRaisesRegex(SBOMError, "bomFormat"):
            validate_sbom(self.path)

        document = valid_sbom()
        document["components"] = []
        self.write_document(document)
        with self.assertRaisesRegex(SBOMError, "at least one component"):
            validate_sbom(self.path)

    def test_rejects_invalid_component_and_duplicate_json_members(self) -> None:
        document = valid_sbom()
        document["components"] = [{"type": "library", "name": " "}]
        self.write_document(document)
        with self.assertRaisesRegex(SBOMError, "nonempty name"):
            validate_sbom(self.path)

        self.path.write_text(
            '{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(SBOMError, "duplicate JSON member"):
            validate_sbom(self.path)

    def test_rejects_symlink(self) -> None:
        target = Path(self.tempdir.name) / "target.json"
        target.write_text(json.dumps(valid_sbom()), encoding="utf-8")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(SBOMError, "regular non-symlink"):
            validate_sbom(self.path)


if __name__ == "__main__":
    unittest.main()
