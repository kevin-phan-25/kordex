from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_container_base_lock import BaseImageError, validate_dockerfile, verify_repository


class ContainerBaseLockTests(unittest.TestCase):
    def test_runtime_dockerfiles_use_digest_pinned_indexes(self) -> None:
        root = Path(__file__).resolve().parent.parent
        result = verify_repository(root)
        self.assertEqual(set(result), {
            "control-plane/Dockerfile", "agent/Dockerfile", "operator/Dockerfile", "dashboard/Dockerfile"
        })
        self.assertTrue(all(count > 0 for count in result.values()))

    def test_rejects_mutable_tags_and_direct_from_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Dockerfile"
            with self.assertRaisesRegex(BaseImageError, "pinned by sha256"):
                validate_dockerfile(path, "ARG KORDEX_RUNTIME_BASE=debian:bookworm-slim\nFROM ${KORDEX_RUNTIME_BASE}\n")
            with self.assertRaisesRegex(BaseImageError, "FROM must reference"):
                validate_dockerfile(path, "FROM debian:bookworm-slim\n")

    def test_rejects_missing_and_unused_base_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Dockerfile"
            with self.assertRaisesRegex(BaseImageError, "undeclared base ARG"):
                validate_dockerfile(path, "FROM ${KORDEX_RUNTIME_BASE}\n")
            digest = "a" * 64
            with self.assertRaisesRegex(BaseImageError, "is not used"):
                validate_dockerfile(
                    path,
                    f"ARG KORDEX_RUNTIME_BASE=debian:stable@sha256:{digest}\n"
                    f"ARG KORDEX_UNUSED_BASE=alpine:stable@sha256:{digest}\n"
                    "FROM ${KORDEX_RUNTIME_BASE}\n",
                )


if __name__ == "__main__":
    unittest.main()
