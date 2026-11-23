import datetime as dt
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/test_postgres_recovery_measurement.py"
SPEC = importlib.util.spec_from_file_location("postgres_recovery_measurement", SCRIPT)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


class PostgresRecoveryMeasurementTests(unittest.TestCase):
    def test_watermark_requires_a_sequence_transaction_id_and_timezone(self):
        parsed = recovery.parse_watermark("7|742|2026-11-23T03:14:14.395742Z")
        self.assertEqual(parsed["sequence"], 7)
        self.assertEqual(parsed["transactionId"], "742")
        self.assertEqual(parsed["markerTimeUtc"], "2026-11-23T03:14:14.395742Z")
        self.assertEqual(parsed["_time"].tzinfo, dt.timezone.utc)
        for invalid in ("0|742|2026-11-23T03:14:14Z", "x|742|2026-11-23T03:14:14Z",
                        "7||2026-11-23T03:14:14Z", "7|742|2026-11-23T03:14:14"):
            with self.subTest(invalid=invalid), self.assertRaises(recovery.RecoveryTestError):
                recovery.parse_watermark(invalid)

    def test_measurement_rejects_non_digest_pinned_image_before_podman(self):
        with patch.object(recovery.shutil, "which") as which:
            with self.assertRaisesRegex(recovery.RecoveryTestError, "pinned by SHA-256"):
                recovery.perform("postgres:17-alpine")
            which.assert_not_called()

    def test_generated_container_collision_is_never_adopted_or_removed(self):
        owned = []
        with patch.object(recovery.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaisesRegex(recovery.RecoveryTestError, "already exists"):
                recovery.start_database("existing-name", "source", "network", "image", owned)
        self.assertEqual(owned, [])


if __name__ == "__main__":
    unittest.main()
