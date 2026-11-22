"""Offline tests for the fixed M3 gcloud executable and environment policy."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m3_gcloud_context", ROOT / "scripts/m3_gcloud_context.py")
context = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(context)


class GCloudContextTests(unittest.TestCase):
    def test_caller_environment_cannot_select_executable_home_or_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "gcloud"
            binary.write_text("synthetic executable", encoding="utf-8")
            with patch.object(context, "executable_path", return_value=binary), \
                 patch.object(context, "_check_config_dir"), \
                 patch.dict(os.environ, {"GCLOUD": "/tmp/attacker", "HOME": "/tmp/home",
                     "PATH": "/tmp/bin", "CLOUDSDK_CONFIG": "/tmp/config",
                     "CLOUDSDK_ACTIVE_CONFIG_NAME": "attacker", "CLOUDSDK_CORE_PROJECT": "other"}, clear=False):
                seen = {}
                def run(argv, **kwargs):
                    seen["argv"] = argv
                    seen["env"] = kwargs["env"]
                    return subprocess.CompletedProcess(argv, 0, "Google Cloud SDK 555.0.0\n", "")
                described = context.describe(config_dir=Path("/etc/kordex/gcloud"), run=run)
            self.assertEqual(seen["argv"][0], str(binary))
            self.assertEqual(seen["env"]["PATH"], context.SEARCH_PATH)
            self.assertEqual(seen["env"]["HOME"], context.HOME)
            self.assertEqual(seen["env"]["CLOUDSDK_CONFIG"], "/etc/kordex/gcloud")
            self.assertNotIn("CLOUDSDK_CORE_PROJECT", seen["env"])
            self.assertEqual(described["version"], "555.0.0")

    def test_executable_outside_controlled_installation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "gcloud"
            fake.write_text("synthetic", encoding="utf-8")
            fake.chmod(0o755)
            with patch.dict(os.environ, {"GCLOUD": str(fake), "PATH": temp,
                                         "HOME": temp, "CLOUDSDK_CONFIG": temp}, clear=False), \
                    patch.object(context.shutil, "which", return_value=str(fake)) as which:
                with self.assertRaisesRegex(context.GCloudContextError, "outside the protected"):
                    context.executable_path()
                which.assert_called_once_with("gcloud", path=context.SEARCH_PATH)

    def test_missing_or_writable_configuration_directory_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "config"
            config.mkdir(mode=0o777)
            config.chmod(0o777)
            with self.assertRaisesRegex(context.GCloudContextError, "protected root-owned"):
                context.environment(config)


if __name__ == "__main__":
    unittest.main()
