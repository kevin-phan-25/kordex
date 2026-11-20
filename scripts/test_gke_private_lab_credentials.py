#!/usr/bin/env python3
"""Check credential helper permissions, confirmation, and no-overwrite behavior."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(__file__).with_name("gke-private-lab-generate-credentials.py")
with tempfile.TemporaryDirectory(prefix="kordex-credential-test-") as temp:
    output = Path(temp) / "secrets"
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    env = os.environ.copy()
    env["KORDEX_CREDENTIAL_GENERATE_CONFIRM"] = "GENERATE PRIVATE GKE LAB CREDENTIAL FILES"
    result = subprocess.run([sys.executable, str(script), str(output)], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    files = list(output.iterdir())
    assert len(files) == 6
    values = [path.read_text().strip() for path in files]
    assert all(value and len(value) >= 20 for value in values)
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in files)
    assert not any(value in result.stdout + result.stderr for value in values)
    again = subprocess.run([sys.executable, str(script), str(output)], env=env, text=True, capture_output=True)
    assert again.returncode != 0 and "refusing to overwrite" in again.stderr
print("private lab credential file tests passed")
