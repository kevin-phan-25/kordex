#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temporary:
    export = Path(temporary)
    (export / "realm.json").write_text(json.dumps({"realm": "kordex", "users": [{"id": "subject-a"}, {"id": "subject-b"}]}))
    verifier = root / "scripts/verify-gke-private-lab-memberships.py"
    good = subprocess.run([sys.executable, str(verifier), str(export)], input="subject-a\nsubject-b\n", text=True, capture_output=True)
    assert good.returncode == 0 and "matched=2 unmatched=0" in good.stdout
    bad = subprocess.run([sys.executable, str(verifier), str(export)], input="subject-not-in-realm\n", text=True, capture_output=True)
    assert bad.returncode == 1 and "unmatched=1" in bad.stdout
    assert "subject-not-in-realm" not in bad.stdout + bad.stderr
    wrong_realm = json.loads((export / "realm.json").read_text())
    wrong_realm["realm"] = "other"
    (export / "realm.json").write_text(json.dumps(wrong_realm))
    wrong = subprocess.run([sys.executable, str(verifier), str(export)], input="subject-a\n", text=True, capture_output=True)
    assert wrong.returncode == 1 and "expected realm export was not found" in wrong.stderr
    assert "subject-a" not in wrong.stdout + wrong.stderr
print("membership subject verifier tests passed without printing subject values")
