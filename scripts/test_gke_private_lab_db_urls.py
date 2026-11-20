#!/usr/bin/env python3
"""Verify generated database DSNs encode secrets and require full TLS verification."""
import importlib.util
from pathlib import Path
import os
import tempfile

path = Path(__file__).with_name("gke-private-lab-prepare-db-urls.py")
spec = importlib.util.spec_from_file_location("gke_private_lab_db_urls", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

runtime, migration = module.build_urls("p@ss:/?#", "migr@te&pass")
assert "p%40ss%3A%2F%3F%23" in runtime
assert "migr%40te%26pass" in migration
assert "kordex-postgres.kordex-management.svc.cluster.local:5432" in runtime
assert "sslmode=verify-full&sslrootcert=/var/run/kordex/ca/ca.crt" in runtime

with tempfile.TemporaryDirectory(prefix="kordex-db-url-test-") as directory:
    base = Path(directory)
    protected = base / "protected"
    protected.mkdir(mode=0o700)
    os.chmod(protected, 0o700)
    runtime_file = protected / "runtime-password"
    migration_file = protected / "migration-password"
    runtime_file.write_text("p@ss:/?#\n")
    migration_file.write_text("migr@te&pass\n")
    os.chmod(runtime_file, 0o600)
    os.chmod(migration_file, 0o600)
    output = protected / "output"
    output.mkdir(mode=0o700)
    assert module.read_password(runtime_file) == "p@ss:/?#"
    value, _ = module.build_urls(module.read_password(runtime_file), module.read_password(migration_file))
    module.write_private(output / "databaseURL", value)
    assert (output / "databaseURL").stat().st_mode & 0o777 == 0o600
print("private lab database URL preparation tests passed")
