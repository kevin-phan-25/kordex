#!/usr/bin/env python3
"""Generate local lab credentials as protected files without displaying values."""
import os
from pathlib import Path
import secrets
import sys


NAMES = (
    "postgresSuperuserPassword",
    "kordexRuntimePassword",
    "kordexMigrationPassword",
    "keycloakDbPassword",
    "keycloakBootstrapPassword",
    "keycloakBootstrapUsername",
)
CONFIRM = "GENERATE PRIVATE GKE LAB CREDENTIAL FILES"
ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    if os.environ.get("KORDEX_CREDENTIAL_GENERATE_CONFIRM") != CONFIRM:
        raise SystemExit(f"Set KORDEX_CREDENTIAL_GENERATE_CONFIRM to the exact phrase: {CONFIRM}")
    if len(sys.argv) != 2:
        raise SystemExit("usage: gke-private-lab-generate-credentials.py PROTECTED_DIRECTORY")
    original = Path(sys.argv[1])
    if original.is_symlink() or not original.is_dir():
        raise SystemExit("credential directory must be an existing non-symlink directory")
    directory = original.resolve(strict=True)
    if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise SystemExit("credential directory must be owned by the invoking user and mode 0700 or stricter")
    if directory == ROOT or ROOT in directory.parents:
        raise SystemExit("credential files must be written outside the Git repository")
    if any((directory / name).exists() for name in NAMES):
        raise SystemExit("credential output already exists; refusing to overwrite")
    values = {name: secrets.token_urlsafe(48) for name in NAMES[:-1]}
    values["keycloakBootstrapUsername"] = f"kordex-bootstrap-{secrets.token_hex(8)}"
    created = []
    try:
        for name, value in values.items():
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(value + "\n")
            created.append(directory / name)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise SystemExit("could not safely create the complete credential file set; no generated files were retained") from None
    print(f"Generated {len(values)} protected credential files; values were not displayed.")


if __name__ == "__main__":
    main()
