#!/usr/bin/env python3
"""Write PostgreSQL verify-full DSN files without printing password material."""
import argparse
import os
from pathlib import Path
from urllib.parse import quote


HOST = "kordex-postgres.kordex-management.svc.cluster.local"
CA = "/var/run/kordex/ca/ca.crt"
ROOT = Path(__file__).resolve().parents[1]


def read_password(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("password file must be a protected regular file owned by the invoking user")
    value = path.read_text(encoding="utf-8")
    if value.endswith("\n"):
        value = value[:-1]
    if not value or "\n" in value or "\r" in value:
        raise ValueError("password file must contain one non-empty line")
    return value


def build_urls(runtime_password: str, migration_password: str) -> tuple[str, str]:
    runtime = f"postgresql://kordex_runtime:{quote(runtime_password, safe='')}@{HOST}:5432/kordex?sslmode=verify-full&sslrootcert={CA}"
    migration = f"postgresql://kordex_migrator:{quote(migration_password, safe='')}@{HOST}:5432/kordex?sslmode=verify-full&sslrootcert={CA}"
    return runtime, migration


def write_private(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(value + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-password-file", required=True, type=Path)
    parser.add_argument("--migration-password-file", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.output_dir.is_symlink() or not args.output_dir.is_dir():
        raise SystemExit("output directory must be an existing non-symlink directory")
    output = args.output_dir.resolve(strict=True)
    if output.stat().st_uid != os.getuid() or output.stat().st_mode & 0o077:
        raise SystemExit("output directory must be protected (mode 0700 or stricter)")
    if output == ROOT or ROOT in output.parents:
        raise SystemExit("database URL files must be written outside the Git repository")
    targets = (output / "databaseURL", output / "migrationDatabaseURL")
    if any(path.exists() for path in targets):
        raise SystemExit("refusing to overwrite existing database URL files")
    try:
        runtime, migration = build_urls(read_password(args.runtime_password_file), read_password(args.migration_password_file))
    except (OSError, UnicodeError, ValueError):
        raise SystemExit("password files are unreadable or malformed") from None
    write_private(targets[0], runtime)
    write_private(targets[1], migration)
    print("Wrote databaseURL and migrationDatabaseURL with sslmode=verify-full; values were not displayed.")


if __name__ == "__main__":
    main()
