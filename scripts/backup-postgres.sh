#!/usr/bin/env bash
set -euo pipefail

: "${KORDEX_BACKUP_DIR:?set KORDEX_BACKUP_DIR to a protected backup directory}"
: "${PGSERVICE:?set PGSERVICE to a service in PGSERVICEFILE}"
: "${PGSERVICEFILE:?set PGSERVICEFILE to a mode-0600 libpq service file}"
command -v pg_dump >/dev/null
command -v pg_restore >/dev/null
command -v sha256sum >/dev/null

umask 077
mkdir -p -- "$KORDEX_BACKUP_DIR"
chmod 700 -- "$KORDEX_BACKUP_DIR"
created_at=$(date -u +%Y%m%dT%H%M%SZ)
archive="$KORDEX_BACKUP_DIR/kordex-$created_at.dump"
temporary=$(mktemp "$KORDEX_BACKUP_DIR/.kordex-backup.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT

pg_dump --format=custom --no-owner --no-privileges --dbname="service=$PGSERVICE" --file="$temporary"
pg_restore --list "$temporary" >/dev/null
mv -- "$temporary" "$archive"
trap - EXIT
sha256sum "$archive" > "$archive.sha256"
{
  printf 'created_at_utc=%s\n' "$created_at"
  printf 'format=postgres-custom-archive\n'
  printf 'pg_dump=%s\n' "$(pg_dump --version)"
} > "$archive.manifest"
chmod 600 -- "$archive" "$archive.sha256" "$archive.manifest"
printf 'Backup complete: %s\n' "$archive"
