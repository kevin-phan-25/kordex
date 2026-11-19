#!/usr/bin/env bash
set -euo pipefail

: "${KORDEX_BACKUP_DIR:?set KORDEX_BACKUP_DIR to a protected backup directory}"
: "${PGSERVICE:?set PGSERVICE to a service in PGSERVICEFILE}"
: "${PGSERVICEFILE:?set PGSERVICEFILE to a mode-0600 libpq service file}"
command -v pg_dump >/dev/null
command -v pg_restore >/dev/null
command -v sha256sum >/dev/null
command -v stat >/dev/null
[[ -f "$PGSERVICEFILE" ]] || { echo "PGSERVICEFILE is not a regular file" >&2; exit 1; }
service_mode=$(stat -c '%a' -- "$PGSERVICEFILE")
[[ -r "$PGSERVICEFILE" && "$service_mode" =~ ^[0-7]{3,4}$ ]] &&
  (( (8#$service_mode & 0400) != 0 && (8#$service_mode & 077) == 0 )) || {
  echo "PGSERVICEFILE must not be accessible by group or other users" >&2
  exit 1
}

umask 077
mkdir -p -- "$KORDEX_BACKUP_DIR"
chmod 700 -- "$KORDEX_BACKUP_DIR"
backup_dir=$(cd -- "$KORDEX_BACKUP_DIR" && pwd -P)
created_at=$(date -u +%Y%m%dT%H%M%SZ)
[[ "$created_at" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "invalid UTC timestamp from date: $created_at" >&2; exit 1; }
temporary=$(mktemp "$backup_dir/.kordex-backup.XXXXXX")
token=${temporary##*.}
archive="$backup_dir/kordex-$created_at-$token.dump"
checksum="$archive.sha256"
manifest="$archive.manifest"
checksum_temporary=
manifest_temporary=
archive_linked=false
checksum_linked=false
manifest_linked=false
complete=false
cleanup() {
  rm -f -- "$temporary"
  [[ -z "$checksum_temporary" ]] || rm -f -- "$checksum_temporary"
  [[ -z "$manifest_temporary" ]] || rm -f -- "$manifest_temporary"
  if [[ "$complete" != true ]]; then
    [[ "$archive_linked" != true ]] || rm -f -- "$archive"
    [[ "$checksum_linked" != true ]] || rm -f -- "$checksum"
    [[ "$manifest_linked" != true ]] || rm -f -- "$manifest"
  fi
}
trap cleanup EXIT
checksum_temporary=$(mktemp "$backup_dir/.kordex-checksum.XXXXXX")
manifest_temporary=$(mktemp "$backup_dir/.kordex-manifest.XXXXXX")

pg_dump --format=custom --no-owner --no-privileges --dbname="service=$PGSERVICE" --file="$temporary"
pg_restore --list "$temporary" >/dev/null
dump_version=$(pg_dump --version)
chmod 600 -- "$temporary"
digest=$(sha256sum -- "$temporary")
digest=${digest%% *}
printf '%s  %s\n' "$digest" "${archive##*/}" > "$checksum_temporary"
{
  printf 'archive=%s\n' "${archive##*/}"
  printf 'created_at_utc=%s\n' "$created_at"
  printf 'format=postgres-custom-archive\n'
  printf 'pg_dump=%s\n' "$dump_version"
  printf 'sha256=%s\n' "$digest"
} > "$manifest_temporary"
chmod 600 -- "$checksum_temporary" "$manifest_temporary"

# Hard links publish each completed file without replacing an earlier backup.
ln -- "$temporary" "$archive"
archive_linked=true
ln -- "$checksum_temporary" "$checksum"
checksum_linked=true
ln -- "$manifest_temporary" "$manifest"
manifest_linked=true
complete=true
printf 'Backup complete: %s\n' "$archive"
