#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: KORDEX_SOURCE_SERVICE=... KORDEX_RESTORE_SERVICE=... $0 backup.dump" >&2
  exit 2
fi
: "${KORDEX_SOURCE_SERVICE:?set to the source service name for same-server protection}"
: "${KORDEX_RESTORE_SERVICE:?set to a fresh isolated PostgreSQL service}"
: "${PGSERVICEFILE:?set PGSERVICEFILE to a mode-0600 libpq service file}"
command -v psql >/dev/null
command -v pg_restore >/dev/null
command -v sha256sum >/dev/null

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
migrations_dir="$script_dir/../control-plane/migrations"
shopt -s nullglob
migrations=("$migrations_dir"/*.sql)
(( ${#migrations[@]} > 0 )) || { echo "embedded schema migrations not found beside the restore script" >&2; exit 1; }
expected_schema_version=0
for migration in "${migrations[@]}"; do
  filename=${migration##*/}
  version_text=${filename%%_*}
  [[ "$version_text" =~ ^[0-9]+$ && "$filename" == *_* ]] || { echo "invalid migration filename: $filename" >&2; exit 1; }
  version=$((10#$version_text))
  (( version == expected_schema_version + 1 )) || {
    echo "migration sequence is not contiguous at $filename" >&2
    exit 1
  }
  expected_schema_version=$version
done

archive_dir=$(cd -- "$(dirname -- "$1")" && pwd -P)
archive="$archive_dir/$(basename -- "$1")"
checksum="$archive.sha256"
[[ -f "$archive" && -f "$checksum" ]] || { echo "backup or checksum file missing" >&2; exit 1; }
(cd -- "$archive_dir" && sha256sum -c "${checksum##*/}") >/dev/null || { echo "backup checksum mismatch" >&2; exit 1; }
source_server=$(psql "service=$KORDEX_SOURCE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT coalesce(inet_server_addr()::text,'local')||'|'||coalesce(inet_server_port()::text,'local')")
restore_server=$(psql "service=$KORDEX_RESTORE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT coalesce(inet_server_addr()::text,'local')||'|'||coalesce(inet_server_port()::text,'local')")
[[ -n "$source_server" && -n "$restore_server" && "$source_server" != "$restore_server" ]] || {
  echo "restore target resolves to the source PostgreSQL server or has unknown identity; refusing" >&2
  exit 1
}
target_objects=$(psql "service=$KORDEX_RESTORE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f')")
[[ "$target_objects" =~ ^0$ ]] || {
  echo "restore target is not empty or its contents could not be verified; refusing" >&2
  exit 1
}

# No --clean: the target must be a new, empty database and existing data is never dropped.
restore_started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
monotonic_centiseconds() {
  local uptime whole fraction
  IFS=' ' read -r uptime _ < /proc/uptime || return 1
  [[ "$uptime" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 1
  whole=${uptime%%.*}
  if [[ "$uptime" == *.* ]]; then fraction=${uptime#*.}; else fraction=0; fi
  fraction="${fraction}00"
  fraction=${fraction:0:2}
  printf '%s' "$((10#$whole * 100 + 10#$fraction))"
}
restore_started_cs=$(monotonic_centiseconds) || { echo "monotonic restore timer is unavailable" >&2; exit 1; }
pg_restore --exit-on-error --single-transaction --no-owner --no-privileges --dbname="service=$KORDEX_RESTORE_SERVICE" "$archive"
summary=$(psql "service=$KORDEX_RESTORE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT (SELECT count(*) FROM schema_migrations)||' migrations|'||(SELECT count(*) FROM organizations)||' organizations|'||(SELECT count(*) FROM audit_events)||' tenant audit events|'||(SELECT count(*) FROM security_audit_events)||' security audit events'")
migration_history=$(psql "service=$KORDEX_RESTORE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT version||'|'||checksum FROM schema_migrations ORDER BY version")
mapfile -t restored_migrations <<< "$migration_history"
[[ ${#restored_migrations[@]} == ${#migrations[@]} ]] || {
  echo "restored schema migration history has ${#restored_migrations[@]} entries; current code requires ${#migrations[@]}" >&2
  exit 1
}
for index in "${!migrations[@]}"; do
  expected_version=$((index + 1))
  expected_checksum=$(sha256sum "${migrations[$index]}")
  expected_checksum=${expected_checksum%% *}
  expected_entry="$expected_version|$expected_checksum"
  [[ "${restored_migrations[$index]}" == "$expected_entry" ]] || {
    echo "restored schema migration/checksum mismatch at version $expected_version" >&2
    exit 1
  }
done
printf 'Restore drill succeeded on isolated target: %s\n' "$summary"
printf 'restore_started_at_utc=%s\n' "$restore_started_at_utc"
printf 'restore_completed_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
restore_duration_cs=$(($(monotonic_centiseconds) - restore_started_cs))
printf 'restore_duration_seconds=%d.%02d\n' "$((restore_duration_cs / 100))" "$((restore_duration_cs % 100))"
