#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: KORDEX_SOURCE_SERVICE=... KORDEX_RESTORE_SERVICE=... $0 backup.dump" >&2
  exit 2
fi
: "${KORDEX_SOURCE_SERVICE:?set to the source service name for same-database protection}"
: "${KORDEX_RESTORE_SERVICE:?set to a fresh isolated PostgreSQL service}"
: "${PGSERVICEFILE:?set PGSERVICEFILE to a mode-0600 libpq service file}"
command -v psql >/dev/null
command -v pg_restore >/dev/null
command -v sha256sum >/dev/null

archive=$1
[[ -f "$archive" && -f "$archive.sha256" ]] || { echo "backup or checksum file missing" >&2; exit 1; }
sha256sum --check --status "$archive.sha256" || { echo "backup checksum mismatch" >&2; exit 1; }
source_identity=$(psql "service=$KORDEX_SOURCE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT current_database()||'|'||coalesce(inet_server_addr()::text,'local')||'|'||coalesce(inet_server_port()::text,'local')")
restore_identity=$(psql "service=$KORDEX_RESTORE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT current_database()||'|'||coalesce(inet_server_addr()::text,'local')||'|'||coalesce(inet_server_port()::text,'local')")
[[ "$source_identity" != "$restore_identity" ]] || { echo "restore target resolves to the source database; refusing" >&2; exit 1; }

# No --clean: the target must be a new, empty database and existing data is never dropped.
pg_restore --exit-on-error --single-transaction --no-owner --no-privileges --dbname="service=$KORDEX_RESTORE_SERVICE" "$archive"
summary=$(psql "service=$KORDEX_RESTORE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT (SELECT count(*) FROM schema_migrations)||' migrations|'||(SELECT count(*) FROM organizations)||' organizations|'||(SELECT count(*) FROM audit_events)||' audit events'")
version=$(psql "service=$KORDEX_RESTORE_SERVICE" -X -v ON_ERROR_STOP=1 -Atqc "SELECT coalesce(max(version),0) FROM schema_migrations")
[[ "$version" -ge 7 ]] || { echo "restored schema version $version is older than required version 7" >&2; exit 1; }
printf 'Restore drill succeeded on isolated target: %s\n' "$summary"
