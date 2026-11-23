#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/backups" "$tmp/failed-backups"
chmod 700 "$tmp/backups" "$tmp/failed-backups"

cat > "$tmp/bin/date" <<'MOCK'
#!/usr/bin/env bash
[[ "$*" == '-u +%Y%m%dT%H%M%SZ' ]] || exit 2
printf '20261118T120000Z\n'
MOCK

cat > "$tmp/bin/pg_dump" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == --version ]]; then
  echo 'pg_dump (PostgreSQL) 17.6'
  exit 0
fi
output=
for arg in "$@"; do
  case "$arg" in
    --file=*) output=${arg#--file=} ;;
    --dbname=service=*) [[ ${arg#--dbname=service=} == kordex-backup ]] || exit 3 ;;
  esac
done
[[ -n "$output" ]] || exit 4
printf 'disposable backup fixture\n' > "$output"
if [[ ${KORDEX_TEST_DUMP_WAIT:-false} == true ]]; then
  printf '%s\n' "$$" > "$KORDEX_TEST_DUMP_PID_FILE"
  touch "$KORDEX_TEST_DUMP_MARKER"
  read -r _ < "$KORDEX_TEST_DUMP_FIFO"
  exit 143
fi
MOCK

cat > "$tmp/bin/pg_restore" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == --list && -s ${2:-} ]] || exit 5
[[ ${KORDEX_TEST_BAD_ARCHIVE:-false} != true ]] || exit 6
MOCK

chmod 700 "$tmp/bin/date" "$tmp/bin/pg_dump" "$tmp/bin/pg_restore"
real_ln=$(command -v ln)
cat > "$tmp/bin/ln" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
destination=${@: -1}
if [[ ${KORDEX_TEST_COLLISION:-false} == true && "$destination" == *.dump ]]; then
  printf 'pre-existing archive\n' > "$destination"
  printf '%s\n' "$destination" > "$KORDEX_TEST_COLLISION_PATH"
fi
exec "$KORDEX_TEST_REAL_LN" "$@"
MOCK
chmod 700 "$tmp/bin/ln"
touch "$tmp/pg_service.conf"
chmod 600 "$tmp/pg_service.conf"
export PATH="$tmp/bin:$PATH"
export PGSERVICE=kordex-backup
export PGSERVICEFILE="$tmp/pg_service.conf"
export KORDEX_BACKUP_DIR="$tmp/backups"
export KORDEX_TEST_REAL_LN="$real_ln"

"$repo_root/scripts/backup-postgres.sh" > "$tmp/first.output"
"$repo_root/scripts/backup-postgres.sh" > "$tmp/second.output"
mapfile -t archives < <(find "$tmp/backups" -maxdepth 1 -type f -name 'kordex-*.dump' | sort)
[[ ${#archives[@]} == 2 ]] || { echo 'same-second backups collided or were overwritten' >&2; exit 1; }
[[ "${archives[0]}" != "${archives[1]}" ]] || { echo 'backup names are not unique' >&2; exit 1; }
[[ $(stat -c '%a' "$tmp/backups") == 700 ]] || { echo 'backup directory is not mode 700' >&2; exit 1; }

for archive in "${archives[@]}"; do
  checksum="$archive.sha256"
  manifest="$archive.manifest"
  [[ -f "$checksum" && -f "$manifest" ]] || { echo 'backup sidecar is missing' >&2; exit 1; }
  [[ $(stat -c '%a' "$archive") == 600 && $(stat -c '%a' "$checksum") == 600 && $(stat -c '%a' "$manifest") == 600 ]] || {
    echo 'backup or sidecar permissions are not mode 600' >&2
    exit 1
  }
  (cd "$tmp/backups" && sha256sum -c "${checksum##*/}" >/dev/null) || { echo 'portable backup checksum did not verify' >&2; exit 1; }
  grep -Fqx "archive=${archive##*/}" "$manifest" || { echo 'manifest does not name its archive' >&2; exit 1; }
  grep -Fxq 'created_at_utc=20261118T120000Z' "$manifest"
  grep -Fxq 'format=postgres-custom-archive' "$manifest"
  grep -Fxq 'pg_dump=pg_dump (PostgreSQL) 17.6' "$manifest"
done

chmod 644 "$PGSERVICEFILE"
if KORDEX_BACKUP_DIR="$tmp/failed-backups" "$repo_root/scripts/backup-postgres.sh" > "$tmp/insecure-service.output" 2>&1; then
  echo 'group-readable PostgreSQL service file unexpectedly accepted' >&2
  exit 1
fi
grep -Fq 'PGSERVICEFILE must not be accessible by group or other users' "$tmp/insecure-service.output"
chmod 600 "$PGSERVICEFILE"

mkfifo "$tmp/dump-wait.fifo"
export KORDEX_TEST_DUMP_WAIT=true
export KORDEX_TEST_DUMP_PID_FILE="$tmp/dump.pid"
export KORDEX_TEST_DUMP_MARKER="$tmp/dump.started"
export KORDEX_TEST_DUMP_FIFO="$tmp/dump-wait.fifo"
"$repo_root/scripts/backup-postgres.sh" > "$tmp/interrupted-dump.output" 2>&1 &
backup_pid=$!
for _ in {1..100}; do
  [[ -f "$KORDEX_TEST_DUMP_MARKER" ]] && break
  sleep 0.05
done
if [[ ! -f "$KORDEX_TEST_DUMP_MARKER" ]]; then
  kill -TERM "$backup_pid" 2>/dev/null || true
  wait "$backup_pid" 2>/dev/null || true
  echo 'backup process did not reach the interrupted pg_dump fixture' >&2
  exit 1
fi
dump_pid=$(cat "$KORDEX_TEST_DUMP_PID_FILE")
kill -TERM "$dump_pid" "$backup_pid"
if wait "$backup_pid"; then
  echo 'SIGTERM-interrupted backup unexpectedly succeeded' >&2
  exit 1
fi
if find "$tmp/failed-backups" -maxdepth 1 -type f | grep -q .; then
  echo 'SIGTERM-interrupted backup left a partial archive or sidecar' >&2
  exit 1
fi
unset KORDEX_TEST_DUMP_WAIT KORDEX_TEST_DUMP_PID_FILE KORDEX_TEST_DUMP_MARKER KORDEX_TEST_DUMP_FIFO

export KORDEX_TEST_COLLISION=true
export KORDEX_TEST_COLLISION_PATH="$tmp/collision.path"
if KORDEX_BACKUP_DIR="$tmp/failed-backups" "$repo_root/scripts/backup-postgres.sh" > "$tmp/collision.output" 2>&1; then
  echo 'backup replaced an archive created at its final path' >&2
  exit 1
fi
collision_archive=$(cat "$KORDEX_TEST_COLLISION_PATH")
[[ $(cat "$collision_archive") == 'pre-existing archive' ]] || { echo 'backup collision changed the pre-existing archive' >&2; exit 1; }
[[ $(find "$tmp/failed-backups" -maxdepth 1 -type f | wc -l) == 1 ]] || { echo 'backup collision left unexpected partial files' >&2; exit 1; }
rm -f -- "$collision_archive" "$KORDEX_TEST_COLLISION_PATH"
unset KORDEX_TEST_COLLISION KORDEX_TEST_COLLISION_PATH

if KORDEX_TEST_BAD_ARCHIVE=true KORDEX_BACKUP_DIR="$tmp/failed-backups" "$repo_root/scripts/backup-postgres.sh" > "$tmp/failed.output" 2>&1; then
  echo 'unreadable archive unexpectedly published as a backup' >&2
  exit 1
fi
if find "$tmp/failed-backups" -maxdepth 1 -type f | grep -q .; then
  echo 'failed backup left a published archive or temporary file' >&2
  exit 1
fi

echo 'PostgreSQL backup tests passed (service-file permissions, same-second uniqueness, collision refusal, checksums, manifest, file modes, SIGTERM interruption cleanup, and failure cleanup).'
