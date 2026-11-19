#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/backups"
chmod 700 "$tmp/backups"

migrations=("$repo_root"/control-plane/migrations/*.sql)
schema_version=0
current_history=
for migration in "${migrations[@]}"; do
  schema_version=$((schema_version + 1))
  checksum=$(sha256sum "$migration")
  checksum=${checksum%% *}
  current_history+="$schema_version|$checksum"$'\n'
done
(( schema_version > 0 )) || { echo 'no schema migrations found for restore-drill test' >&2; exit 1; }

cat > "$tmp/bin/psql" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
service=${1#service=}
query=
for arg in "$@"; do query=$arg; done
if [[ "$query" == *inet_server_addr* ]]; then
  if [[ ${KORDEX_TEST_UNKNOWN_SERVER:-false} == true ]]; then
    printf '\n'
  elif [[ ${KORDEX_TEST_SAME_SERVER:-false} == true ]]; then
    printf '127.0.0.1|5432\n'
  elif [[ "$service" == source ]]; then
    printf '127.0.0.1|5432\n'
  else
    printf '127.0.0.2|5432\n'
  fi
elif [[ "$query" == *"FROM pg_class c JOIN pg_namespace"* ]]; then
  printf '%s\n' "${KORDEX_TEST_TARGET_OBJECTS:-0}"
elif [[ "$query" == *"SELECT version||'|'||checksum FROM schema_migrations ORDER BY version"* ]]; then
  printf '%s\n' "${KORDEX_TEST_MIGRATION_HISTORY:-}"
elif [[ "$query" == *"count(*) FROM schema_migrations"* ]]; then
  printf '%s migrations|2 organizations|5 tenant audit events|0 security audit events\n' "${KORDEX_TEST_SCHEMA_VERSION:?}"
else
  echo "unexpected psql query in restore-drill test: $query" >&2
  exit 1
fi
MOCK

cat > "$tmp/bin/pg_restore" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
args=" $* "
if [[ ${1:-} == --list ]]; then exit 0; fi
[[ "$args" == *" --exit-on-error "* && "$args" == *" --single-transaction "* ]] || exit 20
[[ "$args" != *" --clean "* ]] || exit 21
touch "$KORDEX_TEST_RESTORE_MARKER"
MOCK

chmod 700 "$tmp/bin/psql" "$tmp/bin/pg_restore"
archive="$tmp/backups/qualification.dump"
printf 'test archive\n' > "$archive"
sha256sum "$archive" > "$archive.sha256"
touch "$tmp/pg-service.conf"

export PATH="$tmp/bin:$PATH"
export PGSERVICEFILE="$tmp/pg-service.conf"
export KORDEX_SOURCE_SERVICE=source
export KORDEX_RESTORE_SERVICE=restore
export KORDEX_TEST_RESTORE_MARKER="$tmp/restore-was-run"
export KORDEX_TEST_MIGRATION_HISTORY="$current_history"
export KORDEX_TEST_SCHEMA_VERSION="$schema_version"

expect_failure() {
  local name=$1 expected=$2
  shift 2
  rm -f "$KORDEX_TEST_RESTORE_MARKER"
  local output="$tmp/$name.output"
  if "$@" >"$output" 2>&1; then
    echo "$name unexpectedly succeeded" >&2
    cat "$output" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$output"; then
    echo "$name failed without expected diagnostic: $expected" >&2
    cat "$output" >&2
    exit 1
  fi
}

stale_history=$(printf '%s' "$current_history" | sed '$d')
expect_failure stale "has $((schema_version - 1)) entries; current code requires $schema_version" env KORDEX_TEST_MIGRATION_HISTORY="$stale_history" "$repo_root/scripts/restore-drill.sh" "$archive"
[[ -f "$KORDEX_TEST_RESTORE_MARKER" ]] || { echo 'stale-schema case did not exercise isolated restore' >&2; exit 1; }

gapped_history=$(printf '%s' "$current_history" | sed '4d')
expect_failure gapped "has $((schema_version - 1)) entries; current code requires $schema_version" env KORDEX_TEST_MIGRATION_HISTORY="$gapped_history" "$repo_root/scripts/restore-drill.sh" "$archive"

bad_checksum_history=$(printf '%s' "$current_history" | sed '1s/|.*/|0000000000000000000000000000000000000000000000000000000000000000/')
expect_failure bad-migration-checksum 'migration/checksum mismatch at version 1' env KORDEX_TEST_MIGRATION_HISTORY="$bad_checksum_history" "$repo_root/scripts/restore-drill.sh" "$archive"

rm -f "$KORDEX_TEST_RESTORE_MARKER"
if KORDEX_TEST_SAME_SERVER=true "$repo_root/scripts/restore-drill.sh" "$archive" >"$tmp/same-server.output" 2>&1; then
  echo 'same-server restore unexpectedly succeeded' >&2
  exit 1
fi
grep -Fq 'restore target resolves to the source PostgreSQL server or has unknown identity; refusing' "$tmp/same-server.output"
[[ ! -e "$KORDEX_TEST_RESTORE_MARKER" ]] || { echo 'same-server case reached pg_restore' >&2; exit 1; }

rm -f "$KORDEX_TEST_RESTORE_MARKER"
if KORDEX_TEST_UNKNOWN_SERVER=true "$repo_root/scripts/restore-drill.sh" "$archive" >"$tmp/unknown-server.output" 2>&1; then
  echo 'unknown-server restore unexpectedly succeeded' >&2
  exit 1
fi
grep -Fq 'restore target resolves to the source PostgreSQL server or has unknown identity; refusing' "$tmp/unknown-server.output"
[[ ! -e "$KORDEX_TEST_RESTORE_MARKER" ]] || { echo 'unknown-server case reached pg_restore' >&2; exit 1; }

rm -f "$KORDEX_TEST_RESTORE_MARKER"
if KORDEX_TEST_TARGET_OBJECTS=1 "$repo_root/scripts/restore-drill.sh" "$archive" >"$tmp/nonempty-target.output" 2>&1; then
  echo 'nonempty-target restore unexpectedly succeeded' >&2
  exit 1
fi
grep -Fq 'restore target is not empty or its contents could not be verified; refusing' "$tmp/nonempty-target.output"
[[ ! -e "$KORDEX_TEST_RESTORE_MARKER" ]] || { echo 'nonempty-target case reached pg_restore' >&2; exit 1; }

printf 'incorrect checksum\n' > "$archive.sha256"
expect_failure checksum 'backup checksum mismatch' "$repo_root/scripts/restore-drill.sh" "$archive"
[[ ! -e "$KORDEX_TEST_RESTORE_MARKER" ]] || { echo 'checksum case reached pg_restore' >&2; exit 1; }

sha256sum "$archive" > "$archive.sha256"
rm -f "$KORDEX_TEST_RESTORE_MARKER"
"$repo_root/scripts/restore-drill.sh" "$archive" >"$tmp/success.output"
grep -Fq "Restore drill succeeded on isolated target: $schema_version migrations|2 organizations|5 tenant audit events|0 security audit events" "$tmp/success.output"
[[ -f "$KORDEX_TEST_RESTORE_MARKER" ]] || { echo 'valid restore did not reach pg_restore' >&2; exit 1; }

echo 'Restore drill guard tests passed (current schema checksums, complete history, separate empty server, archive checksum, transactional restore).'
