#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
[[ "${KORDEX_RESTORE_CONFIRM:-}" == 'RESTORE KORDEX BACKUP TO EMPTY PRIVATE LAB DATABASE' ]] || {
  echo "Set KORDEX_RESTORE_CONFIRM='RESTORE KORDEX BACKUP TO EMPTY PRIVATE LAB DATABASE' to continue." >&2
  exit 2
}
: "${KORDEX_ENCRYPTED_BACKUP:?Set KORDEX_ENCRYPTED_BACKUP to the encrypted archive}"
: "${KORDEX_BACKUP_SHA256:?Set KORDEX_BACKUP_SHA256 to its checksum manifest}"
: "${AGE_IDENTITY_FILE:?Set AGE_IDENTITY_FILE to the protected age identity file}"
for tool in age sha256sum pg_restore kubectl; do command -v "$tool" >/dev/null || { echo "required command not found: $tool" >&2; exit 2; }; done
EXPECTED_CONTEXT='gke_kordex-fleet-platform_us-east1-b_kordex-gke-test'
[[ "$(kubectl config current-context)" == "$EXPECTED_CONTEXT" ]] || { echo 'Unexpected Kubernetes context; restore refused.' >&2; exit 2; }
[[ "$(kubectl -n kordex-management get pod kordex-postgres-0 -o jsonpath='{.status.phase}')" == Running ]] || { echo 'Target PostgreSQL Pod is not running.' >&2; exit 2; }
[[ "$(kubectl -n kordex-management get pod kordex-postgres-0 -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}')" == True ]] || { echo 'Target PostgreSQL Pod is not Ready.' >&2; exit 2; }
(cd -- "$(dirname -- "$KORDEX_BACKUP_SHA256")" && sha256sum --check "$(basename -- "$KORDEX_BACKUP_SHA256")")
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kordex-pg-restore.XXXXXXXX")"
chmod 700 "$TMP_DIR"
trap 'rm -rf -- "$TMP_DIR"' EXIT HUP INT TERM
PLAIN="$TMP_DIR/kordex.dump"
age --decrypt --identity "$AGE_IDENTITY_FILE" --output "$PLAIN" "$KORDEX_ENCRYPTED_BACKUP"
pg_restore --list "$PLAIN" >/dev/null
EMPTY_COUNT="$(kubectl -n kordex-management exec kordex-postgres-0 -- psql -XAt -U postgres -d kordex -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_toast' AND c.relkind IN ('r','p','v','m','S','f')")"
[[ "$EMPTY_COUNT" == 0 ]] || { echo 'Target database is not empty; restore refused.' >&2; exit 2; }
kubectl -n kordex-management exec -i kordex-postgres-0 -- pg_restore --exit-on-error --no-owner --no-acl --role=kordex_migrator --username=postgres --dbname=kordex < "$PLAIN"
kubectl -n kordex-management exec -i kordex-postgres-0 -- psql -X -v ON_ERROR_STOP=1 -U postgres -d kordex < "$ROOT/deployments/local/postgres-runtime-grants.sql"
echo 'PostgreSQL restore completed into the verified empty lab database. Run schema, row-count, and authorization checks before starting the API.'
