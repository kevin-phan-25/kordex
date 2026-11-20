#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
[[ "${KORDEX_BACKUP_CONFIRM:-}" == 'BACK UP EXISTING KORDEX DATABASE' ]] || {
  echo "Set KORDEX_BACKUP_CONFIRM='BACK UP EXISTING KORDEX DATABASE' to continue." >&2
  exit 2
}
[[ "${KORDEX_SOURCE_WRITES_QUIESCED:-}" == YES ]] || {
  echo 'Pause local API writes and set KORDEX_SOURCE_WRITES_QUIESCED=YES before the final migration backup.' >&2
  exit 2
}
: "${KORDEX_PG_CONTAINER:?Set KORDEX_PG_CONTAINER to the existing PostgreSQL container name}"
: "${AGE_RECIPIENT:?Set AGE_RECIPIENT to the approved age public recipient}"
: "${KORDEX_BACKUP_DIR:?Set KORDEX_BACKUP_DIR to a protected directory outside the repository}"
for tool in podman age pg_restore sha256sum realpath; do command -v "$tool" >/dev/null || { echo "required command not found: $tool" >&2; exit 2; }; done
mkdir -p -- "$KORDEX_BACKUP_DIR"
BACKUP_DIR="$(realpath -- "$KORDEX_BACKUP_DIR")"
case "$BACKUP_DIR/" in "$ROOT/"*) echo 'Backup output must remain outside the Git repository.' >&2; exit 2;; esac
chmod 700 "$BACKUP_DIR"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kordex-pg-backup.XXXXXXXX")"
chmod 700 "$TMP_DIR"
trap 'rm -rf -- "$TMP_DIR"' EXIT HUP INT TERM
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PLAIN="$TMP_DIR/kordex-$STAMP.dump"
OUT="$BACKUP_DIR/kordex-$STAMP.dump.age"

podman exec "$KORDEX_PG_CONTAINER" pg_dump --format=custom --no-owner --no-acl --username=kordex --dbname=kordex > "$PLAIN"
pg_restore --list "$PLAIN" >/dev/null
age --encrypt --recipient "$AGE_RECIPIENT" --output "$OUT" "$PLAIN"
chmod 600 "$OUT"
(cd -- "$BACKUP_DIR" && sha256sum "$(basename -- "$OUT")" > "$(basename -- "$OUT").sha256")
chmod 600 "$OUT.sha256"
echo "Encrypted PostgreSQL archive: $OUT"
echo "SHA-256 manifest: $OUT.sha256"
