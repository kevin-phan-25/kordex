#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
[[ "${KORDEX_KEYCLOAK_EXPORT_CONFIRM:-}" == 'EXPORT KORDEX KEYCLOAK REALM FROM QUIESCED VOLUME' ]] || {
  echo "Set KORDEX_KEYCLOAK_EXPORT_CONFIRM='EXPORT KORDEX KEYCLOAK REALM FROM QUIESCED VOLUME' to continue." >&2
  exit 2
}
: "${KORDEX_KEYCLOAK_CONTAINER:?Set the existing Keycloak container name}"
: "${KORDEX_KEYCLOAK_VOLUME:?Set the existing Keycloak data volume name}"
: "${AGE_RECIPIENT:?Set AGE_RECIPIENT to the approved age public recipient}"
: "${KORDEX_BACKUP_DIR:?Set KORDEX_BACKUP_DIR to a protected directory outside the repository}"
for tool in podman age jq tar sha256sum realpath; do command -v "$tool" >/dev/null || { echo "required command not found: $tool" >&2; exit 2; }; done
[[ "$(podman inspect --format '{{.State.Running}}' "$KORDEX_KEYCLOAK_CONTAINER")" == false ]] || {
  echo 'Stop Keycloak before exporting its embedded database; this script never stops it.' >&2
  exit 2
}
mkdir -p -- "$KORDEX_BACKUP_DIR"
BACKUP_DIR="$(realpath -- "$KORDEX_BACKUP_DIR")"
case "$BACKUP_DIR/" in "$ROOT/"*) echo 'Backup output must remain outside the Git repository.' >&2; exit 2;; esac
chmod 700 "$BACKUP_DIR"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kordex-keycloak-export.XXXXXXXX")"
chmod 700 "$TMP_DIR"
TMP_VOLUME="kordex-keycloak-export-$$"
podman volume create "$TMP_VOLUME" >/dev/null
cleanup(){ podman volume rm -f "$TMP_VOLUME" >/dev/null 2>&1 || true; rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$TMP_DIR/export"
podman volume export --output "$TMP_DIR/source-volume.tar" "$KORDEX_KEYCLOAK_VOLUME"
podman volume import "$TMP_VOLUME" "$TMP_DIR/source-volume.tar" >/dev/null
KEYCLOAK_IMAGE='quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3'
podman run --rm --volume "$TMP_VOLUME:/opt/keycloak/data:Z" --volume "$TMP_DIR/export:/export:Z" \
  --env KC_DB=dev-file --entrypoint /opt/keycloak/bin/kc.sh "$KEYCLOAK_IMAGE" \
  export --realm kordex --dir /export >/dev/null
shopt -s nullglob
JSON_FILES=("$TMP_DIR"/export/*.json)
(( ${#JSON_FILES[@]} > 0 )) || { echo 'Keycloak export produced no JSON files.' >&2; exit 1; }
TOTAL_BYTES="$(du -sb -- "$TMP_DIR/export" | cut -f1)"
(( TOTAL_BYTES <= 900000 )) || { echo 'Realm export exceeds the Kubernetes Secret size safety limit; use an approved protected import volume instead.' >&2; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TAR="$TMP_DIR/kordex-realm.tar"
tar -C "$TMP_DIR/export" -cf "$TAR" .
OUT="$BACKUP_DIR/kordex-realm-$STAMP.tar.age"
age --encrypt --recipient "$AGE_RECIPIENT" --output "$OUT" "$TAR"
chmod 600 "$OUT"
(cd -- "$BACKUP_DIR" && sha256sum "$(basename -- "$OUT")" > "$(basename -- "$OUT").sha256")
jq -s -r '[.[] | .users[]? | .id] | sort | join("\n")' "${JSON_FILES[@]}" | sha256sum > "$BACKUP_DIR/kordex-realm-$STAMP.subject-ids.sha256"
chmod 600 "$OUT.sha256" "$BACKUP_DIR/kordex-realm-$STAMP.subject-ids.sha256"
echo "Encrypted Keycloak realm archive: $OUT"
echo "SHA-256 manifest: $OUT.sha256"
echo "Subject-ID set fingerprint: $BACKUP_DIR/kordex-realm-$STAMP.subject-ids.sha256"
