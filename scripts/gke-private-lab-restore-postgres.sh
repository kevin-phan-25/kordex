#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
fail(){ echo "$*" >&2; exit 2; }
source "$ROOT/scripts/gke-private-lab-context.sh"
EXPECTED_CONTEXT="$(kordex_private_lab_expected_context)" || fail 'Private lab target identity is invalid.'
kordex_verify_private_lab_cluster "$EXPECTED_CONTEXT" || fail 'GKE target verification failed; restore refused.'
[[ "${KORDEX_RESTORE_CONFIRM:-}" == "RESTORE KORDEX BACKUP TO EMPTY PRIVATE LAB DATABASE IN $EXPECTED_CONTEXT" ]] || \
  fail "Set KORDEX_RESTORE_CONFIRM to the exact phrase naming $EXPECTED_CONTEXT before continuing."
: "${KORDEX_ENCRYPTED_BACKUP:?Set KORDEX_ENCRYPTED_BACKUP to the encrypted archive path}"
: "${KORDEX_BACKUP_SHA256:?Set KORDEX_BACKUP_SHA256 to the matching checksum manifest path}"
: "${AGE_IDENTITY_FILE:?Set AGE_IDENTITY_FILE to the protected age identity file}"
: "${KORDEX_EXPECTED_SCHEMA_VERSION:?Set KORDEX_EXPECTED_SCHEMA_VERSION explicitly}"
: "${KORDEX_EXPECTED_ORGANIZATION_ID:?Set the expected organization UUID}"
: "${KORDEX_EXPECTED_FLEET_ID:?Set the expected fleet UUID}"
: "${KORDEX_EXPECTED_SITE_ID:?Set the expected site UUID}"
: "${KORDEX_EXPECTED_CLUSTER_ID:?Set the expected Kordex cluster UUID}"
: "${KORDEX_EXPECTED_CLUSTER_UID:?Set the expected Kubernetes cluster UID}"
: "${KORDEX_REALM_EXPORT_DIR:?Set the protected directory containing the kordex realm export JSON files}"

[[ "$KORDEX_EXPECTED_SCHEMA_VERSION" =~ ^[1-9][0-9]{0,5}$ ]] || fail 'Expected schema version must be a positive integer.'
for id in "$KORDEX_EXPECTED_ORGANIZATION_ID" "$KORDEX_EXPECTED_FLEET_ID" "$KORDEX_EXPECTED_SITE_ID" "$KORDEX_EXPECTED_CLUSTER_ID"; do
  [[ "$id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || fail 'An expected organization, fleet, site, or cluster ID is not a UUID.'
done
[[ "$KORDEX_EXPECTED_CLUSTER_UID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || fail 'Expected Kubernetes cluster UID must be a UUID.'
[[ -d "$KORDEX_REALM_EXPORT_DIR" ]] || fail 'Realm export directory is unavailable.'

for tool in age sha256sum pg_restore kubectl realpath stat python3; do
  command -v "$tool" >/dev/null || fail "Required command not found: $tool"
done

ARCHIVE="$(realpath -e -- "$KORDEX_ENCRYPTED_BACKUP")" || fail 'Encrypted backup file is missing.'
MANIFEST="$(realpath -e -- "$KORDEX_BACKUP_SHA256")" || fail 'Checksum manifest is missing.'
[[ -f "$ARCHIVE" && ! -L "$KORDEX_ENCRYPTED_BACKUP" ]] || fail 'Encrypted backup must be a regular, non-symlink file.'
[[ -f "$MANIFEST" && ! -L "$KORDEX_BACKUP_SHA256" ]] || fail 'Checksum manifest must be a regular, non-symlink file.'
[[ "$(dirname -- "$ARCHIVE")" == "$(dirname -- "$MANIFEST")" ]] || fail 'Archive and checksum manifest must be in the same directory.'
ARCHIVE_NAME="$(basename -- "$ARCHIVE")"
[[ "$ARCHIVE_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || fail 'Archive filename contains unsupported characters.'
mapfile -t CHECKSUM_LINES < "$MANIFEST"
[[ ${#CHECKSUM_LINES[@]} -eq 1 ]] || fail 'Checksum manifest must contain exactly one checksum line.'
CHECKSUM_LINE="${CHECKSUM_LINES[0]}"
EXPECTED_HASH="${CHECKSUM_LINE%%  *}"
MANIFEST_NAME="${CHECKSUM_LINE#*  }"
[[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ && "$MANIFEST_NAME" == "$ARCHIVE_NAME" && "$CHECKSUM_LINE" == "$EXPECTED_HASH  $ARCHIVE_NAME" ]] || \
  fail 'Checksum manifest is malformed or names a different archive.'
ACTUAL_HASH="$(sha256sum -- "$ARCHIVE" | cut -d ' ' -f 1)"
[[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]] || fail 'Encrypted archive SHA-256 does not match its manifest.'

[[ -f "$AGE_IDENTITY_FILE" && ! -L "$AGE_IDENTITY_FILE" ]] || fail 'Age identity must be a regular file.'
AGE_MODE="$(stat -c '%a' -- "$AGE_IDENTITY_FILE")"
(( (8#$AGE_MODE & 077) == 0 )) || fail 'Age identity permissions must deny group and other access.'

kubectl_target(){ kubectl --context="$EXPECTED_CONTEXT" "$@"; }
CONTEXT_STATE="$(kubectl_target config view --minify -o jsonpath='{.contexts[0].name}')" || fail 'Expected Kubernetes context could not be selected.'
[[ "$CONTEXT_STATE" == "$EXPECTED_CONTEXT" ]] || fail 'Expected Kubernetes context could not be selected.'
NAMESPACE_STATE="$(kubectl_target get namespace kordex-management -o name)" || fail 'Target namespace is missing or unreadable.'
[[ "$NAMESPACE_STATE" == 'namespace/kordex-management' ]] || fail 'Target namespace is missing.'
STATEFULSET_STATE="$(kubectl_target -n kordex-management get statefulset kordex-postgres -o name)" || fail 'Target PostgreSQL StatefulSet is missing or unreadable.'
[[ "$STATEFULSET_STATE" == 'statefulset.apps/kordex-postgres' ]] || fail 'Target PostgreSQL StatefulSet is missing.'
for app in api keycloak; do
  if [[ "$app" == api ]]; then deployment=kordex-api; selector=app.kubernetes.io/component=api; else deployment=kordex-keycloak; selector=app.kubernetes.io/name=kordex-keycloak; fi
  replicas="$(kubectl_target -n kordex-management get deployment "$deployment" --ignore-not-found -o jsonpath='{.spec.replicas}')" || fail "Could not verify that $deployment is stopped."
  [[ -z "$replicas" || "$replicas" == 0 ]] || fail "$deployment must remain scaled to zero until restore verification succeeds."
  pods="$(kubectl_target -n kordex-management get pods -l "$selector" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')" || fail "Could not verify that no $deployment Pods are running."
  [[ -z "$pods" ]] || fail "$deployment Pods exist; stop the workload before restoring."
done
POD_STATE="$(kubectl_target -n kordex-management get pod kordex-postgres-0 -o jsonpath='{.status.phase}{"|"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}')" || fail 'Target PostgreSQL Pod is missing or unreadable.'
[[ "$POD_STATE" == 'Running|True' ]] || fail 'Target PostgreSQL Pod is not Ready.'
PVC_STATE="$(kubectl_target -n kordex-management get pvc data-kordex-postgres-0 -o jsonpath='{.status.phase}{"|"}{.spec.volumeName}')" || fail 'Target PostgreSQL PVC is missing or unreadable.'
[[ "${PVC_STATE%%|*}" == 'Bound' && -n "${PVC_STATE#*|}" ]] || fail 'Target PostgreSQL PVC is not bound.'
PV_NAME="${PVC_STATE#*|}"
PV_STATE="$(kubectl_target get pv "$PV_NAME" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}{"|"}{.spec.claimRef.namespace}{"|"}{.spec.claimRef.name}')" || \
  fail 'PersistentVolume is missing or unreadable; reclaim policy cannot be verified, restore refused.'
[[ "$PV_STATE" == 'Retain|kordex-management|data-kordex-postgres-0' ]] || \
  fail 'PV reclaim policy or claim reference is not verified as Retain for the expected PostgreSQL PVC; restore refused.'

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kordex-pg-restore.XXXXXXXX")"
chmod 700 "$TMP_DIR"
trap 'rm -rf -- "$TMP_DIR"' EXIT HUP INT TERM
PLAIN="$TMP_DIR/kordex.dump"
age --decrypt --identity "$AGE_IDENTITY_FILE" --output "$PLAIN" "$ARCHIVE"
chmod 600 "$PLAIN"
pg_restore --list "$PLAIN" >/dev/null || fail 'Encrypted backup did not decrypt to a valid PostgreSQL archive.'

EMPTY_COUNT="$(kubectl_target -n kordex-management exec kordex-postgres-0 -- psql -XAt -U postgres -d kordex -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_toast' AND c.relkind IN ('r','p','v','m','S','f')")"
[[ "$EMPTY_COUNT" == 0 ]] || fail 'Target database is not empty; restore refused.'
if ! kubectl_target -n kordex-management exec -i kordex-postgres-0 -- pg_restore --exit-on-error --no-owner --no-acl --role=kordex_migrator --username=postgres --dbname=kordex < "$PLAIN"; then
  fail 'PostgreSQL restore failed; target may contain partial data. API was not started; inspect before any retry.'
fi
kubectl_target -n kordex-management exec -i kordex-postgres-0 -- psql -X -v ON_ERROR_STOP=1 -U postgres -d kordex < "$ROOT/deployments/local/postgres-runtime-grants.sql"

PG_MAJOR="$(kubectl_target -n kordex-management exec kordex-postgres-0 -- psql -XAt -U postgres -d postgres -c 'SHOW server_version_num')"
[[ "$PG_MAJOR" =~ ^17[0-9]{4}$ ]] || fail 'Target PostgreSQL server is not major version 17.'
SCHEMA_STATE="$(kubectl_target -n kordex-management exec kordex-postgres-0 -- psql -XAt -F '|' -U postgres -d kordex -c 'SELECT COALESCE(MAX(version),0),COUNT(*) FROM schema_migrations')"
[[ "$SCHEMA_STATE" == "$KORDEX_EXPECTED_SCHEMA_VERSION|$KORDEX_EXPECTED_SCHEMA_VERSION" ]] || fail 'Restored schema version does not match the expected complete migration set.'
RECORDS="$(kubectl_target -n kordex-management exec kordex-postgres-0 -- psql -XAt -U postgres -d kordex -c "SELECT count(*) FROM organizations o JOIN fleets f ON f.organization_id=o.id JOIN sites s ON s.organization_id=o.id JOIN clusters c ON c.organization_id=o.id AND c.fleet_id=f.id AND c.site_id=s.id WHERE o.id='$KORDEX_EXPECTED_ORGANIZATION_ID' AND f.id='$KORDEX_EXPECTED_FLEET_ID' AND s.id='$KORDEX_EXPECTED_SITE_ID' AND c.id='$KORDEX_EXPECTED_CLUSTER_ID' AND c.cluster_uid='$KORDEX_EXPECTED_CLUSTER_UID' AND c.provider='gke'")"
[[ "$RECORDS" == 1 ]] || fail 'Expected organization, fleet, site, and GKE cluster association was not verified.'
if ! kubectl_target -n kordex-management exec kordex-postgres-0 -- psql -XAt -U postgres -d kordex -c 'SELECT subject FROM memberships ORDER BY organization_id,subject' | \
  python3 "$ROOT/scripts/verify-gke-private-lab-memberships.py" --realm kordex "$KORDEX_REALM_EXPORT_DIR"; then
  fail 'Restored membership subjects did not all match users in the kordex realm; identifiers were not printed.'
fi

echo 'Restore and schema, organization, cluster, and membership checks passed. The API has not been started.'
