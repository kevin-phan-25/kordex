#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
fail(){ echo "$*" >&2; exit 2; }
[[ "${KORDEX_SECRET_PROVISION_CONFIRM:-}" == 'CREATE PRIVATE GKE LAB SECRETS' ]] || fail "Set KORDEX_SECRET_PROVISION_CONFIRM to the exact phrase before creating Secrets."
: "${KORDEX_EXPECTED_KUBE_CONTEXT:?Set KORDEX_EXPECTED_KUBE_CONTEXT explicitly}"
: "${KORDEX_PRIVATE_LAB_SECRET_DIR:?Set KORDEX_PRIVATE_LAB_SECRET_DIR to the protected input directory}"
EXPECTED='gke_kordex-fleet-platform_us-east1-b_kordex-gke-test'
[[ "$KORDEX_EXPECTED_KUBE_CONTEXT" == "$EXPECTED" ]] || fail 'Unexpected Kubernetes context.'
INPUT="$(realpath -e -- "$KORDEX_PRIVATE_LAB_SECRET_DIR")" || fail 'Secret input directory is unavailable.'
[[ -d "$INPUT" && ! -L "$KORDEX_PRIVATE_LAB_SECRET_DIR" && "$(stat -c '%u' -- "$INPUT")" == "$(id -u)" ]] || fail 'Secret input directory must be a non-symlink directory owned by the invoking user.'
INPUT_MODE="$(stat -c '%a' -- "$INPUT")"
(( (8#$INPUT_MODE & 077) == 0 )) || fail 'Secret input directory permissions must deny group and other access.'
case "$INPUT/" in "$ROOT/"*) fail 'Secret inputs must remain outside the Git repository.';; esac
command -v kubectl >/dev/null || fail 'kubectl is required.'
command -v openssl >/dev/null || fail 'openssl is required.'
NAMESPACE="$(kubectl --context="$EXPECTED" get namespace kordex-management -o name)" || fail 'Target namespace is missing or unreadable.'
[[ "$NAMESPACE" == 'namespace/kordex-management' ]] || fail 'Target namespace is missing.'

require_file(){
  local path="$1" sensitive="${2:-true}"
  [[ -s "$path" && -f "$path" && ! -L "$path" ]] || fail "Required protected input file is missing: $(basename -- "$path")"
  [[ "$(stat -c '%u' -- "$path")" == "$(id -u)" ]] || fail "Input file must be owned by the invoking user: $(basename -- "$path")"
  if [[ "$sensitive" == true ]]; then
    (( (8#$(stat -c '%a' -- "$path") & 077) == 0 )) || fail "Sensitive input permissions must deny group and other access: $(basename -- "$path")"
  fi
}
for key in postgresSuperuserPassword kordexRuntimePassword kordexMigrationPassword keycloakDbPassword databaseURL migrationDatabaseURL maintenanceSigningKey auditSigningKey keycloakBootstrapUsername keycloakBootstrapPassword; do
  require_file "$INPUT/$key"
done
for leaf in postgres keycloak api; do
  require_file "$INPUT/$leaf.crt" false
  require_file "$INPUT/$leaf.key"
  openssl x509 -in "$INPUT/$leaf.crt" -noout -checkend 0 >/dev/null 2>&1 || fail "TLS certificate is expired: $leaf"
  CERT_HASH="$(openssl x509 -in "$INPUT/$leaf.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d ' ' -f 1)"
  KEY_HASH="$(openssl pkey -in "$INPUT/$leaf.key" -pubout -outform DER 2>/dev/null | sha256sum | cut -d ' ' -f 1)" || fail "TLS key is unreadable: $leaf"
  [[ -n "$CERT_HASH" && "$CERT_HASH" == "$KEY_HASH" ]] || fail "TLS certificate and key do not match: $leaf"
done
require_file "$INPUT/ca.crt" false
openssl verify -CAfile "$INPUT/ca.crt" -verify_hostname kordex-postgres.kordex-management.svc.cluster.local "$INPUT/postgres.crt" >/dev/null 2>&1 || fail 'PostgreSQL TLS chain/hostname validation failed.'
openssl verify -CAfile "$INPUT/ca.crt" -verify_hostname keycloak.localhost "$INPUT/keycloak.crt" >/dev/null 2>&1 || fail 'Keycloak TLS chain/hostname validation failed.'
openssl verify -CAfile "$INPUT/ca.crt" -verify_hostname kordex-api.kordex-management.svc.cluster.local "$INPUT/api.crt" >/dev/null 2>&1 || fail 'API TLS chain/hostname validation failed.'
openssl verify -CAfile "$INPUT/ca.crt" -verify_ip 127.0.0.1 "$INPUT/api.crt" >/dev/null 2>&1 || fail 'API TLS certificate does not cover the workstation port-forward address.'
shopt -s nullglob
REALM_FILES=("$INPUT"/*.json)
(( ${#REALM_FILES[@]} > 0 )) || fail 'At least one protected .json Keycloak realm export file is required.'
for realm in "${REALM_FILES[@]}"; do require_file "$realm"; done
python3 - "$INPUT" <<'PY'
import json, pathlib, sys
files = list(pathlib.Path(sys.argv[1]).glob("*.json"))
total = sum(path.stat().st_size for path in files)
if total > 900_000:
    raise SystemExit("realm export files exceed the reviewed Kubernetes Secret size bound")
if not any(isinstance((obj := json.loads(path.read_text(encoding="utf-8"))), dict) and obj.get("realm") == "kordex" for path in files):
    raise SystemExit("expected kordex realm export was not found")
PY

for secret in kordex-postgres-credentials kordex-hub-credentials kordex-postgres-tls kordex-keycloak-tls kordex-api-tls kordex-management-ca kordex-keycloak-bootstrap kordex-keycloak-realm-import; do
  existing="$(kubectl --context="$EXPECTED" -n kordex-management get secret "$secret" --ignore-not-found -o name)" || \
    fail "Could not safely check for an existing Secret: $secret"
  [[ -z "$existing" ]] || fail "Secret already exists; refusing to overwrite: $secret"
done

create_secret(){
  local name="$1"; shift
  kubectl create secret generic "$name" -n kordex-management "$@" --dry-run=client -o yaml | \
    kubectl --context="$EXPECTED" -n kordex-management create -f - >/dev/null
  echo "Created Secret: $name"
}
create_secret kordex-postgres-credentials \
  --from-file=postgresSuperuserPassword="$INPUT/postgresSuperuserPassword" \
  --from-file=kordexRuntimePassword="$INPUT/kordexRuntimePassword" \
  --from-file=kordexMigrationPassword="$INPUT/kordexMigrationPassword" \
  --from-file=keycloakDbPassword="$INPUT/keycloakDbPassword"
create_secret kordex-hub-credentials \
  --from-file=databaseURL="$INPUT/databaseURL" \
  --from-file=migrationDatabaseURL="$INPUT/migrationDatabaseURL" \
  --from-file=maintenanceSigningKey="$INPUT/maintenanceSigningKey" \
  --from-file=auditSigningKey="$INPUT/auditSigningKey"
create_secret kordex-postgres-tls --type=kubernetes.io/tls \
  --from-file=tls.crt="$INPUT/postgres.crt" --from-file=tls.key="$INPUT/postgres.key"
create_secret kordex-keycloak-tls --type=kubernetes.io/tls \
  --from-file=tls.crt="$INPUT/keycloak.crt" --from-file=tls.key="$INPUT/keycloak.key"
create_secret kordex-api-tls --type=kubernetes.io/tls \
  --from-file=tls.crt="$INPUT/api.crt" --from-file=tls.key="$INPUT/api.key"
create_secret kordex-management-ca --from-file=ca.crt="$INPUT/ca.crt"
create_secret kordex-keycloak-bootstrap \
  --from-file=username="$INPUT/keycloakBootstrapUsername" --from-file=password="$INPUT/keycloakBootstrapPassword"
realm_args=()
for realm in "${REALM_FILES[@]}"; do realm_args+=("--from-file=$(basename -- "$realm")=$realm"); done
create_secret kordex-keycloak-realm-import "${realm_args[@]}"
KORDEX_EXPECTED_KUBE_CONTEXT="$EXPECTED" "$ROOT/scripts/gke-private-lab-verify-secrets.sh"
