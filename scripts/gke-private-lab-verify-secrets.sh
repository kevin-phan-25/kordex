#!/usr/bin/env bash
set -Eeuo pipefail
set +x
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
source "$ROOT/scripts/gke-private-lab-context.sh"
EXPECTED="$(kordex_private_lab_expected_context)" || { echo 'Private lab target identity is invalid.' >&2; exit 2; }
kordex_verify_private_lab_cluster "$EXPECTED" || { echo 'GKE target verification failed; Secret verification refused.' >&2; exit 2; }
command -v kubectl >/dev/null || { echo 'kubectl is required.' >&2; exit 2; }

verify_secret() {
  local name="$1" required="$2" realm_json="${3:-false}"
  kubectl --context="$EXPECTED" -n kordex-management get secret "$name" -o json | \
    python3 -c '
import json,sys
name, required, realm_json = sys.argv[1], set(filter(None, sys.argv[2].split(","))), sys.argv[3] == "true"
obj=json.load(sys.stdin)
keys=set((obj.get("data") or {}).keys())
missing=required-keys
if realm_json and not any(key.endswith(".json") for key in keys):
    missing.add("<realm JSON file key>")
print(f"{name}: " + ("missing keys: " + ",".join(sorted(missing)) if missing else f"required keys present ({len(keys)} total)"))
sys.exit(bool(missing))
' "$name" "$required" "$realm_json"
}

verify_secret kordex-postgres-credentials postgresSuperuserPassword,kordexRuntimePassword,kordexMigrationPassword,keycloakDbPassword
verify_secret kordex-hub-credentials databaseURL,migrationDatabaseURL,maintenanceSigningKey,auditSigningKey
verify_secret kordex-postgres-tls tls.crt,tls.key
verify_secret kordex-keycloak-tls tls.crt,tls.key
verify_secret kordex-api-tls tls.crt,tls.key
verify_secret kordex-management-ca ca.crt
verify_secret kordex-keycloak-bootstrap username,password
verify_secret kordex-keycloak-realm-import '' true
echo 'Required private-lab Secret names and keys are present; Secret values were not read to the terminal.'
