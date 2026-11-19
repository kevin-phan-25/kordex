#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
local_dir="${KORDEX_LOCAL_OIDC_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/kordex/local-oidc}"
issuer="https://keycloak.localhost:8443/realms/kordex"
ca="$local_dir/certs/ca.crt"
postgres_container="${KORDEX_LOCAL_POSTGRES_CONTAINER:-kordex-local_postgres_1}"
python="${PYTHON:-python3}"

fail() { echo "$*" >&2; exit 1; }
for tool in curl jq podman "$python" openssl; do command -v "$tool" >/dev/null 2>&1 || fail "Required local tool is missing: $tool"; done
[[ -s "$ca" ]] || fail "Local CA not found at $ca; run scripts/local-oidc-init.sh first."

curl --noproxy '*' --fail --silent --show-error --cacert "$ca" --max-time 8 \
  "$issuer/.well-known/openid-configuration" | jq -e --arg issuer "$issuer" '.issuer == $issuer' >/dev/null \
  || fail "Keycloak discovery is unavailable or its issuer does not match."
jwks_uri="$(curl --noproxy '*' --fail --silent --show-error --cacert "$ca" --max-time 8 \
  "$issuer/.well-known/openid-configuration" | jq -er '.jwks_uri')" || fail "Keycloak discovery has no JWKS URI."
curl --noproxy '*' --fail --silent --show-error --cacert "$ca" --max-time 8 "$jwks_uri" \
  | jq -e '.keys | any(.use == "sig" and (.kid | type == "string"))' >/dev/null \
  || fail "Keycloak signing-key endpoint is unavailable or has no signing key."
curl --noproxy '*' --fail --silent --show-error --max-time 8 http://127.0.0.1:8081/readyz >/dev/null \
  || fail "OIDC API is not ready at http://127.0.0.1:8081/readyz."
curl --noproxy '*' --fail --silent --show-error --max-time 8 http://127.0.0.1:3000/ >/dev/null \
  || fail "Dashboard is unavailable at http://127.0.0.1:3000/."
podman exec "$postgres_container" pg_isready -U kordex -d kordex >/dev/null \
  || fail "Local PostgreSQL is not ready."
[[ "$(podman exec "$postgres_container" psql -U kordex -d kordex -Atc 'SHOW ssl' 2>/dev/null)" == on ]] \
  || fail "PostgreSQL TLS is not enabled; refusing OIDC setup."
echo "Keycloak, JWKS, OIDC API, dashboard, and TLS-enabled PostgreSQL are available."

"$repo_root/scripts/local-oidc-trust-ca.sh"

read -r -p "Test username: " username
read -r -p "Test email: " email
[[ -n "$username" && -n "$email" ]] || fail "Username and email are required."
subject="$(cd "$repo_root/scripts" && "$python" local-oidc-provision-user.py --username "$username" --email "$email")" \
  || fail "Keycloak user provisioning did not complete."
[[ "$subject" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]] \
  || fail "Provisioning did not return the actual Keycloak user ID/sub."

read -r -p "Existing Kordex organization UUID: " organization_id
read -r -p "Membership role [viewer/operator/approver/administrator] (default viewer): " role
role="${role:-viewer}"
case "$role" in viewer|operator|approver|administrator) ;; *) fail "Unsupported role: $role" ;; esac
"$python" "$repo_root/scripts/local-oidc-grant-membership.py" \
  --organization "$organization_id" --subject "$subject" --role "$role"

echo "Local OIDC setup is prepared. Open http://127.0.0.1:3000 and choose Sign in."
echo "Complete the Keycloak login interactively; this script does not launch a browser or inspect browser credentials."
