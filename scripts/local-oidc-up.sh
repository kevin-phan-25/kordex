#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
local_dir="${KORDEX_LOCAL_OIDC_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/kordex/local-oidc}"
password_file="$local_dir/keycloak-admin-password"

[[ -s "$password_file" ]] || { echo "Run scripts/local-oidc-init.sh first." >&2; exit 1; }
[[ -f "$repo_root/deployments/local/.env" ]] || { echo "Missing deployments/local/.env; keep the existing bootstrap environment in place." >&2; exit 1; }

export KORDEX_LOCAL_OIDC_DIR="$local_dir"
export KORDEX_KEYCLOAK_ADMIN_USERNAME="kordex-local-admin"
IFS= read -r KORDEX_KEYCLOAK_ADMIN_PASSWORD < "$password_file"
export KORDEX_KEYCLOAK_ADMIN_PASSWORD

cd "$repo_root/deployments/local"

is_running() {
  [[ "$(podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null || true)" == running ]]
}

# PostgreSQL must use the opt-in TLS overlay; applying it recreates that
# container but retains its named data volume. Avoid repeating that restart.
pg_ssl="$(podman exec kordex-local_postgres_1 psql -U kordex -d kordex -Atc 'SHOW ssl' 2>/dev/null || true)"
if [[ "$pg_ssl" != on ]] || ! is_running kordex-local_keycloak_1; then
  podman-compose -p kordex-local \
    -f compose.yaml -f compose.campaigns.yaml -f compose.oidc.yaml \
    up -d postgres keycloak
fi

issuer="https://keycloak.localhost:8443/realms/kordex"
ready=false
for _ in $(seq 1 60); do
  if curl --noproxy '*' --fail --silent --show-error --cacert "$local_dir/certs/ca.crt" \
    "$issuer/.well-known/openid-configuration" |
    jq -e --arg issuer "$issuer" '.issuer == $issuer' >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
[[ "$ready" == true ]] || { echo "Keycloak discovery did not become ready; inspect the keycloak service logs." >&2; exit 1; }

control_plane_image="$(podman inspect --format '{{.Image}}' kordex-local_control-plane_1 2>/dev/null)"
[[ -n "$control_plane_image" ]] || { echo "The existing bootstrap control-plane image is unavailable." >&2; exit 1; }
podman tag "$control_plane_image" localhost/kordex-local-control-plane:local-oidc

podman-compose -p kordex-local \
  -f compose.yaml -f compose.campaigns.yaml -f compose.oidc.yaml \
  up -d control-plane-oidc

for _ in $(seq 1 30); do
  if curl --noproxy '*' --fail --silent --show-error http://127.0.0.1:8081/readyz >/dev/null; then
    echo "OIDC control plane is ready at http://127.0.0.1:8081"
    exit 0
  fi
  sleep 2
done
echo "OIDC control plane did not become ready; inspect its service logs." >&2
exit 1
