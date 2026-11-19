#!/usr/bin/env bash
set -euo pipefail

data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
oidc_dir="${KORDEX_LOCAL_OIDC_DIR:-$data_home/kordex/local-oidc}"
cert_dir="$oidc_dir/certs"
admin_password_file="$oidc_dir/keycloak-admin-password"

umask 077
mkdir -p "$cert_dir"
chmod 700 "$oidc_dir" "$cert_dir"

if [[ ! -e "$admin_password_file" ]]; then
  openssl rand -hex 32 > "$admin_password_file"
  chmod 600 "$admin_password_file"
fi

if [[ ! -e "$cert_dir/ca.key" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$cert_dir/ca.key" >/dev/null 2>&1
  openssl req -x509 -new -sha256 -days 3650 -key "$cert_dir/ca.key" \
    -subj "/CN=Kordex Local OIDC CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$cert_dir/ca.crt"
fi

issue_server_cert() {
  local name="$1" cn="$2" san="$3"
  local key="$cert_dir/$name.key" csr="$cert_dir/$name.csr" cert="$cert_dir/$name.crt" ext="$cert_dir/$name.ext"
  if [[ -e "$key" || -e "$cert" ]]; then
    [[ -s "$key" && -s "$cert" ]] || { echo "Incomplete local certificate pair: $name" >&2; exit 1; }
    return
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" >/dev/null 2>&1
  openssl req -new -key "$key" -subj "/CN=$cn" -out "$csr"
  cat > "$ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF
  openssl x509 -req -sha256 -days 397 -in "$csr" -CA "$cert_dir/ca.crt" \
    -CAkey "$cert_dir/ca.key" -CAcreateserial -extfile "$ext" -out "$cert"
  chmod 600 "$key"
  chmod 644 "$cert"
  rm -f "$csr" "$ext"
}

issue_server_cert keycloak keycloak.localhost "DNS:keycloak.localhost,IP:127.0.0.1,IP:::1"
issue_server_cert postgres postgres "DNS:postgres"
chmod 600 "$cert_dir/ca.key" "$admin_password_file"
chmod 644 "$cert_dir/ca.crt"

# Discover service UIDs from the configured images instead of assuming a
# Debian-based PostgreSQL UID; the checked-in local image is Alpine (UID 70).
keycloak_image="${KORDEX_KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3}"
postgres_image="${KORDEX_POSTGRES_IMAGE:-postgres:17-alpine}"
keycloak_uid="$(podman run --rm --entrypoint id "$keycloak_image" -u keycloak)"
postgres_uid="$(podman run --rm --entrypoint id "$postgres_image" -u postgres)"
podman unshare chown "$keycloak_uid:0" "$cert_dir/keycloak.key" "$cert_dir/keycloak.crt"
podman unshare chown "$postgres_uid:$postgres_uid" "$cert_dir/postgres.key" "$cert_dir/postgres.crt"

echo "Local OIDC materials are stored outside the repository at: $oidc_dir"
echo "Keycloak admin password file: $admin_password_file"
echo "Keep the CA private key private; import only ca.crt into local trust stores."
