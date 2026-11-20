#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
[[ "${KORDEX_TLS_CONFIRM:-}" == 'GENERATE PRIVATE GKE LAB TLS MATERIAL' ]] || {
  echo "Set KORDEX_TLS_CONFIRM='GENERATE PRIVATE GKE LAB TLS MATERIAL' before generating certificates." >&2
  exit 2
}
OIDC_DIR="${KORDEX_LOCAL_OIDC_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/kordex/local-oidc}"
OUT_DIR="${KORDEX_PRIVATE_LAB_CERT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/kordex/private-gke-lab/certs}"
CA_CERT="$OIDC_DIR/certs/ca.crt"
CA_KEY="$OIDC_DIR/certs/ca.key"
command -v openssl >/dev/null || { echo 'openssl is required' >&2; exit 2; }
[[ -s "$CA_CERT" && -s "$CA_KEY" ]] || { echo 'Existing local OIDC CA certificate/key are required.' >&2; exit 2; }
mkdir -p -- "$OUT_DIR"
chmod 700 "$OUT_DIR"
OUT_DIR="$(realpath -- "$OUT_DIR")"
case "$OUT_DIR/" in "$ROOT/"*) echo 'Certificate output must remain outside the Git repository.' >&2; exit 2;; esac
cp -- "$CA_CERT" "$OUT_DIR/ca.crt"
chmod 644 "$OUT_DIR/ca.crt"

issue(){
  local name="$1" san="$2" cn="$3"
  local key="$OUT_DIR/$name.key" csr="$OUT_DIR/$name.csr" cert="$OUT_DIR/$name.crt" ext="$OUT_DIR/$name.ext"
  if [[ -e "$key" || -e "$cert" ]]; then
    echo "Refusing to overwrite existing certificate material: $name" >&2
    exit 2
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" >/dev/null 2>&1
  openssl req -new -key "$key" -subj "/CN=$cn" -out "$csr"
  cat > "$ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF
  openssl x509 -req -sha256 -days 397 -in "$csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -extfile "$ext" -out "$cert" >/dev/null 2>&1
  chmod 600 "$key"
  chmod 644 "$cert"
  rm -f -- "$csr" "$ext"
}

issue postgres 'DNS:kordex-postgres.kordex-management.svc.cluster.local,DNS:kordex-postgres.kordex-management.svc' kordex-postgres
issue keycloak 'DNS:keycloak.localhost,IP:127.0.0.1,IP:::1' keycloak.localhost
issue api 'DNS:kordex-api.kordex-management.svc.cluster.local,IP:127.0.0.1' kordex-api
openssl verify -CAfile "$OUT_DIR/ca.crt" -verify_hostname kordex-postgres.kordex-management.svc.cluster.local "$OUT_DIR/postgres.crt" >/dev/null
openssl verify -CAfile "$OUT_DIR/ca.crt" -verify_hostname keycloak.localhost "$OUT_DIR/keycloak.crt" >/dev/null
openssl verify -CAfile "$OUT_DIR/ca.crt" -verify_ip 127.0.0.1 "$OUT_DIR/api.crt" >/dev/null
echo "Verified TLS leaf certificates and CA written outside the repository: $OUT_DIR"
