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
[[ -s "$CA_CERT" && -f "$CA_CERT" && ! -L "$CA_CERT" && -s "$CA_KEY" && -f "$CA_KEY" && ! -L "$CA_KEY" ]] || {
  echo 'Existing local OIDC CA certificate/key must be regular files.' >&2; exit 2;
}
CA_KEY_MODE="$(stat -c '%a' -- "$CA_KEY")"
(( (8#$CA_KEY_MODE & 077) == 0 )) || { echo 'Local CA private key must deny all group and other access.' >&2; exit 2; }
[[ "$(stat -c '%u' -- "$CA_KEY")" == "$(id -u)" ]] || { echo 'Local CA private key must be owned by the invoking user.' >&2; exit 2; }
openssl x509 -in "$CA_CERT" -noout -checkend 34214400 >/dev/null 2>&1 || {
  echo 'Local CA certificate is expired or will expire before the leaf certificates.' >&2; exit 2;
}
CA_CONSTRAINTS="$(openssl x509 -in "$CA_CERT" -noout -ext basicConstraints 2>/dev/null)" || {
  echo 'Local CA certificate has no usable CA constraints.' >&2; exit 2;
}
[[ "$CA_CONSTRAINTS" == *'CA:TRUE'* ]] || { echo 'Local certificate is not a CA.' >&2; exit 2; }
CA_USAGE="$(openssl x509 -in "$CA_CERT" -noout -ext keyUsage 2>/dev/null)" || {
  echo 'Local CA certificate has no key-usage extension.' >&2; exit 2;
}
[[ "$CA_USAGE" == *'Certificate Sign'* ]] || { echo 'Local CA certificate does not permit certificate signing.' >&2; exit 2; }
CERT_PUBLIC_HASH="$(openssl x509 -in "$CA_CERT" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d ' ' -f 1)"
KEY_PUBLIC_HASH="$(openssl pkey -in "$CA_KEY" -pubout -outform DER 2>/dev/null | sha256sum | cut -d ' ' -f 1)" || {
  echo 'Local CA private key cannot be read.' >&2; exit 2;
}
[[ -n "$CERT_PUBLIC_HASH" && "$CERT_PUBLIC_HASH" == "$KEY_PUBLIC_HASH" ]] || {
  echo 'Local CA certificate and private key do not match.' >&2; exit 2;
}
mkdir -p -m 700 -- "$OUT_DIR"
[[ -d "$OUT_DIR" && ! -L "$OUT_DIR" && "$(stat -c '%u' -- "$OUT_DIR")" == "$(id -u)" ]] || {
  echo 'Certificate output directory must be a non-symlink directory owned by the invoking user.' >&2; exit 2;
}
chmod 700 "$OUT_DIR"
OUT_DIR="$(realpath -- "$OUT_DIR")"
case "$OUT_DIR/" in "$ROOT/"*) echo 'Certificate output must remain outside the Git repository.' >&2; exit 2;; esac
for generated in ca.crt ca.srl postgres.key postgres.crt postgres.csr postgres.ext keycloak.key keycloak.crt keycloak.csr keycloak.ext api.key api.crt api.csr api.ext; do
  [[ ! -e "$OUT_DIR/$generated" ]] || { echo "Refusing to overwrite existing certificate material in $OUT_DIR." >&2; exit 2; }
done
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
    -CAserial "$OUT_DIR/ca.srl" -CAcreateserial -extfile "$ext" -out "$cert" >/dev/null 2>&1
  chmod 600 "$key"
  chmod 644 "$cert"
  [[ "$(stat -c '%a' -- "$key")" == 600 ]] || { echo 'Generated private key permissions are not 0600.' >&2; exit 2; }
  chmod 600 "$OUT_DIR/ca.srl"
  rm -f -- "$csr" "$ext"
}

issue postgres 'DNS:kordex-postgres.kordex-management.svc.cluster.local,DNS:kordex-postgres.kordex-management.svc' kordex-postgres
issue keycloak 'DNS:keycloak.localhost,IP:127.0.0.1,IP:::1' keycloak.localhost
issue api 'DNS:kordex-api.kordex-management.svc.cluster.local,IP:127.0.0.1' kordex-api
openssl verify -CAfile "$OUT_DIR/ca.crt" -verify_hostname kordex-postgres.kordex-management.svc.cluster.local "$OUT_DIR/postgres.crt" >/dev/null
openssl verify -CAfile "$OUT_DIR/ca.crt" -verify_hostname keycloak.localhost "$OUT_DIR/keycloak.crt" >/dev/null
openssl verify -CAfile "$OUT_DIR/ca.crt" -verify_ip 127.0.0.1 "$OUT_DIR/api.crt" >/dev/null
echo "Verified TLS leaf certificates and CA written outside the repository: $OUT_DIR"
