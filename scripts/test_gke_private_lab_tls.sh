#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/kordex-tls-test.XXXXXXXX")"
chmod 700 "$TMP"
trap 'rm -rf -- "$TMP"' EXIT HUP INT TERM

make_ca(){
  local base="$1"
  mkdir -p -m 700 "$base/oidc/certs" "$base/out"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1500 -sha256 \
    -keyout "$base/oidc/certs/ca.key" -out "$base/oidc/certs/ca.crt" \
    -subj '/CN=Kordex isolated test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
  chmod 600 "$base/oidc/certs/ca.key"
}

make_ca "$TMP/valid"
KORDEX_TLS_CONFIRM='GENERATE PRIVATE GKE LAB TLS MATERIAL' \
KORDEX_LOCAL_OIDC_DIR="$TMP/valid/oidc" KORDEX_PRIVATE_LAB_CERT_DIR="$TMP/valid/out" \
  bash "$ROOT/scripts/gke-private-lab-generate-tls.sh" >/dev/null
openssl verify -CAfile "$TMP/valid/out/ca.crt" -verify_hostname \
  kordex-postgres.kordex-management.svc.cluster.local "$TMP/valid/out/postgres.crt" >/dev/null

make_ca "$TMP/wrong-ca"
if openssl verify -CAfile "$TMP/wrong-ca/oidc/certs/ca.crt" -verify_hostname \
  kordex-postgres.kordex-management.svc.cluster.local "$TMP/valid/out/postgres.crt" >/dev/null 2>&1; then
  echo 'wrong CA unexpectedly validated' >&2; exit 1
fi
if openssl verify -CAfile "$TMP/valid/out/ca.crt" -verify_hostname \
  wrong-hostname.invalid "$TMP/valid/out/postgres.crt" >/dev/null 2>&1; then
  echo 'wrong hostname unexpectedly validated' >&2; exit 1
fi

make_ca "$TMP/insecure"
chmod 644 "$TMP/insecure/oidc/certs/ca.key"
if KORDEX_TLS_CONFIRM='GENERATE PRIVATE GKE LAB TLS MATERIAL' \
  KORDEX_LOCAL_OIDC_DIR="$TMP/insecure/oidc" KORDEX_PRIVATE_LAB_CERT_DIR="$TMP/insecure/out" \
  bash "$ROOT/scripts/gke-private-lab-generate-tls.sh" >"$TMP/insecure/stdout" 2>"$TMP/insecure/stderr"; then
  echo 'insecure CA key permissions unexpectedly accepted' >&2; exit 1
fi
grep -q 'deny all group and other access' "$TMP/insecure/stderr"
echo 'private lab TLS generation and CA/hostname verification tests passed'
