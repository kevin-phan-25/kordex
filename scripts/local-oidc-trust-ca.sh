#!/usr/bin/env bash
set -euo pipefail

data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
oidc_dir="${KORDEX_LOCAL_OIDC_DIR:-$data_home/kordex/local-oidc}"
ca="$oidc_dir/certs/ca.crt"
leaf="$oidc_dir/certs/keycloak.crt"
issuer="https://keycloak.localhost:8443/realms/kordex"

fail() { echo "$*" >&2; exit 1; }
for tool in openssl curl jq; do command -v "$tool" >/dev/null 2>&1 || fail "Required local tool is missing: $tool"; done
[[ -s "$ca" && -s "$leaf" ]] || fail "Missing local CA or Keycloak certificate under $oidc_dir; run scripts/local-oidc-init.sh."
openssl x509 -in "$ca" -noout >/dev/null 2>&1 || fail "Local CA is not a valid X.509 certificate."
openssl x509 -in "$ca" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE' || fail "Configured certificate is not a CA certificate."
openssl x509 -in "$ca" -checkend 0 -noout >/dev/null 2>&1 || fail "Local CA has expired or is not yet valid."
openssl x509 -in "$leaf" -checkend 0 -noout >/dev/null 2>&1 || fail "Keycloak server certificate has expired or is not yet valid."
openssl verify -CAfile "$ca" -verify_hostname keycloak.localhost "$leaf" >/dev/null || fail "Keycloak certificate chain or keycloak.localhost SAN validation failed."
curl --noproxy '*' --fail --silent --show-error --max-time 8 --cacert "$ca" \
  "$issuer/.well-known/openid-configuration" | jq -e --arg issuer "$issuer" '.issuer == $issuer' >/dev/null \
  || fail "Keycloak discovery is unavailable or does not match the local issuer; no trust-store change made."

if curl --noproxy '*' --fail --silent --show-error --max-time 8 "$issuer/.well-known/openid-configuration" | jq -e --arg issuer "$issuer" '.issuer == $issuer' >/dev/null; then
  echo "System TLS trust already validates the local Keycloak issuer."
  exit 0
fi

[[ -r /etc/os-release ]] || fail "Cannot identify this Linux distribution; install the CA manually using its documented system trust mechanism."
# shellcheck disable=SC1091
source /etc/os-release
ids="${ID:-} ${ID_LIKE:-}"
mechanism=""
destination=""
if [[ "$ids" =~ (fedora|rhel|rocky|almalinux|centos|ol) ]]; then
  command -v trust >/dev/null 2>&1 || fail "p11-kit 'trust' is unavailable; install it or add only this CA to the distribution trust anchors manually."
  mechanism="p11-kit"
elif [[ "$ids" =~ (debian|ubuntu) ]]; then
  command -v update-ca-certificates >/dev/null 2>&1 || fail "update-ca-certificates is unavailable; install ca-certificates and retry."
  mechanism="update-ca-certificates"
  destination="/usr/local/share/ca-certificates/kordex-local-oidc.crt"
else
  fail "Unsupported distribution '$ids'. Add only $ca to its system CA store manually, then rerun this script."
fi

echo "This installs only the local Kordex development CA into the system trust store."
read -r -p "Type 'INSTALL LOCAL OIDC CA SYSTEM-WIDE' to continue: " confirmation
[[ "$confirmation" == "INSTALL LOCAL OIDC CA SYSTEM-WIDE" ]] || fail "No trust-store change made."
command -v sudo >/dev/null 2>&1 || fail "sudo is required for this system-wide trust-store change."

if [[ "$mechanism" == p11-kit ]]; then
  sudo trust anchor --store "$ca"
else
  if [[ -e "$destination" ]]; then
    existing="$(openssl x509 -in "$destination" -noout -fingerprint -sha256 2>/dev/null || true)"
    wanted="$(openssl x509 -in "$ca" -noout -fingerprint -sha256)"
    [[ "$existing" == "$wanted" ]] || fail "$destination already contains a different certificate; refusing to overwrite it."
  else
    sudo install -o root -g root -m 0644 "$ca" "$destination"
  fi
  sudo update-ca-certificates
fi

# Verify through the ordinary system TLS path: no --cacert and no bypass flags.
curl --noproxy '*' --fail --silent --show-error --max-time 8 "$issuer/.well-known/openid-configuration" \
  | jq -e --arg issuer "$issuer" '.issuer == $issuer' >/dev/null \
  || fail "System trust installation finished but normal TLS validation still fails."
echo "System TLS trust now validates the configured local Keycloak issuer."
echo "Firefox may use a separate certificate store; import only $ca as a website authority in Firefox if that browser does not use the system trust store."
