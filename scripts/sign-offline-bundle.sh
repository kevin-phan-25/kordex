#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 BUNDLE_DIRECTORY ED25519_PRIVATE_KEY" >&2
  exit 2
fi
BUNDLE="$(cd "$1" && pwd -P)"
KEY="$2"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
case "$SCRIPT_DIR/" in
  "$BUNDLE/"*)
    echo "signer scripts must come from a trusted directory outside the candidate bundle" >&2
    exit 1
    ;;
esac
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }
[[ -r "$KEY" ]] || { echo "private signing key is not readable" >&2; exit 2; }
bash "$SCRIPT_DIR/verify-offline-checksums.sh" "$BUNDLE"
bash "$SCRIPT_DIR/check-offline-manifest.sh" "$BUNDLE"
(cd "$BUNDLE" && sha256sum -c SHA256SUMS)
openssl pkeyutl -sign -rawin -inkey "$KEY" \
  -in "$BUNDLE/SHA256SUMS" -out "$BUNDLE/SHA256SUMS.sig"
chmod 0444 "$BUNDLE/SHA256SUMS.sig"
echo "Signed $BUNDLE/SHA256SUMS with the supplied Ed25519 private key."
