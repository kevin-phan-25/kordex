#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 BUNDLE_DIRECTORY ED25519_PUBLIC_KEY" >&2
  exit 2
fi
BUNDLE="$(cd "$1" && pwd)"
KEY="$2"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
: "${KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY:?set the independently trusted tool-lock signer public key}"
: "${KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE:?set the independently trusted Helm signer allowlist}"
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }
[[ -r "$KEY" ]] || { echo "trusted public signing key is not readable" >&2; exit 2; }
[[ -r "$KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY" && -r "$KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE" ]] || { echo "tool provenance trust inputs must be readable" >&2; exit 2; }
[[ -f "$BUNDLE/SHA256SUMS" && ! -L "$BUNDLE/SHA256SUMS" ]] || { echo "SHA256SUMS must be a regular file" >&2; exit 1; }
[[ -f "$BUNDLE/SHA256SUMS.sig" && ! -L "$BUNDLE/SHA256SUMS.sig" ]] || { echo "SHA256SUMS.sig must be a regular file" >&2; exit 1; }
[[ -f "$BUNDLE/bin/tools/offline-tools.signer.pub" && ! -L "$BUNDLE/bin/tools/offline-tools.signer.pub" ]] || { echo "bundled tool-provenance key must be a regular file" >&2; exit 1; }
[[ -f "$BUNDLE/bin/tools/offline-tools.helm-signers.txt" && ! -L "$BUNDLE/bin/tools/offline-tools.helm-signers.txt" ]] || { echo "bundled Helm signer allowlist must be a regular file" >&2; exit 1; }
openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin \
  -in "$BUNDLE/SHA256SUMS" -sigfile "$BUNDLE/SHA256SUMS.sig"
bundle_tool_key_fingerprint="$(openssl pkey -pubin -in "$BUNDLE/bin/tools/offline-tools.signer.pub" -outform DER | sha256sum | awk '{print $1}')"
trusted_tool_key_fingerprint="$(openssl pkey -pubin -in "$KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY" -outform DER | sha256sum | awk '{print $1}')"
[[ "$bundle_tool_key_fingerprint" == "$trusted_tool_key_fingerprint" ]] || { echo "bundle tool-provenance signer differs from the independently trusted key" >&2; exit 1; }
cmp -s "$BUNDLE/bin/tools/offline-tools.helm-signers.txt" "$KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE" || { echo "bundle Helm signer allowlist differs from the independently trusted allowlist" >&2; exit 1; }
bash "$SCRIPT_DIR/check-offline-manifest.sh" "$BUNDLE"
(cd "$BUNDLE" && sha256sum -c SHA256SUMS)
echo "Bundle signature and file checksums verified."
