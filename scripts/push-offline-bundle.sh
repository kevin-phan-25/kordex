#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 BUNDLE_DIRECTORY PRIVATE_REGISTRY_HOST_OR_PATH" >&2
  echo "Example: $0 ./kordex-offline-0.8.0 registry.dc.example/platform" >&2
  exit 2
fi
BUNDLE="$(cd "$1" && pwd)"
REGISTRY="${2%/}"
ENGINE="${KORDEX_CONTAINER_ENGINE:-podman}"
REGISTRY_TLS_VERIFY="${KORDEX_REGISTRY_TLS_VERIFY:-true}"
LOCK_FILE="${KORDEX_IMAGE_LOCK_FILE:-$(dirname "$BUNDLE")/$(basename "$BUNDLE")-image-digests.tsv}"
command -v "$ENGINE" >/dev/null || { echo "container engine not found: $ENGINE" >&2; exit 2; }
case "$REGISTRY_TLS_VERIFY" in
  true|false) ;;
  *) echo "KORDEX_REGISTRY_TLS_VERIFY must be true or false" >&2; exit 2 ;;
esac
if [[ ! "$REGISTRY" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)*$ ]]; then
  echo "registry must be a lowercase host[:port][/path] without a URL scheme or trailing slash" >&2
  exit 2
fi
registry_port="${REGISTRY%%/*}"
if [[ "$registry_port" == *:* ]]; then
  registry_port="${registry_port##*:}"
  if (( 10#$registry_port < 1 || 10#$registry_port > 65535 )); then
    echo "registry port must be between 1 and 65535" >&2
    exit 2
  fi
fi
: "${KORDEX_RELEASE_PUBLIC_KEY:?set path to trusted Ed25519 release public key}"
: "${KORDEX_RELEASE_PRIVATE_KEY:?set path to the protected Ed25519 release private key for signing the mirror lock}"
: "${KORDEX_TRUSTED_BUNDLE_VERIFIER:?set path to independently trusted verify-offline-bundle.sh}"
[[ -d "$(dirname "$LOCK_FILE")" ]] || { echo "image lock parent directory must already exist" >&2; exit 2; }
LOCK_FILE="$(cd "$(dirname "$LOCK_FILE")" && pwd)/$(basename "$LOCK_FILE")"
LOCK_SIGNATURE="${LOCK_FILE}.sig"
case "$LOCK_FILE" in
  "$BUNDLE"/*) echo "image lock file must be outside the signed bundle" >&2; exit 2 ;;
esac
case "$LOCK_SIGNATURE" in
  "$BUNDLE"/*) echo "image lock signature must be outside the signed bundle" >&2; exit 2 ;;
esac
[[ ! -L "$LOCK_FILE" && ! -L "$LOCK_SIGNATURE" ]] || { echo "image lock and signature cannot be symlinks" >&2; exit 2; }
[[ -r "$KORDEX_RELEASE_PRIVATE_KEY" ]] || { echo "release private signing key is not readable" >&2; exit 2; }
[[ -f "$KORDEX_TRUSTED_BUNDLE_VERIFIER" && -x "$KORDEX_TRUSTED_BUNDLE_VERIFIER" && ! -L "$KORDEX_TRUSTED_BUNDLE_VERIFIER" ]] || {
  echo "trusted bundle verifier must be an executable, regular file" >&2; exit 2;
}
TRUSTED_VERIFIER="$(cd "$(dirname "$KORDEX_TRUSTED_BUNDLE_VERIFIER")" && pwd)/$(basename "$KORDEX_TRUSTED_BUNDLE_VERIFIER")"
case "$TRUSTED_VERIFIER" in
  "$BUNDLE"/*) echo "trusted bundle verifier must be outside the bundle" >&2; exit 2 ;;
esac
"$TRUSTED_VERIFIER" "$BUNDLE" "$KORDEX_RELEASE_PUBLIC_KEY"
LOCK_TMP="$(mktemp "${LOCK_FILE}.tmp.XXXXXX")"
SIGNATURE_TMP="$(mktemp "${LOCK_SIGNATURE}.tmp.XXXXXX")"
digest_file=""
manifest_tags=()
cleanup() {
  [[ -z "$digest_file" ]] || rm -f "$digest_file"
  rm -f "$LOCK_TMP"
  rm -f "$SIGNATURE_TMP"
  for manifest_tag in "${manifest_tags[@]}"; do
    "$ENGINE" manifest rm "$manifest_tag" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
declare -A seen_images=()
while IFS=$'\t' read -r name source; do
  [[ -n "$name" && -n "$source" ]] || continue
  case "$name" in
    control-plane|agent|operator|dashboard|ansible-ee|postgres) ;;
    *) echo "unsupported or malformed image name in bundle: $name" >&2; exit 1 ;;
  esac
  [[ -z "${seen_images[$name]:-}" ]] || { echo "duplicate image in bundle: $name" >&2; exit 1; }
  [[ "$source" =~ ^localhost/kordex/${name}:[A-Za-z0-9._+-]+$ ]] || { echo "invalid local image reference for $name" >&2; exit 1; }
  seen_images[$name]=1
done < "$BUNDLE/images.txt"
for required in control-plane agent operator dashboard ansible-ee postgres; do
  [[ -n "${seen_images[$required]:-}" ]] || { echo "required bundle image is missing: $required" >&2; exit 1; }
done

while IFS=$'\t' read -r name source; do
  [[ -n "$name" && -n "$source" ]] || continue
  archive=""
  case "$name" in
    postgres) archive="$BUNDLE/images/postgres-17-alpine.oci.tar" ;;
    *) tag="${source##*:}"; archive="$BUNDLE/images/${name}-${tag}.oci.tar" ;;
  esac
  [[ -f "$archive" ]] || { echo "missing image archive for $name: $archive" >&2; exit 1; }
  target="$REGISTRY/kordex/$name:${source##*:}"
  local_manifest="localhost/kordex-mirror/${name}:${source##*:}-$$"
  manifest_tags+=("$local_manifest")
  # Load every platform directly from the signed OCI archive. `podman push`
  # has no --all option; manifest create/push is the supported multi-arch path.
  "$ENGINE" manifest create --all "$local_manifest" "oci-archive:$archive"
  digest_file="$(mktemp)"
  "$ENGINE" manifest push --all --digestfile "$digest_file" \
    --tls-verify="$REGISTRY_TLS_VERIFY" "$local_manifest" "docker://$target"
  digest="$(tr -d '\r\n' < "$digest_file")"
  rm -f "$digest_file"
  digest_file=""
  [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "registry did not return a valid digest for $target" >&2; exit 1; }
  printf '%s\t%s@%s\n' "$name" "${target%:*}" "$digest" | tee -a "$LOCK_TMP"
done < "$BUNDLE/images.txt"
openssl pkeyutl -sign -rawin -inkey "$KORDEX_RELEASE_PRIVATE_KEY" -in "$LOCK_TMP" -out "$SIGNATURE_TMP"
chmod 0444 "$SIGNATURE_TMP"
mv "$SIGNATURE_TMP" "$LOCK_SIGNATURE"
mv "$LOCK_TMP" "$LOCK_FILE"
trap - EXIT

echo "Push complete. Signed registry digest lock written to $LOCK_FILE and $LOCK_SIGNATURE"
