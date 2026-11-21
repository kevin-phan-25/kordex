#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
TAG="localhost/kordex/oci-qualification:$(date +%s)-$$"
WRAPPER_TAG="localhost/kordex/oci-wrapper-qualification:$(date +%s)-$$"
ARCHIVE="$TMP/multi-platform.oci.tar"
WRAPPER_ARCHIVE="$TMP/multi-platform-wrapper.oci.tar"
DIGEST_FILE="$TMP/index.digest"
PODMAN_BIN="${KORDEX_TEST_PODMAN:-podman}"
USE_SUDO="${KORDEX_TEST_PODMAN_SUDO:-false}"
MANIFEST_TAGS=("$TAG" "$WRAPPER_TAG")
cleanup() {
  if [[ "$USE_SUDO" == true ]]; then
    sudo podman manifest rm "${MANIFEST_TAGS[@]}" >/dev/null 2>&1 || true
  else
    "$PODMAN_BIN" manifest rm "${MANIFEST_TAGS[@]}" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

run_podman() {
  if [[ "$USE_SUDO" == true ]]; then
    sudo podman "$@"
  else
    "$PODMAN_BIN" "$@"
  fi
}

command -v "$PODMAN_BIN" >/dev/null 2>&1 || { echo "Podman is required for real OCI archive validation" >&2; exit 2; }
mkdir -p "$TMP/context"
cat > "$TMP/context/Containerfile" <<'EOF_CONTAINER'
FROM scratch
COPY payload /payload
EOF_CONTAINER
printf 'Kordex offline OCI validation image\n' > "$TMP/context/payload"

run_podman build --platform linux/amd64,linux/arm64 --manifest "$TAG" \
  --file "$TMP/context/Containerfile" "$TMP/context"
run_podman manifest push --all --format oci --digestfile "$DIGEST_FILE" \
  "$TAG" "oci-archive:$ARCHIVE"
[[ -s "$DIGEST_FILE" && -s "$ARCHIVE" ]] || { echo "Podman did not produce the OCI archive and digest" >&2; exit 1; }
KORDEX_TEST_REAL_OCI_ARCHIVE="$ARCHIVE" bash "$ROOT/scripts/test-offline-bundle-integrity.sh"

# Rebuild the locally created index through the same thin wrapper used for the
# offline PostgreSQL image. This checks that the wrapper index contains exactly
# the requested platforms and does not inherit any extra platforms from a base.
cat > "$TMP/context/Wrapper.Containerfile" <<'EOF_CONTAINER'
ARG KORDEX_POSTGRES_BASE
FROM ${KORDEX_POSTGRES_BASE}
ARG KORDEX_POSTGRES_BASE
LABEL org.opencontainers.image.title="Kordex offline PostgreSQL test image" \
      org.opencontainers.image.base.name="${KORDEX_POSTGRES_BASE}"
EOF_CONTAINER
run_podman build --platform linux/amd64,linux/arm64 --manifest "$WRAPPER_TAG" \
  --file "$TMP/context/Wrapper.Containerfile" \
  --build-arg "KORDEX_POSTGRES_BASE=$TAG" "$TMP/context"
run_podman manifest push --all --format oci --digestfile "$DIGEST_FILE" \
  "$WRAPPER_TAG" "oci-archive:$WRAPPER_ARCHIVE"
[[ -s "$DIGEST_FILE" && -s "$WRAPPER_ARCHIVE" ]] || { echo "Podman did not produce the wrapped OCI archive and digest" >&2; exit 1; }
KORDEX_TEST_REAL_OCI_ARCHIVE="$WRAPPER_ARCHIVE" bash "$ROOT/scripts/test-offline-bundle-integrity.sh"

if [[ -n "${KORDEX_TEST_REGISTRY_HOST:-}" ]]; then
  REGISTRY_HOST="$KORDEX_TEST_REGISTRY_HOST"
  REGISTRY_URL="http://$REGISTRY_HOST"
  registry_ready=false
  for attempt in {1..30}; do
    if curl --fail --silent "$REGISTRY_URL/v2/" >/dev/null; then
      registry_ready=true
      break
    fi
    sleep 1
  done
  [[ "$registry_ready" == true ]] || { echo "test registry did not become ready: $REGISTRY_HOST" >&2; exit 1; }
  MIRROR_BUNDLE="$TMP/mirror-bundle"
  mkdir -p "$MIRROR_BUNDLE/images" "$MIRROR_BUNDLE/scripts"
  printf 'control-plane\tlocalhost/kordex/control-plane:0.8.0\nagent\tlocalhost/kordex/agent:0.8.0\noperator\tlocalhost/kordex/operator:0.8.0\ndashboard\tlocalhost/kordex/dashboard:0.8.0\nansible-ee\tlocalhost/kordex/ansible-ee:0.8.0\npostgres\tlocalhost/kordex/postgres:17-alpine\n' > "$MIRROR_BUNDLE/images.txt"
  cat > "$TMP/trusted-bundle-verifier.sh" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ -f "$1/images.txt" && -r "$2" ]]
EOF_VERIFIER
  chmod 0555 "$TMP/trusted-bundle-verifier.sh"
  for image in control-plane agent operator dashboard ansible-ee postgres; do
    source_tag="localhost/kordex/$image:0.8.0"
    [[ "$image" == postgres ]] && source_tag="localhost/kordex/postgres:17-alpine"
    run_podman tag "$WRAPPER_TAG" "$source_tag"
    MANIFEST_TAGS+=("$source_tag")
    if [[ "$image" == postgres ]]; then
      image_archive="$MIRROR_BUNDLE/images/postgres-17-alpine.oci.tar"
    else
      image_archive="$MIRROR_BUNDLE/images/$image-0.8.0.oci.tar"
    fi
    run_podman manifest push --all --format oci --digestfile "$TMP/$image.digest" \
      "$source_tag" "oci-archive:$image_archive"
  done
  if [[ "$USE_SUDO" == true ]]; then
    cat > "$TMP/podman-engine" <<'EOF_ENGINE'
#!/usr/bin/env bash
set -euo pipefail
exec sudo podman "$@"
EOF_ENGINE
  else
    {
      printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail'
      printf 'exec %q "$@"\n' "$PODMAN_BIN"
    } > "$TMP/podman-engine"
  fi
  chmod 0555 "$TMP/podman-engine"
  openssl genpkey -algorithm ED25519 -out "$TMP/mirror-private.pem"
  openssl pkey -in "$TMP/mirror-private.pem" -pubout -out "$TMP/mirror-public.pem"
  KORDEX_CONTAINER_ENGINE="$TMP/podman-engine" \
    KORDEX_REGISTRY_TLS_VERIFY=false \
    KORDEX_RELEASE_PUBLIC_KEY="$TMP/mirror-public.pem" \
    KORDEX_RELEASE_PRIVATE_KEY="$TMP/mirror-private.pem" \
    KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-bundle-verifier.sh" \
    KORDEX_IMAGE_LOCK_FILE="$TMP/mirrored-images.tsv" \
    bash "$ROOT/scripts/push-offline-bundle.sh" "$MIRROR_BUNDLE" "$REGISTRY_HOST"
  "$ROOT/scripts/verify-image-lock.sh" "$TMP/mirrored-images.tsv" \
    "$TMP/mirrored-images.tsv.sig" "$TMP/mirror-public.pem"
  for image in control-plane agent operator dashboard ansible-ee postgres; do
    if [[ "$image" == postgres ]]; then tag="17-alpine"; else tag="0.8.0"; fi
    digest="$(awk -F '\t' -v name="$image" '$1 == name { sub(/^.*@/, "", $2); print $2 }' "$TMP/mirrored-images.tsv")"
    [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "missing mirrored digest for $image" >&2; exit 1; }
    response="$TMP/$image.registry-manifest.json"
    headers="$TMP/$image.registry-headers.txt"
    curl --fail --silent --show-error -D "$headers" -o "$response" \
      -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
      "$REGISTRY_URL/v2/kordex/$image/manifests/$digest"
    python3 - "$response" "$headers" "$digest" <<'PY'
import hashlib
import json
import pathlib
import sys

body = pathlib.Path(sys.argv[1]).read_bytes()
headers = pathlib.Path(sys.argv[2]).read_text().lower()
expected = sys.argv[3]
actual = "sha256:" + hashlib.sha256(body).hexdigest()
if actual != expected:
    raise SystemExit(f"registry manifest bytes do not match mirror lock digest: {actual} != {expected}")
if f"docker-content-digest: {expected}" not in headers:
    raise SystemExit("registry response does not confirm the locked manifest digest")
index = json.loads(body)
platforms = {
    f"{entry.get('platform', {}).get('os')}/{entry.get('platform', {}).get('architecture')}"
    for entry in index.get("manifests", [])
}
if platforms != {"linux/amd64", "linux/arm64"}:
    raise SystemExit(f"mirrored index has wrong platforms: {sorted(platforms)}")
PY
    image_ref="$REGISTRY_HOST/kordex/$image:$tag"
    for platform in linux/amd64 linux/arm64; do
      run_podman pull --tls-verify=false --platform "$platform" "$image_ref@$digest"
      expected_arch="${platform#linux/}"
      # A digest-qualified pull is stored under the digest-qualified reference;
      # inspecting the mutable tag here fails with Podman and does not prove
      # which immutable index was pulled.
      pulled_arch="$(run_podman image inspect --format '{{.Architecture}}' "$image_ref@$digest")"
      [[ "$pulled_arch" == "$expected_arch" ]] || {
        echo "registry pull selected $pulled_arch for $platform on $image" >&2
        exit 1
      }
    done
  done
fi
