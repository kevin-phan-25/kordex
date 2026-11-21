#!/usr/bin/env bash
set -Eeuo pipefail

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
STAGE="initialization"
LAST_COMMAND=""

run_podman() {
  if [[ "$USE_SUDO" == true ]]; then
    LAST_COMMAND='sudo podman'
    local argument
    for argument in "$@"; do printf -v LAST_COMMAND '%s %q' "$LAST_COMMAND" "$argument"; done
    sudo podman "$@"
  else
    printf -v LAST_COMMAND '%q' "$PODMAN_BIN"
    local argument
    for argument in "$@"; do printf -v LAST_COMMAND '%s %q' "$LAST_COMMAND" "$argument"; done
    "$PODMAN_BIN" "$@"
  fi
}

require_archive_output() {
  if [[ -s "$1" && -s "$2" ]]; then return 0; fi
  echo "Podman did not produce the expected OCI archive and digest: $1 $2" >&2
  return 1
}

print_archive_diagnostics() {
  local archive="$1"
  [[ -n "$archive" ]] || return 0
  if [[ ! -e "$archive" ]]; then
    printf 'OCI archive: absent (%s)\n' "$archive" >&2
    return 0
  fi
  stat -c 'OCI archive: %n size=%s mode=%a owner=%U:%G' "$archive" >&2 || true
  sha256sum "$archive" >&2 || true
  tar -tf "$archive" 2>&1 | head -20 >&2 || true
  python3 - "$archive" <<'PY' >&2 || true
import hashlib
import json
import pathlib
import sys
import tarfile

path = pathlib.Path(sys.argv[1])
try:
    with tarfile.open(path, "r:*") as archive:
        files = {item.name: item for item in archive.getmembers() if item.isfile()}
        index_item = files.get("index.json")
        if index_item is None or index_item.size > 4 * 1024 * 1024:
            raise ValueError("missing or oversized index.json")
        index = json.load(archive.extractfile(index_item))
        print("OCI root index:", json.dumps({
            "schemaVersion": index.get("schemaVersion"),
            "mediaType": index.get("mediaType", "<omitted>"),
            "manifestCount": len(index.get("manifests", [])) if isinstance(index.get("manifests"), list) else None,
        }, sort_keys=True))
        pending = list(index.get("manifests", []))
        seen = set()
        platforms = []
        while pending:
            descriptor = pending.pop(0)
            digest = descriptor.get("digest", "")
            if digest in seen:
                continue
            seen.add(digest)
            if descriptor.get("platform"):
                platforms.append((descriptor["platform"].get("os"), descriptor["platform"].get("architecture"), digest))
                continue
            if descriptor.get("mediaType") != "application/vnd.oci.image.index.v1+json":
                platforms.append(("<no-platform>", "<no-platform>", digest))
                continue
            blob = "blobs/sha256/" + digest.removeprefix("sha256:")
            item = files.get(blob)
            if item is None or item.size > 4 * 1024 * 1024:
                raise ValueError("nested index blob missing or oversized: " + blob)
            raw = archive.extractfile(item).read()
            if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("nested index digest mismatch: " + digest)
            nested = json.loads(raw)
            pending.extend(nested.get("manifests", []))
        print("OCI index platforms:", json.dumps(sorted(platforms)))
except Exception as error:
    print("OCI archive inspection failed:", type(error).__name__, str(error))
PY
}

on_error() {
  local status="$1"
  local failed_command="$2"
  trap - ERR
  set +e
  printf '\nOFFLINE OCI DIAGNOSTICS (original exit=%s, stage=%s)\n' "$status" "$STAGE" >&2
  printf 'Failed shell command: %s\n' "$failed_command" >&2
  [[ -z "$LAST_COMMAND" ]] || printf 'Last Podman command: %s\n' "$LAST_COMMAND" >&2
  printf 'User: '; id >&2
  printf 'Architecture: '; uname -m >&2
  printf 'Podman version:\n'; run_podman version >&2
  printf 'Buildah version:\n'; if command -v buildah >/dev/null 2>&1; then buildah version >&2; else echo 'buildah: unavailable' >&2; fi
  printf 'Podman rootless/storage:\n'; run_podman info --format 'rootless={{.Host.Security.Rootless}} driver={{.Store.GraphDriverName}} graphRoot={{.Store.GraphRoot}} runRoot={{.Store.RunRoot}}' >&2
  printf 'Subordinate IDs:\n'
  awk -F: -v user="$(id -un)" '$1 == user { print $0 }' /etc/subuid /etc/subgid >&2 2>/dev/null
  printf 'Filesystem and directory permissions:\n'
  local path
  for path in "$TMP" "$TMP/context" "$TMP/context/Containerfile" "$ARCHIVE" "$WRAPPER_ARCHIVE" "$DIGEST_FILE"; do
    if [[ -e "$path" ]]; then
      stat -c '%A %a %U:%G %n size=%s' "$path" >&2
    else
      printf 'absent: %s\n' "$path" >&2
    fi
  done
  if [[ -s "$DIGEST_FILE" ]]; then printf 'Recorded OCI index digest: '; cat "$DIGEST_FILE" >&2; fi
  df -h "$TMP" >&2
  if command -v findmnt >/dev/null 2>&1; then findmnt -T "$TMP" -n -o TARGET,FSTYPE,OPTIONS >&2; fi
  if [[ -d /proc/sys/fs/binfmt_misc ]]; then
    printf 'Registered binary formats:\n'
    find /proc/sys/fs/binfmt_misc -maxdepth 1 -type f ! -name status -printf '%f\n' 2>/dev/null >&2
  fi
  print_archive_diagnostics "$ARCHIVE"
  print_archive_diagnostics "$WRAPPER_ARCHIVE"
  if [[ -n "${KORDEX_TEST_REGISTRY_HOST:-}" ]]; then
    printf 'Test registry readiness: '
    curl --fail --silent --show-error --output /dev/null --write-out 'HTTP %{http_code}\n' \
      "http://${KORDEX_TEST_REGISTRY_HOST}/v2/" >&2
  fi
  printf 'End offline OCI diagnostics; preserving exit=%s\n\n' "$status" >&2
  exit "$status"
}

trap 'error_status=$?; error_command=$BASH_COMMAND; on_error "$error_status" "$error_command"' ERR
cleanup() {
  if [[ "$USE_SUDO" == true ]]; then
    sudo podman manifest rm "${MANIFEST_TAGS[@]}" >/dev/null 2>&1 || true
  else
    "$PODMAN_BIN" manifest rm "${MANIFEST_TAGS[@]}" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

if ! command -v "$PODMAN_BIN" >/dev/null 2>&1; then
  echo "Podman is required for real OCI archive validation" >&2
  false
fi
mkdir -p "$TMP/context"
cat > "$TMP/context/Containerfile" <<'EOF_CONTAINER'
FROM scratch
COPY payload /payload
EOF_CONTAINER
printf 'Kordex offline OCI validation image\n' > "$TMP/context/payload"

STAGE="building the linux/amd64 and linux/arm64 OCI test image"
run_podman build --platform linux/amd64,linux/arm64 --manifest "$TAG" \
  --file "$TMP/context/Containerfile" "$TMP/context"
STAGE="exporting the first OCI archive and recording its digest"
run_podman manifest push --all --format oci --digestfile "$DIGEST_FILE" \
  "$TAG" "oci-archive:$ARCHIVE"
require_archive_output "$DIGEST_FILE" "$ARCHIVE"
STAGE="offline verification of the first OCI archive"
KORDEX_TEST_REAL_OCI_ARCHIVE="$ARCHIVE" \
  KORDEX_TEST_REAL_OCI_INDEX_DIGEST="$(<"$DIGEST_FILE")" \
  bash "$ROOT/scripts/test-offline-bundle-integrity.sh"

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
STAGE="building the wrapped linux/amd64 and linux/arm64 OCI image"
run_podman build --platform linux/amd64,linux/arm64 --manifest "$WRAPPER_TAG" \
  --file "$TMP/context/Wrapper.Containerfile" \
  --build-arg "KORDEX_POSTGRES_BASE=$TAG" "$TMP/context"
STAGE="exporting the wrapped OCI archive and recording its digest"
run_podman manifest push --all --format oci --digestfile "$DIGEST_FILE" \
  "$WRAPPER_TAG" "oci-archive:$WRAPPER_ARCHIVE"
require_archive_output "$DIGEST_FILE" "$WRAPPER_ARCHIVE"
STAGE="offline verification of the wrapped OCI archive"
KORDEX_TEST_REAL_OCI_ARCHIVE="$WRAPPER_ARCHIVE" \
  KORDEX_TEST_REAL_OCI_INDEX_DIGEST="$(<"$DIGEST_FILE")" \
  bash "$ROOT/scripts/test-offline-bundle-integrity.sh"

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
  if [[ "$registry_ready" != true ]]; then
    echo "test registry did not become ready: $REGISTRY_HOST" >&2
    false
  fi
  STAGE="publishing and digest-verifying OCI archives against the temporary test registry"
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
