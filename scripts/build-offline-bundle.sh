#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  echo "Required: digest-pinned OCI bases and offline tools directory, signed lock, acquisition public key, and approved Helm signer list" >&2
}

if [[ $# -ne 2 ]]; then usage; exit 2; fi
VERSION="$1"
OUT="$2"
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
ENGINE="podman"
IMAGE_PLATFORMS="${KORDEX_IMAGE_PLATFORMS:-linux/amd64,linux/arm64}"

if [[ ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]]; then
  echo "invalid bundle version: $VERSION" >&2; exit 2
fi
if [[ -L "$OUT" ]]; then
  echo "bundle output directory cannot be a symlink" >&2; exit 2
fi
OUT_NAME="$(basename -- "$OUT")"
if [[ -z "$OUT_NAME" || "$OUT_NAME" == . || "$OUT_NAME" == .. || "$OUT_NAME" == / ]]; then
  echo "invalid bundle output directory: $OUT" >&2; exit 2
fi
OUT_PARENT_RAW="$(dirname -- "$OUT")"
mkdir -p "$OUT_PARENT_RAW"
OUT_PARENT="$(cd -- "$OUT_PARENT_RAW" && pwd)"
OUT_FINAL="$OUT_PARENT/$OUT_NAME"
if [[ -L "$OUT_FINAL" || ( -e "$OUT_FINAL" && ( ! -d "$OUT_FINAL" || -n "$(find "$OUT_FINAL" -mindepth 1 -maxdepth 1 -print -quit)" ) ) ]]; then
  echo "bundle output directory must not exist or must be empty: $OUT" >&2; exit 2
fi
command -v "$ENGINE" >/dev/null || { echo "podman is required to build and export the Ansible EE" >&2; exit 2; }
HELM_BIN="${KORDEX_HELM_BIN:-$(command -v helm || true)}"
[[ -n "$HELM_BIN" && -x "$HELM_BIN" ]] || { echo "helm is required to package the charts" >&2; exit 2; }
: "${KORDEX_OFFLINE_TOOLS_DIR:?set directory containing verified linux-amd64 and linux-arm64 helm/kubectl binaries and license notices}"
: "${KORDEX_OFFLINE_TOOLS_LOCK:?set signed TSV tool provenance lock}"
: "${KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE:?set Ed25519 signature for the offline tools lock}"
: "${KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY:?set independently provisioned Ed25519 public key for the tool lock signer}"
: "${KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE:?set independently provisioned allowlist of approved Helm maintainer fingerprints}"
[[ -d "$KORDEX_OFFLINE_TOOLS_DIR" && ! -L "$KORDEX_OFFLINE_TOOLS_DIR" ]] || { echo "offline tools directory must be a regular directory" >&2; exit 2; }
[[ -f "$KORDEX_OFFLINE_TOOLS_LOCK" && ! -L "$KORDEX_OFFLINE_TOOLS_LOCK" ]] || { echo "offline tools lock must be a regular file" >&2; exit 2; }
[[ -f "$KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE" && ! -L "$KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE" ]] || { echo "offline tools lock signature must be a regular file" >&2; exit 2; }
[[ -f "$KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY" && ! -L "$KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY" ]] || { echo "offline tools lock public key must be a regular file" >&2; exit 2; }
[[ -f "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" && ! -L "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" ]] || { echo "approved Helm signer allowlist must be a regular file" >&2; exit 2; }
: "${KORDEX_ANSIBLE_EE_BASE:?set a repository-qualified, sha256 digest-pinned Ansible EE base image}"
: "${KORDEX_GO_BUILDER_BASE:?set digest-pinned Go builder image}"
: "${KORDEX_RUNTIME_BASE:?set digest-pinned Debian runtime image}"
: "${KORDEX_NODE_BASE:?set digest-pinned Node build image}"
: "${KORDEX_NODE_RUNTIME_BASE:?set digest-pinned Node runtime image}"
: "${KORDEX_POSTGRES_BASE:?set digest-pinned PostgreSQL image}"
for base in KORDEX_ANSIBLE_EE_BASE KORDEX_GO_BUILDER_BASE KORDEX_RUNTIME_BASE KORDEX_NODE_BASE KORDEX_NODE_RUNTIME_BASE KORDEX_POSTGRES_BASE; do
  value="${!base}"
  if [[ ! "$value" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]]; then
    echo "$base must be a repository-qualified OCI reference pinned by sha256 digest" >&2
    exit 2
  fi
done
if [[ ! "$IMAGE_PLATFORMS" =~ ^linux/(amd64|arm64)(,linux/(amd64|arm64))*$ ]]; then
  echo "KORDEX_IMAGE_PLATFORMS must be a comma-separated list of linux/amd64 and/or linux/arm64" >&2
  exit 2
fi
IFS=, read -r -a platform_list <<< "$IMAGE_PLATFORMS"
declare -A seen_platforms=()
for platform in "${platform_list[@]}"; do
  [[ -z "${seen_platforms[$platform]:-}" ]] || { echo "duplicate image platform: $platform" >&2; exit 2; }
  seen_platforms[$platform]=1
done

BUILD_DIR="$(mktemp -d "$OUT_PARENT/.${OUT_NAME}.build.XXXXXX")"
cleanup() {
  if [[ -n "${BUILD_DIR:-}" && -d "$BUILD_DIR" ]]; then
    rm -rf -- "$BUILD_DIR"
  fi
}
trap cleanup EXIT
OUT="$BUILD_DIR"
mkdir -p "$OUT/images" "$OUT/bin" "$OUT/charts" "$OUT/manifests" "$OUT/docs" "$OUT/helm-values" "$OUT/qualification"

# Distribute the standard client tools needed to install and render an offline
# deployment. Their source artifacts are staged and digest-locked by the
# release process; no download is performed by this builder.
declare -A offline_tool_versions=() offline_tool_digests=()
"$ROOT/scripts/verify-offline-tools-lock.sh" "$KORDEX_OFFLINE_TOOLS_LOCK" "$KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE" "$KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY" "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" >/dev/null
while IFS=$'\t' read -r name version arch digest artifact_digest artifact_url verification signer extra || [[ -n "${name:-}" ]]; do
  [[ -n "${name:-}" && -z "${extra:-}" ]] || { echo "malformed offline tools lock row" >&2; exit 2; }
  [[ "$name" == helm || "$name" == kubectl ]] || { echo "unsupported offline tool: $name" >&2; exit 2; }
  [[ "$arch" == linux-amd64 || "$arch" == linux-arm64 ]] || { echo "unsupported offline tool architecture: $arch" >&2; exit 2; }
  [[ "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo "invalid offline tool version: $version" >&2; exit 2; }
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid offline tool SHA-256 for $name/$arch" >&2; exit 2; }
  key="$name/$arch"
  [[ -z "${offline_tool_versions[$key]:-}" ]] || { echo "duplicate offline tool lock row: $key" >&2; exit 2; }
  source="$KORDEX_OFFLINE_TOOLS_DIR/$arch/$name"
  [[ -f "$source" && ! -L "$source" && -x "$source" ]] || { echo "missing executable offline tool: $source" >&2; exit 2; }
  actual="$(sha256sum "$source" | awk '{print $1}')"
  [[ "$actual" == "$digest" ]] || { echo "offline tool checksum mismatch: $key" >&2; exit 2; }
  offline_tool_versions[$key]="$version"
  offline_tool_digests[$key]="$digest"
done < "$KORDEX_OFFLINE_TOOLS_LOCK"
for arch in linux-amd64 linux-arm64; do
  [[ -d "$KORDEX_OFFLINE_TOOLS_DIR/$arch" && ! -L "$KORDEX_OFFLINE_TOOLS_DIR/$arch" ]] || { echo "offline tools architecture path must be a regular directory: $arch" >&2; exit 2; }
  for name in helm kubectl; do
    [[ -n "${offline_tool_versions[$name/$arch]:-}" ]] || { echo "offline tools lock is missing $name/$arch" >&2; exit 2; }
  done
done
[[ "${#offline_tool_versions[@]}" -eq 4 ]] || { echo "offline tools lock must contain exactly four rows" >&2; exit 2; }
[[ -d "$KORDEX_OFFLINE_TOOLS_DIR/LICENSES" && ! -L "$KORDEX_OFFLINE_TOOLS_DIR/LICENSES" ]] || { echo "offline tools LICENSES path must be a regular directory" >&2; exit 2; }
for license in helm.txt kubernetes.txt; do
  source="$KORDEX_OFFLINE_TOOLS_DIR/LICENSES/$license"
  [[ -f "$source" && ! -L "$source" && -s "$source" ]] || { echo "missing third-party license notice: $source" >&2; exit 2; }
done
mkdir -p "$OUT/bin/tools/linux-amd64" "$OUT/bin/tools/linux-arm64" "$OUT/bin/tools/LICENSES"
for arch in linux-amd64 linux-arm64; do
  for name in helm kubectl; do
    cp "$KORDEX_OFFLINE_TOOLS_DIR/$arch/$name" "$OUT/bin/tools/$arch/$name"
    chmod 0555 "$OUT/bin/tools/$arch/$name"
  done
done
# Keep the signed acquisition record byte-for-byte: it binds the exact binary
# hashes to official artifact URLs and the upstream verification identity.
cp "$KORDEX_OFFLINE_TOOLS_LOCK" "$OUT/bin/tools/offline-tools.tsv"
cp "$KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE" "$OUT/bin/tools/offline-tools.tsv.sig"
cp "$KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY" "$OUT/bin/tools/offline-tools.signer.pub"
cp "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" "$OUT/bin/tools/offline-tools.helm-signers.txt"
cp "$KORDEX_OFFLINE_TOOLS_DIR/LICENSES/helm.txt" "$OUT/bin/tools/LICENSES/helm.txt"
cp "$KORDEX_OFFLINE_TOOLS_DIR/LICENSES/kubernetes.txt" "$OUT/bin/tools/LICENSES/kubernetes.txt"

# Package host tools as well as images so an isolated site can perform key
# generation and audit verification without fetching dependencies there.
# Cross-compile both architectures commonly used by Kubernetes installations.
command -v go >/dev/null || { echo "Go is required to package offline binaries" >&2; exit 2; }
binary_specs=(
  "kordex:./control-plane/cmd/kordex"
  "kordex-scheduler:./control-plane/cmd/kordex-scheduler"
  "kordex-agent:./agent/cmd/kordex-agent"
  "kordex-operator:./operator/cmd/kordex-operator"
  "kordex-keygen:./api/cmd/kordex-keygen"
  "kordex-audit-verify:./control-plane/cmd/kordex-audit-verify"
  "kordex-audit-sign:./control-plane/cmd/kordex-audit-sign"
  "kordex-security-audit-export:./control-plane/cmd/kordex-security-audit-export"
)
for arch in amd64 arm64; do
  mkdir -p "$OUT/bin/linux-$arch"
  for spec in "${binary_specs[@]}"; do
    name="${spec%%:*}"
    package="${spec#*:}"
    (cd "$ROOT" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$OUT/bin/linux-$arch/$name" "$package")
  done
done

declare -A image_digests=()

build_image() {
  local name="$1" dockerfile="$2" image="localhost/kordex/$1:$VERSION"
  shift 2
  local args=(--file "$ROOT/$dockerfile" --platform "$IMAGE_PLATFORMS" --manifest "$image")
  case "$name" in
    dashboard)
      args+=(--build-arg "KORDEX_NODE_BASE=$KORDEX_NODE_BASE")
      args+=(--build-arg "KORDEX_NODE_RUNTIME_BASE=$KORDEX_NODE_RUNTIME_BASE")
      ;;
    *)
      args+=(--build-arg "KORDEX_GO_BUILDER_BASE=$KORDEX_GO_BUILDER_BASE")
      args+=(--build-arg "KORDEX_RUNTIME_BASE=$KORDEX_RUNTIME_BASE")
      ;;
  esac
  "$ENGINE" build "${args[@]}" "$@" "$ROOT"
  save_image_manifest "$image" "$OUT/images/${name}-${VERSION}.oci.tar"
  printf '%s\t%s\n' "$name" "$image" >> "$OUT/images.txt"
}

save_image_manifest() {
  local image="$1" archive="$2" digest_file="$OUT/images/.manifest-digest"
  "$ENGINE" manifest push --all --format oci --digestfile "$digest_file" "$image" "oci-archive:$archive"
  local digest
  digest="$(tr -d '\r\n' < "$digest_file")"
  rm -f "$digest_file"
  [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "Podman did not return a valid OCI index digest for $image" >&2; exit 1; }
  image_digests[$image]="$digest"
}

: > "$OUT/images.txt"
printf '%s\n' "$IMAGE_PLATFORMS" > "$OUT/images/platforms.txt"
build_image control-plane control-plane/Dockerfile
build_image agent agent/Dockerfile
build_image operator operator/Dockerfile
build_image dashboard dashboard/Dockerfile

EE_TAG="localhost/kordex/ansible-ee:$VERSION"
KORDEX_ANSIBLE_EE_TAG="$EE_TAG" KORDEX_ANSIBLE_EE_PLATFORMS="$IMAGE_PLATFORMS" "$ROOT/integrations/ansible-ee/build-ee.sh"
save_image_manifest "$EE_TAG" "$OUT/images/ansible-ee-${VERSION}.oci.tar"
printf 'ansible-ee\t%s\n' "$EE_TAG" >> "$OUT/images.txt"

# PostgreSQL is included for a fully offline development/test hub. Production
# installations may use an existing, independently managed PostgreSQL service.
POSTGRES_BASE="$KORDEX_POSTGRES_BASE"
POSTGRES_TAG="localhost/kordex/postgres:17-alpine"
"$ENGINE" build \
  --platform "$IMAGE_PLATFORMS" \
  --manifest "$POSTGRES_TAG" \
  --file "$ROOT/integrations/postgres/Containerfile" \
  --build-arg "KORDEX_POSTGRES_BASE=$POSTGRES_BASE" \
  "$ROOT/integrations/postgres"
save_image_manifest "$POSTGRES_TAG" "$OUT/images/postgres-17-alpine.oci.tar"
printf 'postgres\t%s\n' "$POSTGRES_TAG" >> "$OUT/images.txt"

for chart in "$ROOT"/deployments/helm/kordex-*; do
  "$HELM_BIN" package "$chart" --destination "$OUT/charts"
done
for component in agent operator control-plane dashboard; do
  case "$component" in
    agent|operator) image_path="$component" ;;
    control-plane) image_path="control-plane" ;;
    dashboard) image_path="dashboard" ;;
  esac
  cat > "$OUT/helm-values/kordex-${component}.yaml" <<EOF
image:
  repository: registry.example.invalid/platform/kordex/${image_path}
  tag: "${VERSION}"
  digest: ""
  pullPolicy: IfNotPresent
imagePullSecrets:
  - name: kordex-registry
EOF
  if [[ "$component" == operator ]]; then
    cat >> "$OUT/helm-values/kordex-${component}.yaml" <<'EOF'
upgrade:
  enabled: false
  # Passed to Ansible Jobs separately from the operator pod.
  imagePullSecrets:
    - kordex-registry
  # Populate only with reviewed, digest-pinned EE references after mirroring.
  executionEnvironmentAllowlist: []
EOF
  fi
done
"$ROOT/scripts/stage-offline-assets.sh" "$ROOT" "$OUT" "$VERSION"
mkdir -p "$OUT/scripts"
cp "$ROOT/scripts/build-offline-bundle.sh" "$ROOT/scripts/acquire-offline-tools.sh" \
  "$ROOT/scripts/push-offline-bundle.sh" \
  "$ROOT/scripts/configure-offline-kustomize.sh" \
  "$ROOT/scripts/configure-offline-helm.sh" \
  "$ROOT/scripts/generate-offline-upgrade-policy.py" \
  "$ROOT/scripts/build-offline-package-artifacts.py" \
  "$ROOT/scripts/install-offline-package-artifacts.py" \
  "$ROOT/scripts/test_offline_package_artifacts.py" \
  "$ROOT/scripts/verify-image-lock.sh" \
  "$ROOT/scripts/test-push-offline-bundle.sh" \
  "$ROOT/scripts/test-build-offline-bundle-platforms.sh" \
  "$ROOT/scripts/test-offline-oci-podman.sh" \
  "$ROOT/scripts/test-configure-offline-kustomize.sh" \
  "$ROOT/scripts/test-configure-offline-helm.sh" \
  "$ROOT/scripts/test-generate-offline-upgrade-policy.sh" \
  "$ROOT/scripts/verify-offline-tools-lock.sh" \
  "$ROOT/scripts/sign-offline-bundle.sh" "$ROOT/scripts/verify-offline-bundle.sh" \
  "$ROOT/scripts/check-offline-manifest.sh" "$OUT/scripts/"
cp -a "$ROOT/docs/air-gapped-deployment.md" "$ROOT/docs/architecture.md" "$ROOT/docs/security.md" \
  "$ROOT/docs/production-upgrade-requirements.md" "$ROOT/docs/kustomize-hub.md" "$OUT/docs/"
cp "$ROOT/tests/integration/self_managed_upgrade_smoke.py" \
  "$ROOT/tests/integration/debian_upgrade_smoke.py" \
  "$ROOT/tests/integration/record_host_upgrade_fault.py" \
  "$ROOT/tests/integration/host_upgrade_failure_matrix.json" \
  "$ROOT/scripts/verify-host-upgrade-qualification.py" "$OUT/qualification/"
cp "$ROOT/README.md" "$OUT/README.md"
cp "$OUT/images.txt" "$OUT/images/images.txt"

: > "$OUT/images/image-metadata.tsv"
while IFS=$'\t' read -r name image; do
  [[ -n "$name" && -n "$image" ]] || continue
  case "$name" in
    postgres) archive="$OUT/images/postgres-17-alpine.oci.tar" ;;
    *) archive="$OUT/images/${name}-${VERSION}.oci.tar" ;;
  esac
  digest="${image_digests[$image]:-}"
  [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "missing OCI index digest for $image" >&2; exit 1; }
  archive_digest="$(sha256sum "$archive" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$image" "$digest" "$archive_digest" "$IMAGE_PLATFORMS" >> "$OUT/images/image-metadata.tsv"
done < "$OUT/images.txt"

(
  cd "$OUT"
  find images bin charts manifests ansible-ee docs helm-values scripts qualification README.md images.txt -type f -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS
)
if [[ -e "$OUT_FINAL" ]]; then
  if [[ -L "$OUT_FINAL" || ! -d "$OUT_FINAL" || -n "$(find "$OUT_FINAL" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "bundle output path changed during build and is no longer empty: $OUT_FINAL" >&2
    exit 1
  fi
  rmdir "$OUT_FINAL"
fi
mv "$BUILD_DIR" "$OUT_FINAL"
BUILD_DIR=""
trap - EXIT
printf 'Built offline bundle at %s\nVerify with: (cd %s && sha256sum -c SHA256SUMS)\n' "$OUT_FINAL" "$OUT_FINAL"
