#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/podman" <<'EOF_PODMAN'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$KORDEX_PODMAN_LOG"
case "$1 $2" in
  "manifest push")
    digest_file=""
    destination=""
    while (($#)); do
      if [[ "$1" == --digestfile ]]; then shift; digest_file="$1"; fi
      destination="$1"
      shift
    done
    [[ -n "$digest_file" && "$destination" == oci-archive:* ]]
    printf 'sha256:%064d\n' 1 > "$digest_file"
    printf 'fake OCI archive for builder contract\n' > "${destination#oci-archive:}"
    ;;
  build*)
    [[ "${FAIL_PODMAN_BUILD:-}" != 1 ]] || exit 42
    ;;
  manifest*)
    ;;
  *) echo "unexpected fake podman invocation: $*" >&2; exit 1 ;;
esac
EOF_PODMAN
cat > "$TMP/bin/go" <<'EOF_GO'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == build ]]
while (($#)); do
  if [[ "$1" == -o ]]; then shift; mkdir -p "$(dirname "$1")"; printf 'fake executable\n' > "$1"; chmod +x "$1"; exit 0; fi
  shift
done
echo 'fake Go build did not receive an output path' >&2
exit 1
EOF_GO
cat > "$TMP/bin/helm" <<'EOF_HELM'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == package ]]
chart="$(basename "$2")"
while (($#)); do
  if [[ "$1" == --destination ]]; then shift; printf 'fake chart\n' > "$1/$chart-0.8.0.tgz"; exit 0; fi
  shift
done
exit 1
EOF_HELM
chmod +x "$TMP/bin/podman" "$TMP/bin/go" "$TMP/bin/helm"
mkdir -p "$TMP/offline-tools/linux-amd64" "$TMP/offline-tools/linux-arm64" "$TMP/offline-tools/LICENSES"
for arch in amd64 arm64; do
  for tool in helm kubectl; do
    python3 - "$TMP/offline-tools/linux-$arch/$tool" "$arch" <<'PY'
import pathlib
import struct
import sys

path, arch = sys.argv[1:]
header = bytearray(64)
header[:7] = b"\x7fELF\x02\x01\x01"
struct.pack_into("<HHI", header, 16, 2, {"amd64": 62, "arm64": 183}[arch], 1)
struct.pack_into("<H", header, 52, 64)
pathlib.Path(path).write_bytes(header)
PY
    chmod 0755 "$TMP/offline-tools/linux-$arch/$tool"
  done
done
printf 'Helm license fixture\n' > "$TMP/offline-tools/LICENSES/helm.txt"
printf 'Kubernetes license fixture\n' > "$TMP/offline-tools/LICENSES/kubernetes.txt"
openssl genpkey -algorithm ED25519 -out "$TMP/tools-private.pem"
openssl pkey -in "$TMP/tools-private.pem" -pubout -out "$TMP/tools-public.pem"
printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > "$TMP/approved-helm-signers.txt"
: > "$TMP/offline-tools.tsv"
for arch in linux-amd64 linux-arm64; do
  for tool in helm kubectl; do
    digest="$(sha256sum "$TMP/offline-tools/$arch/$tool" | awk '{print $1}')"
    if [[ "$tool" == helm ]]; then
      printf '%s\t%s\t%s\t%s\t%s\thttps://get.helm.sh/helm-v1.0.0-%s.tar.gz\topenpgp\t%s\n' "$tool" v1.0.0 "$arch" "$digest" "$digest" "$arch" 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >> "$TMP/offline-tools.tsv"
    else
      tool_arch="${arch#linux-}"
      printf '%s\t%s\t%s\t%s\t%s\thttps://dl.k8s.io/release/v1.0.0/bin/linux/%s/kubectl\tcosign-keyless\t%s\n' "$tool" v1.0.0 "$arch" "$digest" "$digest" "$tool_arch" 'krel-staging@k8s-releng-prod.iam.gserviceaccount.com|https://accounts.google.com' >> "$TMP/offline-tools.tsv"
    fi
  done
done
openssl pkeyutl -sign -rawin -inkey "$TMP/tools-private.pem" -in "$TMP/offline-tools.tsv" -out "$TMP/offline-tools.tsv.sig"
base='registry.example/base@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export KORDEX_OFFLINE_TOOLS_DIR="$TMP/offline-tools" KORDEX_OFFLINE_TOOLS_LOCK="$TMP/offline-tools.tsv" \
  KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE="$TMP/offline-tools.tsv.sig" KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY="$TMP/tools-public.pem" \
  KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE="$TMP/approved-helm-signers.txt" \
  KORDEX_HELM_BIN="$TMP/bin/helm"
PATH="$TMP/bin:$PATH" KORDEX_PODMAN_LOG="$TMP/podman.log" \
  KORDEX_ANSIBLE_EE_BASE="$base" KORDEX_GO_BUILDER_BASE="$base" \
  KORDEX_RUNTIME_BASE="$base" KORDEX_NODE_BASE="$base" \
  KORDEX_NODE_RUNTIME_BASE="$base" KORDEX_POSTGRES_BASE="$base" \
  "$ROOT/scripts/build-offline-bundle.sh" 0.8.0 "$TMP/bundle" >/dev/null

grep -Fq 'build --file ' "$TMP/podman.log"
[[ "$(grep -Fc -- '--platform linux/amd64,linux/arm64' "$TMP/podman.log")" -eq 6 ]]
[[ "$(grep -Fc -- '--manifest localhost/kordex/' "$TMP/podman.log")" -eq 6 ]]
grep -Fq 'build --platform linux/amd64,linux/arm64 --manifest localhost/kordex/postgres:17-alpine' "$TMP/podman.log"
grep -Fq -- '--build-arg KORDEX_POSTGRES_BASE=registry.example/base@sha256:' "$TMP/podman.log"
grep -Fq 'manifest push --all --format oci --digestfile ' "$TMP/podman.log"
grep -Fxq 'linux/amd64,linux/arm64' "$TMP/bundle/images/platforms.txt"
[[ "$(wc -l < "$TMP/bundle/images/image-metadata.tsv")" -eq 6 ]]
[[ "$(awk -F '\t' '$5 != "linux/amd64,linux/arm64" { bad=1 } END { print bad+0 }' "$TMP/bundle/images/image-metadata.tsv")" -eq 0 ]]
[[ "$(wc -l < "$TMP/bundle/bin/tools/offline-tools.tsv")" -eq 4 ]]
cmp -s "$TMP/offline-tools.tsv" "$TMP/bundle/bin/tools/offline-tools.tsv"
cmp -s "$TMP/offline-tools.tsv.sig" "$TMP/bundle/bin/tools/offline-tools.tsv.sig"
cmp -s "$TMP/tools-public.pem" "$TMP/bundle/bin/tools/offline-tools.signer.pub"
cmp -s "$TMP/approved-helm-signers.txt" "$TMP/bundle/bin/tools/offline-tools.helm-signers.txt"
for arch in linux-amd64 linux-arm64; do
  for tool in helm kubectl; do
    grep -Fq "$tool"$'\t'"v1.0.0"$'\t'"$arch" "$TMP/bundle/bin/tools/offline-tools.tsv"
    [[ -x "$TMP/bundle/bin/tools/$arch/$tool" ]]
  done
done
for file in self_managed_upgrade_smoke.py record_host_upgrade_fault.py \
  host_upgrade_failure_matrix.json verify-host-upgrade-qualification.py; do
  [[ -f "$TMP/bundle/qualification/$file" ]]
done
[[ -x "$TMP/bundle/scripts/generate-offline-upgrade-policy.py" ]]
[[ -x "$TMP/bundle/scripts/test-generate-offline-upgrade-policy.sh" ]]
[[ -s "$TMP/bundle/docs/kustomize-hub.md" ]]
grep -Fq 'job/kordex-migrate' "$TMP/bundle/docs/kustomize-hub.md"
grep -Fq 'kustomize-hub.md' "$TMP/bundle/docs/air-gapped-deployment.md"
[[ -s "$TMP/bundle/manifests/kustomize/hub/README.md" ]]
[[ -s "$TMP/bundle/manifests/kustomize/hub/components/private-ca/kustomization.yaml" ]]
[[ -s "$TMP/bundle/manifests/kustomize/hub/overlays/self-hosted-private-ca/kustomization.yaml" ]]
[[ -s "$TMP/bundle/manifests/kustomize/hub/overlays/self-hosted-migration-private-ca/kustomization.yaml" ]]
python3 "$TMP/bundle/scripts/generate-offline-upgrade-policy.py" --help >/dev/null
python3 "$TMP/bundle/qualification/record_host_upgrade_fault.py" --help >/dev/null
python3 "$TMP/bundle/qualification/verify-host-upgrade-qualification.py" --help >/dev/null

if PATH="$TMP/bin:$PATH" KORDEX_PODMAN_LOG="$TMP/invalid-platform.log" \
  KORDEX_IMAGE_PLATFORMS='linux/amd64,linux/amd64' \
  KORDEX_ANSIBLE_EE_BASE="$base" KORDEX_GO_BUILDER_BASE="$base" \
  KORDEX_RUNTIME_BASE="$base" KORDEX_NODE_BASE="$base" \
  KORDEX_NODE_RUNTIME_BASE="$base" KORDEX_POSTGRES_BASE="$base" \
  "$ROOT/scripts/build-offline-bundle.sh" 0.8.0 "$TMP/invalid" >/dev/null 2>&1; then
  echo 'duplicate build platform was accepted' >&2
  exit 1
fi
[[ ! -s "$TMP/invalid-platform.log" ]]

bad_lock="$TMP/offline-tools-bad.tsv"
awk -F '\t' 'BEGIN { OFS="\t" } NR == 1 { $4="0000000000000000000000000000000000000000000000000000000000000000" } { print }' \
  "$TMP/offline-tools.tsv" > "$bad_lock"
if PATH="$TMP/bin:$PATH" KORDEX_OFFLINE_TOOLS_LOCK="$bad_lock" KORDEX_PODMAN_LOG="$TMP/bad-tools.log" \
  KORDEX_ANSIBLE_EE_BASE="$base" KORDEX_GO_BUILDER_BASE="$base" \
  KORDEX_RUNTIME_BASE="$base" KORDEX_NODE_BASE="$base" \
  KORDEX_NODE_RUNTIME_BASE="$base" KORDEX_POSTGRES_BASE="$base" \
  "$ROOT/scripts/build-offline-bundle.sh" 0.8.0 "$TMP/bad-tools" >/dev/null 2>&1; then
  echo 'offline tool checksum mismatch was accepted' >&2
  exit 1
fi
[[ ! -e "$TMP/bad-tools" ]]
[[ ! -s "$TMP/bad-tools.log" ]]

bad_signer_lock="$TMP/offline-tools-bad-signer.tsv"
awk -F '\t' 'BEGIN { OFS="\t" } $1 == "helm" { $8="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" } { print }' \
  "$TMP/offline-tools.tsv" > "$bad_signer_lock"
bad_signer_signature="$TMP/offline-tools-bad-signer.tsv.sig"
openssl pkeyutl -sign -rawin -inkey "$TMP/tools-private.pem" -in "$bad_signer_lock" -out "$bad_signer_signature"
if PATH="$TMP/bin:$PATH" KORDEX_OFFLINE_TOOLS_LOCK="$bad_signer_lock" \
  KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE="$bad_signer_signature" \
  KORDEX_PODMAN_LOG="$TMP/bad-signer.log" \
  KORDEX_ANSIBLE_EE_BASE="$base" KORDEX_GO_BUILDER_BASE="$base" \
  KORDEX_RUNTIME_BASE="$base" KORDEX_NODE_BASE="$base" \
  KORDEX_NODE_RUNTIME_BASE="$base" KORDEX_POSTGRES_BASE="$base" \
  "$ROOT/scripts/build-offline-bundle.sh" 0.8.0 "$TMP/bad-signer" >/dev/null 2>&1; then
  echo 'signed provenance from an unapproved Helm key was accepted' >&2
  exit 1
fi
[[ ! -e "$TMP/bad-signer" ]]
[[ ! -s "$TMP/bad-signer.log" ]]

if PATH="$TMP/bin:$PATH" FAIL_PODMAN_BUILD=1 KORDEX_PODMAN_LOG="$TMP/failing-build.log" \
  KORDEX_ANSIBLE_EE_BASE="$base" KORDEX_GO_BUILDER_BASE="$base" \
  KORDEX_RUNTIME_BASE="$base" KORDEX_NODE_BASE="$base" \
  KORDEX_NODE_RUNTIME_BASE="$base" KORDEX_POSTGRES_BASE="$base" \
  "$ROOT/scripts/build-offline-bundle.sh" 0.8.0 "$TMP/failing" >/dev/null 2>&1; then
  echo 'injected image build failure unexpectedly succeeded' >&2
  exit 1
fi
[[ ! -e "$TMP/failing" ]]
if find "$TMP" -maxdepth 1 -name '.failing.build.*' -print -quit | grep -q .; then
  echo 'failed build left a temporary partial bundle' >&2
  exit 1
fi
echo 'Offline multi-platform image builder tests passed.'
