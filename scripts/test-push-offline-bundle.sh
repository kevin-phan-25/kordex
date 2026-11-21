#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BUNDLE="$TMP/bundle"
mkdir -p "$TMP/bin" "$BUNDLE/scripts" "$BUNDLE/images"
printf 'linux/amd64,linux/arm64\n' > "$BUNDLE/images/platforms.txt"
openssl genpkey -algorithm ED25519 -out "$TMP/release-private.pem"
openssl pkey -in "$TMP/release-private.pem" -pubout -out "$TMP/release-public.pem"
cat > "$TMP/trusted-verifier.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -d "$1" && -r "$2" ]]
EOF
chmod +x "$TMP/trusted-verifier.sh"
export KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh"
cp "$ROOT/scripts/push-offline-bundle.sh" "$BUNDLE/scripts/"
cat > "$BUNDLE/scripts/verify-offline-bundle.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
chmod +x "$BUNDLE/scripts/verify-offline-bundle.sh"
cat > "$BUNDLE/images.txt" <<'EOF'
control-plane	localhost/kordex/control-plane:0.8.0
agent	localhost/kordex/agent:0.8.0
operator	localhost/kordex/operator:0.8.0
dashboard	localhost/kordex/dashboard:0.8.0
ansible-ee	localhost/kordex/ansible-ee:0.8.0
postgres	localhost/kordex/postgres:17-alpine
EOF
touch "$BUNDLE/images/control-plane-0.8.0.oci.tar" "$BUNDLE/images/agent-0.8.0.oci.tar" \
  "$BUNDLE/images/operator-0.8.0.oci.tar" "$BUNDLE/images/dashboard-0.8.0.oci.tar" \
  "$BUNDLE/images/ansible-ee-0.8.0.oci.tar" "$BUNDLE/images/postgres-17-alpine.oci.tar"
cat > "$TMP/bin/podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  manifest)
    printf '%s\n' "$*" >> "${FAKE_PODMAN_LOG:-/dev/null}"
    case "$2" in
      create) [[ "$3" == --all && "$5" == oci-archive:* ]] || exit 10 ;;
      push)
        [[ "$3" == --all && "$4" == --digestfile && "$6" == --tls-verify=true && "$8" == docker://* ]] || exit 10
        if [[ "${FAIL_PUSH:-}" == 1 ]]; then exit 11; fi
        case "$8" in
          */agent:*) digest_number=1 ;;
          */operator:*) digest_number=2 ;;
          */control-plane:*) digest_number=3 ;;
          */dashboard:*) digest_number=4 ;;
          */ansible-ee:*) digest_number=5 ;;
          */postgres:*) digest_number=6 ;;
          *) exit 13 ;;
        esac
        printf 'sha256:%064d\n' "$digest_number" > "$5"
        ;;
      rm) ;;
      *) exit 12 ;;
    esac
    ;;
  *) exit 12 ;;
esac
EOF
chmod +x "$TMP/bin/podman"
LOCK="$TMP/image-digests.tsv"
printf 'previous-complete-lock\n' > "$LOCK"
openssl pkeyutl -sign -rawin -inkey "$TMP/release-private.pem" -in "$LOCK" -out "$LOCK.sig"
cp "$BUNDLE/images.txt" "$TMP/complete-images.txt"
for invalid_registry in 'https://registry.example/platform' 'registry..example/platform' 'registry.example:65536/platform' 'registry.example/platform;bad'; do
  if PATH="$TMP/bin:$PATH" KORDEX_RELEASE_PUBLIC_KEY=/dev/null KORDEX_RELEASE_PRIVATE_KEY="$TMP/release-private.pem" KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh" \
    KORDEX_IMAGE_LOCK_FILE="$LOCK" FAKE_PODMAN_LOG="$TMP/podman.log" \
    "$ROOT/scripts/push-offline-bundle.sh" "$BUNDLE" "$invalid_registry" >/dev/null 2>&1; then
    echo "expected invalid registry reference to be rejected: $invalid_registry" >&2
    exit 1
  fi
done
[[ "$(cat "$LOCK")" == previous-complete-lock ]]
[[ ! -f "$TMP/podman.log" ]]

if PATH="$TMP/bin:$PATH" KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  KORDEX_RELEASE_PRIVATE_KEY="$TMP/release-private.pem" \
  KORDEX_TRUSTED_BUNDLE_VERIFIER="$BUNDLE/scripts/verify-offline-bundle.sh" \
  KORDEX_IMAGE_LOCK_FILE="$LOCK" FAKE_PODMAN_LOG="$TMP/podman.log" \
  "$ROOT/scripts/push-offline-bundle.sh" "$BUNDLE" registry.example/platform >/dev/null 2>&1; then
  echo 'mirror helper accepted a verifier from inside the bundle' >&2
  exit 1
fi
[[ ! -f "$TMP/podman.log" ]]

if PATH="$TMP/bin:$PATH" KORDEX_REGISTRY_TLS_VERIFY=maybe KORDEX_RELEASE_PUBLIC_KEY=/dev/null KORDEX_RELEASE_PRIVATE_KEY="$TMP/release-private.pem" KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh" \
  KORDEX_IMAGE_LOCK_FILE="$LOCK" FAKE_PODMAN_LOG="$TMP/podman.log" \
  "$ROOT/scripts/push-offline-bundle.sh" "$BUNDLE" registry.example/platform >/dev/null 2>&1; then
  echo 'invalid registry TLS setting was accepted' >&2
  exit 1
fi
[[ ! -f "$TMP/podman.log" ]]

printf 'agent\tlocalhost/kordex/agent:0.8.0\n' > "$BUNDLE/images.txt"
if PATH="$TMP/bin:$PATH" KORDEX_RELEASE_PUBLIC_KEY=/dev/null KORDEX_RELEASE_PRIVATE_KEY="$TMP/release-private.pem" KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh" \
  KORDEX_IMAGE_LOCK_FILE="$LOCK" FAKE_PODMAN_LOG="$TMP/podman.log" \
  "$ROOT/scripts/push-offline-bundle.sh" "$BUNDLE" registry.example/platform >/dev/null 2>&1; then
  echo "expected incomplete bundle image inventory to be rejected" >&2
  exit 1
fi
[[ "$(cat "$LOCK")" == previous-complete-lock ]]
[[ ! -f "$TMP/podman.log" ]]
cp "$TMP/complete-images.txt" "$BUNDLE/images.txt"

if PATH="$TMP/bin:$PATH" FAIL_PUSH=1 KORDEX_RELEASE_PUBLIC_KEY=/dev/null KORDEX_RELEASE_PRIVATE_KEY="$TMP/release-private.pem" KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh" \
  KORDEX_IMAGE_LOCK_FILE="$LOCK" FAKE_PODMAN_LOG="$TMP/podman.log" "$ROOT/scripts/push-offline-bundle.sh" \
  "$BUNDLE" registry.example/platform >/dev/null 2>&1; then
  echo "expected injected registry push failure" >&2
  exit 1
fi
[[ "$(cat "$LOCK")" == previous-complete-lock ]]
openssl pkeyutl -verify -pubin -inkey "$TMP/release-public.pem" -rawin -in "$LOCK" -sigfile "$LOCK.sig" >/dev/null
if compgen -G "$LOCK.tmp.*" >/dev/null; then
  echo "partial image lock temporary file was not cleaned up" >&2
  exit 1
fi

PATH="$TMP/bin:$PATH" KORDEX_RELEASE_PUBLIC_KEY=/dev/null KORDEX_RELEASE_PRIVATE_KEY="$TMP/release-private.pem" KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh" \
  KORDEX_IMAGE_LOCK_FILE="$LOCK" FAKE_PODMAN_LOG="$TMP/podman.log" "$ROOT/scripts/push-offline-bundle.sh" \
  "$BUNDLE" registry.example:5443/platform >/dev/null
[[ "$(wc -l < "$LOCK")" -eq 6 ]]
grep -Fq 'manifest create --all ' "$TMP/podman.log"
grep -Fq 'manifest push --all --digestfile ' "$TMP/podman.log"
for image in agent operator control-plane dashboard ansible-ee postgres; do
  case "$image" in
    agent) digest_number=1 ;;
    operator) digest_number=2 ;;
    control-plane) digest_number=3 ;;
    dashboard) digest_number=4 ;;
    ansible-ee) digest_number=5 ;;
    postgres) digest_number=6 ;;
  esac
  expected_lock_row="$(printf '%s\t%s@sha256:%s' "$image" "registry.example:5443/platform/kordex/$image" "$(printf '%064d' "$digest_number")")"
  grep -Fxq "$expected_lock_row" "$LOCK"
done
openssl pkeyutl -verify -pubin -inkey "$TMP/release-public.pem" -rawin -in "$LOCK" -sigfile "$LOCK.sig" >/dev/null

# Exercise the actual handoff from the digest emitted by the mirror push into
# both installation paths. The same per-image registry digest must survive
# unchanged into Kustomize image refs, Helm values, and the EE allowlist.
mkdir -p "$BUNDLE/manifests" "$BUNDLE/charts"
cp -a "$ROOT/deployments/kustomize" "$BUNDLE/manifests/"
printf '{"keys":[]}\n' > "$TMP/keys.json"
for chart in agent operator control-plane dashboard; do
  : > "$BUNDLE/charts/kordex-$chart-0.8.0.tgz"
done
KUSTOMIZE_OUT="$TMP/configured-kustomize"
HELM_OUT="$TMP/configured-helm"
KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-kustomize.sh" \
  "$BUNDLE" "$LOCK" 733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$TMP/keys.json" "$KUSTOMIZE_OUT" >/dev/null
KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-helm.sh" \
  "$BUNDLE" "$LOCK" "$HELM_OUT" >/dev/null
for image in agent operator; do
  case "$image" in agent) digest_number=1 ;; operator) digest_number=2 ;; esac
  digest="sha256:$(printf '%064d' "$digest_number")"
  grep -Fq "newName: registry.example:5443/platform/kordex/$image" \
    "$KUSTOMIZE_OUT/overlays/self-managed/kustomization.yaml"
  grep -Fq "digest: $digest" "$KUSTOMIZE_OUT/overlays/self-managed/kustomization.yaml"
  grep -Fq "repository: registry.example:5443/platform/kordex/$image" "$HELM_OUT/kordex-$image-images.yaml"
  grep -Fq "digest: $digest" "$HELM_OUT/kordex-$image-images.yaml"
done
for image in control-plane dashboard; do
  case "$image" in control-plane) digest_number=3 ;; dashboard) digest_number=4 ;; esac
  digest="sha256:$(printf '%064d' "$digest_number")"
  grep -Fq "repository: registry.example:5443/platform/kordex/$image" "$HELM_OUT/kordex-$image-images.yaml"
  grep -Fq "digest: $digest" "$HELM_OUT/kordex-$image-images.yaml"
done
grep -Fq 'registry.example:5443/platform/kordex/ansible-ee@sha256:'"$(printf '%064d' 5)" \
  "$KUSTOMIZE_OUT/overlays/self-managed/operator-settings.patch.yaml"
grep -Fq 'registry.example:5443/platform/kordex/ansible-ee@sha256:'"$(printf '%064d' 5)" \
  "$HELM_OUT/kordex-operator-images.yaml"
cp "$LOCK" "$TMP/tampered-lock.tsv"
printf 'tampered\n' >> "$TMP/tampered-lock.tsv"
if "$ROOT/scripts/verify-image-lock.sh" "$TMP/tampered-lock.tsv" "$LOCK.sig" "$TMP/release-public.pem" >/dev/null 2>&1; then
  echo 'tampered mirror image lock was accepted' >&2
  exit 1
fi
echo "offline image mirror lock tests passed"
