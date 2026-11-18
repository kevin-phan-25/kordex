#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/store" "$TMP/gnupg"
chmod 0700 "$TMP/gnupg"

cat > "$TMP/bin/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
out=""; url=""
while (($#)); do
  case "$1" in
    --output) shift; out="$1" ;;
    http://*|https://*) url="$1" ;;
  esac
  shift
done
[[ -n "$out" && -n "$url" ]]
mkdir -p "$(dirname "$out")"
case "$url" in
  https://get.helm.sh/helm-*-linux-*.tar.gz)
    arch="${url##*-linux-}"; arch="${arch%.tar.gz}"
    work="$(mktemp -d)"; mkdir -p "$work/linux-$arch"
    printf '#!/bin/sh\necho helm fixture\n' > "$work/linux-$arch/helm"; chmod 0755 "$work/linux-$arch/helm"
    tar -czf "$out" -C "$work" "linux-$arch/helm"
    sha256sum "$out" | awk '{print $1}' > "$KORDEX_FAKE_CURL_STORE/helm-$arch.sha"
    rm -rf "$work"
    ;;
  https://get.helm.sh/*.tar.gz.sha256sum)
    arch="${url%%.tar.gz.sha256sum}"; arch="${arch##*-linux-}"
    digest="$(cat "$KORDEX_FAKE_CURL_STORE/helm-$arch.sha")"
    [[ "${KORDEX_FAKE_BAD_HELM_SHA:-}" != 1 ]] || digest=0000000000000000000000000000000000000000000000000000000000000000
    printf '%s  helm-linux-%s.tar.gz\n' "$digest" "$arch" > "$out"
    ;;
  https://get.helm.sh/*.tar.gz.asc) printf 'fixture signature\n' > "$out" ;;
  https://dl.k8s.io/release/*/bin/linux/*/kubectl)
    arch="${url%/kubectl}"; arch="${arch##*/}"
    printf '#!/bin/sh\necho kubectl %s fixture\n' "$arch" > "$out"; chmod 0755 "$out"
    sha256sum "$out" | awk '{print $1}' > "$KORDEX_FAKE_CURL_STORE/kubectl-$arch.sha"
    ;;
  https://dl.k8s.io/release/*/bin/linux/*/kubectl.sha256)
    arch="${url%/kubectl.sha256}"; arch="${arch##*/}"
    digest="$(cat "$KORDEX_FAKE_CURL_STORE/kubectl-$arch.sha")"
    [[ "${KORDEX_FAKE_BAD_KUBECTL_SHA:-}" != 1 ]] || digest=0000000000000000000000000000000000000000000000000000000000000000
    printf '%s\n' "$digest" > "$out"
    ;;
  https://dl.k8s.io/release/*/bin/linux/*/kubectl.sig) printf 'fixture signature\n' > "$out" ;;
  https://dl.k8s.io/release/*/bin/linux/*/kubectl.cert) printf 'fixture certificate\n' > "$out" ;;
  https://raw.githubusercontent.com/helm/helm/*/LICENSE) printf 'Helm license fixture\n' > "$out" ;;
  https://raw.githubusercontent.com/kubernetes/kubernetes/*/LICENSE) printf 'Kubernetes license fixture\n' > "$out" ;;
  *) echo "unexpected acquisition URL: $url" >&2; exit 1 ;;
esac
EOF_CURL
cat > "$TMP/bin/gpg" <<'EOF_GPG'
#!/usr/bin/env bash
set -euo pipefail
[[ "${KORDEX_FAKE_GPG_FAIL:-}" != 1 ]] || exit 1
fingerprint="${KORDEX_FAKE_GPG_FINGERPRINT:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}"
signing_subkey="${KORDEX_FAKE_GPG_SUBKEY:-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB}"
printf '[GNUPG:] VALIDSIG %s 20261117 0 0 4 0 1 8 00 %s\n' "$signing_subkey" "$fingerprint"
EOF_GPG
cat > "$TMP/bin/cosign" <<'EOF_COSIGN'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == verify-blob && "${KORDEX_FAKE_COSIGN_FAIL:-}" != 1 ]]
[[ "$*" == *'--certificate-identity krel-staging@k8s-releng-prod.iam.gserviceaccount.com'* ]]
[[ "$*" == *'--certificate-oidc-issuer https://accounts.google.com'* ]]
EOF_COSIGN
chmod +x "$TMP/bin/curl" "$TMP/bin/gpg" "$TMP/bin/cosign"
openssl genpkey -algorithm ED25519 -out "$TMP/acquisition-private.pem"
openssl pkey -in "$TMP/acquisition-private.pem" -pubout -out "$TMP/acquisition-public.pem"
printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > "$TMP/helm-signers.txt"

PATH="$TMP/bin:$PATH" GNUPGHOME="$TMP/gnupg" KORDEX_FAKE_CURL_STORE="$TMP/store" \
  KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE="$TMP/helm-signers.txt" \
  KORDEX_TOOLS_LOCK_PRIVATE_KEY="$TMP/acquisition-private.pem" KORDEX_TOOLS_LOCK_PUBLIC_KEY="$TMP/acquisition-public.pem" \
  "$ROOT/scripts/acquire-offline-tools.sh" v3.16.4 1.31.3 "$TMP/acquired"
[[ "$(wc -l < "$TMP/acquired/offline-tools.tsv")" -eq 4 ]]
for row in $'helm\tv3.16.4\tlinux-amd64' $'helm\tv3.16.4\tlinux-arm64' $'kubectl\tv1.31.3\tlinux-amd64' $'kubectl\tv1.31.3\tlinux-arm64'; do
  grep -Fq "$row" "$TMP/acquired/offline-tools.tsv"
done
"$ROOT/scripts/verify-offline-tools-lock.sh" "$TMP/acquired/offline-tools.tsv" \
  "$TMP/acquired/offline-tools.tsv.sig" "$TMP/acquisition-public.pem" "$TMP/helm-signers.txt" >/dev/null

if PATH="$TMP/bin:$PATH" GNUPGHOME="$TMP/gnupg" KORDEX_FAKE_CURL_STORE="$TMP/store" KORDEX_FAKE_GPG_FAIL=1 \
  KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE="$TMP/helm-signers.txt" KORDEX_TOOLS_LOCK_PRIVATE_KEY="$TMP/acquisition-private.pem" \
  KORDEX_TOOLS_LOCK_PUBLIC_KEY="$TMP/acquisition-public.pem" \
  "$ROOT/scripts/acquire-offline-tools.sh" v3.16.4 1.31.3 "$TMP/rejected-gpg" >/dev/null 2>&1; then
  echo 'unverified Helm artifact was accepted' >&2; exit 1
fi
[[ ! -e "$TMP/rejected-gpg" ]]
if PATH="$TMP/bin:$PATH" GNUPGHOME="$TMP/gnupg" KORDEX_FAKE_CURL_STORE="$TMP/store" \
  KORDEX_FAKE_GPG_FINGERPRINT=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
  KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE="$TMP/helm-signers.txt" KORDEX_TOOLS_LOCK_PRIVATE_KEY="$TMP/acquisition-private.pem" \
  KORDEX_TOOLS_LOCK_PUBLIC_KEY="$TMP/acquisition-public.pem" \
  "$ROOT/scripts/acquire-offline-tools.sh" v3.16.4 1.31.3 "$TMP/rejected-unapproved-key" >/dev/null 2>&1; then
  echo 'Helm signature from an unapproved key was accepted' >&2; exit 1
fi
[[ ! -e "$TMP/rejected-unapproved-key" ]]
if PATH="$TMP/bin:$PATH" GNUPGHOME="$TMP/gnupg" KORDEX_FAKE_CURL_STORE="$TMP/store" KORDEX_FAKE_BAD_HELM_SHA=1 \
  KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE="$TMP/helm-signers.txt" KORDEX_TOOLS_LOCK_PRIVATE_KEY="$TMP/acquisition-private.pem" \
  KORDEX_TOOLS_LOCK_PUBLIC_KEY="$TMP/acquisition-public.pem" \
  "$ROOT/scripts/acquire-offline-tools.sh" v3.16.4 1.31.3 "$TMP/rejected-helm-checksum" >/dev/null 2>&1; then
  echo 'Helm artifact with a mismatched upstream checksum was accepted' >&2; exit 1
fi
[[ ! -e "$TMP/rejected-helm-checksum" ]]
if PATH="$TMP/bin:$PATH" GNUPGHOME="$TMP/gnupg" KORDEX_FAKE_CURL_STORE="$TMP/store" KORDEX_FAKE_COSIGN_FAIL=1 \
  KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE="$TMP/helm-signers.txt" KORDEX_TOOLS_LOCK_PRIVATE_KEY="$TMP/acquisition-private.pem" \
  KORDEX_TOOLS_LOCK_PUBLIC_KEY="$TMP/acquisition-public.pem" \
  "$ROOT/scripts/acquire-offline-tools.sh" v3.16.4 1.31.3 "$TMP/rejected-cosign" >/dev/null 2>&1; then
  echo 'unverified kubectl artifact was accepted' >&2; exit 1
fi
[[ ! -e "$TMP/rejected-cosign" ]]
if PATH="$TMP/bin:$PATH" GNUPGHOME="$TMP/gnupg" KORDEX_FAKE_CURL_STORE="$TMP/store" KORDEX_FAKE_BAD_KUBECTL_SHA=1 \
  KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE="$TMP/helm-signers.txt" KORDEX_TOOLS_LOCK_PRIVATE_KEY="$TMP/acquisition-private.pem" \
  KORDEX_TOOLS_LOCK_PUBLIC_KEY="$TMP/acquisition-public.pem" \
  "$ROOT/scripts/acquire-offline-tools.sh" v3.16.4 1.31.3 "$TMP/rejected-kubectl-checksum" >/dev/null 2>&1; then
  echo 'kubectl artifact with a mismatched upstream checksum was accepted' >&2; exit 1
fi
[[ ! -e "$TMP/rejected-kubectl-checksum" ]]
if find "$TMP" -maxdepth 1 -name '.rejected-*.acquire.*' -print -quit | grep -q .; then
  echo 'failed acquisition left a partial temporary tree' >&2; exit 1
fi
echo 'Offline tool acquisition verification tests passed.'
