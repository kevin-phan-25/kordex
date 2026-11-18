#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 HELM_VERSION KUBECTL_VERSION OUTPUT_DIRECTORY" >&2
  echo "Requires trusted Helm keys in GNUPGHOME, KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE, KORDEX_TOOLS_LOCK_PRIVATE_KEY, and KORDEX_TOOLS_LOCK_PUBLIC_KEY." >&2
}
if [[ $# -ne 3 ]]; then usage; exit 2; fi
HELM_VERSION="$1"
KUBECTL_VERSION="$2"
OUTPUT="$3"
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"

for version in "$HELM_VERSION" "$KUBECTL_VERSION"; do
  [[ "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo "invalid pinned client version: $version" >&2; exit 2; }
done
HELM_VERSION="${HELM_VERSION#v}"
[[ "$KUBECTL_VERSION" == v* ]] || KUBECTL_VERSION="v$KUBECTL_VERSION"
: "${GNUPGHOME:?GNUPGHOME must point at a keyring populated from trusted Helm maintainer keys}"
: "${KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE:?set independently reviewed Helm maintainer fingerprints}"
: "${KORDEX_TOOLS_LOCK_PRIVATE_KEY:?set protected Ed25519 tool-lock signing key}"
: "${KORDEX_TOOLS_LOCK_PUBLIC_KEY:?set independently provisioned Ed25519 tool-lock public key}"
[[ -d "$GNUPGHOME" && ! -L "$GNUPGHOME" ]] || { echo "GNUPGHOME must be a regular directory" >&2; exit 2; }
[[ -f "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" && ! -L "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" ]] || { echo "Helm signer allowlist must be a regular file" >&2; exit 2; }
[[ -f "$KORDEX_TOOLS_LOCK_PRIVATE_KEY" && ! -L "$KORDEX_TOOLS_LOCK_PRIVATE_KEY" ]] || { echo "tool-lock private key must be a regular file" >&2; exit 2; }
[[ -f "$KORDEX_TOOLS_LOCK_PUBLIC_KEY" && ! -L "$KORDEX_TOOLS_LOCK_PUBLIC_KEY" ]] || { echo "tool-lock public key must be a regular file" >&2; exit 2; }
for tool in curl gpg cosign sha256sum openssl awk find install tail python3; do
  command -v "$tool" >/dev/null || { echo "$tool is required for upstream artifact verification" >&2; exit 2; }
done
"$ROOT/scripts/verify-offline-tools-lock.sh" --check-helm-signers "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE"

private_fingerprint="$(openssl pkey -in "$KORDEX_TOOLS_LOCK_PRIVATE_KEY" -pubout -outform DER | sha256sum | awk '{print $1}')"
public_fingerprint="$(openssl pkey -pubin -in "$KORDEX_TOOLS_LOCK_PUBLIC_KEY" -outform DER | sha256sum | awk '{print $1}')"
[[ "$private_fingerprint" == "$public_fingerprint" ]] || { echo "tool-lock public/private keys do not match" >&2; exit 2; }

if [[ -L "$OUTPUT" ]]; then echo "output directory cannot be a symlink" >&2; exit 2; fi
out_parent_raw="$(dirname -- "$OUTPUT")"
mkdir -p -- "$out_parent_raw"
out_parent="$(cd "$out_parent_raw" && pwd)"
out_name="$(basename -- "$OUTPUT")"
[[ "$out_name" != . && "$out_name" != .. && "$out_name" != / ]] || { echo "invalid output directory" >&2; exit 2; }
out_final="$out_parent/$out_name"
if [[ -e "$out_final" && ( ! -d "$out_final" || -n "$(find "$out_final" -mindepth 1 -maxdepth 1 -print -quit)" ) ]]; then
  echo "output directory must not exist or must be empty: $out_final" >&2
  exit 2
fi
tmp="$(mktemp -d "$out_parent/.${out_name}.acquire.XXXXXX")"
cleanup() { [[ -z "${tmp:-}" || ! -d "$tmp" ]] || rm -rf -- "$tmp"; }
trap cleanup EXIT
stage="$tmp/tools"
mkdir -p "$stage/linux-amd64" "$stage/linux-arm64" "$stage/LICENSES"
: > "$tmp/offline-tools.tsv"

download() {
  curl -fsSL --retry 3 --retry-delay 2 --output "$2" "$1"
}
is_approved_helm_fingerprint() {
  local candidate="${1^^}" line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//[[:space:]]/}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "${line^^}" == "$candidate" ]] && return 0
  done < "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE"
  return 1
}

for arch in amd64 arm64; do
  architecture="linux-$arch"
  helm_archive="helm-v${HELM_VERSION}-${architecture}.tar.gz"
  helm_url="https://get.helm.sh/$helm_archive"
  helm_work="$tmp/helm-$arch"
  mkdir -p "$helm_work"
  download "$helm_url" "$helm_work/$helm_archive"
  download "$helm_url.sha256sum" "$helm_work/$helm_archive.sha256sum"
  download "$helm_url.asc" "$helm_work/$helm_archive.asc"
  helm_expected="$(awk 'NR==1 {print $1}' "$helm_work/$helm_archive.sha256sum")"
  helm_actual="$(sha256sum "$helm_work/$helm_archive" | awk '{print $1}')"
  [[ "$helm_expected" =~ ^[a-fA-F0-9]{64}$ && "${helm_expected,,}" == "$helm_actual" ]] || { echo "Helm upstream archive checksum mismatch: $helm_archive" >&2; exit 1; }
  gpg_status="$tmp/helm-$arch.gpg-status"
  if ! gpg --batch --status-fd 1 --verify "$helm_work/$helm_archive.asc" "$helm_work/$helm_archive" >"$gpg_status" 2>"$tmp/helm-$arch.gpg-error"; then
    cat "$tmp/helm-$arch.gpg-error" >&2
    echo "Helm archive signature verification failed: $helm_archive" >&2
    exit 1
  fi
  helm_signer="$(awk '$2 == "VALIDSIG" { candidate=$NF; if (candidate !~ /^[A-Fa-f0-9]+$/ || length(candidate) < 40 || length(candidate) > 64) candidate=$3; print candidate }' "$gpg_status" | tail -n 1)"
  [[ "$helm_signer" =~ ^[A-Fa-f0-9]{40,64}$ ]] || { echo "GPG did not report a valid Helm signing fingerprint" >&2; exit 1; }
  is_approved_helm_fingerprint "$helm_signer" || { echo "Helm archive signer is not in the independently trusted allowlist: $helm_signer" >&2; exit 1; }
  python3 - "$helm_work/$helm_archive" "$architecture/helm" "$helm_work/helm" <<'PY'
import pathlib
import sys
import tarfile

archive, expected, destination = sys.argv[1:]
seen = set()
target = None
try:
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
                raise ValueError("archive contains an unsafe path")
            if member.name in seen:
                raise ValueError("archive contains a duplicate path")
            seen.add(member.name)
            if not (member.isdir() or member.isfile()):
                raise ValueError("archive contains a link or special file")
            if member.name == expected:
                if not member.isfile() or member.size <= 0 or member.size > 200 * 1024 * 1024:
                    raise ValueError("expected Helm binary is not a bounded regular file")
                target = member
        if target is None:
            raise ValueError("expected architecture-specific Helm binary is missing")
        stream = source.extractfile(target)
        if stream is None:
            raise ValueError("Helm binary could not be read from archive")
        output = pathlib.Path(destination)
        with output.open("xb") as dest:
            total = 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 200 * 1024 * 1024:
                    raise ValueError("Helm binary exceeds size limit")
                dest.write(chunk)
        if total != target.size:
            raise ValueError("Helm binary size does not match tar metadata")
        output.chmod(0o555)
except (OSError, tarfile.TarError, ValueError) as error:
    print(f"invalid Helm release archive: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
  install -m 0555 "$helm_work/helm" "$stage/$architecture/helm"
  helm_binary_digest="$(sha256sum "$stage/$architecture/helm" | awk '{print $1}')"
  helm_artifact_digest="$helm_actual"
  printf 'helm\tv%s\t%s\t%s\t%s\t%s\topenpgp\t%s\n' \
    "$HELM_VERSION" "$architecture" "$helm_binary_digest" "$helm_artifact_digest" "$helm_url" "$helm_signer" >> "$tmp/offline-tools.tsv"

  kubectl_url="https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl"
  kubectl_work="$tmp/kubectl-$arch"
  mkdir -p "$kubectl_work"
  download "$kubectl_url" "$kubectl_work/kubectl"
  download "$kubectl_url.sha256" "$kubectl_work/kubectl.sha256"
  download "$kubectl_url.sig" "$kubectl_work/kubectl.sig"
  download "$kubectl_url.cert" "$kubectl_work/kubectl.cert"
  kubectl_expected="$(awk 'NR==1 {print $1}' "$kubectl_work/kubectl.sha256")"
  kubectl_actual="$(sha256sum "$kubectl_work/kubectl" | awk '{print $1}')"
  [[ "$kubectl_expected" =~ ^[a-fA-F0-9]{64}$ && "${kubectl_expected,,}" == "$kubectl_actual" ]] || { echo "kubectl upstream checksum mismatch: linux/$arch" >&2; exit 1; }
  cosign verify-blob "$kubectl_work/kubectl" \
    --signature "$kubectl_work/kubectl.sig" \
    --certificate "$kubectl_work/kubectl.cert" \
    --certificate-identity krel-staging@k8s-releng-prod.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com >/dev/null
  install -m 0555 "$kubectl_work/kubectl" "$stage/$architecture/kubectl"
  printf 'kubectl\t%s\t%s\t%s\t%s\t%s\tcosign-keyless\t%s\n' \
    "$KUBECTL_VERSION" "$architecture" "$kubectl_actual" "$kubectl_actual" "$kubectl_url" \
    'krel-staging@k8s-releng-prod.iam.gserviceaccount.com|https://accounts.google.com' >> "$tmp/offline-tools.tsv"
done

download "https://raw.githubusercontent.com/helm/helm/v${HELM_VERSION}/LICENSE" "$stage/LICENSES/helm.txt"
download "https://raw.githubusercontent.com/kubernetes/kubernetes/${KUBECTL_VERSION}/LICENSE" "$stage/LICENSES/kubernetes.txt"
[[ -s "$stage/LICENSES/helm.txt" && -s "$stage/LICENSES/kubernetes.txt" ]] || { echo "upstream license notice is empty" >&2; exit 1; }
openssl pkeyutl -sign -rawin -inkey "$KORDEX_TOOLS_LOCK_PRIVATE_KEY" -in "$tmp/offline-tools.tsv" -out "$tmp/offline-tools.tsv.sig"
"$ROOT/scripts/verify-offline-tools-lock.sh" "$tmp/offline-tools.tsv" "$tmp/offline-tools.tsv.sig" \
  "$KORDEX_TOOLS_LOCK_PUBLIC_KEY" "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" >/dev/null

cp "$tmp/offline-tools.tsv" "$tmp/offline-tools.tsv.sig" "$stage/"
cp "$KORDEX_TOOLS_LOCK_PUBLIC_KEY" "$stage/offline-tools.signer.pub"
cp "$KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE" "$stage/offline-tools.helm-signers.txt"
if [[ -e "$out_final" ]]; then rmdir "$out_final"; fi
mv "$stage" "$out_final"
rm -rf -- "$tmp"
tmp=""
printf 'Verified Helm %s and kubectl %s artifacts staged at %s\n' "$HELM_VERSION" "$KUBECTL_VERSION" "$out_final"
printf 'Set KORDEX_OFFLINE_TOOLS_DIR=%s\n' "$out_final"
printf 'Set KORDEX_OFFLINE_TOOLS_LOCK=%s/offline-tools.tsv\n' "$out_final"
printf 'Set KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE=%s/offline-tools.tsv.sig\n' "$out_final"
printf 'Set KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY=%s/offline-tools.signer.pub\n' "$out_final"
