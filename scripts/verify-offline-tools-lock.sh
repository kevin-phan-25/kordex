#!/usr/bin/env bash
set -euo pipefail

validate_helm_signers() {
  local file="$1" fingerprint
  [[ -f "$file" && ! -L "$file" && -r "$file" ]] || { echo "Helm signer allowlist must be a readable regular file" >&2; return 1; }
  declare -A approved=()
  while IFS= read -r fingerprint || [[ -n "${fingerprint:-}" ]]; do
    fingerprint="${fingerprint//[[:space:]]/}"
    [[ -z "$fingerprint" || "$fingerprint" == \#* ]] && continue
    [[ "$fingerprint" =~ ^[A-Fa-f0-9]{40,64}$ ]] || { echo "invalid fingerprint in Helm signer allowlist" >&2; return 1; }
    approved["${fingerprint^^}"]=1
  done < "$file"
  [[ "${#approved[@]}" -gt 0 ]] || { echo "Helm signer allowlist is empty" >&2; return 1; }
}

if [[ $# -eq 2 && "$1" == --check-helm-signers ]]; then
  validate_helm_signers "$2"
  exit
fi
if [[ $# -ne 4 ]]; then
  echo "Usage: $0 LOCK.tsv LOCK.tsv.sig ED25519_PUBLIC_KEY APPROVED_HELM_SIGNERS.txt" >&2
  exit 2
fi
LOCK="$1"
SIGNATURE="$2"
PUBLIC_KEY="$3"
HELM_SIGNERS="$4"
for file in "$LOCK" "$SIGNATURE" "$PUBLIC_KEY" "$HELM_SIGNERS"; do
  [[ -f "$file" && ! -L "$file" && -r "$file" ]] || { echo "tool provenance input must be a readable regular file: $file" >&2; exit 2; }
done
command -v openssl >/dev/null || { echo "openssl is required to verify the signed tool provenance lock" >&2; exit 2; }
openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -rawin -in "$LOCK" -sigfile "$SIGNATURE" >/dev/null

validate_helm_signers "$HELM_SIGNERS"
declare -A approved_helm_signers=()
while IFS= read -r fingerprint || [[ -n "${fingerprint:-}" ]]; do
  fingerprint="${fingerprint//[[:space:]]/}"
  [[ -z "$fingerprint" || "$fingerprint" == \#* ]] && continue
  approved_helm_signers["${fingerprint^^}"]=1
done < "$HELM_SIGNERS"

declare -A seen=()
count=0
while IFS=$'\t' read -r name version architecture binary_digest artifact_digest artifact_url verification signer extra || [[ -n "${name:-}" ]]; do
  [[ -n "${name:-}" && -z "${extra:-}" ]] || { echo "malformed tool provenance row" >&2; exit 1; }
  [[ "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo "invalid pinned tool version: $version" >&2; exit 1; }
  [[ "$binary_digest" =~ ^[a-f0-9]{64}$ && "$artifact_digest" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid pinned tool or upstream artifact checksum: $name/$architecture" >&2; exit 1; }
  [[ "$architecture" == linux-amd64 || "$architecture" == linux-arm64 ]] || { echo "unsupported tool architecture: $architecture" >&2; exit 1; }
  case "$name" in
    helm)
      [[ "$artifact_url" == "https://get.helm.sh/helm-${version}-${architecture}.tar.gz" ]] || { echo "Helm artifact URL does not match the official pinned release path" >&2; exit 1; }
      [[ "$verification" == openpgp && "$signer" =~ ^[A-Fa-f0-9]{40,64}$ ]] || { echo "Helm provenance must name the verified OpenPGP signing-key fingerprint" >&2; exit 1; }
      [[ -n "${approved_helm_signers[${signer^^}]:-}" ]] || { echo "Helm release was signed by a key outside the approved signer allowlist: $signer" >&2; exit 1; }
      ;;
    kubectl)
      arch="${architecture#linux-}"
      [[ "$artifact_url" == "https://dl.k8s.io/release/${version}/bin/linux/${arch}/kubectl" ]] || { echo "kubectl artifact URL does not match the official pinned release path" >&2; exit 1; }
      [[ "$verification" == cosign-keyless && "$signer" == 'krel-staging@k8s-releng-prod.iam.gserviceaccount.com|https://accounts.google.com' ]] || { echo "kubectl provenance must name the Kubernetes Release Engineering signing identity and issuer" >&2; exit 1; }
      ;;
    *) echo "unsupported offline tool: $name" >&2; exit 1 ;;
  esac
  key="$name/$architecture"
  [[ -z "${seen[$key]:-}" ]] || { echo "duplicate tool provenance row: $key" >&2; exit 1; }
  seen[$key]=1
  count=$((count + 1))
done < "$LOCK"
[[ "$count" -eq 4 ]] || { echo "tool provenance lock must contain exactly four rows" >&2; exit 1; }
for architecture in linux-amd64 linux-arm64; do
  for name in helm kubectl; do
    [[ -n "${seen[$name/$architecture]:-}" ]] || { echo "tool provenance lock is missing $name/$architecture" >&2; exit 1; }
  done
done
echo "Signed offline tool provenance verified."
