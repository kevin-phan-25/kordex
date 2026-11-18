#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 VERIFIED_BUNDLE IMAGE_DIGEST_LOCK OUTPUT_DIRECTORY" >&2
  exit 2
fi
BUNDLE="$(cd "$1" && pwd)"
LOCK="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
OUTPUT="$3"
LOCK_SIGNATURE="${KORDEX_IMAGE_LOCK_SIGNATURE:-${LOCK}.sig}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REGISTRY_PULL_SECRET="${KORDEX_REGISTRY_PULL_SECRET:-kordex-registry}"
UPGRADE_PULL_SECRETS="${KORDEX_UPGRADE_IMAGE_PULL_SECRETS:-$REGISTRY_PULL_SECRET}"
UPGRADE_SSH_USER="${KORDEX_UPGRADE_SSH_USER:-}"
UPGRADE_SSH_SECRET="${KORDEX_UPGRADE_SSH_SECRET:-}"
UPGRADE_KNOWN_HOSTS="${KORDEX_UPGRADE_KNOWN_HOSTS:-}"
if [[ -n "$UPGRADE_SSH_USER$UPGRADE_SSH_SECRET$UPGRADE_KNOWN_HOSTS" ]]; then
  if [[ -z "$UPGRADE_SSH_USER" || -z "$UPGRADE_SSH_SECRET" || -z "$UPGRADE_KNOWN_HOSTS" ]]; then
    echo "configure all of KORDEX_UPGRADE_SSH_USER, KORDEX_UPGRADE_SSH_SECRET, and KORDEX_UPGRADE_KNOWN_HOSTS together" >&2
    exit 2
  fi
  if [[ ! "$UPGRADE_SSH_USER" =~ ^[A-Za-z0-9_.-]{1,32}$ ]]; then
    echo "upgrade SSH user must contain 1 to 32 letters, digits, dots, underscores, or hyphens" >&2
    exit 2
  fi
  for resource_name in "$UPGRADE_SSH_SECRET" "$UPGRADE_KNOWN_HOSTS"; do
    if [[ ! "$resource_name" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ || ${#resource_name} -gt 63 ]]; then
      echo "upgrade SSH Secret and known-hosts ConfigMap names must be DNS labels of at most 63 characters" >&2
      exit 2
    fi
  done
fi
for secret_name in "$REGISTRY_PULL_SECRET"; do
  if [[ ! "$secret_name" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ || ${#secret_name} -gt 63 ]]; then
    echo "registry pull Secret names must be DNS labels of at most 63 characters" >&2
    exit 2
  fi
done
declare -A seen_upgrade_pull_secrets=()
[[ "$UPGRADE_PULL_SECRETS" != ,* && "$UPGRADE_PULL_SECRETS" != *, && "$UPGRADE_PULL_SECRETS" != *,,* ]] || {
  echo "upgrade image pull Secret list contains an empty entry" >&2; exit 2;
}
IFS=',' read -r -a upgrade_pull_secret_names <<< "$UPGRADE_PULL_SECRETS"
for secret_name in "${upgrade_pull_secret_names[@]}"; do
  if [[ ! "$secret_name" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ || ${#secret_name} -gt 63 ]]; then
    echo "upgrade image pull Secret names must be DNS labels of at most 63 characters" >&2
    exit 2
  fi
  if [[ -n "${seen_upgrade_pull_secrets[$secret_name]:-}" ]]; then
    echo "duplicate upgrade image pull Secret name: $secret_name" >&2
    exit 2
  fi
  seen_upgrade_pull_secrets[$secret_name]=1
done
[[ -d "$BUNDLE/charts" && -f "$BUNDLE/images.txt" ]] || { echo "bundle is missing charts or image inventory" >&2; exit 2; }
[[ -f "$LOCK" && ! -L "$LOCK" ]] || { echo "image digest lock must be a regular file" >&2; exit 2; }
[[ ! -e "$OUTPUT" ]] || { echo "output directory already exists: $OUTPUT" >&2; exit 2; }
: "${KORDEX_RELEASE_PUBLIC_KEY:?set path to trusted Ed25519 release public key}"
: "${KORDEX_TRUSTED_BUNDLE_VERIFIER:?set path to independently trusted verify-offline-bundle.sh}"
[[ -f "$KORDEX_TRUSTED_BUNDLE_VERIFIER" && -x "$KORDEX_TRUSTED_BUNDLE_VERIFIER" && ! -L "$KORDEX_TRUSTED_BUNDLE_VERIFIER" ]] || {
  echo "trusted bundle verifier must be an executable, regular file" >&2; exit 2;
}
TRUSTED_VERIFIER="$(cd "$(dirname "$KORDEX_TRUSTED_BUNDLE_VERIFIER")" && pwd)/$(basename "$KORDEX_TRUSTED_BUNDLE_VERIFIER")"
case "$TRUSTED_VERIFIER" in
  "$BUNDLE"/*) echo "trusted bundle verifier must be outside the bundle" >&2; exit 2 ;;
esac
"$TRUSTED_VERIFIER" "$BUNDLE" "$KORDEX_RELEASE_PUBLIC_KEY"
"$SCRIPT_DIR/verify-image-lock.sh" "$LOCK" "$LOCK_SIGNATURE" "$KORDEX_RELEASE_PUBLIC_KEY"

# Validate every image reference and require the complete mirrored release set,
# even though PostgreSQL is consumed by Compose rather than a Kordex Helm chart.
declare -A images=()
while IFS=$'\t' read -r name ref extra || [[ -n "${name:-}" ]]; do
  [[ -n "${name:-}" && -z "${extra:-}" ]] || { echo "malformed image lock row" >&2; exit 2; }
  case "$name" in agent|operator|control-plane|dashboard|ansible-ee|postgres) ;; *) echo "unsupported image in lock: $name" >&2; exit 2 ;; esac
  [[ -z "${images[$name]:-}" ]] || { echo "duplicate image lock entry: $name" >&2; exit 2; }
  if [[ ! "$ref" =~ ^([a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+)@sha256:([a-f0-9]{64})$ ]]; then
    echo "image lock entry is not a repository-qualified digest: $name" >&2
    exit 2
  fi
  if [[ "${BASH_REMATCH[3]:-}" == :* ]]; then
    port="${BASH_REMATCH[3]#:}"
    (( 10#$port >= 1 && 10#$port <= 65535 )) || { echo "invalid registry port for $name" >&2; exit 2; }
  fi
  repository="${ref%@*}"
  [[ "$repository" == */kordex/$name ]] || { echo "image lock repository does not match image name: $name" >&2; exit 2; }
  images[$name]="$ref"
done < "$LOCK"
for name in agent operator control-plane dashboard ansible-ee postgres; do
  [[ -n "${images[$name]:-}" ]] || { echo "required image missing from lock: $name" >&2; exit 2; }
done
for chart in agent operator control-plane dashboard; do
  compgen -G "$BUNDLE/charts/kordex-$chart-*.tgz" >/dev/null || { echo "packaged Helm chart is missing: kordex-$chart" >&2; exit 2; }
done

mkdir -p "$(dirname "$OUTPUT")"
mkdir "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
for chart in agent operator control-plane dashboard; do
  ref="${images[$chart]}"
  repository="${ref%@*}"
  digest="${ref##*@}"
  cat > "$OUTPUT/kordex-$chart-images.yaml" <<EOF_VALUES
image:
  repository: $repository
  digest: $digest
  pullPolicy: IfNotPresent
imagePullSecrets:
  - name: $REGISTRY_PULL_SECRET
EOF_VALUES
  if [[ "$chart" == operator ]]; then
    cat >> "$OUTPUT/kordex-$chart-images.yaml" <<EOF_VALUES
upgrade:
  enabled: false
  imagePullSecrets:
EOF_VALUES
    for secret_name in "${upgrade_pull_secret_names[@]}"; do
      printf '    - %s\n' "$secret_name" >> "$OUTPUT/kordex-$chart-images.yaml"
    done
    cat >> "$OUTPUT/kordex-$chart-images.yaml" <<EOF_VALUES
  executionEnvironmentAllowlist:
    - ${images[ansible-ee]}
EOF_VALUES
    if [[ -n "$UPGRADE_SSH_USER" ]]; then
      cat >> "$OUTPUT/kordex-$chart-images.yaml" <<EOF_VALUES
  sshUser: "$UPGRADE_SSH_USER"
  sshCredentialSecret: "$UPGRADE_SSH_SECRET"
  knownHostsConfigMap: "$UPGRADE_KNOWN_HOSTS"
EOF_VALUES
    fi
  fi
done
printf 'Generated digest-pinned Helm image values at %s\n' "$OUTPUT"
