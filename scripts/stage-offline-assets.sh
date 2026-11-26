#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 SOURCE_ROOT OUTPUT_DIRECTORY VERSION" >&2
  exit 2
fi
ROOT="$(cd "$1" && pwd)"
OUT="$2"
VERSION="$3"
if [[ ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]]; then
  echo "invalid bundle version: $VERSION" >&2
  exit 2
fi
[[ -d "$ROOT/deployments/kustomize" && -d "$ROOT/integrations/ansible-ee" ]] || {
  echo "source root is missing Kustomize or Ansible EE assets" >&2
  exit 2
}
if find "$ROOT/deployments/kustomize" -type l -print -quit | grep -q .; then
  echo "Kustomize source must not contain symbolic links" >&2
  exit 1
fi
for asset in Containerfile README.md build-ee.sh upgrade.py upgrade-debian.yml upgrade-rhel.yml upgrade_test.py collections.lock; do
  source="$ROOT/integrations/ansible-ee/$asset"
  [[ -f "$source" && ! -L "$source" ]] || {
    echo "Ansible EE release asset must be a regular file: $asset" >&2
    exit 1
  }
done
if find "$ROOT/deployments/kustomize" -type f \
  \( -name '*.pem' -o -name '*.key' -o -name 'kubeconfig' -o -name '.env' -o -name '*.env' \) \
  -print -quit | grep -q .; then
  echo "Kustomize source contains a private-key, kubeconfig, or environment file" >&2
  exit 1
fi
if grep -RIlE --binary-files=without-match -e \
  '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' "$ROOT/deployments/kustomize" >/dev/null; then
  echo "Kustomize source contains PEM private key material" >&2
  exit 1
fi
while IFS= read -r secret_file; do
  [[ -n "$secret_file" ]] || continue
  if [[ "$secret_file" != "$ROOT/deployments/kustomize/components/agent/identity.yaml" ]] \
    || grep -Eq '^[[:space:]]*(data|stringData):([[:space:]]|$)' "$secret_file"; then
    echo "Kustomize source contains an unapproved Secret resource or Secret payload" >&2
    exit 1
  fi
done < <(grep -RIlE --binary-files=without-match \
  '^[[:space:]]*kind:[[:space:]]*Secret([[:space:]]|$)' "$ROOT/deployments/kustomize" || true)
mkdir -p "$OUT/manifests" "$OUT/ansible-ee" "$OUT/tools"

cp -a "$ROOT/deployments/kustomize" "$OUT/manifests/"
# Keep every shipped Kustomize overlay aligned with the image release. The
# provider-specific overlays are optional, but stale image tags in the bundle
# can make an apparently valid install pull an older image unexpectedly.
while IFS= read -r kustomization; do
  sed -i -E "s/(newTag: ).*/\\1\"$VERSION\"/" "$kustomization"
done < <(find "$OUT/manifests/kustomize" -type f -path '*/overlays/*/kustomization.yaml' -print)
# Trust keys are cluster-specific. Never carry a workstation's ignored key
# file into a generic, signed release bundle.
find "$OUT/manifests/kustomize" -type f -name keys.json -delete

# Copy only release source and tests; recursive copying can capture generated
# Python bytecode and other local build artifacts from developer workstations.
cp "$ROOT/integrations/ansible-ee/Containerfile" \
  "$ROOT/integrations/ansible-ee/README.md" \
  "$ROOT/integrations/ansible-ee/build-ee.sh" \
  "$ROOT/integrations/ansible-ee/upgrade.py" \
  "$ROOT/integrations/ansible-ee/upgrade-debian.yml" \
  "$ROOT/integrations/ansible-ee/upgrade-rhel.yml" \
  "$ROOT/integrations/ansible-ee/upgrade_test.py" \
  "$ROOT/integrations/ansible-ee/collections.lock" "$OUT/ansible-ee/"

# The identity Secret bootstrap writes only the public empty JSON CAS seed and
# uses a Kubernetes resourceVersion test. Keep it available in offline installs.
install -m 0755 "$ROOT/scripts/seed_agent_identity_secret.py" "$OUT/tools/seed_agent_identity_secret.py"
