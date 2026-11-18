#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FIXTURE="$TMP/source"
OUT="$TMP/bundle"
mkdir -p "$FIXTURE/deployments/kustomize/overlays/self-managed" \
  "$FIXTURE/deployments/kustomize/overlays/gke-operator" \
  "$FIXTURE/deployments/kustomize/hub/overlays/self-hosted" \
  "$FIXTURE/deployments/kustomize/components/agent" \
  "$FIXTURE/integrations/ansible-ee/__pycache__"
cat > "$FIXTURE/deployments/kustomize/overlays/self-managed/kustomization.yaml" <<'EOF'
images:
  - name: kordex/agent
    newName: registry.example.invalid/platform/kordex/agent
    newTag: "old"
EOF
cat > "$FIXTURE/deployments/kustomize/overlays/gke-operator/kustomization.yaml" <<'EOF_GKE'
images:
  - name: kordex/operator
    newName: registry.example.invalid/platform/kordex/operator
    newTag: "old"
EOF_GKE
cat > "$FIXTURE/deployments/kustomize/hub/overlays/self-hosted/kustomization.yaml" <<'EOF_HUB'
images:
  - name: kordex/control-plane
    newName: registry.example.invalid/platform/kordex/control-plane
    newTag: "old"
EOF_HUB
printf '{"keys":[]}\n' > "$FIXTURE/deployments/kustomize/overlays/self-managed/keys.json"
cat > "$FIXTURE/deployments/kustomize/components/agent/identity.yaml" <<'EOF_IDENTITY'
apiVersion: v1
kind: Secret
metadata:
  name: kordex-agent-identity
  namespace: kordex-system
type: Opaque
EOF_IDENTITY
for file in Containerfile README.md build-ee.sh upgrade.py upgrade-debian.yml upgrade-rhel.yml upgrade_test.py collections.lock; do
  printf '%s\n' "$file" > "$FIXTURE/integrations/ansible-ee/$file"
done
printf 'compiled python bytecode\n' > "$FIXTURE/integrations/ansible-ee/__pycache__/upgrade.cpython.pyc"

printf 'apiVersion: v1\nkind: Secret\n' > "$FIXTURE/deployments/kustomize/overlays/self-managed/secret.yaml"
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3 >/dev/null 2>&1; then
  echo 'Kustomize Secret manifest was allowed into the offline bundle' >&2
  exit 1
fi
rm "$FIXTURE/deployments/kustomize/overlays/self-managed/secret.yaml"
cat > "$FIXTURE/deployments/kustomize/components/agent/identity.yaml" <<'EOF_IDENTITY_WITH_DATA'
apiVersion: v1
kind: Secret
metadata:
  name: kordex-agent-identity
data:
  privateKey: c2VjcmV0
EOF_IDENTITY_WITH_DATA
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3 >/dev/null 2>&1; then
  echo 'Kustomize identity Secret with data was allowed into the offline bundle' >&2
  exit 1
fi
sed -i 's/^data:$/stringData: {privateKey: must-not-be-packaged}/' \
  "$FIXTURE/deployments/kustomize/components/agent/identity.yaml"
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3 >/dev/null 2>&1; then
  echo 'Kustomize inline identity Secret payload was allowed into the offline bundle' >&2
  exit 1
fi
cat > "$FIXTURE/deployments/kustomize/components/agent/identity.yaml" <<'EOF_IDENTITY'
apiVersion: v1
kind: Secret
metadata:
  name: kordex-agent-identity
  namespace: kordex-system
type: Opaque
EOF_IDENTITY
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' > "$FIXTURE/deployments/kustomize/overlays/self-managed/private.pem"
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3 >/dev/null 2>&1; then
  echo 'Kustomize private key file was allowed into the offline bundle' >&2
  exit 1
fi
rm "$FIXTURE/deployments/kustomize/overlays/self-managed/private.pem"
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' > "$FIXTURE/deployments/kustomize/overlays/self-managed/private-material.yaml"
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3 >/dev/null 2>&1; then
  echo 'embedded PEM private key material was allowed into the offline bundle' >&2
  exit 1
fi
rm "$FIXTURE/deployments/kustomize/overlays/self-managed/private-material.yaml"
printf x > "$TMP/outside-source"
ln -s "$TMP/outside-source" "$FIXTURE/deployments/kustomize/overlays/self-managed/external.yaml"
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3 >/dev/null 2>&1; then
  echo 'Kustomize source symlink was followed into the offline bundle' >&2
  exit 1
fi
rm "$FIXTURE/deployments/kustomize/overlays/self-managed/external.yaml"
rm "$FIXTURE/integrations/ansible-ee/upgrade.py"
ln -s "$TMP/outside-source" "$FIXTURE/integrations/ansible-ee/upgrade.py"
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3 >/dev/null 2>&1; then
  echo 'Ansible EE release symlink was followed into the offline bundle' >&2
  exit 1
fi
rm "$FIXTURE/integrations/ansible-ee/upgrade.py"
printf 'upgrade.py' > "$FIXTURE/integrations/ansible-ee/upgrade.py"

bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$OUT" 1.2.3
[[ ! -e "$OUT/manifests/kustomize/overlays/self-managed/keys.json" ]]
grep -Fq 'newTag: "1.2.3"' "$OUT/manifests/kustomize/overlays/self-managed/kustomization.yaml"
grep -Fq 'newTag: "1.2.3"' "$OUT/manifests/kustomize/overlays/gke-operator/kustomization.yaml"
grep -Fq 'newTag: "1.2.3"' "$OUT/manifests/kustomize/hub/overlays/self-hosted/kustomization.yaml"
for file in Containerfile README.md build-ee.sh upgrade.py upgrade-debian.yml upgrade-rhel.yml upgrade_test.py collections.lock; do
  [[ -f "$OUT/ansible-ee/$file" ]]
done
if find "$OUT/ansible-ee" -type f | grep -Eq '__pycache__|\.py[co]$'; then
  echo 'Python cache artifact was copied into the bundle' >&2
  exit 1
fi
if bash "$ROOT/scripts/stage-offline-assets.sh" "$FIXTURE" "$TMP/invalid" '../bad'; then
  echo 'invalid bundle version was accepted' >&2
  exit 1
fi
echo 'offline source staging tests passed'
