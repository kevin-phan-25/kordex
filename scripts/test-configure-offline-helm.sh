#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
openssl genpkey -algorithm ED25519 -out "$TMP/release-private.pem"
openssl pkey -in "$TMP/release-private.pem" -pubout -out "$TMP/release-public.pem"
BUNDLE="$TMP/bundle"
mkdir -p "$BUNDLE/charts"
printf 'bundle image inventory\n' > "$BUNDLE/images.txt"
cat > "$TMP/trusted-verifier.sh" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ -d "$1" && -r "$2" ]]
EOF_VERIFIER
chmod 0555 "$TMP/trusted-verifier.sh"
export KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh"
for chart in agent operator control-plane dashboard; do
  : > "$BUNDLE/charts/kordex-$chart-0.8.0.tgz"
done
LOCK="$TMP/images.tsv"
cat > "$LOCK" <<'EOF_LOCK'
agent	registry.dc.example:5443/kordex/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
operator	registry.dc.example:5443/kordex/operator@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
control-plane	registry.dc.example:5443/kordex/control-plane@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
dashboard	registry.dc.example:5443/kordex/dashboard@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
ansible-ee	registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
postgres	registry.dc.example:5443/kordex/postgres@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
EOF_LOCK
openssl pkeyutl -sign -rawin -inkey "$TMP/release-private.pem" -in "$LOCK" -out "$LOCK.sig"
OUT="$TMP/values"
KORDEX_REGISTRY_PULL_SECRET='cluster-registry' KORDEX_UPGRADE_IMAGE_PULL_SECRETS='ee-pull,shared-pull' \
KORDEX_UPGRADE_SSH_USER=labops KORDEX_UPGRADE_SSH_SECRET=maintenance-ssh-auth \
KORDEX_UPGRADE_KNOWN_HOSTS=approved-host-keys \
  KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$OUT" >/dev/null
grep -Fq 'repository: registry.dc.example:5443/kordex/agent' "$OUT/kordex-agent-images.yaml"
grep -Fq 'digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$OUT/kordex-agent-images.yaml"
grep -Fq 'repository: registry.dc.example:5443/kordex/control-plane' "$OUT/kordex-control-plane-images.yaml"
grep -Fq 'digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' "$OUT/kordex-dashboard-images.yaml"
grep -Fq 'enabled: false' "$OUT/kordex-operator-images.yaml"
grep -Fq 'registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$OUT/kordex-operator-images.yaml"
grep -Fq 'name: cluster-registry' "$OUT/kordex-operator-images.yaml"
grep -Fq '    - ee-pull' "$OUT/kordex-operator-images.yaml"
grep -Fq '    - shared-pull' "$OUT/kordex-operator-images.yaml"
grep -Fq 'sshUser: "labops"' "$OUT/kordex-operator-images.yaml"
grep -Fq 'sshCredentialSecret: "maintenance-ssh-auth"' "$OUT/kordex-operator-images.yaml"
grep -Fq 'knownHostsConfigMap: "approved-host-keys"' "$OUT/kordex-operator-images.yaml"
if command -v helm >/dev/null 2>&1; then
  helm template offline-check "$ROOT/deployments/helm/kordex-operator" \
    --namespace kordex-system \
    -f "$OUT/kordex-operator-images.yaml" \
    --set clusterID=733ff86d-5dd0-4ad9-8476-0910f9eac046 \
    --set hubPublicKeysConfigMap=kordex-hub-trust \
    --set upgrade.enabled=true \
    > "$TMP/operator-rendered.yaml"
  grep -Fq 'name: cluster-registry' "$TMP/operator-rendered.yaml"
  grep -Fq 'name: KORDEX_UPGRADE_IMAGE_PULL_SECRETS' "$TMP/operator-rendered.yaml"
  grep -Fq 'value: "labops"' "$TMP/operator-rendered.yaml"
  grep -Fq 'value: "maintenance-ssh-auth"' "$TMP/operator-rendered.yaml"
  grep -Fq 'value: "approved-host-keys"' "$TMP/operator-rendered.yaml"
  grep -Eq 'value: "?ee-pull,shared-pull"?$' "$TMP/operator-rendered.yaml"
  grep -Fq 'registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$TMP/operator-rendered.yaml"
fi
if KORDEX_REGISTRY_PULL_SECRET='Invalid_Name' KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/bad-secret" >/dev/null 2>&1; then
  echo 'accepted invalid workload image pull Secret name' >&2; exit 1
fi
if KORDEX_UPGRADE_SSH_USER=labops KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/partial-ssh-config" >/dev/null 2>&1; then
  echo 'accepted incomplete host-upgrade SSH configuration' >&2; exit 1
fi
if KORDEX_UPGRADE_SSH_USER=labops KORDEX_UPGRADE_SSH_SECRET=ssh-auth KORDEX_UPGRADE_KNOWN_HOSTS='known hosts' \
  KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/invalid-ssh-resource" >/dev/null 2>&1; then
  echo 'accepted invalid host-upgrade Kubernetes resource name' >&2; exit 1
fi
if KORDEX_UPGRADE_IMAGE_PULL_SECRETS='same,same' KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/duplicate-ee-secret" >/dev/null 2>&1; then
  echo 'accepted duplicate upgrade image pull Secret name' >&2; exit 1
fi
if KORDEX_UPGRADE_IMAGE_PULL_SECRETS=',ee-pull' KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/empty-pull-secret-entry" >/dev/null 2>&1; then
  echo 'accepted empty upgrade image pull Secret list entry' >&2; exit 1
fi
if KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$OUT" >/dev/null 2>&1; then
  echo 'refused existing output directory was expected' >&2; exit 1
fi
sed -i '/^postgres/d' "$LOCK"
openssl pkeyutl -sign -rawin -inkey "$TMP/release-private.pem" -in "$LOCK" -out "$LOCK.sig"
if KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/incomplete" >/dev/null 2>&1; then
  echo 'incomplete image lock was accepted' >&2; exit 1
fi
printf 'tampered\n' >> "$LOCK"
if KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/tampered" >/dev/null 2>&1; then
  echo 'tampered image lock was accepted' >&2; exit 1
fi
cat > "$TMP/reject-verifier.sh" <<'EOF_VERIFIER'
#!/usr/bin/env bash
exit 1
EOF_VERIFIER
chmod 0555 "$TMP/reject-verifier.sh"
if KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/reject-verifier.sh" \
  "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/rejected-bundle" >/dev/null 2>&1; then
  echo 'unverified offline bundle was accepted by Helm helper' >&2; exit 1
fi
cp "$TMP/trusted-verifier.sh" "$BUNDLE/local-verifier.sh"
chmod 0555 "$BUNDLE/local-verifier.sh"
if KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" KORDEX_TRUSTED_BUNDLE_VERIFIER="$BUNDLE/local-verifier.sh" \
  "$ROOT/scripts/configure-offline-helm.sh" "$BUNDLE" "$LOCK" "$TMP/internal-verifier" >/dev/null 2>&1; then
  echo 'Helm helper accepted a verifier from inside the bundle' >&2; exit 1
fi
echo 'Offline Helm image values tests passed.'
