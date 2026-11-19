#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cmp "$ROOT/deployments/kustomize/hub/base/namespace.yaml" \
  "$ROOT/deployments/kustomize/hub/overlays/self-hosted-migration/namespace.yaml"
cmp "$ROOT/deployments/kustomize/hub/base/settings.yaml" \
  "$ROOT/deployments/kustomize/hub/overlays/self-hosted-migration/settings.yaml"
openssl genpkey -algorithm ED25519 -out "$TMP/release-private.pem"
openssl pkey -in "$TMP/release-private.pem" -pubout -out "$TMP/release-public.pem"
BUNDLE="$TMP/bundle"
mkdir -p "$BUNDLE/manifests"
cp -a "$ROOT/deployments/kustomize" "$BUNDLE/manifests/"
cat > "$TMP/trusted-verifier.sh" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ -d "$1" && -r "$2" ]]
EOF_VERIFIER
chmod 0555 "$TMP/trusted-verifier.sh"
export KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh"
OVERLAY="$BUNDLE/manifests/kustomize/overlays/self-managed"
LOCK="$TMP/image-digests.tsv"
KEYS="$TMP/keys.json"
cat > "$LOCK" <<'EOF'
agent	registry.dc.example:5443/kordex/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
operator	registry.dc.example:5443/kordex/operator@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
control-plane	registry.dc.example:5443/kordex/control-plane@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
dashboard	registry.dc.example:5443/kordex/dashboard@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
ansible-ee	registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
postgres	registry.dc.example:5443/kordex/postgres@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
EOF
openssl pkeyutl -sign -rawin -inkey "$TMP/release-private.pem" -in "$LOCK" -out "$LOCK.sig"
printf '{"keys":[] }\n' > "$KEYS"
OUTPUT="$TMP/configured"
KORDEX_REGISTRY_PULL_SECRET='cluster-registry' KORDEX_UPGRADE_IMAGE_PULL_SECRETS='ee-pull,shared-pull' \
KORDEX_UPGRADE_SSH_USER=labops KORDEX_UPGRADE_SSH_SECRET=maintenance-ssh-auth \
KORDEX_UPGRADE_KNOWN_HOSTS=approved-host-keys \
KORDEX_HUB_OIDC_ISSUER=https://identity.dc.example/realms/platform \
KORDEX_HUB_OIDC_CLIENT_ID=kordex-ui KORDEX_HUB_OIDC_AUDIENCE=kordex-api \
KORDEX_HUB_OIDC_TOKEN_MODE=access_token KORDEX_HUB_OIDC_ACCESS_CLIENT_ID=kordex-ui \
KORDEX_HUB_OIDC_ACCESS_REQUIRED_SCOPES='kordex.read kordex.operate' \
KORDEX_HUB_DASHBOARD_URL=https://kordex.dc.example/ \
KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$OUTPUT" >/dev/null
CONFIGURED="$OUTPUT/overlays/self-managed"
grep -Fq 'newName: registry.dc.example:5443/kordex/agent' "$CONFIGURED/kustomization.yaml"
grep -Fq 'digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$CONFIGURED/kustomization.yaml"
grep -Fq 'newName: registry.dc.example:5443/kordex/operator' "$CONFIGURED/kustomization.yaml"
grep -Fq 'clusterID: 733ff86d-5dd0-4ad9-8476-0910f9eac046' "$CONFIGURED/agent-settings.patch.yaml"
grep -Fq 'controlPlaneURL: https://hub.dc.example' "$CONFIGURED/agent-settings.patch.yaml"
grep -Fq 'maintenanceEnabled: "false"' "$CONFIGURED/agent-settings.patch.yaml"
grep -Fq 'upgradeEnabled: "false"' "$CONFIGURED/operator-settings.patch.yaml"
grep -Fq 'gkeUpgradeEnabled: "false"' "$CONFIGURED/operator-settings.patch.yaml"
grep -Fq 'upgradeExecutionEnvironmentAllowlist: "registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' "$CONFIGURED/operator-settings.patch.yaml"
grep -Fq 'upgradeImagePullSecrets: "ee-pull,shared-pull"' "$CONFIGURED/operator-settings.patch.yaml"
grep -Fq 'upgradeSSHUser: "labops"' "$CONFIGURED/operator-settings.patch.yaml"
grep -Fq 'upgradeSSHSecret: "maintenance-ssh-auth"' "$CONFIGURED/operator-settings.patch.yaml"
grep -Fq 'upgradeKnownHosts: "approved-host-keys"' "$CONFIGURED/operator-settings.patch.yaml"
grep -Fq 'resourceNames: [maintenance-ssh-auth]' "$OUTPUT/components/operator-host-execution/rbac.yaml"
grep -Fq 'resources: [selfsubjectaccessreviews]' "$OUTPUT/components/operator/rbac.yaml"
grep -Fq 'name: cluster-registry' "$CONFIGURED/agent-pull-secret.patch.yaml"
grep -Fq 'name: cluster-registry' "$CONFIGURED/operator-pull-secret.patch.yaml"
cmp "$KEYS" "$CONFIGURED/keys.json"
[[ -d "$OUTPUT/base" && -d "$OUTPUT/components/agent" && -d "$OUTPUT/components/operator" ]]
HUB_KUSTOMIZATION="$OUTPUT/hub/overlays/self-hosted/kustomization.yaml"
grep -Fq 'newName: registry.dc.example:5443/kordex/control-plane' "$HUB_KUSTOMIZATION"
grep -Fq 'digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "$HUB_KUSTOMIZATION"
grep -Fq 'newName: registry.dc.example:5443/kordex/dashboard' "$HUB_KUSTOMIZATION"
grep -Fq 'digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' "$HUB_KUSTOMIZATION"
grep -Fq 'name: cluster-registry' "$OUTPUT/hub/base/api-deployment.yaml"
grep -Fq 'name: cluster-registry' "$OUTPUT/hub/base/scheduler-deployment.yaml"
grep -Fq 'name: cluster-registry' "$OUTPUT/hub/base/dashboard-deployment.yaml"
grep -Fq 'name: cluster-registry' "$OUTPUT/hub/overlays/self-hosted-migration/migration-job.yaml"
for settings in "$OUTPUT/hub/base/settings.yaml" "$OUTPUT/hub/overlays/self-hosted-migration/settings.yaml"; do
  grep -Fq 'apiURL: "https://hub.dc.example"' "$settings"
  grep -Fq 'oidcIssuer: "https://identity.dc.example/realms/platform"' "$settings"
  grep -Fq 'oidcAudience: "kordex-api"' "$settings"
  grep -Fq 'oidcClientID: "kordex-ui"' "$settings"
  grep -Fq 'oidcTokenMode: "access_token"' "$settings"
  grep -Fq 'oidcAccessClientID: "kordex-ui"' "$settings"
  grep -Fq 'oidcAccessRequiredScopes: "kordex.read kordex.operate"' "$settings"
  grep -Fq 'dashboardApiTokenMode: "access_token"' "$settings"
  grep -Fq 'dashboardApiScopes: "kordex.read kordex.operate"' "$settings"
  grep -Fq 'dashboardURL: "https://kordex.dc.example"' "$settings"
done
kubectl kustomize "$OUTPUT/hub/overlays/self-hosted" > "$TMP/hub-access-rendered.yaml"
grep -Fq 'oidcTokenMode: access_token' "$TMP/hub-access-rendered.yaml"
grep -Fq 'dashboardApiTokenMode: access_token' "$TMP/hub-access-rendered.yaml"
grep -Fq 'key: oidcAccessClientID' "$TMP/hub-access-rendered.yaml"
grep -Fq 'key: oidcAccessRequiredScopes' "$TMP/hub-access-rendered.yaml"
grep -Fq 'key: dashboardApiScopes' "$TMP/hub-access-rendered.yaml"
OUTPUT_ID="$TMP/configured-id-token"
KORDEX_HUB_OIDC_ISSUER=https://identity.dc.example/realms/platform \
KORDEX_HUB_OIDC_CLIENT_ID=kordex-dashboard \
KORDEX_HUB_DASHBOARD_URL=https://kordex.dc.example \
KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$OUTPUT_ID" >/dev/null
grep -Fq 'oidcAudience: "kordex-dashboard"' "$OUTPUT_ID/hub/base/settings.yaml"
grep -Fq 'oidcTokenMode: "id_token"' "$OUTPUT_ID/hub/base/settings.yaml"
grep -Fq 'dashboardApiTokenMode: "id_token"' "$OUTPUT_ID/hub/base/settings.yaml"
HUB_MIGRATION_KUSTOMIZATION="$OUTPUT/hub/overlays/self-hosted-migration/kustomization.yaml"
grep -Fq 'newName: registry.dc.example:5443/kordex/control-plane' "$HUB_MIGRATION_KUSTOMIZATION"
grep -Fq 'digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "$HUB_MIGRATION_KUSTOMIZATION"
for overlay_name in gke-fleet gke-operator; do
  cmp "$KEYS" "$OUTPUT/overlays/$overlay_name/keys.json"
  grep -Fq 'newName: registry.dc.example:5443/kordex/operator' "$OUTPUT/overlays/$overlay_name/kustomization.yaml"
  grep -Fq 'digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$OUTPUT/overlays/$overlay_name/kustomization.yaml"
  grep -Fq 'upgradeExecutionEnvironmentAllowlist: "registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' "$OUTPUT/overlays/$overlay_name/operator-settings.patch.yaml"
  grep -Fq 'upgradeImagePullSecrets: "ee-pull,shared-pull"' "$OUTPUT/overlays/$overlay_name/operator-settings.patch.yaml"
  grep -Fq 'upgradeSSHUser: "labops"' "$OUTPUT/overlays/$overlay_name/operator-settings.patch.yaml"
  grep -Fq 'upgradeSSHSecret: "maintenance-ssh-auth"' "$OUTPUT/overlays/$overlay_name/operator-settings.patch.yaml"
  grep -Fq 'upgradeKnownHosts: "approved-host-keys"' "$OUTPUT/overlays/$overlay_name/operator-settings.patch.yaml"
  grep -Fq 'clusterID: 733ff86d-5dd0-4ad9-8476-0910f9eac046' "$OUTPUT/overlays/$overlay_name/operator-settings.patch.yaml"
  grep -Fq 'offline-operator-pull-secret.patch.yaml' "$OUTPUT/overlays/$overlay_name/kustomization.yaml"
  grep -Fq 'name: cluster-registry' "$OUTPUT/overlays/$overlay_name/offline-operator-pull-secret.patch.yaml"
done
grep -Fq 'newName: registry.dc.example:5443/kordex/agent' "$OUTPUT/overlays/gke-fleet/kustomization.yaml"
grep -Fq 'digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$OUTPUT/overlays/gke-fleet/kustomization.yaml"
grep -Fq 'clusterID: 733ff86d-5dd0-4ad9-8476-0910f9eac046' "$OUTPUT/overlays/gke-fleet/agent-settings.patch.yaml"
grep -Fq 'controlPlaneURL: https://hub.dc.example' "$OUTPUT/overlays/gke-fleet/agent-settings.patch.yaml"
grep -Fq 'maintenanceEnabled: "false"' "$OUTPUT/overlays/gke-fleet/agent-settings.patch.yaml"
grep -Fq 'offline-agent-pull-secret.patch.yaml' "$OUTPUT/overlays/gke-fleet/kustomization.yaml"
PRIVATE_OUTPUT="$TMP/configured-private-ca"
PRIVATE_MESSAGE="$(KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$PRIVATE_OUTPUT" --private-ca)"
grep -Fq 'kubectl kustomize '"$PRIVATE_OUTPUT"'/overlays/self-managed-private-ca' <<< "$PRIVATE_MESSAGE"
PRIVATE_CONFIGURED="$PRIVATE_OUTPUT/overlays/self-managed-private-ca"
grep -Fq 'newName: registry.dc.example:5443/kordex/agent' "$PRIVATE_OUTPUT/overlays/self-managed/kustomization.yaml"
grep -Fq 'digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$PRIVATE_OUTPUT/overlays/self-managed/kustomization.yaml"
grep -Fq 'clusterID: 733ff86d-5dd0-4ad9-8476-0910f9eac046' "$PRIVATE_OUTPUT/overlays/self-managed/agent-settings.patch.yaml"
grep -Fq 'controlPlaneURL: https://hub.dc.example' "$PRIVATE_OUTPUT/overlays/self-managed/agent-settings.patch.yaml"
grep -Fq 'upgradeExecutionEnvironmentAllowlist: "registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' "$PRIVATE_OUTPUT/overlays/self-managed/operator-settings.patch.yaml"
grep -Fq 'upgradeImagePullSecrets: "kordex-registry"' "$PRIVATE_OUTPUT/overlays/self-managed/operator-settings.patch.yaml"
cmp "$KEYS" "$PRIVATE_OUTPUT/overlays/self-managed/keys.json"
  if command -v kubectl >/dev/null 2>&1; then
  KUBECONFIG=/dev/null kubectl kustomize "$CONFIGURED" > "$TMP/rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$TMP/rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/operator@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$TMP/rendered.yaml"
  grep -Fq 'controlPlaneURL: https://hub.dc.example' "$TMP/rendered.yaml"
  grep -Fq 'maintenanceEnabled: "false"' "$TMP/rendered.yaml"
  grep -Fq 'name: KORDEX_ENABLE_MAINTENANCE' "$TMP/rendered.yaml"
  grep -Fq 'key: maintenanceEnabled' "$TMP/rendered.yaml"
  grep -Fq 'upgradeEnabled: "false"' "$TMP/rendered.yaml"
  grep -Fq 'gkeUpgradeEnabled: "false"' "$TMP/rendered.yaml"
  grep -Fq 'name: KORDEX_ROOK_METRICS_CA_FILE' "$TMP/rendered.yaml"
  grep -Fq 'key: rookMetricsCAFile' "$TMP/rendered.yaml"
  grep -Fq 'name: kordex-rook-metrics-ca' "$TMP/rendered.yaml"
  grep -Fq 'upgradeExecutionEnvironmentAllowlist: registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$TMP/rendered.yaml"
  grep -Fq 'upgradeImagePullSecrets: ee-pull,shared-pull' "$TMP/rendered.yaml"
  grep -Fq 'upgradeSSHUser: labops' "$TMP/rendered.yaml"
  grep -Fq 'upgradeSSHSecret: maintenance-ssh-auth' "$TMP/rendered.yaml"
  grep -Fq 'upgradeKnownHosts: approved-host-keys' "$TMP/rendered.yaml"
  if grep -Eiq 'gkeUpgradeEnabled: "true"|googleapis\.com|metadata\.google\.internal|container\.googleapis\.com|iam\.gke\.io|cloud\.google\.com|registry\.example\.invalid|docker\.io|quay\.io|newTag:' "$TMP/rendered.yaml"; then
    echo 'self-managed overlay unexpectedly enables an upgrade adapter or references a cloud API/public registry' >&2; exit 1
  fi
  if [[ "$(grep -Ec '^[[:space:]]*image: registry\.dc\.example:5443/kordex/(agent|operator)@sha256:[a-f0-9]{64}$' "$TMP/rendered.yaml")" -ne 2 ]]; then
    echo 'self-managed overlay does not render both workload images as private digest-pinned references' >&2; exit 1
  fi
  KUBECONFIG=/dev/null kubectl kustomize "$OUTPUT/overlays/gke-fleet" > "$TMP/gke-offline-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$TMP/gke-offline-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/operator@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$TMP/gke-offline-rendered.yaml"
  grep -Fq 'maintenanceEnabled: "false"' "$TMP/gke-offline-rendered.yaml"
  grep -Fq 'name: cluster-registry' "$TMP/gke-offline-rendered.yaml"
  KUBECONFIG=/dev/null kubectl kustomize "$OUTPUT/overlays/gke-operator" > "$TMP/gke-operator-offline-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/operator@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$TMP/gke-operator-offline-rendered.yaml"
  grep -Fq 'name: cluster-registry' "$TMP/gke-operator-offline-rendered.yaml"
  KUBECONFIG=/dev/null kubectl kustomize "$OUTPUT/hub/overlays/self-hosted" > "$TMP/hub-offline-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/control-plane@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "$TMP/hub-offline-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/dashboard@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' "$TMP/hub-offline-rendered.yaml"
  grep -Fq 'oidcIssuer: https://identity.dc.example/realms/platform' "$TMP/hub-offline-rendered.yaml"
  grep -Fq 'dashboardURL: https://kordex.dc.example' "$TMP/hub-offline-rendered.yaml"
  grep -Fq 'apiURL: https://hub.dc.example' "$TMP/hub-offline-rendered.yaml"
  [[ "$(grep -c '^kind: PodDisruptionBudget$' "$TMP/hub-offline-rendered.yaml")" == 3 ]]
  [[ "$(grep -c 'preferredDuringSchedulingIgnoredDuringExecution:' "$TMP/hub-offline-rendered.yaml")" == 3 ]]
  if grep -q '^kind: Secret$' "$TMP/hub-offline-rendered.yaml"; then
    echo 'self-hosted hub overlay unexpectedly embeds a Secret' >&2; exit 1
  fi
  KUBECONFIG=/dev/null kubectl kustomize "$OUTPUT/hub/overlays/self-hosted-migration" > "$TMP/hub-migration-offline-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/control-plane@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "$TMP/hub-migration-offline-rendered.yaml"
  grep -Fq 'kind: Job' "$TMP/hub-migration-offline-rendered.yaml"
  grep -Fq 'oidcAudience: kordex-api' "$TMP/hub-migration-offline-rendered.yaml"
  if grep -q '^kind: Secret$' "$TMP/hub-migration-offline-rendered.yaml"; then
    echo 'self-hosted migration overlay unexpectedly embeds a Secret' >&2; exit 1
  fi
  KUBECONFIG=/dev/null kubectl kustomize "$OUTPUT/hub/overlays/self-hosted-private-ca" > "$TMP/hub-private-ca-rendered.yaml"
  KUBECONFIG=/dev/null kubectl kustomize "$OUTPUT/hub/overlays/self-hosted-migration-private-ca" > "$TMP/hub-migration-private-ca-rendered.yaml"
  grep -Fq 'name: NODE_EXTRA_CA_CERTS' "$TMP/hub-private-ca-rendered.yaml"
  grep -Fq 'name: SSL_CERT_FILE' "$TMP/hub-private-ca-rendered.yaml"
  grep -Fq 'secretName: kordex-management-ca' "$TMP/hub-private-ca-rendered.yaml"
  grep -Fq 'secretName: kordex-management-ca' "$TMP/hub-migration-private-ca-rendered.yaml"
  grep -Fq 'kind: Job' "$TMP/hub-migration-private-ca-rendered.yaml"
  KUBECONFIG=/dev/null kubectl kustomize "$PRIVATE_OUTPUT/overlays/self-managed-private-ca" > "$TMP/private-ca-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$TMP/private-ca-rendered.yaml"
  grep -Fq 'image: registry.dc.example:5443/kordex/operator@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$TMP/private-ca-rendered.yaml"
  grep -Fq 'controlPlaneURL: https://hub.dc.example' "$TMP/private-ca-rendered.yaml"
  grep -Fq 'upgradeExecutionEnvironmentAllowlist: registry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$TMP/private-ca-rendered.yaml"
  grep -Fq 'name: KORDEX_CA_FILE' "$TMP/private-ca-rendered.yaml"
  grep -Fq 'secretName: kordex-management-ca' "$TMP/private-ca-rendered.yaml"
  KUBECONFIG=/dev/null kubectl kustomize "$PRIVATE_OUTPUT/overlays/gke-fleet" > "$TMP/gke-private-ca-rendered.yaml"
  grep -Fq 'name: KORDEX_CA_FILE' "$TMP/gke-private-ca-rendered.yaml"
  grep -Fq 'secretName: kordex-management-ca' "$TMP/gke-private-ca-rendered.yaml"

  GKE_TREE="$TMP/gke-kustomize"
  cp -a "$ROOT/deployments/kustomize" "$GKE_TREE"
  printf '{"keys":[]}\n' > "$GKE_TREE/overlays/gke-fleet/keys.json"
  KUBECONFIG=/dev/null kubectl kustomize "$GKE_TREE/overlays/gke-fleet" > "$TMP/gke-fleet-rendered.yaml"
  grep -Fq 'maintenanceEnabled: "true"' "$TMP/gke-fleet-rendered.yaml"
fi

if "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 http://hub.dc.example "$KEYS" "$TMP/bad-url" >/dev/null 2>&1; then
  echo 'accepted non-HTTPS hub URL' >&2; exit 1
fi
if "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  not-a-uuid https://hub.dc.example "$KEYS" "$TMP/bad-id" >/dev/null 2>&1; then
  echo 'accepted invalid cluster UUID' >&2; exit 1
fi
if "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/bad-option" --unknown >/dev/null 2>&1; then
  echo 'accepted unknown configuration option' >&2; exit 1
fi
if KORDEX_HUB_OIDC_ISSUER=https://identity.dc.example KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/partial-hub-oidc" >/dev/null 2>&1; then
  echo 'accepted incomplete hub OIDC configuration' >&2; exit 1
fi
if KORDEX_HUB_OIDC_ISSUER=https://identity.dc.example KORDEX_HUB_OIDC_CLIENT_ID=kordex-ui \
  KORDEX_HUB_DASHBOARD_URL=https://hub.dc.example/path KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/hub-dashboard-path" >/dev/null 2>&1; then
  echo 'accepted hub dashboard URL containing a path' >&2; exit 1
fi
if KORDEX_HUB_OIDC_ISSUER=https://identity.dc.example KORDEX_HUB_OIDC_CLIENT_ID=kordex-ui \
  KORDEX_HUB_OIDC_AUDIENCE=kordex-api KORDEX_HUB_DASHBOARD_URL=https://hub.dc.example \
  KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/id-token-audience-mismatch" >/dev/null 2>&1; then
  echo 'accepted a distinct audience in default ID-token mode' >&2; exit 1
fi
if KORDEX_HUB_OIDC_ISSUER=https://identity.dc.example KORDEX_HUB_OIDC_CLIENT_ID=kordex-ui \
  KORDEX_HUB_OIDC_AUDIENCE=kordex-api KORDEX_HUB_OIDC_TOKEN_MODE=access_token \
  KORDEX_HUB_OIDC_ACCESS_CLIENT_ID=other-client KORDEX_HUB_OIDC_ACCESS_REQUIRED_SCOPES=kordex.read \
  KORDEX_HUB_DASHBOARD_URL=https://hub.dc.example KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/access-token-wrong-client" >/dev/null 2>&1; then
  echo 'accepted an access-token client ID different from the dashboard client' >&2; exit 1
fi
if KORDEX_UPGRADE_IMAGE_PULL_SECRETS='valid-name,Invalid_Name' KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/bad-pull-secret" >/dev/null 2>&1; then
  echo 'accepted invalid upgrade image pull Secret name' >&2; exit 1
fi
if KORDEX_UPGRADE_IMAGE_PULL_SECRETS='same,same' KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/duplicate-pull-secret" >/dev/null 2>&1; then
  echo 'accepted duplicate upgrade image pull Secret name' >&2; exit 1
fi
if KORDEX_UPGRADE_IMAGE_PULL_SECRETS='ee-pull,' KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/empty-pull-secret-entry" >/dev/null 2>&1; then
  echo 'accepted empty upgrade image pull Secret list entry' >&2; exit 1
fi
if KORDEX_REGISTRY_PULL_SECRET='Invalid_Name' KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/bad-registry-secret" >/dev/null 2>&1; then
  echo 'accepted invalid workload image pull Secret name' >&2; exit 1
fi
if KORDEX_UPGRADE_SSH_USER=labops KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/partial-ssh-config" >/dev/null 2>&1; then
  echo 'accepted incomplete host-upgrade SSH configuration' >&2; exit 1
fi
if KORDEX_UPGRADE_SSH_USER='lab ops' KORDEX_UPGRADE_SSH_SECRET=ssh-auth KORDEX_UPGRADE_KNOWN_HOSTS=known-hosts \
  KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/invalid-ssh-user" >/dev/null 2>&1; then
  echo 'accepted invalid host-upgrade SSH user' >&2; exit 1
fi
cat > "$TMP/reject-verifier.sh" <<'EOF_VERIFIER'
#!/usr/bin/env bash
exit 1
EOF_VERIFIER
chmod 0555 "$TMP/reject-verifier.sh"
if KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/reject-verifier.sh" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/rejected-bundle" >/dev/null 2>&1; then
  echo 'unverified offline bundle was accepted by Kustomize helper' >&2; exit 1
fi
ATOMIC_BUNDLE="$TMP/malformed-kustomize-bundle"
cp -a "$BUNDLE" "$ATOMIC_BUNDLE"
sed -i '/newName: registry\.example\.invalid\/platform\/kordex\/control-plane/d' \
  "$ATOMIC_BUNDLE/manifests/kustomize/hub/overlays/self-hosted/kustomization.yaml"
if KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$ATOMIC_BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/atomic-failure" >/dev/null 2>&1; then
  echo 'malformed Kustomize image entry unexpectedly configured' >&2; exit 1
fi
[[ ! -e "$TMP/atomic-failure" ]]
if find "$TMP" -maxdepth 1 -name '.atomic-failure.configure.*' -print -quit | grep -q .; then
  echo 'failed Kustomize configuration left a partial staging directory' >&2; exit 1
fi
cp "$TMP/trusted-verifier.sh" "$BUNDLE/local-verifier.sh"
chmod 0555 "$BUNDLE/local-verifier.sh"
if KORDEX_TRUSTED_BUNDLE_VERIFIER="$BUNDLE/local-verifier.sh" \
  "$ROOT/scripts/configure-offline-kustomize.sh" "$BUNDLE" "$LOCK" \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 https://hub.dc.example "$KEYS" "$TMP/internal-verifier" >/dev/null 2>&1; then
  echo 'Kustomize helper accepted a verifier from inside the bundle' >&2; exit 1
fi
echo 'Offline Kustomize configuration tests passed.'
