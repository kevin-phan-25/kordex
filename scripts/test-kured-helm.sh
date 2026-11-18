#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
HELM="${HELM:-helm}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

render() {
  "$HELM" template kured-test "$ROOT/deployments/helm/kordex-operator" \
    --namespace kordex-system \
    --set clusterID=80bd80f9-f097-4474-86f4-b80986fd5423 \
    --set hubPublicKeysConfigMap=hub-trust "$@"
}

render > "$TMP/default.yaml"
if grep -q '^  name: .*-kured$' "$TMP/default.yaml"; then
  echo 'kured RBAC must be absent by default' >&2
  exit 1
fi
render --set kured.enabled=true --show-only templates/kured-rbac.yaml > "$TMP/enabled.yaml"
grep -Fq 'resourceNames: ["kured"]' "$TMP/enabled.yaml"
grep -Fq 'verbs: [get, patch]' "$TMP/enabled.yaml"
grep -Fq 'namespace: kube-system' "$TMP/enabled.yaml"
render --set kured.enabled=true > "$TMP/enabled-deployment.yaml"
grep -A1 'name: KORDEX_KURED_ENABLED' "$TMP/enabled-deployment.yaml" | grep -Fq 'value: "true"'
grep -A1 'name: KORDEX_ENABLE_HOST_UPGRADES' "$TMP/enabled-deployment.yaml" | grep -Fq 'value: "false"'

render --set kured.enabled=false --set kured.rbacEnabled=true \
  --show-only templates/kured-rbac.yaml > "$TMP/cleanup.yaml"
cmp "$TMP/enabled.yaml" "$TMP/cleanup.yaml"
render --set kured.enabled=false --set kured.rbacEnabled=true > "$TMP/cleanup-deployment.yaml"
grep -A1 'name: KORDEX_KURED_ENABLED' "$TMP/cleanup-deployment.yaml" | grep -Fq 'value: "false"'
grep -A1 'name: KORDEX_ENABLE_HOST_UPGRADES' "$TMP/cleanup-deployment.yaml" | grep -Fq 'value: "false"'

render --set kured.enabled=true --set kured.namespace=reboot-system --set kured.daemonSet=rebootd \
  --show-only templates/kured-rbac.yaml > "$TMP/custom.yaml"
grep -Fq 'resourceNames: ["rebootd"]' "$TMP/custom.yaml"
grep -Fq 'namespace: reboot-system' "$TMP/custom.yaml"
echo 'kured interlock Helm checks passed'
