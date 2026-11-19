#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
HELM=${HELM:-helm}
KUBECTL=${KUBECTL:-kubectl}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

"$HELM" template kordex-prod "$ROOT/deployments/helm/kordex-control-plane" \
  --namespace kordex-management \
  --set credentialsSecretName=kordex-credentials \
  --set oidc.issuer=https://identity.example \
  --set oidc.audience=kordex \
  --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  > "$TMP/helm.yaml"
"$HELM" template kordex-dashboard "$ROOT/deployments/helm/kordex-dashboard" \
  --namespace kordex-management \
  --set image.repository=ghcr.io/kordex/dashboard \
  --set dashboardURL=https://dashboard.example \
  --set apiURL=https://api.example \
  --set oidc.issuer=https://identity.example \
  --set oidc.clientID=kordex \
  --set oidc.secretName=kordex-dashboard-identity \
  --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  > "$TMP/dashboard-helm.yaml"
"$KUBECTL" kustomize "$ROOT/deployments/kustomize/hub/overlays/self-hosted" \
  > "$TMP/kustomize.yaml"

if grep -Fq 'KORDEX_AUDIT_SIGNING_KEY_FILE' "$TMP/helm.yaml"; then
  echo 'Helm enabled dashboard audit signing by default' >&2
  exit 1
fi
"$HELM" template kordex-audit-export "$ROOT/deployments/helm/kordex-control-plane" \
  --namespace kordex-management \
  --set credentialsSecretName=kordex-credentials \
  --set oidc.issuer=https://identity.example \
  --set oidc.audience=kordex \
  --set auditExport.enabled=true \
  --set auditExport.secretKey=auditSigningKey \
  --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  > "$TMP/audit-export-helm.yaml"
awk '
  function check() {
    if (index(doc, "kind: Deployment") == 0) return
    if (index(doc, "name: kordex-audit-export-api") > 0) {
      if (index(doc, "KORDEX_AUDIT_SIGNING_KEY_FILE") == 0 ||
          index(doc, "key: auditSigningKey") == 0 ||
          index(doc, "path: auditSigningKey") == 0 ||
          index(doc, "defaultMode: 0440") == 0 ||
          index(doc, "fsGroup: 65532") == 0) exit 1
      api++
    }
    if (index(doc, "name: kordex-audit-export-scheduler") > 0) {
      if (index(doc, "KORDEX_AUDIT_SIGNING_KEY_FILE") > 0 ||
          index(doc, "key: auditSigningKey") > 0) exit 1
      scheduler++
    }
  }
  /^---[[:space:]]*$/ { check(); doc = ""; next }
  { doc = doc $0 "\n" }
  END { check(); if (api != 1 || scheduler != 1) exit 1 }
' "$TMP/audit-export-helm.yaml" || {
  echo 'Helm audit key was not mounted exclusively into the configured API' >&2
  exit 1
}
grep -Fq 'KORDEX_AUDIT_SIGNING_KEY_FILE' "$TMP/kustomize.yaml"
grep -Fq 'key: auditSigningKey' "$TMP/kustomize.yaml"

assert_pdb() {
  local file=$1 name=$2 component=$3
  awk -v expected_name="$name" -v expected_component="$component" '
    function verify() {
      if (index(doc, "kind: PodDisruptionBudget") == 0) return
      expected_label = "app.kubernetes.io/component: " expected_component
      copy = doc
      labels = 0
      while ((position = index(copy, expected_label)) > 0) {
        labels++
        copy = substr(copy, position + length(expected_label))
      }
      if (index(doc, "name: " expected_name "\n") > 0 &&
          index(doc, "minAvailable: 1") > 0 &&
          index(doc, "selector:") > 0 && index(doc, "matchLabels:") > 0 &&
          labels == 2) found++
    }
    /^---[[:space:]]*$/ { verify(); doc = ""; next }
    { doc = doc $0 "\n" }
    END { verify(); if (found != 1) exit 1 }
  ' "$file" || {
    echo "$file: expected one minAvailable: 1 PDB named $name selecting only $component pods" >&2
    return 1
  }
}

assert_deployment_spread() {
  local file=$1 name=$2 component=$3
  awk -v expected_name="$name" -v expected_component="$component" '
    function verify() {
      if (index(doc, "kind: Deployment") == 0 ||
          index(doc, "name: " expected_name "\n") == 0) return
      expected_label = "app.kubernetes.io/component: " expected_component
      if (index(doc, "preferredDuringSchedulingIgnoredDuringExecution:") > 0 &&
          index(doc, "topologyKey: kubernetes.io/hostname") > 0 &&
          index(doc, expected_label) > 0) found++
    }
    /^---[[:space:]]*$/ { verify(); doc = ""; next }
    { doc = doc $0 "\n" }
    END { verify(); if (found != 1) exit 1 }
  ' "$file" || {
    echo "$file: expected a preferred hostname anti-affinity rule for $name" >&2
    return 1
  }
}

assert_dashboard_pdb() {
  local file=$1 name=$2
  awk -v expected_name="$name" '
    function verify() {
      if (index(doc, "kind: PodDisruptionBudget") == 0) return
      if (index(doc, "name: " expected_name "\n") > 0 &&
          index(doc, "minAvailable: 1") > 0 &&
          index(doc, "app.kubernetes.io/name: kordex-dashboard") > 0 &&
          index(doc, "app.kubernetes.io/instance: kordex-dashboard") > 0) found++
    }
    /^---[[:space:]]*$/ { verify(); doc = ""; next }
    { doc = doc $0 "\n" }
    END { verify(); if (found != 1) exit 1 }
  ' "$file" || {
    echo "$file: expected dashboard PDB $name with minAvailable: 1 and release-scoped selector" >&2
    return 1
  }
}

assert_dashboard_spread() {
  local file=$1 name=$2
  awk -v expected_name="$name" '
    function verify() {
      if (index(doc, "kind: Deployment") == 0 ||
          index(doc, "name: " expected_name "\n") == 0) return
      if (index(doc, "preferredDuringSchedulingIgnoredDuringExecution:") > 0 &&
          index(doc, "topologyKey: kubernetes.io/hostname") > 0 &&
          index(doc, "app.kubernetes.io/name: kordex-dashboard") > 0) found++
    }
    /^---[[:space:]]*$/ { verify(); doc = ""; next }
    { doc = doc $0 "\n" }
    END { verify(); if (found != 1) exit 1 }
  ' "$file" || {
    echo "$file: expected a preferred hostname anti-affinity rule for dashboard $name" >&2
    return 1
  }
}

assert_scheduler_probes() {
  local file=$1 name=$2
  awk -v expected_name="$name" '
    function verify() {
      if (index(doc, "kind: Deployment") == 0 ||
          index(doc, "name: " expected_name "\n") == 0) return
      if (index(doc, "name: health") > 0 && index(doc, "containerPort: 8081") > 0 &&
          index(doc, "path: /readyz") > 0 && index(doc, "path: /healthz") > 0 &&
          index(doc, "port: health") > 0) found++
    }
    /^---[[:space:]]*$/ { verify(); doc = ""; next }
    { doc = doc $0 "\n" }
    END { verify(); if (found != 1) exit 1 }
  ' "$file" || {
    echo "$file: expected scheduler readiness/liveness probes on the health port for $name" >&2
    return 1
  }
}

[[ $(grep -c '^kind: PodDisruptionBudget$' "$TMP/helm.yaml") == 2 ]] || {
  echo "$TMP/helm.yaml: expected API and scheduler PodDisruptionBudgets" >&2
  exit 1
}
[[ $(grep -c '^kind: PodDisruptionBudget$' "$TMP/kustomize.yaml") == 3 ]] || {
  echo "$TMP/kustomize.yaml: expected API, scheduler, and dashboard PodDisruptionBudgets" >&2
  exit 1
}
[[ $(grep -c '^kind: PodDisruptionBudget$' "$TMP/dashboard-helm.yaml") == 1 ]] || {
  echo "$TMP/dashboard-helm.yaml: expected one dashboard PodDisruptionBudget" >&2
  exit 1
}
[[ $(grep -c 'startupProbe:' "$TMP/helm.yaml") == 2 ]] || {
  echo "$TMP/helm.yaml: expected startup probes for API and scheduler" >&2
  exit 1
}
[[ $(grep -c 'startupProbe:' "$TMP/dashboard-helm.yaml") == 1 ]] || {
  echo "$TMP/dashboard-helm.yaml: expected dashboard startup probe" >&2
  exit 1
}
[[ $(grep -c 'startupProbe:' "$TMP/kustomize.yaml") == 3 ]] || {
  echo "$TMP/kustomize.yaml: expected startup probes for API, scheduler, and dashboard" >&2
  exit 1
}

for component in api scheduler; do
  assert_pdb "$TMP/helm.yaml" "kordex-prod-$component" "$component"
  assert_deployment_spread "$TMP/helm.yaml" "kordex-prod-$component" "$component"
  assert_pdb "$TMP/kustomize.yaml" "kordex-$component" "$component"
  assert_deployment_spread "$TMP/kustomize.yaml" "kordex-$component" "$component"
done
assert_scheduler_probes "$TMP/helm.yaml" kordex-prod-scheduler
assert_scheduler_probes "$TMP/kustomize.yaml" kordex-scheduler

assert_dashboard_pdb "$TMP/dashboard-helm.yaml" kordex-dashboard
assert_dashboard_spread "$TMP/dashboard-helm.yaml" kordex-dashboard
assert_pdb "$TMP/kustomize.yaml" kordex-dashboard dashboard
assert_deployment_spread "$TMP/kustomize.yaml" kordex-dashboard dashboard

echo 'Management-plane availability render checks passed for Helm and Kustomize.'
