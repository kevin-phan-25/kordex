#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helm=${HELM:-helm}
kubectl=${KUBECTL:-kubectl}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

api_base=(
  --set credentialsSecretName=kordex-credentials
  --set oidc.issuer=https://identity.example.test
  --set oidc.audience=kordex-api
  --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
)
dashboard_base=(
  --set image.repository=registry.example.test/kordex-dashboard
  --set-string image.digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  --set apiURL=https://api.example.test
  --set dashboardURL=https://dashboard.example.test
  --set oidc.issuer=https://identity.example.test
  --set oidc.clientID=kordex-dashboard
  --set oidc.secretName=kordex-dashboard-identity
)

"$helm" template api-id "$root/deployments/helm/kordex-control-plane" "${api_base[@]}" > "$tmp/api-id.yaml"
"$helm" template dashboard-id "$root/deployments/helm/kordex-dashboard" "${dashboard_base[@]}" > "$tmp/dashboard-id.yaml"
grep -Fq 'name: KORDEX_OIDC_TOKEN_MODE' "$tmp/api-id.yaml"
grep -Fq 'value: "id_token"' "$tmp/api-id.yaml"
grep -Fq 'name: KORDEX_OIDC_API_TOKEN_MODE, value: "id_token"' "$tmp/dashboard-id.yaml"

"$helm" template api-access "$root/deployments/helm/kordex-control-plane" "${api_base[@]}" \
  --set oidc.tokenMode=access_token --set oidc.accessClientID=kordex-dashboard \
  --set-string 'oidc.accessRequiredScopes=kordex.read kordex.operate' > "$tmp/api-access.yaml"
"$helm" template dashboard-access "$root/deployments/helm/kordex-dashboard" "${dashboard_base[@]}" \
  --set oidc.apiTokenMode=access_token --set-string 'oidc.apiScopes=kordex.read kordex.operate' > "$tmp/dashboard-access.yaml"
grep -Fq 'value: "access_token"' "$tmp/api-access.yaml"
grep -Fq 'name: KORDEX_OIDC_ACCESS_CLIENT_ID' "$tmp/api-access.yaml"
grep -Fq 'value: "kordex-dashboard"' "$tmp/api-access.yaml"
grep -Fq 'value: "kordex.read kordex.operate"' "$tmp/api-access.yaml"
grep -Fq 'name: KORDEX_OIDC_API_TOKEN_MODE, value: "access_token"' "$tmp/dashboard-access.yaml"
grep -Fq 'name: KORDEX_OIDC_API_SCOPES, value: "kordex.read kordex.operate"' "$tmp/dashboard-access.yaml"

if "$helm" template api-incomplete "$root/deployments/helm/kordex-control-plane" "${api_base[@]}" \
  --set oidc.tokenMode=access_token --set oidc.accessClientID=kordex-dashboard > "$tmp/api-incomplete.yaml" 2> "$tmp/api-incomplete.err"; then
  echo 'control-plane chart accepted access-token mode without required scopes' >&2
  exit 1
fi
grep -Fq 'oidc.accessRequiredScopes is required' "$tmp/api-incomplete.err"
if "$helm" template dashboard-incomplete "$root/deployments/helm/kordex-dashboard" "${dashboard_base[@]}" \
  --set oidc.apiTokenMode=access_token > "$tmp/dashboard-incomplete.yaml" 2> "$tmp/dashboard-incomplete.err"; then
  echo 'dashboard chart accepted access-token mode without requested API scopes' >&2
  exit 1
fi
grep -Fq 'oidc.apiScopes is required' "$tmp/dashboard-incomplete.err"
if "$helm" template api-same-audience "$root/deployments/helm/kordex-control-plane" "${api_base[@]}" \
  --set oidc.tokenMode=access_token --set oidc.accessClientID=kordex-api \
  --set oidc.accessRequiredScopes=kordex.read > "$tmp/api-same-audience.yaml" 2> "$tmp/api-same-audience.err"; then
  echo 'control-plane chart accepted identical API audience and OAuth client ID' >&2
  exit 1
fi
grep -Fq 'oidc.accessClientID must differ from the API audience' "$tmp/api-same-audience.err"

"$kubectl" kustomize "$root/deployments/kustomize/hub/overlays/self-hosted" > "$tmp/hub.yaml"
grep -Fq 'key: oidcTokenMode' "$tmp/hub.yaml"
grep -Fq 'key: dashboardApiTokenMode' "$tmp/hub.yaml"
grep -Fq 'oidcTokenMode: id_token' "$tmp/hub.yaml"
grep -Fq 'dashboardApiTokenMode: id_token' "$tmp/hub.yaml"

echo 'OIDC ID-token compatibility and strict access-token render checks passed.'
