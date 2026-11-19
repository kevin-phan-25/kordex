#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helm=${HELM:-helm}
kubectl=${KUBECTL:-kubectl}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

cp_values=(
  --set credentialsSecretName=kordex-credentials
  --set oidc.issuer=https://identity.example
  --set oidc.audience=kordex
  --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
)
dashboard_values=(
  --set image.repository=ghcr.io/acme/kordex-dashboard
  --set dashboardURL=https://dashboard.example.invalid
  --set apiURL=https://api.example.invalid
  --set oidc.issuer=https://identity.example
  --set oidc.clientID=kordex-dashboard
  --set oidc.secretName=kordex-dashboard-identity
  --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
)

"$helm" template kordex-prod "$root/deployments/helm/kordex-control-plane" "${cp_values[@]}" > "$tmp/cp-default.yaml"
"$helm" template kordex-dashboard "$root/deployments/helm/kordex-dashboard" "${dashboard_values[@]}" > "$tmp/dashboard-default.yaml"
if grep -q '^kind: Ingress$' "$tmp/cp-default.yaml" "$tmp/dashboard-default.yaml"; then
  echo 'Helm ingress must stay disabled by default' >&2
  exit 1
fi
if grep -q '^kind: NetworkPolicy$' "$tmp/cp-default.yaml" "$tmp/dashboard-default.yaml"; then
  echo 'Helm ingress NetworkPolicies must stay disabled by default' >&2
  exit 1
fi

"$helm" template kordex-prod "$root/deployments/helm/kordex-control-plane" \
  "${cp_values[@]}" --set ingress.enabled=true --set ingress.className=nginx \
  --set ingress.host=api.kordex.example --set ingress.tls.secretName=kordex-hub-tls \
  > "$tmp/cp-ingress.yaml"
"$helm" template kordex-dashboard "$root/deployments/helm/kordex-dashboard" \
  "${dashboard_values[@]}" --set ingress.enabled=true --set ingress.className=nginx \
  --set ingress.host=dashboard.kordex.example --set ingress.tls.secretName=kordex-hub-tls \
  > "$tmp/dashboard-ingress.yaml"
[[ $(grep -c '^kind: Ingress$' "$tmp/cp-ingress.yaml") == 1 ]]
[[ $(grep -c '^kind: Ingress$' "$tmp/dashboard-ingress.yaml") == 1 ]]
grep -Fq 'name: kordex-prod-api' "$tmp/cp-ingress.yaml"
grep -Fq 'api.kordex.example' "$tmp/cp-ingress.yaml"
grep -Fq 'ingressClassName: "nginx"' "$tmp/cp-ingress.yaml"
grep -Fq 'secretName: "kordex-hub-tls"' "$tmp/cp-ingress.yaml"
grep -Fq '                name: kordex-prod-api' "$tmp/cp-ingress.yaml"
grep -Fq 'name: kordex-dashboard' "$tmp/dashboard-ingress.yaml"
grep -Fq 'dashboard.kordex.example' "$tmp/dashboard-ingress.yaml"
grep -Fq 'ingressClassName: "nginx"' "$tmp/dashboard-ingress.yaml"
grep -Fq 'secretName: "kordex-hub-tls"' "$tmp/dashboard-ingress.yaml"
grep -Fq '                name: kordex-dashboard' "$tmp/dashboard-ingress.yaml"

"$helm" template kordex-prod "$root/deployments/helm/kordex-control-plane" \
  "${cp_values[@]}" --set networkPolicy.ingress.enabled=true \
  --set-json 'networkPolicy.ingress.apiFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}},"podSelector":{"matchLabels":{"app.kubernetes.io/component":"controller"}}}]' \
  > "$tmp/cp-networkpolicy.yaml"
"$helm" template kordex-dashboard "$root/deployments/helm/kordex-dashboard" \
  "${dashboard_values[@]}" --set networkPolicy.ingress.enabled=true \
  --set-json 'networkPolicy.ingress.dashboardFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}},"podSelector":{"matchLabels":{"app.kubernetes.io/component":"controller"}}}]' \
  > "$tmp/dashboard-networkpolicy.yaml"
[[ $(grep -c '^kind: NetworkPolicy$' "$tmp/cp-networkpolicy.yaml") == 1 ]]
[[ $(grep -c '^kind: NetworkPolicy$' "$tmp/dashboard-networkpolicy.yaml") == 1 ]]
grep -Fq 'port: 8080' "$tmp/cp-networkpolicy.yaml"
grep -Fq 'port: 3000' "$tmp/dashboard-networkpolicy.yaml"
grep -Fq 'kubernetes.io/metadata.name: ingress-nginx' "$tmp/cp-networkpolicy.yaml"
grep -Fq 'kubernetes.io/metadata.name: ingress-nginx' "$tmp/dashboard-networkpolicy.yaml"

for chart in control-plane dashboard; do
  case "$chart" in
    control-plane) chart_dir="$root/deployments/helm/kordex-control-plane"; values=("${cp_values[@]}") ;;
    dashboard) chart_dir="$root/deployments/helm/kordex-dashboard"; values=("${dashboard_values[@]}") ;;
  esac
  for missing in host tls; do
    ingress_values=(--set ingress.enabled=true --set ingress.className=nginx)
    if [[ "$missing" == host ]]; then
      ingress_values+=(--set ingress.tls.secretName=kordex-hub-tls)
      expected_error='ingress.host must be set'
    else
      ingress_values+=(--set ingress.host=platform.example --set ingress.tls.secretName=)
      expected_error='ingress.tls.secretName must be set'
    fi
    if "$helm" template ingress-invalid "$chart_dir" "${values[@]}" "${ingress_values[@]}" > "$tmp/invalid-$chart-$missing.yaml" 2> "$tmp/invalid-$chart-$missing.err"; then
      echo "$chart chart accepted ingress with missing required $missing" >&2
      exit 1
    fi
    grep -Fq "$expected_error" "$tmp/invalid-$chart-$missing.err"
  done
  if [[ "$chart" == control-plane ]]; then
    missing_source=(--set networkPolicy.ingress.enabled=true)
    expected_source_error='networkPolicy.ingress.apiFrom must contain at least one trusted source rule'
  else
    missing_source=(--set networkPolicy.ingress.enabled=true)
    expected_source_error='networkPolicy.ingress.dashboardFrom must contain at least one trusted source rule'
  fi
  if "$helm" template networkpolicy-invalid "$chart_dir" "${values[@]}" "${missing_source[@]}" > "$tmp/invalid-$chart-networkpolicy.yaml" 2> "$tmp/invalid-$chart-networkpolicy.err"; then
    echo "$chart chart accepted ingress NetworkPolicy without trusted sources" >&2
    exit 1
  fi
  grep -Fq "$expected_source_error" "$tmp/invalid-$chart-networkpolicy.err"
  if [[ "$chart" == control-plane ]]; then
    invalid_peer=(--set-json 'networkPolicy.ingress.apiFrom=[{"namespaceSelector":{"matchLabels":{}}}]')
  else
    invalid_peer=(--set-json 'networkPolicy.ingress.dashboardFrom=[{"namespaceSelector":{"matchLabels":{}}}]')
  fi
  if "$helm" template networkpolicy-broad "$chart_dir" "${values[@]}" \
    --set networkPolicy.ingress.enabled=true "${invalid_peer[@]}" > "$tmp/invalid-$chart-peer.yaml" 2> "$tmp/invalid-$chart-peer.err"; then
    echo "$chart chart accepted a NetworkPolicy peer with an empty allow-all selector" >&2
    exit 1
  fi
  if [[ "$chart" == control-plane ]]; then
    wildcard_peer=(--set-json 'networkPolicy.ingress.apiFrom=[{"ipBlock":{"cidr":"0.0.0.0/0"}}]')
  else
    wildcard_peer=(--set-json 'networkPolicy.ingress.dashboardFrom=[{"ipBlock":{"cidr":"::/0"}}]')
  fi
  if "$helm" template networkpolicy-wildcard "$chart_dir" "${values[@]}" \
    --set networkPolicy.ingress.enabled=true "${wildcard_peer[@]}" > "$tmp/invalid-$chart-wildcard.yaml" 2> "$tmp/invalid-$chart-wildcard.err"; then
    echo "$chart chart accepted a universal CIDR ingress peer" >&2
    exit 1
  fi
done

"$kubectl" kustomize "$root/deployments/kustomize/hub/overlays/self-hosted" > "$tmp/kustomize-default.yaml"
if grep -q '^kind: Ingress$' "$tmp/kustomize-default.yaml"; then
  echo 'default Kustomize hub must not include opt-in ingress resources' >&2
  exit 1
fi
"$kubectl" kustomize "$root/deployments/kustomize/hub/overlays/self-hosted-ingress" > "$tmp/kustomize-ingress.yaml"
[[ $(grep -c '^kind: Ingress$' "$tmp/kustomize-ingress.yaml") == 2 ]]
[[ $(grep -c '^kind: NetworkPolicy$' "$tmp/kustomize-ingress.yaml") == 2 ]]
grep -Fq 'host: api.example.invalid' "$tmp/kustomize-ingress.yaml"
grep -Fq 'host: dashboard.example.invalid' "$tmp/kustomize-ingress.yaml"
grep -Fq 'ingressClassName: nginx' "$tmp/kustomize-ingress.yaml"
[[ $(grep -c 'kubernetes.io/metadata.name: ingress-nginx' "$tmp/kustomize-ingress.yaml") == 2 ]]
grep -Fq 'port: 8080' "$tmp/kustomize-ingress.yaml"
grep -Fq 'port: 3000' "$tmp/kustomize-ingress.yaml"
grep -Fq 'secretName: kordex-api-tls' "$tmp/kustomize-ingress.yaml"
grep -Fq 'secretName: kordex-dashboard-tls' "$tmp/kustomize-ingress.yaml"
grep -Fq 'name: kordex-api' "$tmp/kustomize-ingress.yaml"
grep -Fq 'name: kordex-dashboard' "$tmp/kustomize-ingress.yaml"
grep -Fq '            name: kordex-api' "$tmp/kustomize-ingress.yaml"
grep -Fq '            name: kordex-dashboard' "$tmp/kustomize-ingress.yaml"
grep -Fq 'apiURL: https://api.example.invalid' "$tmp/kustomize-ingress.yaml"
grep -Fq 'dashboardURL: https://dashboard.example.invalid' "$tmp/kustomize-ingress.yaml"
if grep -q '^kind: Secret$' "$tmp/kustomize-ingress.yaml"; then
  echo 'ingress overlay must reference, not generate, the operator-provided TLS Secret' >&2
  exit 1
fi

echo 'Self-hosted ingress checks passed (opt-in TLS routes, constrained source policies, and default-off parity).'
