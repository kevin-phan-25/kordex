#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELM="${HELM:-helm}"
DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

test_chart() {
  local component="$1" expected_repository="$2" default_tag="$3"
  shift 3
  local chart="$ROOT/deployments/helm/kordex-$component"
  local profile="$chart/values-production.yaml"
  [[ -f "$profile" && ! -L "$profile" ]] || {
    echo "production image profile missing or unsafe: $profile" >&2
    exit 1
  }

  local default_render
  default_render="$("$HELM" template development-tag "$chart" "$@")"
  grep -Fq "image: \"$expected_repository:$default_tag\"" <<<"$default_render" || {
    echo "development chart no longer renders its default tag: $component" >&2
    exit 1
  }

  if "$HELM" template production-pin "$chart" -f "$profile" "$@" >/dev/null 2>&1; then
    echo "production profile accepted a tag-only image: $component" >&2
    exit 1
  fi

  local rendered
  rendered="$("$HELM" template production-pin "$chart" -f "$profile" "$@" --set-string image.digest="$DIGEST")"
  grep -Fq "image: \"$expected_repository@$DIGEST\"" <<<"$rendered" || {
    echo "production profile did not render an immutable digest reference: $component" >&2
    exit 1
  }
  while IFS= read -r image_line; do
    [[ "$image_line" == *"@$DIGEST"* ]] || {
      echo "production profile rendered an unpinned image: $component: $image_line" >&2
      exit 1
    }
  done < <(grep -E '^[[:space:]]+image:' <<<"$rendered")

  if "$HELM" template production-pin "$chart" -f "$profile" "$@" --set-string image.digest=bad >/dev/null 2>&1; then
    echo "production profile accepted a malformed image digest: $component" >&2
    exit 1
  fi
}

test_chart agent kordex/agent 0.4.0 \
  --set controlPlaneURL=https://hub.example \
  --set clusterID=80bd80f9-f097-4474-86f4-b80986fd5423 \
  --set enrollmentSecretName=enrollment
test_chart operator kordex/operator 0.4.0 \
  --set clusterID=80bd80f9-f097-4474-86f4-b80986fd5423 \
  --set hubPublicKeysConfigMap=hub-trust
test_chart control-plane kordex/control-plane 0.8.0 \
  --set credentialsSecretName=kordex-credentials \
  --set oidc.issuer=https://identity.example \
  --set oidc.audience=kordex
test_chart dashboard ghcr.io/acme/kordex-dashboard 0.8.0 \
  --set image.repository=ghcr.io/acme/kordex-dashboard \
  --set dashboardURL=https://dashboard.example.com \
  --set apiURL=https://api.example.com \
  --set oidc.issuer=https://identity.example.com \
  --set oidc.clientID=kordex-dashboard \
  --set oidc.secretName=kordex-dashboard-identity

echo "production Helm image digest requirement passed for all four charts"
