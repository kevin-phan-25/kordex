#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL_MODULE="$ROOT/tools/controller-gen/go.mod"
EXPECTED_VERSION="$(awk '($1 == "require" && $2 == "sigs.k8s.io/controller-tools") { print $3; exit } $1 == "sigs.k8s.io/controller-tools" { print $2; exit }' "$TOOL_MODULE")"
if [[ ! "$EXPECTED_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "controller-gen version pin is missing or invalid in $TOOL_MODULE" >&2
  exit 2
fi

TOOL="${CONTROLLER_GEN:-$(go env GOPATH)/bin/controller-gen}"
if [[ "$TOOL" != */* ]]; then
  TOOL="$(command -v "$TOOL" || true)"
fi
if [[ -z "$TOOL" || ! -x "$TOOL" ]]; then
  echo "pinned controller-gen $EXPECTED_VERSION is unavailable; install it explicitly with 'make install-controller-gen' or set CONTROLLER_GEN to that binary" >&2
  exit 127
fi

VERSION_OUTPUT="$("$TOOL" --version 2>&1)" || {
  echo "could not read controller-gen version from configured executable" >&2
  exit 2
}
if [[ "$VERSION_OUTPUT" != "Version: $EXPECTED_VERSION" ]]; then
  echo "controller-gen version mismatch: expected $EXPECTED_VERSION, got '$VERSION_OUTPUT'" >&2
  exit 2
fi

if [[ "${1:-}" == "--check-tool" && $# -eq 1 ]]; then
  exit 0
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--check-tool]" >&2
  exit 2
fi

cd "$ROOT"
"$TOOL" object crd paths=./api/operations/... output:crd:artifacts:config=operator/config/crd
cp operator/config/crd/*.yaml deployments/helm/kordex-operator/crds/
cp operator/config/crd/*.yaml deployments/kustomize/base/crds/

for source in operator/config/crd/*.yaml; do
  name="${source##*/}"
  cmp -s "$source" "deployments/helm/kordex-operator/crds/$name" || {
    echo "Helm CRD copy differs from generated source: $name" >&2
    exit 1
  }
  cmp -s "$source" "deployments/kustomize/base/crds/$name" || {
    echo "Kustomize CRD copy differs from generated source: $name" >&2
    exit 1
  }
done
