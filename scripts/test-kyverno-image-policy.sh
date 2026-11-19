#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

VERSION=v1.18.0
ARCHIVE=kyverno-cli_v1.18.0_linux_x86_64.tar.gz
ARCHIVE_SHA256=3aa7b7aa68732fd6bc5732f1030d0ed12e1b0ffe7dbac5f5aa21fd8695718904
curl -fsSLo "$TMP/$ARCHIVE" "https://github.com/kyverno/kyverno/releases/download/$VERSION/$ARCHIVE"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$TMP/$ARCHIVE" | sha256sum --check --status
tar -xzf "$TMP/$ARCHIVE" -C "$TMP" kyverno
version_output="$("$TMP/kyverno" version)"
grep -Fq 'Version: 1.18.0' <<< "$version_output"

python3 - "$ROOT" "$TMP" <<'PY'
from pathlib import Path
import sys
import yaml

root, temp = map(Path, sys.argv[1:])
policy = yaml.safe_load((root / "deployments/policies/kyverno/kordex-release-images.yaml").read_text())
policy["spec"]["rules"][0]["verifyImages"][0]["imageReferences"] = [
    "ghcr.io/kyverno/test-verify-image*",
]
(temp / "test-policy.yaml").write_text(yaml.safe_dump(policy, sort_keys=False))
PY

cat > "$TMP/unsigned-pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: unsigned-image
  namespace: default
spec:
  containers:
    - name: app
      image: ghcr.io/kyverno/test-verify-image@sha256:74a98f0e4d750c9052f092a7f7a72de7b20f94f176a490088f7a744c76c53ea5
EOF

if "$TMP/kyverno" apply "$TMP/test-policy.yaml" --resource "$TMP/unsigned-pod.yaml" >"$TMP/unsigned.out" 2>&1; then
  cat "$TMP/unsigned.out" >&2
  echo 'Kyverno accepted the unsigned matching image' >&2
  exit 1
fi
grep -Fq 'pass: 0, fail:' "$TMP/unsigned.out" || {
  cat "$TMP/unsigned.out" >&2
  echo 'Kyverno did not report a policy denial for the unsigned matching image' >&2
  exit 1
}

cat > "$TMP/unrelated-pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: unrelated-image
  namespace: default
spec:
  containers:
    - name: app
      image: registry.example.invalid/team/app:dev
EOF
"$TMP/kyverno" apply "$ROOT/deployments/policies/kyverno/kordex-release-images.yaml" \
  --resource "$TMP/unrelated-pod.yaml" >"$TMP/unrelated.out" 2>&1
grep -Fq 'pass: 0, fail: 0' "$TMP/unrelated.out"
echo 'Kyverno CLI denied the unsigned matching digest and ignored unrelated images.'
