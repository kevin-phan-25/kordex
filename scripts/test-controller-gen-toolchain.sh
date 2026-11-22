#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/generate-api-crds.sh"
EXPECTED="$(awk '($1 == "require" && $2 == "sigs.k8s.io/controller-tools") { print $3; exit } $1 == "sigs.k8s.io/controller-tools" { print $2; exit }' "$ROOT/tools/controller-gen/go.mod")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/matching-controller-gen" <<EOF
#!/usr/bin/env sh
if [ "\$1" = "--version" ]; then
  printf 'Version: %s\\n' '$EXPECTED'
  exit 0
fi
exit 91
EOF
chmod 700 "$TMP/matching-controller-gen"
CONTROLLER_GEN="$TMP/matching-controller-gen" "$SCRIPT" --check-tool

cat >"$TMP/wrong-controller-gen" <<'EOF'
#!/usr/bin/env sh
if [ "$1" = "--version" ]; then
  printf 'Version: v0.0.0\n'
  exit 0
fi
exit 91
EOF
chmod 700 "$TMP/wrong-controller-gen"
if CONTROLLER_GEN="$TMP/wrong-controller-gen" "$SCRIPT" --check-tool >"$TMP/out" 2>&1; then
  echo "unexpectedly accepted a mismatched controller-gen version" >&2
  exit 1
fi
grep -q "controller-gen version mismatch" "$TMP/out"

if CONTROLLER_GEN="$TMP/absent-controller-gen" "$SCRIPT" --check-tool >"$TMP/out" 2>&1; then
  echo "unexpectedly accepted a missing controller-gen executable" >&2
  exit 1
fi
grep -q "install it explicitly with 'make install-controller-gen'" "$TMP/out"

echo "controller-gen toolchain guard tests passed"
