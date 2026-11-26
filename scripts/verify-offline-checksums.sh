#!/usr/bin/env bash
set -euo pipefail

# Trusted, non-executing preflight used before the deeper offline-bundle
# checker. Accept only the canonical SHA256SUMS syntax emitted by the bundle
# builder, reject paths that escape or follow links, then verify listed bytes.
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 BUNDLE_DIRECTORY" >&2
  exit 2
fi
BUNDLE="$(cd -- "$1" && pwd -P)"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
case "$SCRIPT_DIR/" in
  "$BUNDLE/"*)
    echo "checksum verifier must come from a trusted directory outside the candidate bundle" >&2
    exit 1
    ;;
esac
MANIFEST="$BUNDLE/SHA256SUMS"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || {
  echo "SHA256SUMS must be a regular file" >&2
  exit 1
}
if ! tr -d '\000' < "$MANIFEST" | cmp -s - "$MANIFEST"; then
  echo "SHA256SUMS must not contain NUL bytes" >&2
  exit 1
fi
if find "$BUNDLE" -type l -print -quit | grep -q .; then
  echo "offline bundle must not contain symbolic links" >&2
  exit 1
fi

declare -A listed=()
while IFS= read -r line || [[ -n "$line" ]]; do
  digest="${line:0:64}"
  separator="${line:64:2}"
  relative="${line:66}"
  [[ "$digest" =~ ^[a-f0-9]{64}$ && "$separator" == "  " && "$relative" =~ ^[A-Za-z0-9._/+\-]+$ ]] || {
    echo "invalid SHA256SUMS entry" >&2
    exit 1
  }
  [[ "$relative" != /* && "$relative" != */ && "$relative" != "SHA256SUMS" && "$relative" != "SHA256SUMS.sig" ]] || {
    echo "invalid bundle path in SHA256SUMS: $relative" >&2
    exit 1
  }
  IFS=/ read -r -a path_parts <<< "$relative"
  for component in "${path_parts[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || {
      echo "invalid bundle path in SHA256SUMS: $relative" >&2
      exit 1
    }
  done
  [[ -z "${listed[$relative]:-}" ]] || {
    echo "duplicate SHA256SUMS entry: $relative" >&2
    exit 1
  }
  [[ -f "$BUNDLE/$relative" && ! -L "$BUNDLE/$relative" ]] || {
    echo "manifest path is missing or not a regular file: $relative" >&2
    exit 1
  }
  listed["$relative"]=1
done < "$MANIFEST"
(( ${#listed[@]} > 0 )) || {
  echo "SHA256SUMS contains no entries" >&2
  exit 1
}

# The full manifest checker repeats the hash after structural checks to catch
# changes made while validation was running.
(cd "$BUNDLE" && sha256sum -c -- SHA256SUMS)
