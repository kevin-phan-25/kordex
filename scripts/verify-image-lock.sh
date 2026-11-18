#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 IMAGE_DIGEST_LOCK LOCK_SIGNATURE ED25519_PUBLIC_KEY" >&2
  exit 2
fi
LOCK="$1"
SIGNATURE="$2"
PUBLIC_KEY="$3"
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }
for file in "$LOCK" "$SIGNATURE" "$PUBLIC_KEY"; do
  [[ -f "$file" && ! -L "$file" && -r "$file" ]] || { echo "image lock trust input is missing or unsafe: $file" >&2; exit 2; }
done
openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -rawin -in "$LOCK" -sigfile "$SIGNATURE"
