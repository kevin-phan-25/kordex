#!/usr/bin/env bash
set -euo pipefail

: "${KORDEX_API_URL:?set the control plane HTTPS URL}"
: "${KORDEX_ORGANIZATION_ID:?set the organization UUID}"
: "${KORDEX_CURL_CONFIG:?set to a protected curl config file with the OIDC bearer header}"
if [[ $# -ne 1 ]]; then
  echo "usage: KORDEX_API_URL=https://... KORDEX_ORGANIZATION_ID=... KORDEX_CURL_CONFIG=... $0 output.jsonl" >&2
  exit 2
fi
[[ "$KORDEX_API_URL" == https://* ]] || { echo "audit export requires HTTPS" >&2; exit 1; }
[[ "$KORDEX_ORGANIZATION_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "organization ID must be a UUID" >&2; exit 1; }
[[ -f "$KORDEX_CURL_CONFIG" ]] || { echo "curl config file not found" >&2; exit 1; }
command -v curl >/dev/null
command -v jq >/dev/null
command -v sha256sum >/dev/null

output=$1
output_dir=$(dirname -- "$output")
mkdir -p -- "$output_dir"
umask 077
temporary=$(mktemp "$output_dir/.audit-export.XXXXXX")
page=$(mktemp "$output_dir/.audit-page.XXXXXX")
trap 'rm -f -- "$temporary" "$page"' EXIT
base="${KORDEX_API_URL%/}/v1/organizations/${KORDEX_ORGANIZATION_ID}/audit"

curl --fail --silent --show-error --config "$KORDEX_CURL_CONFIG" --url "$base?order=desc&limit=1&offset=0" --output "$page"
through_id=$(jq -er '.items[0].id // 0' "$page")
after_id=0
while (( through_id > 0 && after_id < through_id )); do
  curl --fail --silent --show-error --config "$KORDEX_CURL_CONFIG" \
    --url "$base?order=asc&limit=500&offset=0&afterId=$after_id&throughId=$through_id" \
    --output "$page"
  count=$(jq -er '.items | length' "$page")
  (( count > 0 )) || break
  jq -c '.items[]' "$page" >> "$temporary"
  after_id=$(jq -er '.items[-1].id' "$page")
done

mv -- "$temporary" "$output"
trap 'rm -f -- "$page"' EXIT
sha256sum "$output" > "$output.sha256"
printf 'organization_id=%s\nthrough_event_id=%s\ncreated_at_utc=%s\n' \
  "$KORDEX_ORGANIZATION_ID" "$through_id" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$output.manifest"
chmod 600 -- "$output" "$output.sha256" "$output.manifest"
printf 'Audit export written: %s\n' "$output"
