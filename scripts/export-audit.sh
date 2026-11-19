#!/usr/bin/env bash
set -euo pipefail

: "${KORDEX_API_URL:?set the control plane HTTPS URL}"
: "${KORDEX_ORGANIZATION_ID:?set the organization UUID}"
: "${KORDEX_CURL_CONFIG:?set to a protected curl config file with the OIDC bearer header}"
: "${KORDEX_AUDIT_SIGNING_KEY_FILE:?set to the protected Ed25519 audit signing key file}"
if [[ $# -ne 1 ]]; then
  echo "usage: KORDEX_API_URL=https://... KORDEX_ORGANIZATION_ID=... KORDEX_CURL_CONFIG=... $0 output.jsonl" >&2
  exit 2
fi
[[ "$KORDEX_API_URL" == https://* ]] || { echo "audit export requires HTTPS" >&2; exit 1; }
[[ "$KORDEX_ORGANIZATION_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "organization ID must be a UUID" >&2; exit 1; }
[[ -f "$KORDEX_CURL_CONFIG" ]] || { echo "curl config file not found" >&2; exit 1; }
curl_config_mode=$(stat -c '%a' -- "$KORDEX_CURL_CONFIG")
(( (8#$curl_config_mode & 077) == 0 )) || { echo "curl config file must not be accessible by group or other users" >&2; exit 1; }
command -v curl >/dev/null
command -v jq >/dev/null
command -v sha256sum >/dev/null
audit_signer=${KORDEX_AUDIT_SIGNER:-kordex-audit-sign}
command -v "$audit_signer" >/dev/null

output=$1
output_dir=$(dirname -- "$output")
mkdir -p -- "$output_dir"
umask 077
temporary_dir=$(mktemp -d "$output_dir/.audit-export.XXXXXX")
temporary="$temporary_dir/export.jsonl"
page="$temporary_dir/page.json"
checksum_temporary="$temporary_dir/export.sha256"
manifest_temporary="$temporary_dir/export.manifest"
published=()
cleanup() {
  status=$?
  trap - EXIT
  rm -rf -- "$temporary_dir"
  if (( status != 0 )); then
    for path in "${published[@]}"; do rm -f -- "$path"; done
  fi
  exit "$status"
}
trap cleanup EXIT
base="${KORDEX_API_URL%/}/v1/organizations/${KORDEX_ORGANIZATION_ID}/audit"

curl --fail --silent --show-error --config "$KORDEX_CURL_CONFIG" --url "$base?order=desc&limit=1&offset=0" --output "$page"
through_id=$(jq -er '.items[0].id // 0' "$page")
(( through_id > 0 )) || { echo "organization has no audit events to export" >&2; exit 1; }
after_id=0
record_count=0
while (( through_id > 0 && after_id < through_id )); do
  curl --fail --silent --show-error --config "$KORDEX_CURL_CONFIG" \
    --url "$base?order=asc&limit=500&offset=0&afterId=$after_id&throughId=$through_id" \
    --output "$page"
  count=$(jq -er '.items | if type == "array" then length else error end' "$page")
  (( count > 0 )) || { echo "audit export ended before checkpoint $through_id" >&2; exit 1; }
  first_id=$(jq -er '.items[0].id | numbers' "$page")
  next_id=$(jq -er '.items[-1].id | numbers' "$page")
  (( first_id > after_id && next_id >= first_id && next_id <= through_id )) || {
    echo "audit export page has invalid or nonadvancing event IDs" >&2
    exit 1
  }
  jq -e --argjson after "$after_id" --argjson through "$through_id" '
    [.items[].id] as $ids |
    all(range(1; ($ids | length)); $ids[.] > $ids[.-1]) and
    all($ids[]; . > $after and . <= $through)
  ' "$page" >/dev/null || { echo "audit export page IDs are not strictly ascending within the checkpoint" >&2; exit 1; }
  jq -c '.items[]' "$page" >> "$temporary"
  after_id=$next_id
  record_count=$((record_count + count))
  (( record_count <= 100000 )) || { echo "audit export exceeds the 100000-record limit" >&2; exit 1; }
done
(( after_id == through_id )) || { echo "audit export did not reach checkpoint $through_id" >&2; exit 1; }

checksum=$(sha256sum "$temporary" | awk '{print $1}')
printf '%s  %s\n' "$checksum" "$(basename -- "$output")" > "$checksum_temporary"
chmod 600 -- "$temporary" "$checksum_temporary"
"$audit_signer" -input "$temporary" -organization-id "$KORDEX_ORGANIZATION_ID" -through-id "$through_id" -output "$manifest_temporary"

for destination in "$output" "$output.sha256" "$output.manifest"; do
  [[ ! -e "$destination" && ! -L "$destination" ]] || {
    echo "refusing to replace existing audit export artifact: $destination" >&2
    exit 1
  }
done
ln -- "$temporary" "$output"
published+=("$output")
ln -- "$checksum_temporary" "$output.sha256"
published+=("$output.sha256")
ln -- "$manifest_temporary" "$output.manifest"
published+=("$output.manifest")
printf 'Audit export written: %s\n' "$output"
