#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/output"
go build -o "$temporary/bin/kordex-audit-sign" ./control-plane/cmd/kordex-audit-sign
go build -o "$temporary/bin/kordex-audit-verify" ./control-plane/cmd/kordex-audit-verify
go build -o "$temporary/bin/kordex-keygen" ./api/cmd/kordex-keygen
"$temporary/bin/kordex-keygen" -private-file "$temporary/audit-key" -public-file "$temporary/audit-trust.json" >/dev/null
export KORDEX_AUDIT_SIGNING_KEY_FILE="$temporary/audit-key"
export KORDEX_AUDIT_TRUST_BUNDLE="$temporary/audit-trust.json"
export KORDEX_AUDIT_SIGNER="$temporary/bin/kordex-audit-sign"
export KORDEX_AUDIT_VERIFY="$temporary/bin/kordex-audit-verify"
touch "$temporary/curl.conf"
chmod 600 "$temporary/curl.conf"
touch "$temporary/insecure-curl.conf"
chmod 644 "$temporary/insecure-curl.conf"

cat > "$temporary/bin/curl" <<'MOCK_CURL'
#!/usr/bin/env bash
set -euo pipefail
url=
output=
while (($#)); do
  case "$1" in
    --url) url=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    --config) shift 2 ;;
    --fail|--silent|--show-error) shift ;;
    *) echo "unexpected curl argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$url" && -n "$output" ]]
if [[ "$url" == *"order=desc"* ]]; then
  cat > "$output" <<'JSON'
{"items":[{"id":9,"organizationId":"12345678-1234-1234-1234-123456789abc"}]}
JSON
  exit
fi
[[ "$url" == *"order=asc"* ]]
cursor=0
if [[ "$url" =~ afterId=([0-9]+) ]]; then cursor=${BASH_REMATCH[1]}; fi
if [[ "${KORDEX_TEST_EMPTY_PAGE_AFTER:-}" == "$cursor" ]]; then
  cat > "$output" <<'JSON'
{"items":[]}
JSON
elif [[ "$cursor" == 0 ]]; then
  cat > "$output" <<'JSON'
{"items":[{"id":1,"organizationId":"12345678-1234-1234-1234-123456789abc","actor":"test","action":"first","resourceId":"r1","requestId":"12345678-1234-1234-1234-123456789abc","occurredAt":"2026-11-19T00:00:01Z","metadata":{}},{"id":4,"organizationId":"12345678-1234-1234-1234-123456789abc","actor":"test","action":"second","resourceId":"r2","requestId":"12345678-1234-1234-1234-123456789abc","occurredAt":"2026-11-19T00:00:04Z","metadata":{}}]}
JSON
elif [[ "$cursor" == 4 ]]; then
  cat > "$output" <<'JSON'
{"items":[{"id":9,"organizationId":"12345678-1234-1234-1234-123456789abc","actor":"test","action":"last","resourceId":"r3","requestId":"12345678-1234-1234-1234-123456789abc","occurredAt":"2026-11-19T00:00:09Z","metadata":{}}]}
JSON
else
  echo "unexpected audit cursor: $cursor" >&2
  exit 2
fi
MOCK_CURL
chmod +x "$temporary/bin/curl"

export PATH="$temporary/bin:$PATH"
export KORDEX_API_URL=https://kordex.example.test
export KORDEX_ORGANIZATION_ID=12345678-1234-1234-1234-123456789abc
export KORDEX_CURL_CONFIG="$temporary/curl.conf"

if KORDEX_CURL_CONFIG="$temporary/insecure-curl.conf" bash "$root/scripts/export-audit.sh" "$temporary/output/insecure.jsonl" 2>"$temporary/insecure.err"; then
  echo 'export unexpectedly accepted a curl config readable by other users' >&2
  exit 1
fi
grep -q 'curl config file must not be accessible' "$temporary/insecure.err"
[[ ! -e "$temporary/output/insecure.jsonl" ]]

output="$temporary/output/audit.jsonl"
bash "$root/scripts/export-audit.sh" "$output"
[[ $(wc -l < "$output") -eq 3 ]]
[[ "$(stat -c '%a' "$output")" == 600 ]]
(cd "$temporary/output" && sha256sum -c audit.jsonl.sha256)
jq -e --arg org "$KORDEX_ORGANIZATION_ID" --arg digest "$(sha256sum "$output" | awk '{print $1}')" '
  .format == "kordex-audit-checkpoint-v1" and .organizationId == $org and
  .throughEventId == 9 and .recordCount == 3 and .recordsSha256 == $digest and
  (.signingKeyId | length) == 64 and (.signature | length) > 0
' "$output.manifest" >/dev/null
"$KORDEX_AUDIT_VERIFY" -input "$output" -checkpoint "$output.manifest" -trust-bundle "$KORDEX_AUDIT_TRUST_BUNDLE" -through-id 9
sed 's/"action":"first"/"action":"tampered"/' "$output" > "$temporary/output/tampered.jsonl"
if "$KORDEX_AUDIT_VERIFY" -input "$temporary/output/tampered.jsonl" -checkpoint "$output.manifest" -trust-bundle "$KORDEX_AUDIT_TRUST_BUNDLE" -through-id 9 2>"$temporary/tamper.err"; then
  echo 'signed checkpoint unexpectedly accepted modified tenant audit records' >&2
  exit 1
fi
grep -q 'SHA-256 mismatch' "$temporary/tamper.err"
[[ $(find "$temporary/output" -maxdepth 1 -name '.audit-export.*' | wc -l) -eq 0 ]]

before=$(sha256sum "$output" "$output.sha256" "$output.manifest")
if bash "$root/scripts/export-audit.sh" "$output" 2>"$temporary/overwrite.err"; then
  echo 'export unexpectedly overwrote existing evidence' >&2
  exit 1
fi
grep -q 'refusing to replace existing audit export artifact' "$temporary/overwrite.err"
[[ "$(sha256sum "$output" "$output.sha256" "$output.manifest")" == "$before" ]]

incomplete="$temporary/output/incomplete.jsonl"
if KORDEX_TEST_EMPTY_PAGE_AFTER=4 bash "$root/scripts/export-audit.sh" "$incomplete" 2>"$temporary/incomplete.err"; then
  echo 'export unexpectedly accepted an incomplete page sequence' >&2
  exit 1
fi
grep -q 'audit export ended before checkpoint 9' "$temporary/incomplete.err"
[[ ! -e "$incomplete" && ! -e "$incomplete.sha256" && ! -e "$incomplete.manifest" ]]
[[ $(find "$temporary/output" -maxdepth 1 -name '.audit-export.*' | wc -l) -eq 0 ]]

echo 'Audit export checkpoint and publication guards passed.'
