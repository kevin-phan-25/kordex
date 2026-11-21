#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BUNDLE="$TMP/bundle"
mkdir -p "$BUNDLE/scripts" "$BUNDLE/ansible-ee"
cp "$ROOT/scripts/verify-image-lock.sh" "$BUNDLE/scripts/verify-image-lock.sh"
cp "$ROOT/integrations/ansible-ee/upgrade-debian.yml" "$ROOT/integrations/ansible-ee/upgrade-rhel.yml" "$ROOT/integrations/ansible-ee/collections.lock" "$BUNDLE/ansible-ee/"
printf 'verified-bundle-fixture\n' > "$BUNDLE/SHA256SUMS"
openssl genpkey -algorithm ED25519 -out "$TMP/release-private.pem"
openssl pkey -in "$TMP/release-private.pem" -pubout -out "$TMP/release-public.pem"
LOCK="$TMP/images.tsv"
cat > "$LOCK" <<'EOF_LOCK'
agent\tregistry.dc.example:5443/kordex/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
operator\tregistry.dc.example:5443/kordex/operator@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
control-plane\tregistry.dc.example:5443/kordex/control-plane@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
dashboard\tregistry.dc.example:5443/kordex/dashboard@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
ansible-ee\tregistry.dc.example:5443/kordex/ansible-ee@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
postgres\tregistry.dc.example:5443/kordex/postgres@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
EOF_LOCK
# Convert the visible separators above into actual TSV separators.
python3 - "$LOCK" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
p.write_text(p.read_text().replace("\\t", "\t"))
PY
openssl pkeyutl -sign -rawin -inkey "$TMP/release-private.pem" -in "$LOCK" -out "$LOCK.sig"
cat > "$TMP/trusted-verifier.sh" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ -d "$1" && -r "$2" && -f "$1/SHA256SUMS" ]]
EOF_VERIFIER
chmod 0555 "$TMP/trusted-verifier.sh"
export KORDEX_RELEASE_PUBLIC_KEY="$TMP/release-public.pem"
export KORDEX_TRUSTED_BUNDLE_VERIFIER="$TMP/trusted-verifier.sh"
OUTPUT="$TMP/maintenance-policy.json"
python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$OUTPUT" \
  --family debian --os-id ubuntu --os-major 24 --os-minor 04 --name offline-workers \
  --selector operations.kordex.local/maintenance=stateless \
  --selector node-role.kubernetes.io/worker= \
  --package openssl=3.0.2-1 --package ca-certificates=20230311 \
  --execution-timeout-seconds 1800 >/dev/null
python3 - "$OUTPUT" <<'PY'
import json
import sys
from pathlib import Path
policy = json.loads(Path(sys.argv[1]).read_text())
assert policy["kind"] == "MaintenancePolicy"
assert policy["metadata"]["name"] == "offline-workers"
assert policy["spec"]["nodeSelector"]["matchLabels"]["operations.kordex.local/maintenance"] == "stateless"
plan = policy["spec"]["upgrade"]
assert plan["executionEnvironment"].endswith("@sha256:" + "e" * 64)
assert plan["playbookCatalogId"] == "kordex.os-upgrade.debian.v2"
assert (plan["osId"], plan["osMajor"], plan["osMinor"]) == ("ubuntu", "24", "04")
assert plan["playbookDigest"] and plan["collectionsDigest"]
assert plan["actionMarkerVersion"] == 1 and plan["maxAttempts"] == 1
assert plan["executionTimeout"] == 1_800_000_000_000
assert [item["name"] for item in plan["packages"]] == ["ca-certificates", "openssl"]
PY
python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/debian13-policy.json" \
  --family debian --os-id debian --os-major 13 --os-point-release 13.8 --name debian13-workers \
  --selector pool=workers --package openssl=3.0.2-1 >/dev/null
python3 - "$TMP/debian13-policy.json" <<'PY'
import json
import sys
from pathlib import Path
plan = json.loads(Path(sys.argv[1]).read_text())["spec"]["upgrade"]
assert (plan["osId"], plan["osMajor"], plan["osMinor"], plan["osPointRelease"]) == ("debian", "13", "", "13.8")
PY
if python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/debian13-missing-point.json" \
  --family debian --os-id debian --os-major 13 --name missing-point --selector pool=workers \
  --package openssl=3.0.2-1 >/dev/null 2>&1; then
  echo 'accepted Debian 13 policy without selected stable point release' >&2; exit 1
fi
python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/offline-artifact-policy.json" \
  --family debian --os-id ubuntu --os-major 24 --os-minor 04 --name offline-artifacts --selector pool=workers \
  --artifact-mode OfflineArtifacts \
  --package openssl=3.0.2-1 --artifact-sha256 openssl=$(printf 'a%.0s' {1..64}) \
  --package ca-certificates=20230311 --artifact-sha256 ca-certificates=$(printf 'b%.0s' {1..64}) >/dev/null
python3 - "$TMP/offline-artifact-policy.json" <<'PY'
import json
import sys
from pathlib import Path
plan = json.loads(Path(sys.argv[1]).read_text())["spec"]["upgrade"]
assert plan["schemaVersion"] == 2
assert plan["artifactMode"] == "OfflineArtifacts"
assert all(len(item["artifactSHA256"]) == 64 for item in plan["packages"])
assert {item["name"]: item["artifactSHA256"] for item in plan["packages"]} == {
    "ca-certificates": "b" * 64,
    "openssl": "a" * 64,
}
PY
if python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/missing-artifact-policy.json" \
  --family debian --os-id ubuntu --os-major 24 --os-minor 04 --name missing-artifact --selector pool=workers --artifact-mode OfflineArtifacts \
  --package openssl=3.0.2-1 >/dev/null 2>&1; then
  echo 'accepted offline package plan without an artifact digest' >&2; exit 1
fi
if python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/unexpected-artifact-policy.json" \
  --family debian --os-id ubuntu --os-major 24 --os-minor 04 --name unexpected-artifact --selector pool=workers --package openssl=3.0.2-1 \
  --artifact-sha256 openssl=$(printf 'a%.0s' {1..64}) >/dev/null 2>&1; then
  echo 'accepted package artifact digest in repository mode' >&2; exit 1
fi
if python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/bad-policy.json" \
  --family debian --os-id ubuntu --os-major 24 --os-minor 04 --name bad-workers --selector pool=workers --package openssl=latest >/dev/null 2>&1; then
  echo 'accepted floating package version' >&2; exit 1
fi
if python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/bad-kernel.json" \
  --family debian --os-id ubuntu --os-major 24 --os-minor 04 --name bad-kernel --selector pool=workers --package linux-image-amd64=6.1.0-1 >/dev/null 2>&1; then
  echo 'accepted kernel plan without a reboot policy and expected kernel' >&2; exit 1
fi
if python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/bad-rpm.json" \
  --family rhel --os-id rhel --os-major 9 --os-minor 9 --os-point-release 9.9 --name bad-rpm --selector pool=workers --package kernel=6.1.0 >/dev/null 2>&1; then
  echo 'accepted RPM package pin without a release component' >&2; exit 1
fi
python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/rhel-policy.json" \
  --family rhel --os-id rhel --os-major 9 --os-minor 9 --os-point-release 9.9 --name rhel-kernel-workers --selector pool=workers \
  --package kernel=6.1.0-10.el9 --reboot IfNeeded \
  --expected-kernel-version 6.1.0-10.el9.x86_64 >/dev/null
python3 - "$TMP/rhel-policy.json" <<'PY'
import json
import sys
from pathlib import Path
plan = json.loads(Path(sys.argv[1]).read_text())["spec"]["upgrade"]
assert plan["osFamily"] == "rhel"
assert (plan["osId"], plan["osMajor"], plan["osMinor"], plan["osPointRelease"]) == ("rhel", "9", "9", "9.9")
assert plan["playbookCatalogId"] == "kordex.os-upgrade.rhel.v1"
assert plan["reboot"] == "IfNeeded"
assert plan["expectedKernelVersion"] == "6.1.0-10.el9.x86_64"
PY
if python3 "$ROOT/scripts/generate-offline-upgrade-policy.py" "$BUNDLE" "$LOCK" "$TMP/unlisted-os.json" \
  --family rhel --os-id rhel --os-major 9 --os-minor 7 --os-point-release 9.7 --name unlisted-os --selector pool=workers --package openssl=3.0.2-1 >/dev/null 2>&1; then
  echo 'accepted an unlisted OS release' >&2; exit 1
fi
if [[ "${KORDEX_TEST_GO_CONTRACT:-false}" == true ]]; then
  (cd "$ROOT/api" && KORDEX_GENERATED_OFFLINE_POLICY_DIR="$TMP" go test ./protocol -run '^TestGeneratedOfflineUpgradePolicyContract$' -count=1)
fi
if [[ -e "$TMP/bad-policy.json" || -e "$TMP/bad-kernel.json" || -e "$TMP/bad-rpm.json" ]]; then
  echo 'invalid policy generation left an output file' >&2; exit 1
fi
echo 'Offline upgrade policy generator tests passed.'
