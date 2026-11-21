#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/podman" <<'EOF_PODMAN'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  version) echo 'podman version 0.0.0-diagnostic-fixture' ;;
  info) echo 'rootless=true driver=overlay graphRoot=/fixture runRoot=/fixture' ;;
  build) echo 'intentional diagnostic fixture failure' >&2; exit 42 ;;
  manifest) [[ "${2:-}" == rm ]] ;;
  *) echo "unexpected fixture Podman command: $*" >&2; exit 90 ;;
esac
EOF_PODMAN
cat > "$TMP/bin/buildah" <<'EOF_BUILDAH'
#!/usr/bin/env bash
echo 'Buildah version 0.0.0-diagnostic-fixture'
EOF_BUILDAH
chmod 0755 "$TMP/bin/podman" "$TMP/bin/buildah"

set +e
output="$(PATH="$TMP/bin:$PATH" KORDEX_TEST_PODMAN=podman \
  bash "$ROOT/scripts/test-offline-oci-podman.sh" 2>&1)"
status=$?
set -e

[[ "$status" -eq 42 ]] || {
  printf 'diagnostic wrapper changed original exit: expected=42 actual=%s\n%s\n' "$status" "$output" >&2
  exit 1
}
for expected in \
  'original exit=42' \
  'building the linux/amd64 and linux/arm64 OCI test image' \
  'Last Podman command: podman build --platform linux/amd64\,linux/arm64' \
  'podman version 0.0.0-diagnostic-fixture' \
  'Buildah version 0.0.0-diagnostic-fixture' \
  'rootless=true driver=overlay' \
  'Architecture: x86_64' \
  'Filesystem and directory permissions:' \
  'OCI archive: absent'; do
  grep -Fq "$expected" <<< "$output" || {
    printf 'diagnostics omitted %q\n%s\n' "$expected" "$output" >&2
    exit 1
  }
done

echo 'offline OCI failure diagnostics preserve the command and original exit status'
