#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
if [[ $# -ne 1 ]]; then
  echo "Usage: sudo $0 PINNED_SKOPEO_RPM" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer as root; it installs only the verified local Rocky Skopeo RPM." >&2
  exit 2
fi
[[ -r /etc/os-release ]] || { echo "Rocky Linux identity is unavailable" >&2; exit 2; }
os_id="$(sed -n 's/^ID="\?\([^"]*\)"\?$/\1/p' /etc/os-release | head -n 1)"
os_version="$(sed -n 's/^VERSION_ID="\?\([^"]*\)"\?$/\1/p' /etc/os-release | head -n 1)"
[[ "$os_id" == rocky && "$os_version" == 10* ]] || { echo "Pinned Skopeo installer supports Rocky Linux 10 only" >&2; exit 2; }
case "$(uname -m)" in
  x86_64) architecture=linux-amd64 ;;
  aarch64) architecture=linux-arm64 ;;
  *) echo "Pinned Skopeo package is unavailable for this architecture" >&2; exit 2 ;;
esac
python3 "$ROOT/scripts/m3_skopeo_tool.py" verify-rpm --architecture "$architecture" "$1" >/dev/null
# The artifact is already acquired and verified. Do not let installation
# refresh metadata or resolve dependencies from a public repository; if local
# dependencies are absent, fail and provision them through the approved path.
dnf install --assumeyes --disablerepo='*' "$1"
python3 "$ROOT/scripts/m3_skopeo_tool.py" verify-runtime
