#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
KUBECTL=${KUBECTL:-kubectl}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

python3 - "$ROOT/deployments/kustomize" "$TMP/kustomize" <<'PY'
import shutil
import sys
from pathlib import Path

source_root, target_root = map(Path, sys.argv[1:])
paths = (
    "base",
    "components/agent",
    "components/operator",
    "overlays/self-managed",
    "overlays/self-managed-production",
    "hub/base",
    "hub/overlays/self-hosted",
    "hub/overlays/self-hosted-production",
)
for relative in paths:
    source = source_root / relative
    target = target_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    ignore = (lambda _directory, names: {"keys.json"} & set(names)) if relative == "overlays/self-managed" else None
    shutil.copytree(source, target, ignore=ignore)
PY
# The self-managed overlay references customer trust material. Keep this test
# isolated from any ignored operator key file in the working tree.
printf '{"test-key":"public-test-key-only"}\n' > "$TMP/kustomize/overlays/self-managed/keys.json"

python3 - "$TMP/kustomize" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
test_digest = "a" * 64
for relative, count in (
    ("hub/overlays/self-hosted-production/kustomization.yaml", 2),
    ("overlays/self-managed-production/kustomization.yaml", 2),
):
    path = root / relative
    content = path.read_text()
    if content.count("digest: sha256:" + "0" * 64) != count or "newTag:" in content:
        raise SystemExit(f"{path}: production overlay must use only explicit digest pins, without tag fallback")
    path.write_text(content.replace("sha256:" + "0" * 64, "sha256:" + test_digest))
PY

"$KUBECTL" kustomize "$TMP/kustomize/hub/overlays/self-hosted-production" > "$TMP/hub.yaml"
"$KUBECTL" kustomize "$TMP/kustomize/overlays/self-managed-production" > "$TMP/spoke.yaml"

validate_images() {
  local manifest=$1 expected_control_plane=$2 expected_dashboard=$3 expected_agent=$4 expected_operator=$5
  python3 - "$manifest" "$expected_control_plane" "$expected_dashboard" "$expected_agent" "$expected_operator" <<'PY'
import re
import sys
from pathlib import Path

path, expected_control_plane, expected_dashboard, expected_agent, expected_operator = sys.argv[1:]
images = []
for line in Path(path).read_text().splitlines():
    stripped = line.strip()
    if stripped.startswith("image:"):
        value = stripped.removeprefix("image:").strip().strip("\"'")
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", value):
            raise SystemExit(f"{path}: non-immutable production image reference: {value}")
        if value.endswith("@sha256:" + "0" * 64):
            raise SystemExit(f"{path}: unresolved example image digest: {value}")
        images.append(value)

expected = {
    "control-plane": expected_control_plane,
    "dashboard": expected_dashboard,
    "agent": expected_agent,
    "operator": expected_operator,
}
for component, count in expected.items():
    actual = sum(f"/kordex/{component}@sha256:" in image for image in images)
    if actual != int(count):
        raise SystemExit(f"{path}: expected {count} pinned {component} image(s), found {actual}: {images}")
if len(images) != sum(map(int, expected.values())):
    raise SystemExit(f"{path}: unexpected workload image set: {images}")
PY
}

validate_images "$TMP/hub.yaml" 2 1 0 0
validate_images "$TMP/spoke.yaml" 0 0 1 1
echo 'Kustomize production overlays render digest-pinned management-plane and spoke images.'
