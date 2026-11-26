#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BUNDLE="$TMP/bundle"
mkdir -p "$BUNDLE/images" "$BUNDLE/bin/linux-amd64" "$BUNDLE/bin/linux-arm64" \
  "$BUNDLE/bin/tools/linux-amd64" "$BUNDLE/bin/tools/linux-arm64" "$BUNDLE/bin/tools/LICENSES" \
  "$BUNDLE/charts" "$BUNDLE/manifests/kustomize/overlays/self-managed" \
  "$BUNDLE/manifests/kustomize/overlays/self-managed-private-ca" \
  "$BUNDLE/manifests/kustomize/components/private-management-ca" \
  "$BUNDLE/manifests/kustomize/base/crds" "$BUNDLE/ansible-ee" "$BUNDLE/docs" \
  "$BUNDLE/helm-values" "$BUNDLE/scripts" "$BUNDLE/qualification"
images=(control-plane agent operator dashboard ansible-ee postgres)
printf 'control-plane\tlocalhost/kordex/control-plane:0.8.0\nagent\tlocalhost/kordex/agent:0.8.0\noperator\tlocalhost/kordex/operator:0.8.0\ndashboard\tlocalhost/kordex/dashboard:0.8.0\nansible-ee\tlocalhost/kordex/ansible-ee:0.8.0\npostgres\tlocalhost/kordex/postgres:17-alpine\n' > "$BUNDLE/images.txt"
printf 'linux/amd64,linux/arm64\n' > "$BUNDLE/images/platforms.txt"
: > "$BUNDLE/images/image-metadata.tsv"
for image in control-plane agent operator dashboard ansible-ee postgres; do
  if [[ "$image" == postgres ]]; then
    archive="$BUNDLE/images/postgres-17-alpine.oci.tar"
  else
    archive="$BUNDLE/images/${image}-0.8.0.oci.tar"
  fi
  if [[ -n "${KORDEX_TEST_REAL_OCI_ARCHIVE:-}" ]]; then
    cp "$KORDEX_TEST_REAL_OCI_ARCHIVE" "$archive"
    image_metadata="$(python3 - "$archive" "${KORDEX_TEST_REAL_OCI_INDEX_DIGEST:-}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
recorded_digest = sys.argv[2]
with tarfile.open(archive, "r:*") as bundle:
    index_raw = bundle.extractfile("index.json").read()
index = json.loads(index_raw)
if recorded_digest:
    if re.fullmatch(r"sha256:[a-f0-9]{64}", recorded_digest) is None:
        raise SystemExit("Podman reported an invalid OCI index digest")
    digest = recorded_digest
elif len(index["manifests"]) == 1 \
        and index["manifests"][0].get("mediaType") == "application/vnd.oci.image.index.v1+json" \
        and "platform" not in index["manifests"][0]:
    digest = index["manifests"][0]["digest"]
else:
    digest = "sha256:" + hashlib.sha256(index_raw).hexdigest()
print(digest + "\t" + hashlib.sha256(archive.read_bytes()).hexdigest())
PY
)"
  else
    image_metadata="$(python3 - "$archive" <<'PY'
import hashlib
import io
import json
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
blobs = []
members = []
for architecture in ("amd64", "arm64"):
    config = json.dumps({"architecture": architecture, "os": "linux"}, separators=(",", ":")).encode()
    config_digest = hashlib.sha256(config).hexdigest()
    layer = b"offline bundle OCI layer fixture"
    layer_digest = hashlib.sha256(layer).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + config_digest, "size": len(config)}, "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:" + layer_digest, "size": len(layer)}]}, separators=(",", ":")).encode()
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    blobs.extend(((config_digest, config), (manifest_digest, manifest), (layer_digest, layer)))
    members.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + manifest_digest, "size": len(manifest), "platform": {"os": "linux", "architecture": architecture}})
inner_index = json.dumps({"schemaVersion": 2, "manifests": members}, separators=(",", ":")).encode()
inner_digest = hashlib.sha256(inner_index).hexdigest()
blobs.append((inner_digest, inner_index))
index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + inner_digest, "size": len(inner_index)}]}, separators=(",", ":")).encode()
with tarfile.open(archive, "w") as bundle:
    for digest, content in dict(blobs).items():
        info = tarfile.TarInfo("blobs/sha256/" + digest)
        info.size = len(content)
        bundle.addfile(info, io.BytesIO(content))
    info = tarfile.TarInfo("index.json")
    info.size = len(index)
    bundle.addfile(info, io.BytesIO(index))
print("sha256:" + inner_digest + "\t" + hashlib.sha256(archive.read_bytes()).hexdigest())
PY
)"
  fi
  index_digest="${image_metadata%%$'\t'*}"
  archive_digest="${image_metadata#*$'\t'}"
  image_reference="localhost/kordex/$image:0.8.0"
  [[ "$image" == postgres ]] && image_reference="localhost/kordex/postgres:17-alpine"
  printf '%s\t%s\t%s\t%s\tlinux/amd64,linux/arm64\n' "$image" "$image_reference" "$index_digest" "$archive_digest" >> "$BUNDLE/images/image-metadata.tsv"
done
for arch in amd64 arm64; do
  for binary in kordex kordex-scheduler kordex-agent kordex-operator kordex-keygen kordex-audit-verify kordex-audit-sign kordex-security-audit-export; do
    python3 - "$BUNDLE/bin/linux-$arch/$binary" "$arch" <<'PY'
import pathlib
import struct
import sys

path, arch = sys.argv[1:]
header = bytearray(64)
header[:7] = b"\x7fELF\x02\x01\x01"
struct.pack_into("<HHI", header, 16, 2, {"amd64": 62, "arm64": 183}[arch], 1)
struct.pack_into("<H", header, 52, 64)
pathlib.Path(path).write_bytes(header)
PY
    chmod 0755 "$BUNDLE/bin/linux-$arch/$binary"
  done
  for tool in helm kubectl; do
    python3 - "$BUNDLE/bin/tools/linux-$arch/$tool" "$arch" <<'PY'
import pathlib
import struct
import sys

path, arch = sys.argv[1:]
header = bytearray(64)
header[:7] = b"\x7fELF\x02\x01\x01"
struct.pack_into("<HHI", header, 16, 2, {"amd64": 62, "arm64": 183}[arch], 1)
struct.pack_into("<H", header, 52, 64)
pathlib.Path(path).write_bytes(header)
PY
    chmod 0755 "$BUNDLE/bin/tools/linux-$arch/$tool"
  done
done
printf 'Helm license fixture\n' > "$BUNDLE/bin/tools/LICENSES/helm.txt"
printf 'Kubernetes license fixture\n' > "$BUNDLE/bin/tools/LICENSES/kubernetes.txt"
openssl genpkey -algorithm ED25519 -out "$TMP/tools-private.pem"
openssl pkey -in "$TMP/tools-private.pem" -pubout -out "$BUNDLE/bin/tools/offline-tools.signer.pub"
printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > "$BUNDLE/bin/tools/offline-tools.helm-signers.txt"
: > "$BUNDLE/bin/tools/offline-tools.tsv"
for arch in linux-amd64 linux-arm64; do
  for tool in helm kubectl; do
    digest="$(sha256sum "$BUNDLE/bin/tools/$arch/$tool" | awk '{print $1}')"
    if [[ "$tool" == helm ]]; then
      printf '%s\tv1.0.0\t%s\t%s\t%s\thttps://get.helm.sh/helm-v1.0.0-%s.tar.gz\topenpgp\t%s\n' "$tool" "$arch" "$digest" "$digest" "$arch" 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >> "$BUNDLE/bin/tools/offline-tools.tsv"
    else
      tool_arch="${arch#linux-}"
      printf '%s\tv1.0.0\t%s\t%s\t%s\thttps://dl.k8s.io/release/v1.0.0/bin/linux/%s/kubectl\tcosign-keyless\t%s\n' "$tool" "$arch" "$digest" "$digest" "$tool_arch" 'krel-staging@k8s-releng-prod.iam.gserviceaccount.com|https://accounts.google.com' >> "$BUNDLE/bin/tools/offline-tools.tsv"
    fi
  done
done
openssl pkeyutl -sign -rawin -inkey "$TMP/tools-private.pem" -in "$BUNDLE/bin/tools/offline-tools.tsv" -out "$BUNDLE/bin/tools/offline-tools.tsv.sig"
cp "$BUNDLE/bin/tools/offline-tools.signer.pub" "$TMP/tools-trusted-public.pem"
cp "$BUNDLE/bin/tools/offline-tools.helm-signers.txt" "$TMP/tools-trusted-helm-signers.txt"
export KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY="$TMP/tools-trusted-public.pem"
export KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE="$TMP/tools-trusted-helm-signers.txt"
for chart in agent operator control-plane dashboard; do
  python3 - "$BUNDLE/charts/kordex-$chart-0.8.0.tgz" "$chart" <<'PY'
import io
import sys
import tarfile

path, component = sys.argv[1:]
name = "kordex-" + component
members = {
    name + "/Chart.yaml": f"apiVersion: v2\nname: {name}\nversion: 0.8.0\n",
    name + "/values.yaml": "image: {}\n",
    name + "/templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
}
with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
    for member_name, content in members.items():
        data = content.encode()
        info = tarfile.TarInfo(member_name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
PY
done
printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n' > "$BUNDLE/manifests/kustomize/overlays/self-managed/kustomization.yaml"
printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n' > "$BUNDLE/manifests/kustomize/overlays/self-managed-private-ca/kustomization.yaml"
printf 'apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\n' > "$BUNDLE/manifests/kustomize/components/private-management-ca/kustomization.yaml"
for crd in maintenancecampaigns maintenancepolicies nodemaintenances; do
  printf 'apiVersion: apiextensions.k8s.io/v1\n' > "$BUNDLE/manifests/kustomize/base/crds/operations.kordex.local_$crd.yaml"
done
for asset in Containerfile README.md build-ee.sh upgrade.py upgrade-debian.yml upgrade-rhel.yml upgrade_test.py collections.lock; do
  printf 'test Ansible EE asset\n' > "$BUNDLE/ansible-ee/$asset"
done
printf 'air-gapped deployment guide\n' > "$BUNDLE/docs/air-gapped-deployment.md"
printf 'architecture\n' > "$BUNDLE/docs/architecture.md"
printf 'security\n' > "$BUNDLE/docs/security.md"
printf 'upgrade qualification procedure\n' > "$BUNDLE/docs/production-upgrade-requirements.md"
printf 'guarded qualification runner\n' > "$BUNDLE/qualification/self_managed_upgrade_smoke.py"
printf 'compatibility entrypoint\n' > "$BUNDLE/qualification/debian_upgrade_smoke.py"
printf '{"cases":[]}\n' > "$BUNDLE/qualification/host_upgrade_failure_matrix.json"
printf 'evidence verifier\n' > "$BUNDLE/qualification/verify-host-upgrade-qualification.py"
printf 'release instructions\n' > "$BUNDLE/README.md"
for asset in build-offline-bundle.sh push-offline-bundle.sh configure-offline-kustomize.sh \
  configure-offline-helm.sh verify-image-lock.sh test-push-offline-bundle.sh test-offline-oci-podman.sh \
  generate-offline-upgrade-policy.py test-generate-offline-upgrade-policy.sh \
  test-configure-offline-kustomize.sh test-configure-offline-helm.sh \
  sign-offline-bundle.sh verify-offline-bundle.sh verify-offline-checksums.sh check-offline-manifest.sh; do
  printf '#!/bin/sh\nexit 0\n' > "$BUNDLE/scripts/$asset"
done
cp "$ROOT/scripts/verify-offline-tools-lock.sh" "$BUNDLE/scripts/verify-offline-tools-lock.sh"
cp "$ROOT/scripts/acquire-offline-tools.sh" "$BUNDLE/scripts/acquire-offline-tools.sh"
cp "$ROOT/scripts/build-offline-package-artifacts.py" \
  "$ROOT/scripts/install-offline-package-artifacts.py" \
  "$ROOT/scripts/test_offline_package_artifacts.py" "$BUNDLE/scripts/"
printf 'agent values\n' > "$BUNDLE/helm-values/kordex-agent.yaml"
for component in operator control-plane dashboard; do
  printf '%s values\n' "$component" > "$BUNDLE/helm-values/kordex-$component.yaml"
done
printf 'versioned test image archive\n' > "$BUNDLE/images/operator+build.oci.tar"
printf 'test install note\n' > "$BUNDLE/docs/install.md"
openssl genpkey -algorithm ED25519 -out "$TMP/private.pem"
openssl pkey -in "$TMP/private.pem" -pubout -out "$TMP/public.pem"
(cd "$BUNDLE" && find images bin charts manifests ansible-ee docs helm-values scripts qualification README.md images.txt -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" -in "$BUNDLE/SHA256SUMS" -out "$BUNDLE/SHA256SUMS.sig"

resign_bundle() {
  local directory="$1"
  (cd "$directory" && find images bin charts manifests ansible-ee docs helm-values scripts qualification README.md images.txt -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" -in "$directory/SHA256SUMS" -out "$directory/SHA256SUMS.sig"
}

"$ROOT/scripts/verify-offline-bundle.sh" "$BUNDLE" "$TMP/public.pem" >/dev/null

# Candidate-provided helper scripts are data, never code. Exercise both the
# signer and verifier with marker scripts in the bundle and a valid signed
# checksum manifest. The Skopeo Python helper is included as a candidate file;
# its executable path must resolve to the trusted checkout, never this bundle.
UNTRUSTED_SCRIPTS="$TMP/untrusted-scripts"
cp -a "$BUNDLE" "$UNTRUSTED_SCRIPTS"
M3_BUNDLE_MARKER="$TMP/candidate-script-executed"
export M3_BUNDLE_MARKER
cat > "$UNTRUSTED_SCRIPTS/scripts/verify-offline-tools-lock.sh" <<'EOF'
#!/bin/sh
touch "$M3_BUNDLE_MARKER"
exit 91
EOF
cat > "$UNTRUSTED_SCRIPTS/scripts/m3_skopeo_tool.py" <<'EOF'
#!/usr/bin/env python3
from pathlib import Path
import os
Path(os.environ["M3_BUNDLE_MARKER"]).touch()
raise SystemExit(91)
EOF
chmod 0755 "$UNTRUSTED_SCRIPTS/scripts/verify-offline-tools-lock.sh" \
  "$UNTRUSTED_SCRIPTS/scripts/m3_skopeo_tool.py"
resign_bundle "$UNTRUSTED_SCRIPTS"
openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" \
  -in "$UNTRUSTED_SCRIPTS/SHA256SUMS" -out "$UNTRUSTED_SCRIPTS/SHA256SUMS.sig"
"$ROOT/scripts/sign-offline-bundle.sh" "$UNTRUSTED_SCRIPTS" "$TMP/private.pem" >/dev/null
"$ROOT/scripts/verify-offline-bundle.sh" "$UNTRUSTED_SCRIPTS" "$TMP/public.pem" >/dev/null
[[ ! -e "$M3_BUNDLE_MARKER" ]] || {
  echo "candidate offline-bundle helper script was executed" >&2
  exit 1
}
grep -Fq 'bash "$SCRIPT_DIR/verify-offline-tools-lock.sh"' "$ROOT/scripts/check-offline-manifest.sh"
grep -Fq 'python3 -I "$SCRIPT_DIR/m3_skopeo_tool.py" verify-lock-row' "$ROOT/scripts/check-offline-manifest.sh"
if grep -Fq '$BUNDLE/scripts/' "$ROOT/scripts/check-offline-manifest.sh"; then
  echo "offline-bundle checker still executes a candidate script path" >&2
  exit 1
fi

# A malformed archive whose metadata is internally consistent but whose
# manifest checksum is stale must be rejected by sha256sum before deep archive
# parsing. This distinguishes checksum-first validation from a later integrity
# check that happens only after parsing attacker-controlled archives.
CHECKSUM_ORDER="$TMP/checksum-order"
cp -a "$BUNDLE" "$CHECKSUM_ORDER"
python3 - "$CHECKSUM_ORDER" <<'PY'
import hashlib
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
archive = bundle / "images/agent-0.8.0.oci.tar"
archive.write_bytes(b"malformed OCI archive")
metadata = bundle / "images/image-metadata.tsv"
rows = []
for line in metadata.read_text().splitlines():
    fields = line.split("\t")
    if fields[0] == "agent":
        fields[3] = hashlib.sha256(archive.read_bytes()).hexdigest()
    rows.append("\t".join(fields))
metadata.write_text("\n".join(rows) + "\n")
metadata_digest = hashlib.sha256(metadata.read_bytes()).hexdigest()
manifest = bundle / "SHA256SUMS"
lines = manifest.read_text().splitlines()
manifest.write_text("\n".join(
    f"{metadata_digest}  images/image-metadata.tsv" if line.endswith("  images/image-metadata.tsv") else line
    for line in lines
) + "\n")
PY
if bash "$ROOT/scripts/check-offline-manifest.sh" "$CHECKSUM_ORDER" \
  >"$TMP/checksum-order.log" 2>&1; then
  echo "bundle with stale archive checksum was accepted" >&2
  exit 1
fi
grep -Fq 'images/agent-0.8.0.oci.tar: FAILED' "$TMP/checksum-order.log" || {
  cat "$TMP/checksum-order.log" >&2
  echo "stale archive checksum was not rejected before deep archive parsing" >&2
  exit 1
}

# Traversal and symlink paths must be rejected before sha256sum -c is invoked.
FAKE_BIN="$TMP/fake-bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/sha256sum" <<'EOF'
#!/bin/sh
touch "$M3_SHA256SUM_CALLED"
exit 0
EOF
chmod 0755 "$FAKE_BIN/sha256sum"
export M3_SHA256SUM_CALLED="$TMP/sha256sum-called"
TRAVERSAL="$TMP/traversal-manifest"
cp -a "$BUNDLE" "$TRAVERSAL"
printf '%064d  ../outside\n' 0 >> "$TRAVERSAL/SHA256SUMS"
if PATH="$FAKE_BIN:$PATH" bash "$ROOT/scripts/check-offline-manifest.sh" "$TRAVERSAL" >/dev/null 2>&1; then
  echo "manifest traversal path was accepted" >&2
  exit 1
fi
[[ ! -e "$M3_SHA256SUM_CALLED" ]] || {
  echo "sha256sum -c ran before traversal validation" >&2
  exit 1
}
if PATH="$FAKE_BIN:$PATH" bash "$ROOT/scripts/verify-offline-checksums.sh" "$TRAVERSAL" >/dev/null 2>&1; then
  echo "checksum preflight accepted a traversal path" >&2
  exit 1
fi
[[ ! -e "$M3_SHA256SUM_CALLED" ]] || {
  echo "checksum preflight invoked sha256sum before traversal validation" >&2
  exit 1
}
EMPTY_MANIFEST="$TMP/empty-manifest"
cp -a "$BUNDLE" "$EMPTY_MANIFEST"
: > "$EMPTY_MANIFEST/SHA256SUMS"
if PATH="$FAKE_BIN:$PATH" bash "$ROOT/scripts/verify-offline-checksums.sh" "$EMPTY_MANIFEST" >/dev/null 2>&1; then
  echo "checksum preflight accepted an empty SHA256SUMS manifest" >&2
  exit 1
fi
[[ ! -e "$M3_SHA256SUM_CALLED" ]] || {
  echo "checksum preflight invoked sha256sum on an empty manifest" >&2
  exit 1
}
NUL_MANIFEST="$TMP/nul-manifest"
cp -a "$BUNDLE" "$NUL_MANIFEST"
printf '\0' >> "$NUL_MANIFEST/SHA256SUMS"
if PATH="$FAKE_BIN:$PATH" bash "$ROOT/scripts/verify-offline-checksums.sh" "$NUL_MANIFEST" >/dev/null 2>&1; then
  echo "checksum preflight accepted a NUL-containing manifest" >&2
  exit 1
fi
[[ ! -e "$M3_SHA256SUM_CALLED" ]] || {
  echo "checksum preflight invoked sha256sum before rejecting a NUL-containing manifest" >&2
  exit 1
}
DUPLICATE_PATH="$TMP/duplicate-manifest"
cp -a "$BUNDLE" "$DUPLICATE_PATH"
head -n 1 "$DUPLICATE_PATH/SHA256SUMS" >> "$DUPLICATE_PATH/SHA256SUMS"
if PATH="$FAKE_BIN:$PATH" bash "$ROOT/scripts/check-offline-manifest.sh" "$DUPLICATE_PATH" >/dev/null 2>&1; then
  echo "duplicate manifest path was accepted" >&2
  exit 1
fi
[[ ! -e "$M3_SHA256SUM_CALLED" ]] || {
  echo "sha256sum -c ran before duplicate-path validation" >&2
  exit 1
}
SYMLINK_PATH="$TMP/symlink-manifest"
cp -a "$BUNDLE" "$SYMLINK_PATH"
ln -s README.md "$SYMLINK_PATH/docs/manifest-link"
printf '%064d  docs/manifest-link\n' 0 >> "$SYMLINK_PATH/SHA256SUMS"
if PATH="$FAKE_BIN:$PATH" bash "$ROOT/scripts/check-offline-manifest.sh" "$SYMLINK_PATH" >/dev/null 2>&1; then
  echo "manifest symlink path was accepted" >&2
  exit 1
fi
[[ ! -e "$M3_SHA256SUM_CALLED" ]] || {
  echo "sha256sum -c ran before symlink validation" >&2
  exit 1
}

# Podman may emit a valid OCI root index without the optional root mediaType.
# This synthetic direct multi-platform archive matches the reported shape and
# must still pass the same descriptor, blob, architecture, and digest checks.
DIRECT_INDEX_NO_MEDIATYPE="$TMP/direct-index-no-media-type"
cp -a "$BUNDLE" "$DIRECT_INDEX_NO_MEDIATYPE"
python3 - "$DIRECT_INDEX_NO_MEDIATYPE/images" <<'PY'
import copy
import io
import json
import pathlib
import tarfile
import sys

images = pathlib.Path(sys.argv[1])
paths = sorted(images.glob("*-0.8.0.oci.tar")) + [images / "postgres-17-alpine.oci.tar"]
for path in paths:
    with tarfile.open(path, "r:*") as source:
        members = [(copy.copy(member), source.extractfile(member).read() if member.isfile() else None)
                   for member in source.getmembers()]
    files = {member.name: content for member, content in members if content is not None}
    root = json.loads(files["index.json"])
    wrapper = root["manifests"][0]
    nested_path = "blobs/sha256/" + wrapper["digest"][7:]
    direct_index = json.loads(files[nested_path])
    direct_index.pop("mediaType", None)
    direct_raw = json.dumps(direct_index, separators=(",", ":")).encode()
    with tarfile.open(path, "w") as output:
        for member, content in members:
            if member.name == "index.json":
                content = direct_raw
            if content is not None:
                member.size = len(content)
            output.addfile(member, io.BytesIO(content) if content is not None else None)
PY
python3 - "$DIRECT_INDEX_NO_MEDIATYPE" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
metadata = root / "images/image-metadata.tsv"
rows = []
for line in metadata.read_text().splitlines():
    fields = line.split("\t")
    name = fields[0]
    archive_name = f"{name}-0.8.0.oci.tar" if name != "postgres" else "postgres-17-alpine.oci.tar"
    archive = root / "images" / archive_name
    with tarfile.open(archive, "r:*") as bundle:
        index_raw = bundle.extractfile("index.json").read()
    fields[2] = "sha256:" + hashlib.sha256(index_raw).hexdigest()
    fields[3] = hashlib.sha256(archive.read_bytes()).hexdigest()
    rows.append("\t".join(fields))
metadata.write_text("\n".join(rows) + "\n")
PY
resign_bundle "$DIRECT_INDEX_NO_MEDIATYPE"
"$ROOT/scripts/verify-offline-bundle.sh" "$DIRECT_INDEX_NO_MEDIATYPE" "$TMP/public.pem" >/dev/null

# A present but conflicting root mediaType remains invalid.
UNSUPPORTED_INDEX_MEDIATYPE="$TMP/unsupported-index-media-type"
cp -a "$DIRECT_INDEX_NO_MEDIATYPE" "$UNSUPPORTED_INDEX_MEDIATYPE"
python3 - "$UNSUPPORTED_INDEX_MEDIATYPE" <<'PY'
import copy
import hashlib
import io
import json
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
metadata = root / "images/image-metadata.tsv"
rows = []
for line in metadata.read_text().splitlines():
    fields = line.split("\t")
    name = fields[0]
    archive_name = f"{name}-0.8.0.oci.tar" if name != "postgres" else "postgres-17-alpine.oci.tar"
    path = root / "images" / archive_name
    with tarfile.open(path, "r:*") as source:
        members = [(copy.copy(member), source.extractfile(member).read() if member.isfile() else None)
                   for member in source.getmembers()]
    index_raw = next(content for member, content in members if member.name == "index.json")
    index = json.loads(index_raw)
    index["mediaType"] = "application/vnd.docker.distribution.manifest.list.v2+json"
    index_raw = json.dumps(index, separators=(",", ":")).encode()
    with tarfile.open(path, "w") as output:
        for member, content in members:
            if member.name == "index.json":
                content = index_raw
            if content is not None:
                member.size = len(content)
            output.addfile(member, io.BytesIO(content) if content is not None else None)
    fields[2] = "sha256:" + hashlib.sha256(index_raw).hexdigest()
    fields[3] = hashlib.sha256(path.read_bytes()).hexdigest()
    rows.append("\t".join(fields))
metadata.write_text("\n".join(rows) + "\n")
PY
resign_bundle "$UNSUPPORTED_INDEX_MEDIATYPE"
if "$ROOT/scripts/verify-offline-bundle.sh" "$UNSUPPORTED_INDEX_MEDIATYPE" "$TMP/public.pem" >"$TMP/unsupported-index-media-type.log" 2>&1; then
  echo "signed bundle with a conflicting OCI index mediaType was accepted" >&2
  exit 1
fi
grep -Fq "invalid OCI image index" "$TMP/unsupported-index-media-type.log"

# The release signature alone cannot substitute a different tool-acquisition
# trust root or Helm signer policy for the values provisioned out of band.
BAD_TOOLS_KEY="$TMP/bad-tools-key"
cp -a "$BUNDLE" "$BAD_TOOLS_KEY"
openssl genpkey -algorithm ED25519 -out "$TMP/other-tools-private.pem"
openssl pkey -in "$TMP/other-tools-private.pem" -pubout -out "$BAD_TOOLS_KEY/bin/tools/offline-tools.signer.pub"
resign_bundle "$BAD_TOOLS_KEY"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BAD_TOOLS_KEY" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "bundle with substituted tool-provenance trust key was accepted" >&2
  exit 1
fi

BAD_HELM_SIGNERS="$TMP/bad-helm-signers"
cp -a "$BUNDLE" "$BAD_HELM_SIGNERS"
printf '%s\n' 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' > "$BAD_HELM_SIGNERS/bin/tools/offline-tools.helm-signers.txt"
resign_bundle "$BAD_HELM_SIGNERS"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BAD_HELM_SIGNERS" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "bundle with substituted Helm signer policy was accepted" >&2
  exit 1
fi

# A release signature authenticates files but cannot make an invalid Helm
# package installable. Reject malformed chart archives even when re-signed.
BAD_CHART="$TMP/bad-helm-chart"
cp -a "$BUNDLE" "$BAD_CHART"
printf 'not a Helm chart archive\n' > "$BAD_CHART/charts/kordex-agent-0.8.0.tgz"
resign_bundle "$BAD_CHART"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BAD_CHART" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle with malformed Helm chart was accepted" >&2
  exit 1
fi

# A valid signature cannot make a binary in the wrong architecture directory
# runnable on the promised platform.
BAD_BINARY="$TMP/bad-binary-architecture"
cp -a "$BUNDLE" "$BAD_BINARY"
python3 - "$BAD_BINARY/bin/linux-arm64/kordex" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
header = bytearray(path.read_bytes())
struct.pack_into("<H", header, 18, 62)
path.write_bytes(header)
PY
resign_bundle "$BAD_BINARY"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BAD_BINARY" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle with wrong-architecture offline binary was accepted" >&2
  exit 1
fi

# A signed bundle may not claim a narrower platform set than its OCI indexes
# actually contain; verify the image index itself, not just release metadata.
PLATFORM_MISMATCH="$TMP/platform-mismatch"
cp -a "$BUNDLE" "$PLATFORM_MISMATCH"
sed -i 's/linux\/amd64,linux\/arm64/linux\/amd64/g' \
  "$PLATFORM_MISMATCH/images/platforms.txt" "$PLATFORM_MISMATCH/images/image-metadata.tsv"
(cd "$PLATFORM_MISMATCH" && find images bin charts manifests ansible-ee docs helm-values scripts qualification README.md images.txt -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" -in "$PLATFORM_MISMATCH/SHA256SUMS" -out "$PLATFORM_MISMATCH/SHA256SUMS.sig"
if "$ROOT/scripts/verify-offline-bundle.sh" "$PLATFORM_MISMATCH" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle with false OCI platform metadata was accepted" >&2
  exit 1
fi

# Duplicate and missing metadata rows must be rejected even when the release
# signer produces a valid signature over the altered file inventory.
DUPLICATE_METADATA="$TMP/duplicate-image-metadata"
cp -a "$BUNDLE" "$DUPLICATE_METADATA"
head -n 1 "$DUPLICATE_METADATA/images/image-metadata.tsv" >> "$DUPLICATE_METADATA/images/image-metadata.tsv"
resign_bundle "$DUPLICATE_METADATA"
if "$ROOT/scripts/verify-offline-bundle.sh" "$DUPLICATE_METADATA" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle with duplicate image metadata was accepted" >&2
  exit 1
fi

MISSING_METADATA="$TMP/missing-image-metadata"
cp -a "$BUNDLE" "$MISSING_METADATA"
sed -i '/^postgres\t/d' "$MISSING_METADATA/images/image-metadata.tsv"
resign_bundle "$MISSING_METADATA"
if "$ROOT/scripts/verify-offline-bundle.sh" "$MISSING_METADATA" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle with missing image metadata was accepted" >&2
  exit 1
fi

# A valid signature and corrected archive checksum do not make a blob whose
# bytes contradict its OCI descriptor digest acceptable.
BAD_BLOB="$TMP/bad-oci-blob"
cp -a "$BUNDLE" "$BAD_BLOB"
python3 - "$BAD_BLOB/images/control-plane-0.8.0.oci.tar" <<'PY'
import copy
import io
import json
import sys
import tarfile

path = sys.argv[1]
with tarfile.open(path, "r:*") as source:
    members = [(copy.copy(member), source.extractfile(member).read() if member.isfile() else None)
               for member in source.getmembers()]
files = {member.name: contents for member, contents in members if contents is not None}
root_index = json.loads(files["index.json"])
descriptor = root_index["manifests"][0]
if descriptor.get("mediaType") == "application/vnd.oci.image.index.v1+json":
    descriptor = json.loads(files["blobs/sha256/" + descriptor["digest"][7:]])["manifests"][0]
image_manifest = json.loads(files["blobs/sha256/" + descriptor["digest"][7:]])
if not image_manifest["layers"]:
    raise SystemExit("OCI test archive did not contain a layer to corrupt")
layer_path = "blobs/sha256/" + image_manifest["layers"][0]["digest"][7:]
changed = False
with tarfile.open(path, "w") as output:
    for member, contents in members:
        if member.name == layer_path:
            contents = bytes([contents[0] ^ 1]) + contents[1:]
            changed = True
        if contents is not None:
            member.size = len(contents)
        output.addfile(member, io.BytesIO(contents) if contents is not None else None)
if not changed:
    raise SystemExit("OCI test fixture did not contain its expected layer blob")
PY
python3 - "$BAD_BLOB" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
metadata = root / "images/image-metadata.tsv"
rows = []
for line in metadata.read_text().splitlines():
    fields = line.split("\t")
    if fields[0] == "control-plane":
        fields[3] = hashlib.sha256((root / "images/control-plane-0.8.0.oci.tar").read_bytes()).hexdigest()
    rows.append("\t".join(fields))
metadata.write_text("\n".join(rows) + "\n")
PY
resign_bundle "$BAD_BLOB"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BAD_BLOB" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle with OCI blob bytes inconsistent with its descriptor was accepted" >&2
  exit 1
fi

# Private-CA deployment assets are part of the required offline release, not an
# optional file set that may be silently omitted from an otherwise signed bundle.
WITHOUT_CA="$TMP/without-private-ca"
cp -a "$BUNDLE" "$WITHOUT_CA"
rm -rf "$WITHOUT_CA/manifests/kustomize/overlays/self-managed-private-ca" \
  "$WITHOUT_CA/manifests/kustomize/components/private-management-ca"
sed -i '/manifests\/kustomize\/overlays\/self-managed-private-ca\//d; /manifests\/kustomize\/components\/private-management-ca\//d' "$WITHOUT_CA/SHA256SUMS"
openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" -in "$WITHOUT_CA/SHA256SUMS" -out "$WITHOUT_CA/SHA256SUMS.sig"
if "$ROOT/scripts/verify-offline-bundle.sh" "$WITHOUT_CA" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle without private-CA Kustomize assets was accepted" >&2
  exit 1
fi

# Qualification tooling is a required part of the self-managed release kit.
# A signer must not accidentally distribute an install-only bundle that lacks
# the guarded drill and evidence acceptance process.
cp -a "$BUNDLE" "$TMP/without-qualification"
rm -rf "$TMP/without-qualification/qualification"
sed -i '/^.*qualification\//d' "$TMP/without-qualification/SHA256SUMS"
openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" \
  -in "$TMP/without-qualification/SHA256SUMS" \
  -out "$TMP/without-qualification/SHA256SUMS.sig"
if "$ROOT/scripts/verify-offline-bundle.sh" "$TMP/without-qualification" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle without qualification tooling was accepted" >&2
  exit 1
fi

# A signed manifest must describe a complete distributable release, not just
# authenticate whatever small subset happened to be placed in the directory.
INCOMPLETE="$TMP/incomplete"
mkdir -p "$INCOMPLETE"
printf 'partial signed bundle\n' > "$INCOMPLETE/README.md"
(cd "$INCOMPLETE" && sha256sum README.md > SHA256SUMS)
openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" -in "$INCOMPLETE/SHA256SUMS" -out "$INCOMPLETE/SHA256SUMS.sig"
if "$ROOT/scripts/verify-offline-bundle.sh" "$INCOMPLETE" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed but incomplete offline bundle was accepted" >&2
  exit 1
fi

# Client tools must be distributable and match their checksummed version lock,
# even when a signer creates a fresh valid release signature for a bad bundle.
WITHOUT_KUBECTL="$TMP/without-kubectl"
cp -a "$BUNDLE" "$WITHOUT_KUBECTL"
rm "$WITHOUT_KUBECTL/bin/tools/linux-arm64/kubectl"
sed -i '\|bin/tools/linux-arm64/kubectl|d' "$WITHOUT_KUBECTL/SHA256SUMS"
openssl pkeyutl -sign -rawin -inkey "$TMP/private.pem" \
  -in "$WITHOUT_KUBECTL/SHA256SUMS" -out "$WITHOUT_KUBECTL/SHA256SUMS.sig"
if "$ROOT/scripts/verify-offline-bundle.sh" "$WITHOUT_KUBECTL" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle without the arm64 kubectl binary was accepted" >&2
  exit 1
fi

TAMPERED_TOOL="$TMP/tampered-tool"
cp -a "$BUNDLE" "$TAMPERED_TOOL"
printf 'changed tool bytes' >> "$TAMPERED_TOOL/bin/tools/linux-amd64/helm"
resign_bundle "$TAMPERED_TOOL"
if "$ROOT/scripts/verify-offline-bundle.sh" "$TAMPERED_TOOL" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "signed bundle with client-tool checksum mismatch was accepted" >&2
  exit 1
fi

# Both entrypoints must reject changed bytes before invoking the structural
# checker. Removing a required file creates a competing later failure, so the
# observed checksum error proves which gate ran first.
ORDER_GUARD="$TMP/checksum-order-guard"
cp -a "$BUNDLE" "$ORDER_GUARD"
printf 'tampered bytes before structural inspection\n' >> "$ORDER_GUARD/docs/install.md"
printf 'unexpected content\n' > "$ORDER_GUARD/images/unlisted.oci.tar"
if "$ROOT/scripts/verify-offline-bundle.sh" "$ORDER_GUARD" "$TMP/public.pem" >"$TMP/verify-checksum-order.log" 2>&1; then
  echo "verifier accepted a bundle with a checksum mismatch" >&2
  exit 1
fi
grep -Fq 'docs/install.md: FAILED' "$TMP/verify-checksum-order.log" || {
  cat "$TMP/verify-checksum-order.log" >&2
  echo "verifier did not perform checksum validation before structural inspection" >&2
  exit 1
}
if grep -Eq 'required offline bundle asset is missing|unlisted file in offline bundle' "$TMP/verify-checksum-order.log"; then
  echo "verifier reached structural inspection before the checksum gate" >&2
  exit 1
fi
if "$ROOT/scripts/sign-offline-bundle.sh" "$ORDER_GUARD" "$TMP/private.pem" >"$TMP/sign-checksum-order.log" 2>&1; then
  echo "signer accepted a bundle with a checksum mismatch" >&2
  exit 1
fi
grep -Fq 'docs/install.md: FAILED' "$TMP/sign-checksum-order.log" || {
  cat "$TMP/sign-checksum-order.log" >&2
  echo "signer did not perform checksum validation before structural inspection" >&2
  exit 1
}
if grep -Eq 'required offline bundle asset is missing|unlisted file in offline bundle' "$TMP/sign-checksum-order.log"; then
  echo "signer reached structural inspection before the checksum gate" >&2
  exit 1
fi

printf 'unreviewed content\n' > "$BUNDLE/images/extra.oci.tar"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BUNDLE" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "unlisted bundle file was accepted" >&2
  exit 1
fi
if "$ROOT/scripts/sign-offline-bundle.sh" "$BUNDLE" "$TMP/private.pem" >/dev/null 2>&1; then
  echo "signer accepted a bundle with an unlisted file" >&2
  exit 1
fi
rm "$BUNDLE/images/extra.oci.tar"

ln -s "$BUNDLE/docs/install.md" "$BUNDLE/docs/untrusted-link"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BUNDLE" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "symbolic link in bundle was accepted" >&2
  exit 1
fi
rm "$BUNDLE/docs/untrusted-link"

printf 'tampered instructions\n' > "$BUNDLE/docs/install.md"
if "$ROOT/scripts/verify-offline-bundle.sh" "$BUNDLE" "$TMP/public.pem" >/dev/null 2>&1; then
  echo "tampered bundle file was accepted" >&2
  exit 1
fi

echo "offline bundle integrity tests passed"
