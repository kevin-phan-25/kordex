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
    image_metadata="$(python3 - "$archive" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
with tarfile.open(archive, "r:*") as bundle:
    index = json.load(bundle.extractfile("index.json"))
digest = index["manifests"][0]["digest"]
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
inner_index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": members}, separators=(",", ":")).encode()
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
  for binary in kordex kordex-scheduler kordex-agent kordex-operator kordex-keygen kordex-audit-verify; do
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
  sign-offline-bundle.sh verify-offline-bundle.sh check-offline-manifest.sh; do
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
