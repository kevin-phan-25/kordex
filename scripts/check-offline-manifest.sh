#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 BUNDLE_DIRECTORY" >&2
  exit 2
fi
BUNDLE="$(cd "$1" && pwd)"
MANIFEST="$BUNDLE/SHA256SUMS"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || { echo "SHA256SUMS must be a regular file" >&2; exit 1; }
if find "$BUNDLE" -type l -print -quit | grep -q .; then
  echo "offline bundle must not contain symbolic links" >&2
  exit 1
fi

declare -A listed=()
while IFS= read -r line || [[ -n "$line" ]]; do
  digest="${line:0:64}"
  separator="${line:64:2}"
  relative="${line:66}"
  [[ "$digest" =~ ^[a-f0-9]{64}$ && "$separator" == "  " && "$relative" =~ ^[A-Za-z0-9._/+\-]+$ ]] || {
    echo "invalid SHA256SUMS entry" >&2
    exit 1
  }
  [[ "$relative" != /* && "$relative" != "SHA256SUMS" && "$relative" != "SHA256SUMS.sig" ]] || {
    echo "invalid bundle path in SHA256SUMS: $relative" >&2
    exit 1
  }
  IFS=/ read -r -a path_parts <<< "$relative"
  for component in "${path_parts[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || {
      echo "invalid bundle path in SHA256SUMS: $relative" >&2
      exit 1
    }
  done
  [[ -z "${listed[$relative]:-}" ]] || { echo "duplicate SHA256SUMS entry: $relative" >&2; exit 1; }
  [[ -f "$BUNDLE/$relative" ]] || { echo "manifest file is missing: $relative" >&2; exit 1; }
  listed["$relative"]=1
done < "$MANIFEST"

while IFS= read -r -d '' path; do
  relative="${path#"$BUNDLE"/}"
  case "$relative" in
    SHA256SUMS|SHA256SUMS.sig) continue ;;
  esac
  [[ -n "${listed[$relative]:-}" ]] || { echo "unlisted file in offline bundle: $relative" >&2; exit 1; }
done < <(find "$BUNDLE" -type f -print0)

require_file() {
  local relative="$1"
  [[ -f "$BUNDLE/$relative" && ! -L "$BUNDLE/$relative" && -n "${listed[$relative]:-}" ]] || {
    echo "required offline bundle asset is missing or unsigned: $relative" >&2
    exit 1
  }
}

for relative in README.md images.txt images/platforms.txt images/image-metadata.tsv \
  docs/air-gapped-deployment.md docs/architecture.md docs/security.md \
  docs/production-upgrade-requirements.md \
  bin/tools/offline-tools.tsv bin/tools/offline-tools.tsv.sig bin/tools/offline-tools.signer.pub \
  bin/tools/offline-tools.helm-signers.txt \
  bin/tools/LICENSES/helm.txt bin/tools/LICENSES/kubernetes.txt \
  helm-values/kordex-agent.yaml helm-values/kordex-operator.yaml \
  helm-values/kordex-control-plane.yaml helm-values/kordex-dashboard.yaml \
  scripts/build-offline-bundle.sh scripts/acquire-offline-tools.sh scripts/push-offline-bundle.sh \
  scripts/test-offline-oci-podman.sh \
  scripts/configure-offline-kustomize.sh scripts/configure-offline-helm.sh \
  scripts/generate-offline-upgrade-policy.py scripts/test-generate-offline-upgrade-policy.sh \
  scripts/build-offline-package-artifacts.py scripts/install-offline-package-artifacts.py \
  scripts/test_offline_package_artifacts.py \
  scripts/verify-image-lock.sh scripts/test-push-offline-bundle.sh \
  scripts/test-configure-offline-kustomize.sh scripts/test-configure-offline-helm.sh \
  scripts/sign-offline-bundle.sh \
  scripts/verify-offline-bundle.sh scripts/check-offline-manifest.sh scripts/verify-offline-tools-lock.sh \
  qualification/self_managed_upgrade_smoke.py qualification/debian_upgrade_smoke.py \
  qualification/host_upgrade_failure_matrix.json \
  qualification/verify-host-upgrade-qualification.py \
  ansible-ee/Containerfile ansible-ee/README.md ansible-ee/build-ee.sh \
  ansible-ee/upgrade.py ansible-ee/upgrade-debian.yml ansible-ee/upgrade-rhel.yml ansible-ee/upgrade_test.py \
  ansible-ee/collections.lock \
  manifests/kustomize/overlays/self-managed/kustomization.yaml \
  manifests/kustomize/overlays/self-managed-private-ca/kustomization.yaml \
  manifests/kustomize/components/private-management-ca/kustomization.yaml \
  manifests/kustomize/base/crds/operations.kordex.local_maintenancecampaigns.yaml \
  manifests/kustomize/base/crds/operations.kordex.local_maintenancepolicies.yaml \
  manifests/kustomize/base/crds/operations.kordex.local_nodemaintenances.yaml; do
  require_file "$relative"
done

PLATFORMS="$(tr -d '\r\n' < "$BUNDLE/images/platforms.txt")"
[[ "$PLATFORMS" =~ ^linux/(amd64|arm64)(,linux/(amd64|arm64))*$ ]] || {
  echo "invalid offline image platform inventory" >&2
  exit 1
}
IFS=, read -r -a platform_list <<< "$PLATFORMS"
declare -A unique_platforms=()
for platform in "${platform_list[@]}"; do
  [[ -z "${unique_platforms[$platform]:-}" ]] || { echo "duplicate offline image platform: $platform" >&2; exit 1; }
  unique_platforms[$platform]=1
done
declare -A image_refs=() image_metadata=()
while IFS=$'\t' read -r name reference extra || [[ -n "${name:-}" ]]; do
  [[ -n "${name:-}" && -z "${extra:-}" ]] || { echo "malformed images.txt row" >&2; exit 1; }
  case "$name" in control-plane|agent|operator|dashboard|ansible-ee|postgres) ;; *) echo "unsupported image in images.txt: $name" >&2; exit 1 ;; esac
  [[ "$reference" =~ ^localhost/kordex/${name}:[A-Za-z0-9._+-]+$ ]] || { echo "invalid local image reference for $name" >&2; exit 1; }
  [[ -z "${image_refs[$name]:-}" ]] || { echo "duplicate image in images.txt: $name" >&2; exit 1; }
  image_refs[$name]="$reference"
done < "$BUNDLE/images.txt"
for name in control-plane agent operator dashboard ansible-ee postgres; do
  [[ -n "${image_refs[$name]:-}" ]] || { echo "required image is missing from images.txt: $name" >&2; exit 1; }
  if [[ "$name" == postgres ]]; then
    archive="images/postgres-17-alpine.oci.tar"
  else
    archive="images/${name}-${image_refs[$name]##*:}.oci.tar"
  fi
  require_file "$archive"
  [[ -s "$BUNDLE/$archive" ]] || { echo "OCI image archive is empty: $archive" >&2; exit 1; }
done

while IFS=$'\t' read -r name reference image_digest archive_digest platforms extra || [[ -n "${name:-}" ]]; do
  [[ -n "${name:-}" && -z "${extra:-}" && "${platforms:-}" == "$PLATFORMS" && -n "${image_refs[$name]:-}" ]] || { echo "malformed image metadata row or platform mismatch" >&2; exit 1; }
  [[ "${image_metadata[$name]:-}" == "" && "$reference" == "${image_refs[$name]}" ]] || { echo "duplicate or mismatched image metadata for $name" >&2; exit 1; }
  [[ "$image_digest" =~ ^sha256:[a-f0-9]{64}$ && "$archive_digest" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid image digest metadata for $name" >&2; exit 1; }
  if [[ "$name" == postgres ]]; then
    archive="images/postgres-17-alpine.oci.tar"
  else
    archive="images/${name}-${reference##*:}.oci.tar"
  fi
  actual_archive_digest="$(sha256sum "$BUNDLE/$archive" | awk '{print $1}')"
  [[ "$archive_digest" == "$actual_archive_digest" ]] || { echo "archive checksum metadata mismatch for $name" >&2; exit 1; }
  python3 - "$BUNDLE/$archive" "$PLATFORMS" "$image_digest" "$name" <<'PY'
import hashlib
import json
import re
import sys
import tarfile

archive, configured, expected_digest, image = sys.argv[1:]
expected = set(configured.split(","))
try:
    with tarfile.open(archive, "r:*") as bundle:
        entries = {}
        for member in bundle.getmembers():
            if member.name in entries:
                raise ValueError("OCI archive contains a duplicate path")
            entries[member.name] = member
        entry = entries["index.json"]
        if not entry.isfile() or entry.size < 0 or entry.size > 4 * 1024 * 1024:
            raise ValueError("OCI index exceeds size limit")
        stream = bundle.extractfile(entry)
        if stream is None:
            raise ValueError("OCI index is not a regular archive entry")
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("OCI index exceeds size limit")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate OCI index JSON key")
            result[key] = value
        return result
    index = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(index, dict) or index.get("schemaVersion") != 2 \
            or index.get("mediaType") != "application/vnd.oci.image.index.v1+json" \
            or not isinstance(index.get("manifests"), list):
        raise ValueError("invalid OCI image index")

    def read_blob(digest, max_read=None):
        if not isinstance(digest, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
            raise ValueError("OCI descriptor has an invalid digest")
        member = entries.get("blobs/sha256/" + digest[7:])
        if member is None or not member.isfile():
            raise ValueError("OCI descriptor references a missing blob")
        if member.size < 0 or (max_read is not None and member.size > max_read):
            raise ValueError("OCI blob size is invalid or exceeds the metadata limit")
        hasher = hashlib.sha256()
        raw = bytearray() if max_read is not None else None
        total = 0
        with tarfile.open(archive, "r:*") as source:
            stream = source.extractfile(member.name)
            if stream is None:
                raise ValueError("OCI blob is not a regular archive entry")
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                hasher.update(chunk)
                if raw is not None:
                    raw.extend(chunk)
        if total != member.size or "sha256:" + hasher.hexdigest() != digest:
            raise ValueError("OCI blob content does not match its descriptor digest or size")
        return member, bytes(raw) if raw is not None else None

    # Podman writes a wrapper index into OCI archives and stores the actual
    # multi-platform index as a blob. The digest file identifies that inner
    # index. Also accept archives whose root index directly lists platforms.
    effective_index = index
    metadata_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    root_descriptors = index["manifests"]
    if len(root_descriptors) == 1 and isinstance(root_descriptors[0], dict) \
            and root_descriptors[0].get("mediaType") == "application/vnd.oci.image.index.v1+json" \
            and "platform" not in root_descriptors[0]:
        wrapper = root_descriptors[0]
        if type(wrapper.get("size")) is not int or wrapper["size"] < 0:
            raise ValueError("OCI wrapper index descriptor has an invalid size")
        wrapped_entry, wrapped_raw = read_blob(wrapper.get("digest"), 4 * 1024 * 1024)
        if wrapped_entry.size != wrapper["size"] or "sha256:" + hashlib.sha256(wrapped_raw).hexdigest() != wrapper["digest"]:
            raise ValueError("nested OCI index does not match its wrapper descriptor")
        effective_index = json.loads(wrapped_raw, object_pairs_hook=unique_object)
        if not isinstance(effective_index, dict) or effective_index.get("schemaVersion") != 2 \
                or effective_index.get("mediaType") != "application/vnd.oci.image.index.v1+json" \
                or not isinstance(effective_index.get("manifests"), list):
            raise ValueError("invalid nested OCI image index")
        metadata_digest = wrapper["digest"]
    elif len(root_descriptors) == 1 and isinstance(root_descriptors[0], dict) \
            and root_descriptors[0].get("mediaType") == "application/vnd.oci.image.manifest.v1+json" \
            and "platform" not in root_descriptors[0]:
        # Single-platform OCI archives may identify the image manifest itself.
        metadata_digest = root_descriptors[0].get("digest", "")

    platforms = set()
    for descriptor in effective_index["manifests"]:
        if not isinstance(descriptor, dict):
            raise ValueError("OCI image index contains a non-object descriptor")
        if descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
            raise ValueError("OCI image index contains a non-image-manifest descriptor")
        platform = descriptor.get("platform")
        if platform is not None and (not isinstance(platform, dict) or platform.get("os") != "linux" or platform.get("architecture") not in {"amd64", "arm64"}):
            raise ValueError("OCI image index contains an unsupported or missing platform")
        if type(descriptor.get("size")) is not int or descriptor["size"] < 0:
            raise ValueError("OCI manifest descriptor has an invalid size")
        manifest_entry, manifest_raw = read_blob(descriptor.get("digest"), 4 * 1024 * 1024)
        if manifest_entry.size != descriptor["size"] or manifest_entry.size > 4 * 1024 * 1024:
            raise ValueError("OCI image manifest size does not match its index descriptor")
        if len(manifest_raw) > 4 * 1024 * 1024 or "sha256:" + hashlib.sha256(manifest_raw).hexdigest() != descriptor["digest"]:
            raise ValueError("OCI image manifest digest does not match its index descriptor")
        image_manifest = json.loads(manifest_raw, object_pairs_hook=unique_object)
        if not isinstance(image_manifest, dict) or image_manifest.get("schemaVersion") != 2 \
                or image_manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json" \
                or not isinstance(image_manifest.get("layers"), list):
            raise ValueError("invalid OCI image manifest")
        config_descriptor = image_manifest.get("config")
        if not isinstance(config_descriptor, dict) \
                or config_descriptor.get("mediaType") != "application/vnd.oci.image.config.v1+json" \
                or type(config_descriptor.get("size")) is not int:
            raise ValueError("OCI image manifest has an invalid config descriptor")
        config_entry, config_raw = read_blob(config_descriptor.get("digest"), 4 * 1024 * 1024)
        if config_entry.size != config_descriptor["size"] or config_entry.size > 4 * 1024 * 1024:
            raise ValueError("OCI image config size does not match its manifest descriptor")
        if len(config_raw) > 4 * 1024 * 1024 or "sha256:" + hashlib.sha256(config_raw).hexdigest() != config_descriptor["digest"]:
            raise ValueError("OCI image config digest does not match its manifest descriptor")
        image_config = json.loads(config_raw, object_pairs_hook=unique_object)
        if not isinstance(image_config, dict) or image_config.get("os") != "linux" or image_config.get("architecture") not in {"amd64", "arm64"}:
            raise ValueError("OCI config architecture does not match its index descriptor")
        if platform is not None and image_config["architecture"] != platform["architecture"]:
            raise ValueError("OCI config architecture does not match its index descriptor")
        for layer in image_manifest["layers"]:
            if not isinstance(layer, dict) or type(layer.get("size")) is not int or layer["size"] < 0:
                raise ValueError("OCI image manifest contains an invalid layer descriptor")
            layer_entry, _ = read_blob(layer.get("digest"))
            if layer_entry.size != layer["size"]:
                raise ValueError("OCI layer size does not match its manifest descriptor")
        value = f"linux/{image_config['architecture']}"
        if value in platforms:
            raise ValueError("OCI image index contains a duplicate platform")
        platforms.add(value)
    if platforms != expected:
        raise ValueError(f"platform mismatch: expected {sorted(expected)}, found {sorted(platforms)}")
    if metadata_digest != expected_digest:
        raise ValueError("OCI image index digest metadata mismatch")
except (OSError, tarfile.TarError, KeyError, TypeError, AttributeError, ValueError, json.JSONDecodeError) as error:
    print(f"invalid multi-platform OCI archive for {image}: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
  image_metadata[$name]=1
done < "$BUNDLE/images/image-metadata.tsv"
for name in control-plane agent operator dashboard ansible-ee postgres; do
  [[ -n "${image_metadata[$name]:-}" ]] || { echo "image metadata is missing: $name" >&2; exit 1; }
done

declare -A offline_tools=()
bash "$BUNDLE/scripts/verify-offline-tools-lock.sh" \
  "$BUNDLE/bin/tools/offline-tools.tsv" \
  "$BUNDLE/bin/tools/offline-tools.tsv.sig" \
  "$BUNDLE/bin/tools/offline-tools.signer.pub" \
  "$BUNDLE/bin/tools/offline-tools.helm-signers.txt" >/dev/null
while IFS=$'\t' read -r name version architecture digest artifact_digest artifact_url verification signer extra || [[ -n "${name:-}" ]]; do
  [[ -n "${name:-}" && -z "${extra:-}" && ( "$name" == helm || "$name" == kubectl ) ]] || { echo "malformed offline tools inventory" >&2; exit 1; }
  [[ "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo "invalid offline tool version: $version" >&2; exit 1; }
  [[ "$architecture" == linux-amd64 || "$architecture" == linux-arm64 ]] || { echo "invalid offline tool architecture: $architecture" >&2; exit 1; }
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid offline tool checksum: $name/$architecture" >&2; exit 1; }
  key="$name/$architecture"
  [[ -z "${offline_tools[$key]:-}" ]] || { echo "duplicate offline tool entry: $key" >&2; exit 1; }
  relative="bin/tools/$architecture/$name"
  require_file "$relative"
  actual="$(sha256sum "$BUNDLE/$relative" | awk '{print $1}')"
  [[ "$actual" == "$digest" ]] || { echo "offline tool checksum mismatch: $key" >&2; exit 1; }
  offline_tools[$key]="$version"
done < "$BUNDLE/bin/tools/offline-tools.tsv"
[[ "${#offline_tools[@]}" -eq 4 ]] || { echo "offline tools inventory must have exactly four entries" >&2; exit 1; }
for architecture in linux-amd64 linux-arm64; do
  for name in helm kubectl; do
    [[ -n "${offline_tools[$name/$architecture]:-}" ]] || { echo "offline tools inventory is missing $name/$architecture" >&2; exit 1; }
  done
done

for arch in amd64 arm64; do
  for binary in kordex kordex-scheduler kordex-agent kordex-operator kordex-keygen kordex-audit-verify kordex-audit-sign kordex-security-audit-export helm kubectl; do
    if [[ "$binary" == helm || "$binary" == kubectl ]]; then
      relative="bin/tools/linux-$arch/$binary"
    else
      relative="bin/linux-$arch/$binary"
    fi
    require_file "$relative"
    [[ -x "$BUNDLE/$relative" ]] || { echo "offline binary is not executable: $relative" >&2; exit 1; }
    python3 - "$BUNDLE/$relative" "$arch" <<'PY'
import struct
import sys

path, expected_arch = sys.argv[1:]
expected_machine = {"amd64": 62, "arm64": 183}[expected_arch]
try:
    with open(path, "rb") as binary:
        header = binary.read(64)
    if len(header) < 64 or header[:4] != b"\x7fELF":
        raise ValueError("binary is not a complete ELF64 executable")
    if header[4] != 2 or header[5] != 1 or header[6] != 1:
        raise ValueError("binary has an unsupported ELF class, byte order, or version")
    machine = struct.unpack_from("<H", header, 18)[0]
    header_size = struct.unpack_from("<H", header, 52)[0]
    if machine != expected_machine or header_size < 64:
        raise ValueError(f"expected linux/{expected_arch} ELF, found e_machine={machine}")
except (OSError, ValueError, struct.error) as error:
    print(f"invalid offline binary {path}: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
  done
done

for chart in agent operator control-plane dashboard; do
  mapfile -t chart_paths < <(compgen -G "$BUNDLE/charts/kordex-$chart-*.tgz" || true)
  [[ ${#chart_paths[@]} -eq 1 ]] || { echo "expected exactly one packaged Helm chart for kordex-$chart" >&2; exit 1; }
  chart_path="${chart_paths[0]}"
  relative="${chart_path#"$BUNDLE"/}"
  require_file "$relative"
  python3 - "$chart_path" "$chart" <<'PY'
import re
import sys
import tarfile

path, expected_name = sys.argv[1:]
expected_root = "kordex-" + expected_name
filename = path.rsplit("/", 1)[-1]
match = re.fullmatch(re.escape(expected_root) + r"-(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\.tgz", filename)
if match is None:
    raise SystemExit(f"invalid packaged Helm chart filename: {filename}")
expected_version = match.group(1)
try:
    with tarfile.open(path, "r:gz") as archive:
        files = {}
        for member in archive.getmembers():
            parts = member.name.split("/")
            if member.name.startswith("/") or ".." in parts or not parts or parts[0] != expected_root:
                raise ValueError("chart contains a path outside its chart root")
            if member.name in files:
                raise ValueError("chart contains a duplicate archive path")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise ValueError("chart contains a link or unsupported archive entry")
            files[member.name] = member
        chart_yaml = files.get(expected_root + "/Chart.yaml")
        values_yaml = files.get(expected_root + "/values.yaml")
        if chart_yaml is None or not chart_yaml.isfile() or chart_yaml.size > 65536:
            raise ValueError("chart is missing a bounded regular Chart.yaml")
        if values_yaml is None or not values_yaml.isfile():
            raise ValueError("chart is missing a regular values.yaml")
        if not any(name.startswith(expected_root + "/templates/") and member.isfile()
                   for name, member in files.items()):
            raise ValueError("chart is missing templates")
        stream = archive.extractfile(chart_yaml)
        if stream is None:
            raise ValueError("Chart.yaml cannot be read")
        content = stream.read(65537).decode("utf-8")
        if len(content.encode("utf-8")) > 65536:
            raise ValueError("Chart.yaml exceeds the size limit")
        fields = {}
        for key in ("apiVersion", "name", "version"):
            matches = list(re.finditer(r"^" + key + r":\s*['\"]?([^'\"#\s]+)", content, re.MULTILINE))
            if len(matches) != 1:
                raise ValueError("Chart.yaml must contain exactly one " + key)
            fields[key] = matches[0].group(1)
        if fields != {"apiVersion": "v2", "name": expected_root, "version": expected_version}:
            raise ValueError("Chart.yaml name, version, or apiVersion does not match its package")
except (OSError, tarfile.TarError, UnicodeDecodeError, ValueError) as error:
    print(f"invalid Helm chart archive for {expected_name}: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
done

echo "Offline bundle manifest is complete."
