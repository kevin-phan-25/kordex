#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 VERIFIED_BUNDLE IMAGE_DIGEST_LOCK CLUSTER_UUID HUB_HTTPS_ORIGIN PUBLIC_KEYS_JSON OUTPUT_TREE [--private-ca]" >&2
}

if [[ $# -lt 6 || $# -gt 7 ]]; then usage; exit 2; fi
PRIVATE_CA=false
if [[ $# -eq 7 ]]; then
  [[ "$7" == "--private-ca" ]] || { usage; exit 2; }
  PRIVATE_CA=true
fi
BUNDLE="$(cd "$1" && pwd)"
LOCK="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
CLUSTER_ID="$3"
HUB_URL="${4%/}"
PUBLIC_KEYS="$(cd "$(dirname "$5")" && pwd)/$(basename "$5")"
OUTPUT_REQUESTED="$6"
LOCK_SIGNATURE="${KORDEX_IMAGE_LOCK_SIGNATURE:-${LOCK}.sig}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REGISTRY_PULL_SECRET="${KORDEX_REGISTRY_PULL_SECRET:-kordex-registry}"
UPGRADE_PULL_SECRETS="${KORDEX_UPGRADE_IMAGE_PULL_SECRETS:-$REGISTRY_PULL_SECRET}"
UPGRADE_SSH_USER="${KORDEX_UPGRADE_SSH_USER:-}"
UPGRADE_SSH_SECRET="${KORDEX_UPGRADE_SSH_SECRET:-}"
UPGRADE_KNOWN_HOSTS="${KORDEX_UPGRADE_KNOWN_HOSTS:-}"
HUB_OIDC_ISSUER="${KORDEX_HUB_OIDC_ISSUER:-}"
HUB_OIDC_CLIENT_ID="${KORDEX_HUB_OIDC_CLIENT_ID:-}"
HUB_OIDC_AUDIENCE="${KORDEX_HUB_OIDC_AUDIENCE:-$HUB_OIDC_CLIENT_ID}"
HUB_DASHBOARD_URL="${KORDEX_HUB_DASHBOARD_URL:-}"

if [[ -n "$HUB_OIDC_ISSUER$HUB_OIDC_CLIENT_ID$HUB_DASHBOARD_URL" ]]; then
  if [[ -z "$HUB_OIDC_ISSUER" || -z "$HUB_OIDC_CLIENT_ID" || -z "$HUB_DASHBOARD_URL" ]]; then
    echo "configure all of KORDEX_HUB_OIDC_ISSUER, KORDEX_HUB_OIDC_CLIENT_ID, and KORDEX_HUB_DASHBOARD_URL together" >&2
    exit 2
  fi
  python3 - "$HUB_OIDC_ISSUER" "$HUB_OIDC_CLIENT_ID" "$HUB_OIDC_AUDIENCE" "$HUB_DASHBOARD_URL" <<'PY'
import sys
from urllib.parse import urlsplit

issuer, client_id, audience, dashboard = sys.argv[1:]
def validate_https(value, label, origin_only=False):
    if any(ord(char) < 32 or char in "\\\"'" for char in value):
        raise SystemExit(f"{label} contains an invalid character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise SystemExit(f"invalid {label}: {error}")
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit(f"{label} must be an HTTPS URL without credentials, query, or fragment")
    if port is not None and not 1 <= port <= 65535:
        raise SystemExit(f"{label} port must be between 1 and 65535")
    if origin_only and parsed.path not in ("", "/"):
        raise SystemExit(f"{label} must be an HTTPS origin without a path")

validate_https(issuer, "OIDC issuer")
validate_https(dashboard, "dashboard URL", origin_only=True)
for label, value in (("OIDC client ID", client_id), ("OIDC audience", audience)):
    if not value or len(value) > 256 or value.strip() != value or any(ord(char) < 32 for char in value):
        raise SystemExit(f"{label} must contain 1 to 256 printable characters without surrounding whitespace")
PY
fi

if [[ -n "$UPGRADE_SSH_USER$UPGRADE_SSH_SECRET$UPGRADE_KNOWN_HOSTS" ]]; then
  if [[ -z "$UPGRADE_SSH_USER" || -z "$UPGRADE_SSH_SECRET" || -z "$UPGRADE_KNOWN_HOSTS" ]]; then
    echo "configure all of KORDEX_UPGRADE_SSH_USER, KORDEX_UPGRADE_SSH_SECRET, and KORDEX_UPGRADE_KNOWN_HOSTS together" >&2
    exit 2
  fi
  if [[ ! "$UPGRADE_SSH_USER" =~ ^[A-Za-z0-9_.-]{1,32}$ ]]; then
    echo "upgrade SSH user must contain 1 to 32 letters, digits, dots, underscores, or hyphens" >&2
    exit 2
  fi
  for secret_name in "$UPGRADE_SSH_SECRET" "$UPGRADE_KNOWN_HOSTS"; do
    if [[ ! "$secret_name" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ || ${#secret_name} -gt 63 ]]; then
      echo "upgrade SSH Secret and known-hosts ConfigMap names must be DNS labels of at most 63 characters" >&2
      exit 2
    fi
  done
fi

if [[ ! "$REGISTRY_PULL_SECRET" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ || ${#REGISTRY_PULL_SECRET} -gt 63 ]]; then
  echo "registry pull Secret name must be a DNS label of at most 63 characters" >&2
  exit 2
fi

# Keep the value safe to write into the generated ConfigMap YAML. This is a
# deliberately strict subset of Kubernetes Secret names.
declare -A seen_upgrade_pull_secrets=()
if [[ -n "$UPGRADE_PULL_SECRETS" ]]; then
  [[ "$UPGRADE_PULL_SECRETS" != ,* && "$UPGRADE_PULL_SECRETS" != *, && "$UPGRADE_PULL_SECRETS" != *,,* ]] || {
    echo "upgrade image pull Secret list contains an empty entry" >&2; exit 2;
  }
  IFS=',' read -r -a upgrade_pull_secret_names <<< "$UPGRADE_PULL_SECRETS"
  for secret_name in "${upgrade_pull_secret_names[@]}"; do
    if [[ ! "$secret_name" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ || ${#secret_name} -gt 63 ]]; then
      echo "upgrade image pull Secret names must be DNS labels of at most 63 characters" >&2
      exit 2
    fi
    if [[ -n "${seen_upgrade_pull_secrets[$secret_name]:-}" ]]; then
      echo "duplicate upgrade image pull Secret name: $secret_name" >&2
      exit 2
    fi
    seen_upgrade_pull_secrets[$secret_name]=1
  done
fi

if [[ ! "$CLUSTER_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]; then
  echo "cluster ID must be a UUID" >&2; exit 2
fi
if [[ ! "$HUB_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]]; then
  echo "hub URL must be an HTTPS origin without a path, query, or fragment" >&2; exit 2
fi
if [[ "$HUB_URL" =~ :([0-9]+)$ ]] && (( 10#${BASH_REMATCH[1]} < 1 || 10#${BASH_REMATCH[1]} > 65535 )); then
  echo "hub URL port must be between 1 and 65535" >&2; exit 2
fi
[[ -f "$LOCK" && ! -L "$LOCK" ]] || { echo "image digest lock must be a regular file" >&2; exit 2; }
[[ -f "$PUBLIC_KEYS" && ! -L "$PUBLIC_KEYS" ]] || { echo "public trust JSON must be a regular file" >&2; exit 2; }
[[ -d "$BUNDLE/manifests/kustomize/overlays/self-managed" ]] || { echo "bundle has no self-managed Kustomize overlay" >&2; exit 2; }
if [[ "$PRIVATE_CA" == true ]]; then
  [[ -d "$BUNDLE/manifests/kustomize/overlays/self-managed-private-ca" ]] || { echo "bundle has no self-managed private-CA Kustomize overlay" >&2; exit 2; }
fi
[[ ! -e "$OUTPUT_REQUESTED" && ! -L "$OUTPUT_REQUESTED" ]] || { echo "output overlay already exists: $OUTPUT_REQUESTED" >&2; exit 2; }
: "${KORDEX_RELEASE_PUBLIC_KEY:?set path to trusted Ed25519 release public key}"
: "${KORDEX_TRUSTED_BUNDLE_VERIFIER:?set path to independently trusted verify-offline-bundle.sh}"
[[ -f "$KORDEX_TRUSTED_BUNDLE_VERIFIER" && -x "$KORDEX_TRUSTED_BUNDLE_VERIFIER" && ! -L "$KORDEX_TRUSTED_BUNDLE_VERIFIER" ]] || {
  echo "trusted bundle verifier must be an executable, regular file" >&2; exit 2;
}
TRUSTED_VERIFIER="$(cd "$(dirname "$KORDEX_TRUSTED_BUNDLE_VERIFIER")" && pwd)/$(basename "$KORDEX_TRUSTED_BUNDLE_VERIFIER")"
case "$TRUSTED_VERIFIER" in
  "$BUNDLE"/*) echo "trusted bundle verifier must be outside the bundle" >&2; exit 2 ;;
esac
"$TRUSTED_VERIFIER" "$BUNDLE" "$KORDEX_RELEASE_PUBLIC_KEY"
"$SCRIPT_DIR/verify-image-lock.sh" "$LOCK" "$LOCK_SIGNATURE" "$KORDEX_RELEASE_PUBLIC_KEY"

declare -A images=()
while IFS=$'\t' read -r name ref extra; do
  [[ -n "$name" ]] || continue
  [[ -z "${extra:-}" ]] || { echo "malformed image lock row for $name" >&2; exit 2; }
  case "$name" in agent|operator|control-plane|dashboard|ansible-ee|postgres) ;; *) echo "unsupported image in lock: $name" >&2; exit 2 ;; esac
  [[ -z "${images[$name]:-}" ]] || { echo "duplicate image lock entry: $name" >&2; exit 2; }
  if [[ ! "$ref" =~ ^([a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+)@sha256:([a-f0-9]{64})$ ]]; then
    echo "image lock entry is not a repository-qualified digest: $name" >&2; exit 2
  fi
  if [[ "${BASH_REMATCH[3]:-}" == :* ]]; then
    port="${BASH_REMATCH[3]#:}"
    (( 10#$port >= 1 && 10#$port <= 65535 )) || { echo "invalid registry port for $name" >&2; exit 2; }
  fi
  repository="${ref%@*}"
  [[ "$repository" == */kordex/$name ]] || { echo "image lock repository does not match image name: $name" >&2; exit 2; }
  images[$name]="$ref"
done < "$LOCK"
for name in agent operator control-plane dashboard ansible-ee postgres; do
  [[ -n "${images[$name]:-}" ]] || { echo "required image missing from lock: $name" >&2; exit 2; }
done

OUTPUT_NAME="$(basename -- "$OUTPUT_REQUESTED")"
if [[ -z "$OUTPUT_NAME" || "$OUTPUT_NAME" == . || "$OUTPUT_NAME" == .. || "$OUTPUT_NAME" == / ]]; then
  echo "invalid output overlay path: $OUTPUT_REQUESTED" >&2
  exit 2
fi
mkdir -p "$(dirname -- "$OUTPUT_REQUESTED")"
OUTPUT_PARENT="$(cd -- "$(dirname -- "$OUTPUT_REQUESTED")" && pwd)"
OUTPUT_FINAL="$OUTPUT_PARENT/$OUTPUT_NAME"
[[ ! -e "$OUTPUT_FINAL" && ! -L "$OUTPUT_FINAL" ]] || { echo "output overlay already exists: $OUTPUT_FINAL" >&2; exit 2; }
STAGING_ROOT="$(mktemp -d "$OUTPUT_PARENT/.${OUTPUT_NAME}.configure.XXXXXX")"
cleanup_staging() {
  if [[ -n "${STAGING_ROOT:-}" && -d "$STAGING_ROOT" ]]; then
    rm -rf -- "$STAGING_ROOT"
  fi
}
trap cleanup_staging EXIT
OUTPUT="$STAGING_ROOT/tree"
cp -a "$BUNDLE/manifests/kustomize" "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
CONFIG_OVERLAY="$OUTPUT/overlays/self-managed"
OVERLAY="$CONFIG_OVERLAY"
if [[ "$PRIVATE_CA" == true ]]; then
  OVERLAY="$OUTPUT/overlays/self-managed-private-ca"
fi
KUSTOMIZATION="$CONFIG_OVERLAY/kustomization.yaml"
for name in agent operator; do
  ref="${images[$name]}"
  repository="${ref%@*}"
  digest="${ref##*@}"
  sed -i "/^  - name: kordex\/$name$/,/^  - name:/ { s#newName: registry.example.invalid/platform/kordex/$name#newName: $repository#; s#newTag: .*#digest: $digest#; }" "$KUSTOMIZATION"
done
sed -i "s#clusterID: REPLACE_WITH_REGISTERED_CLUSTER_UUID#clusterID: $CLUSTER_ID#" "$CONFIG_OVERLAY/agent-settings.patch.yaml" "$CONFIG_OVERLAY/operator-settings.patch.yaml"
sed -i "s#controlPlaneURL: https://REPLACE_WITH_MANAGEMENT_HOST#controlPlaneURL: $HUB_URL#" "$CONFIG_OVERLAY/agent-settings.patch.yaml"
sed -i "s#upgradeExecutionEnvironmentAllowlist: \"\"#upgradeExecutionEnvironmentAllowlist: \"${images[ansible-ee]}\"#" "$CONFIG_OVERLAY/operator-settings.patch.yaml"
sed -i "s#upgradeImagePullSecrets: \"\"#upgradeImagePullSecrets: \"$UPGRADE_PULL_SECRETS\"#" "$CONFIG_OVERLAY/operator-settings.patch.yaml"
if [[ -n "$UPGRADE_SSH_USER" ]]; then
  sed -i "s#upgradeSSHUser: \"\"#upgradeSSHUser: \"$UPGRADE_SSH_USER\"#; s#upgradeSSHSecret: \"\"#upgradeSSHSecret: \"$UPGRADE_SSH_SECRET\"#; s#upgradeKnownHosts: \"\"#upgradeKnownHosts: \"$UPGRADE_KNOWN_HOSTS\"#" "$CONFIG_OVERLAY/operator-settings.patch.yaml"
  if [[ "$UPGRADE_SSH_SECRET" != kordex-upgrade-ssh ]]; then
    sed -i "s#resourceNames: \[kordex-upgrade-ssh\]#resourceNames: [$UPGRADE_SSH_SECRET]#" "$OUTPUT/components/operator/rbac.yaml"
  fi
fi
sed -i 's#maintenanceEnabled: "true"#maintenanceEnabled: "false"#g' "$CONFIG_OVERLAY/agent-settings.patch.yaml"
cp "$PUBLIC_KEYS" "$CONFIG_OVERLAY/keys.json"
chmod 600 "$CONFIG_OVERLAY/keys.json"
# These source patches are part of the provider-neutral base overlay.
sed -i "s#name: kordex-registry#name: $REGISTRY_PULL_SECRET#g" \
  "$CONFIG_OVERLAY/agent-pull-secret.patch.yaml" \
  "$CONFIG_OVERLAY/operator-pull-secret.patch.yaml"

if grep -En 'REPLACE_WITH|registry\.example\.invalid|newTag:|upgradeExecutionEnvironmentAllowlist: ""' "$KUSTOMIZATION" "$CONFIG_OVERLAY/agent-settings.patch.yaml" "$CONFIG_OVERLAY/operator-settings.patch.yaml"; then
  echo "configured overlay still contains placeholders or mutable image tags" >&2
  exit 1
fi

# The bundle intentionally removes cluster-specific keys.json files from every
# overlay. Configure optional provider overlays from the same signed lock so
# their images and trust material are usable from a private registry as well.
for overlay_name in gke-fleet gke-operator; do
  overlay_dir="$OUTPUT/overlays/$overlay_name"
  [[ -d "$overlay_dir" ]] || continue
  kustomization="$overlay_dir/kustomization.yaml"
  cp "$PUBLIC_KEYS" "$overlay_dir/keys.json"
  chmod 600 "$overlay_dir/keys.json"
  if [[ "$PRIVATE_CA" == true && "$overlay_name" == gke-fleet ]]; then
    sed -i '/^  - \.\.\/\.\.\/components\/operator$/a\  - ../../components/private-management-ca' "$kustomization"
  fi
  for name in agent operator; do
    ref="${images[$name]}"
    python3 - "$kustomization" "kordex/$name" "${ref%@*}" "${ref##*@}" <<'PY'
import re
import sys

path, image_name, repository, digest = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    lines = source.readlines()
starts = [i for i, line in enumerate(lines) if re.match(r"^\s*-\s+name:\s*" + re.escape(image_name) + r"\s*$", line)]
if not starts:
    raise SystemExit(0)
if len(starts) != 1:
    raise SystemExit(f"expected one image entry for {image_name} in {path}")
start = starts[0]
end = next((i for i in range(start + 1, len(lines)) if re.match(r"^\s*-\s+name:\s*", lines[i])), len(lines))
block = lines[start:end]
rewritten = []
inserted = False
for line in block:
    match = re.match(r"^(\s*)newName:\s*.*$", line.rstrip("\n"))
    if match:
        rewritten.extend((f"{match.group(1)}newName: {repository}\n", f"{match.group(1)}digest: {digest}\n"))
        inserted = True
    elif not re.match(r"^\s*(?:newTag|digest):\s*.*$", line.rstrip("\n")):
        rewritten.append(line)
if not inserted:
    raise SystemExit(f"image entry {image_name} has no newName in {path}")
lines[start:end] = rewritten
with open(path, "w", encoding="utf-8") as output:
    output.writelines(lines)
PY
  done
  for settings in "$overlay_dir"/*-settings.patch.yaml; do
    [[ -f "$settings" ]] || continue
    sed -i "s#clusterID: REPLACE_WITH_REGISTERED_CLUSTER_UUID#clusterID: $CLUSTER_ID#g" "$settings"
    sed -i "s#controlPlaneURL: https://REPLACE_WITH_MANAGEMENT_HOST#controlPlaneURL: $HUB_URL#g" "$settings"
    sed -i 's#maintenanceEnabled: "true"#maintenanceEnabled: "false"#g' "$settings"
    if [[ "$settings" == *operator-settings.patch.yaml ]] && ! grep -q '^  upgradeExecutionEnvironmentAllowlist:' "$settings"; then
      printf '  upgradeExecutionEnvironmentAllowlist: "%s"\n' "${images[ansible-ee]}" >> "$settings"
    fi
    if [[ "$settings" == *operator-settings.patch.yaml ]]; then
      if grep -q '^  upgradeImagePullSecrets:' "$settings"; then
        sed -i "s#^  upgradeImagePullSecrets: .*#  upgradeImagePullSecrets: \"$UPGRADE_PULL_SECRETS\"#" "$settings"
      else
        printf '  upgradeImagePullSecrets: "%s"\n' "$UPGRADE_PULL_SECRETS" >> "$settings"
      fi
      if [[ -n "$UPGRADE_SSH_USER" ]]; then
        for entry in "upgradeSSHUser:$UPGRADE_SSH_USER" "upgradeSSHSecret:$UPGRADE_SSH_SECRET" "upgradeKnownHosts:$UPGRADE_KNOWN_HOSTS"; do
          key="${entry%%:*}"
          value="${entry#*:}"
          if grep -q "^  $key:" "$settings"; then
            sed -i "s#^  $key: .*#  $key: \"$value\"#" "$settings"
          else
            printf '  %s: "%s"\n' "$key" "$value" >> "$settings"
          fi
        done
      fi
    fi
  done
  for name in agent operator; do
    grep -Fq -- "- name: kordex/$name" "$kustomization" || continue
    cat > "$overlay_dir/offline-$name-pull-secret.patch.yaml" <<EOF_PATCH
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kordex-$name
  namespace: kordex-system
spec:
  template:
    spec:
      imagePullSecrets:
        - name: $REGISTRY_PULL_SECRET
EOF_PATCH
    printf '  - path: offline-%s-pull-secret.patch.yaml\n' "$name" >> "$kustomization"
  done
  if grep -En 'REPLACE_WITH|registry\.example\.invalid|newTag:|upgradeExecutionEnvironmentAllowlist: ""' "$kustomization" "$overlay_dir"/*-settings.patch.yaml; then
    echo "configured overlay $overlay_name still contains placeholders or mutable image tags" >&2
    exit 1
  fi
done

# The same signed image lock also configures the optional self-hosted hub tree.
# OIDC/database endpoints and Secret objects remain site-specific and are
# supplied separately in kordex-hub-settings and the referenced Secrets.
HUB_OVERLAY="$OUTPUT/hub/overlays/self-hosted"
for overlay_name in self-hosted self-hosted-migration; do
  HUB_OVERLAY="$OUTPUT/hub/overlays/$overlay_name"
  [[ -d "$HUB_OVERLAY" ]] || continue
  for name in control-plane dashboard; do
    ref="${images[$name]}"
    python3 - "$HUB_OVERLAY/kustomization.yaml" "kordex/$name" "${ref%@*}" "${ref##*@}" <<'PY'
import re
import sys

path, image_name, repository, digest = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    lines = source.readlines()
starts = [i for i, line in enumerate(lines) if re.match(r"^\s*-\s+name:\s*" + re.escape(image_name) + r"\s*$", line)]
if not starts:
    raise SystemExit(0)
if len(starts) != 1:
    raise SystemExit(f"expected one image entry for {image_name} in {path}")
start = starts[0]
end = next((i for i in range(start + 1, len(lines)) if re.match(r"^\s*-\s+name:\s*", lines[i])), len(lines))
indent = re.match(r"^(\s*)", lines[start]).group(1)
block = lines[start:end]
rewritten = []
inserted = False
for line in block:
    match = re.match(r"^(\s*)newName:\s*.*$", line.rstrip("\n"))
    if match:
        rewritten.extend((f"{match.group(1)}newName: {repository}\n", f"{match.group(1)}digest: {digest}\n"))
        inserted = True
    elif not re.match(r"^\s*(?:newTag|digest):\s*.*$", line.rstrip("\n")):
        rewritten.append(line)
if not inserted:
    raise SystemExit(f"image entry {image_name} has no newName in {path}")
lines[start:end] = rewritten
with open(path, "w", encoding="utf-8") as output:
    output.writelines(lines)
PY
  done
done
sed -i "s#name: kordex-registry#name: $REGISTRY_PULL_SECRET#g" \
  "$OUTPUT/hub/base/api-deployment.yaml" \
  "$OUTPUT/hub/base/scheduler-deployment.yaml" \
  "$OUTPUT/hub/base/dashboard-deployment.yaml" \
  "$OUTPUT/hub/overlays/self-hosted-migration/migration-job.yaml"

if [[ -n "$HUB_OIDC_ISSUER" ]]; then
  python3 - "$HUB_OIDC_ISSUER" "$HUB_OIDC_CLIENT_ID" "$HUB_OIDC_AUDIENCE" "$HUB_DASHBOARD_URL" \
    "$OUTPUT/hub/base/settings.yaml" \
    "$OUTPUT/hub/overlays/self-hosted-migration/settings.yaml" <<'PY'
import json
import pathlib
import re
import sys

issuer, client_id, audience, dashboard, *paths = sys.argv[1:]
values = {
    "oidcIssuer": issuer,
    "oidcAudience": audience,
    "oidcClientID": client_id,
    "dashboardURL": dashboard.rstrip("/"),
}
for filename in paths:
    path = pathlib.Path(filename)
    text = path.read_text(encoding="utf-8")
    for key, value in values.items():
        pattern = re.compile(r"^(  " + re.escape(key) + r": ).*$", re.MULTILINE)
        text, count = pattern.subn(lambda match: match.group(1) + json.dumps(value), text)
        if count != 1:
            raise SystemExit(f"expected one {key} setting in {path}, found {count}")
    path.write_text(text, encoding="utf-8")
PY
fi
mv -- "$OUTPUT" "$OUTPUT_FINAL"
OUTPUT="$OUTPUT_FINAL"
OVERLAY="$OUTPUT/overlays/self-managed"
if [[ "$PRIVATE_CA" == true ]]; then
  OVERLAY="$OUTPUT/overlays/self-managed-private-ca"
fi
rmdir -- "$STAGING_ROOT"
STAGING_ROOT=""
trap - EXIT
printf 'Configured digest-pinned Kustomize tree at %s\n' "$OUTPUT"
printf 'Render and review with: kubectl kustomize %q\n' "$OVERLAY"
