#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "${GITHUB_OUTPUT:-}" || -L "${GITHUB_OUTPUT:-/dev/null}" ]]; then
  echo "usage: GITHUB_OUTPUT=<workflow-output-file> $0 <component>" >&2
  exit 2
fi
component="$1"
output_file="$GITHUB_OUTPUT"
args_file="$(mktemp)"
trap 'rm -f "$args_file"' EXIT

validate_digest_reference() {
  local value="$1" name="$2"
  [[ "$value" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+(:[A-Za-z0-9._-]+)?@sha256:[a-f0-9]{64}$ ]] || {
    echo "$name must be a repository-qualified sha256-pinned OCI reference" >&2
    exit 2
  }
}

case "$component" in
  ansible-ee)
    validate_digest_reference "${KORDEX_ANSIBLE_EE_BASE:-}" KORDEX_ANSIBLE_EE_BASE
    printf 'KORDEX_EE_BASE=%s\n' "$KORDEX_ANSIBLE_EE_BASE" > "$args_file"
    printf 'KORDEX_DEBIAN_PLAYBOOK_SHA256=%s\n' "$(sha256sum integrations/ansible-ee/upgrade-debian.yml | awk '{print $1}')" >> "$args_file"
    printf 'KORDEX_RHEL_PLAYBOOK_SHA256=%s\n' "$(sha256sum integrations/ansible-ee/upgrade-rhel.yml | awk '{print $1}')" >> "$args_file"
    printf 'KORDEX_COLLECTIONS_SHA256=%s\nKORDEX_ACTION_MARKER_VERSION=1\n' \
      "$(sha256sum integrations/ansible-ee/collections.lock | awk '{print $1}')" >> "$args_file"
    ;;
  postgres)
    validate_digest_reference "${KORDEX_POSTGRES_BASE:-}" KORDEX_POSTGRES_BASE
    printf 'KORDEX_POSTGRES_BASE=%s\n' "$KORDEX_POSTGRES_BASE" > "$args_file"
    ;;
  control-plane|agent|operator|dashboard|agent-relay)
    : > "$args_file"
    ;;
  *)
    echo "unsupported release image component" >&2
    exit 2
    ;;
esac

{
  printf 'args<<KORDEX_BUILD_ARGS\n'
  cat "$args_file"
  printf 'KORDEX_BUILD_ARGS\n'
} >> "$output_file"
