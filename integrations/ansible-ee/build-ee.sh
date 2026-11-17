#!/usr/bin/env bash
set -euo pipefail

: "${KORDEX_ANSIBLE_EE_BASE:?set a base Ansible EE image reference pinned with @sha256:...}"
: "${KORDEX_ANSIBLE_EE_TAG:?set the local output image tag}"

if [[ ! "${KORDEX_ANSIBLE_EE_BASE}" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]]; then
  echo "KORDEX_ANSIBLE_EE_BASE must be a repository-qualified OCI reference pinned by sha256 digest" >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
PLAYBOOK_DIGEST="$(sha256sum "${SCRIPT_DIR}/upgrade-debian.yml" | awk '{print $1}')"
COLLECTIONS_DIGEST="$(sha256sum "${SCRIPT_DIR}/collections.lock" | awk '{print $1}')"

podman build \
  --file "${SCRIPT_DIR}/Containerfile" \
  --tag "${KORDEX_ANSIBLE_EE_TAG}" \
  --build-arg "KORDEX_EE_BASE=${KORDEX_ANSIBLE_EE_BASE}" \
  --build-arg "KORDEX_PLAYBOOK_SHA256=${PLAYBOOK_DIGEST}" \
  --build-arg "KORDEX_COLLECTIONS_SHA256=${COLLECTIONS_DIGEST}" \
  --build-arg "KORDEX_PLAYBOOK_CATALOG=kordex.os-upgrade.debian.v2" \
  "${SCRIPT_DIR}"

printf 'playbookDigest=%s\ncollectionsDigest=%s\n' "${PLAYBOOK_DIGEST}" "${COLLECTIONS_DIGEST}"
