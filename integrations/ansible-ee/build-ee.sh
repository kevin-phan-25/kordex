#!/usr/bin/env bash
set -euo pipefail

: "${KORDEX_ANSIBLE_EE_BASE:?set a base Ansible EE image reference pinned with @sha256:...}"
: "${KORDEX_ANSIBLE_EE_TAG:?set the local output image tag}"
KORDEX_ACTION_MARKER_VERSION="${KORDEX_ACTION_MARKER_VERSION:-1}"
KORDEX_ANSIBLE_EE_PLATFORMS="${KORDEX_ANSIBLE_EE_PLATFORMS:-linux/amd64,linux/arm64}"
if [[ "${KORDEX_ACTION_MARKER_VERSION}" != 1 ]]; then
  echo "KORDEX_ACTION_MARKER_VERSION must be 1 for executable host upgrades" >&2
  exit 2
fi

if [[ ! "${KORDEX_ANSIBLE_EE_BASE}" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]]; then
  echo "KORDEX_ANSIBLE_EE_BASE must be a repository-qualified OCI reference pinned by sha256 digest" >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
DEBIAN_PLAYBOOK_DIGEST="$(sha256sum "${SCRIPT_DIR}/upgrade-debian.yml" | awk '{print $1}')"
RHEL_PLAYBOOK_DIGEST="$(sha256sum "${SCRIPT_DIR}/upgrade-rhel.yml" | awk '{print $1}')"
COLLECTIONS_DIGEST="$(sha256sum "${SCRIPT_DIR}/collections.lock" | awk '{print $1}')"

if [[ ! "${KORDEX_ANSIBLE_EE_PLATFORMS}" =~ ^linux/(amd64|arm64)(,linux/(amd64|arm64))*$ ]]; then
  echo "KORDEX_ANSIBLE_EE_PLATFORMS must be a comma-separated list of linux/amd64 and/or linux/arm64" >&2
  exit 2
fi

podman build \
  --platform "${KORDEX_ANSIBLE_EE_PLATFORMS}" \
  --file "${SCRIPT_DIR}/Containerfile" \
  --manifest "${KORDEX_ANSIBLE_EE_TAG}" \
  --build-arg "KORDEX_EE_BASE=${KORDEX_ANSIBLE_EE_BASE}" \
  --build-arg "KORDEX_DEBIAN_PLAYBOOK_SHA256=${DEBIAN_PLAYBOOK_DIGEST}" \
  --build-arg "KORDEX_RHEL_PLAYBOOK_SHA256=${RHEL_PLAYBOOK_DIGEST}" \
  --build-arg "KORDEX_COLLECTIONS_SHA256=${COLLECTIONS_DIGEST}" \
  --build-arg "KORDEX_ACTION_MARKER_VERSION=${KORDEX_ACTION_MARKER_VERSION}" \
  "${SCRIPT_DIR}"

printf 'debianPlaybookDigest=%s\nrhelPlaybookDigest=%s\ncollectionsDigest=%s\n' "${DEBIAN_PLAYBOOK_DIGEST}" "${RHEL_PLAYBOOK_DIGEST}" "${COLLECTIONS_DIGEST}"
