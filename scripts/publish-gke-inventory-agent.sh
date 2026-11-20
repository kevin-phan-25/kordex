#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
PROJECT="kordex-fleet-platform"
REPOSITORY="${1:-${KORDEX_AGENT_IMAGE_REPOSITORY:-}}"

usage() {
  echo "Usage: $0 LOCATION-docker.pkg.dev/$PROJECT/EXISTING_REPOSITORY/kordex-agent" >&2
  echo "The script only publishes to an existing Artifact Registry Docker repository; it never creates one." >&2
}

if [[ -z "$REPOSITORY" ]]; then usage; exit 2; fi
if [[ ! "$REPOSITORY" =~ ^([a-z0-9-]+-docker\.pkg\.dev)/${PROJECT}/([a-z][a-z0-9-]{0,62})/kordex-agent$ ]]; then
  echo "image repository must be an Artifact Registry path in project ${PROJECT}, ending in /kordex-agent" >&2
  exit 2
fi

REGISTRY="${BASH_REMATCH[1]}"
REPOSITORY_NAME="${BASH_REMATCH[2]}"
LOCATION="${REGISTRY%-docker.pkg.dev}"
for tool in gcloud podman git sha256sum sort find xargs; do
  command -v "$tool" >/dev/null || { echo "required command not found: $tool" >&2; exit 2; }
done

if ! REPOSITORY_INFO="$(gcloud artifacts repositories describe "$REPOSITORY_NAME" \
  --project="$PROJECT" --location="$LOCATION" --format='value(format)' 2>&1)"; then
  echo "could not verify Artifact Registry repository; check gcloud authentication, permissions, and repository name. No repository was created." >&2
  exit 1
fi
if [[ "$REPOSITORY_INFO" != "DOCKER" ]]; then
  echo "the specified Artifact Registry repository is not a Docker repository; no repository was created" >&2
  exit 1
fi

COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
SOURCE_HASH="$(cd "$ROOT" && find api agent -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)"
TAG="gke-inventory-${COMMIT}-${SOURCE_HASH}"
IMAGE="${REPOSITORY}:${TAG}"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT HUP INT TERM
AUTH_FILE="$TEMP_DIR/registry-auth.json"
DIGEST_FILE="$TEMP_DIR/digest"

echo "Building ${IMAGE} for linux/amd64 from the current api/ and agent/ source tree."
podman build --platform linux/amd64 --timestamp 0 \
  --label "org.opencontainers.image.revision=${COMMIT}" \
  --label "io.kordex.source.sha256=${SOURCE_HASH}" \
  --file "$ROOT/agent/Dockerfile" --tag "$IMAGE" "$ROOT"

# The short-lived access token is piped directly to Podman and stored only in
# a private temporary auth file that is removed on exit.
gcloud auth print-access-token --project="$PROJECT" | \
  podman login --authfile "$AUTH_FILE" --username oauth2accesstoken --password-stdin "$REGISTRY" >/dev/null
podman push --authfile "$AUTH_FILE" --digestfile "$DIGEST_FILE" "$IMAGE"

DIGEST="$(cat "$DIGEST_FILE")"
if [[ ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "registry push did not return a valid sha256 manifest digest" >&2
  exit 1
fi

echo "Published image: ${REPOSITORY}@${DIGEST}"
echo "Tag: ${TAG}"
echo "Source tree SHA-256: ${SOURCE_HASH}"
