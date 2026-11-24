#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SCRIPT="$ROOT/scripts/prepare-release-image-build-args.sh"
BASE='registry.example/kordex/ee-base@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

if KORDEX_ANSIBLE_EE_BASE= bash "$SCRIPT" ansible-ee 2>/dev/null; then
  echo 'missing GitHub output path and EE base were accepted' >&2
  exit 1
fi
if GITHUB_OUTPUT="$TMP/empty" KORDEX_ANSIBLE_EE_BASE= bash "$SCRIPT" ansible-ee 2>/dev/null; then
  echo 'missing EE base was accepted' >&2
  exit 1
fi
if GITHUB_OUTPUT="$TMP/empty" KORDEX_ANSIBLE_EE_BASE='registry.example/ee:mutable' bash "$SCRIPT" ansible-ee 2>/dev/null; then
  echo 'mutable EE base was accepted' >&2
  exit 1
fi
GITHUB_OUTPUT="$TMP/ee" KORDEX_ANSIBLE_EE_BASE="$BASE" bash "$SCRIPT" ansible-ee
grep -Fxq "KORDEX_EE_BASE=$BASE" "$TMP/ee"
grep -Fxq "KORDEX_ACTION_MARKER_VERSION=1" "$TMP/ee"
grep -Fxq "KORDEX_DEBIAN_PLAYBOOK_SHA256=$(sha256sum "$ROOT/integrations/ansible-ee/upgrade-debian.yml" | awk '{print $1}')" "$TMP/ee"
grep -Fxq "KORDEX_RHEL_PLAYBOOK_SHA256=$(sha256sum "$ROOT/integrations/ansible-ee/upgrade-rhel.yml" | awk '{print $1}')" "$TMP/ee"

if GITHUB_OUTPUT="$TMP/pg" KORDEX_POSTGRES_BASE='postgres:17-alpine' bash "$SCRIPT" postgres 2>/dev/null; then
  echo 'mutable PostgreSQL base was accepted' >&2
  exit 1
fi
GITHUB_OUTPUT="$TMP/pg" KORDEX_POSTGRES_BASE='docker.io/library/postgres:17-alpine@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' bash "$SCRIPT" postgres
grep -Fxq 'KORDEX_POSTGRES_BASE=docker.io/library/postgres:17-alpine@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$TMP/pg"

GITHUB_OUTPUT="$TMP/other" bash "$SCRIPT" control-plane
grep -Fxq 'args<<KORDEX_BUILD_ARGS' "$TMP/other"
grep -Fxq 'KORDEX_BUILD_ARGS' "$TMP/other"
echo 'release image build-argument checks passed (test-only base references)'
