#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
# shellcheck source=release.conf
source "${SCRIPT_DIR}/../release.conf"

if [[ -z "${RELEASE_ID:-}" && -f .release-id ]]; then
  RELEASE_ID="$( cat .release-id )"
fi
: "${RELEASE_ID:?RELEASE_ID must be set}"

: "${RELEASE_BUCKET:?RELEASE_BUCKET must be set in release.conf}"
: "${RELEASE_PREFIX:?RELEASE_PREFIX must be set in release.conf}"

[[ ! -f "${BUNDLE_FILE}" ]] && { echo "error: missing ${BUNDLE_FILE} - build the bundle first" >&2; exit 1; }
[[ ! -f "${BUNDLE_FILE}.sha256" ]] && { echo "error: missing ${BUNDLE_FILE}.sha256 - sign the bundle first" >&2; exit 1; }

echo "==> Uploading site bundle to s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${RELEASE_ID}/${BUNDLE_FILE}"
aws s3 cp "${BUNDLE_FILE}" "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${RELEASE_ID}/${BUNDLE_FILE}"

echo "==> Uploading site bundle checksum to s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${RELEASE_ID}/${BUNDLE_FILE}.sha256"
aws s3 cp "${BUNDLE_FILE}.sha256" "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${RELEASE_ID}/${BUNDLE_FILE}.sha256"

echo "==> store-s3-bundle done"