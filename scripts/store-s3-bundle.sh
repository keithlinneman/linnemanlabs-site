#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
# shellcheck source=release.conf
source "${SCRIPT_DIR}/../release.conf"

if [[ -z "${RELEASE_ID:-}" && -f .release-id ]]; then
  RELEASE_ID="$( cat .release-id )"
fi
: "${RELEASE_ID:?RELEASE_ID must be set}"
# 65 with newline
rel_len="$( wc -c <<< "${RELEASE_ID}" )"
if [[ "${rel_len}" != 65 ]]; then
  echo "error: RELEASE_ID length is ${rel_len} expected 65" >&2
  exit 1
fi

: "${RELEASE_BUCKET:?RELEASE_BUCKET must be set in release.conf}"
: "${RELEASE_PREFIX:?RELEASE_PREFIX must be set in release.conf}"

bundle_file="${RELEASE_ID}.tar.gz"

# sanity checks
[[ ! -f "${bundle_file}" ]] && { echo "error: bundle file ${bundle_file} does not exist" >&2; exit 1; }
[[ ! -s "${bundle_file}" ]] && { echo "error: bundle file ${bundle_file} is empty" >&2; exit 1; }

echo "==> Uploading site bundle to s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${RELEASE_ID}/${bundle_file}"
aws s3 cp "${bundle_file}" "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${RELEASE_ID}/${bundle_file}"

echo "==> store-s3-bundle done"