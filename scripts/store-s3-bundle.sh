#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

echo "==> Starting store-s3-bundle"

: "${RELEASE_BUCKET:?RELEASE_BUCKET must be set in release.conf}"
: "${RELEASE_PREFIX:?RELEASE_PREFIX must be set in release.conf}"

# sanity checks
[[ ! -f "${BUNDLE_FILE}" ]] && { echo "error: bundle file ${BUNDLE_FILE} does not exist" >&2; exit 1; }
[[ ! -s "${BUNDLE_FILE}" ]] && { echo "error: bundle file ${BUNDLE_FILE} is empty" >&2; exit 1; }

# get sha256sum of the bundle
bundlesha256sum=$( sha256sum "${BUNDLE_FILE}" | awk '{print $1}' )
: "${bundlesha256sum:?failed to calculate sha256sum of bundle file ${BUNDLE_FILE}}"

# validate gzip
gzip -t "${BUNDLE_FILE}" || { echo "error: invalid gzip"; exit 1; }
# validate tar validity (tests gzip too)
tar -tzf "${BUNDLE_FILE}" > /dev/null || { echo "error: invalid tar"; exit 1; }
# todo: check for some expected files inside the tar

# upload the bundle to s3 named by its sha256sum
bundle_upload_file="${bundlesha256sum}.tar.gz"
echo "==> Uploading site bundle to s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_upload_file}"
aws s3 cp "${BUNDLE_FILE}" "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_upload_file}"

# verify upload by re-downloading and checking sha256sum
bundle_temp="$( mktemp -u bundle-verify-XXXXXX.tar.gz )"
aws s3 cp "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_upload_file}" "${bundle_temp}"
download_sha256sum=$( sha256sum "${bundle_temp}" | awk '{print $1}' )
if [[ "${download_sha256sum}" != "${bundlesha256sum}" ]]; then
  echo "error: uploaded bundle sha256sum ${download_sha256sum} does not match original ${bundlesha256sum}" >&2
  exit 1
fi
rm -f "${bundle_temp}"

echo "${bundlesha256sum}" > .release-id

echo "==> store-s3-bundle done"