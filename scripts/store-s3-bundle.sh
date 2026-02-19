#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

verifys3hash()
{
  s3uri="$1"
  expectedhash="$2"
  s3_tmp="$( mktemp -u s3-verify-XXXXXX )"
  aws s3 cp "${s3uri}" "${s3_tmp}"
  download_sha384sum=$( sha384sum "${s3_tmp}" | awk '{print $1}' )
  if [[ "${download_sha384sum}" != "${expectedhash}" ]]; then
    echo "error: uploaded s3 object sha384sum ${download_sha384sum} does not match original ${expectedhash}" >&2
    exit 1
  fi
  rm -f "${s3_tmp}"
}

echo "==> Starting store-s3-bundle"

: "${RELEASE_BUCKET:?RELEASE_BUCKET must be set in release.conf}"
: "${RELEASE_PREFIX:?RELEASE_PREFIX must be set in release.conf}"

# sanity checks
[[ ! -f "${BUNDLE_FILE}" ]] && { echo "error: bundle file ${BUNDLE_FILE} does not exist" >&2; exit 1; }
[[ ! -s "${BUNDLE_FILE}" ]] && { echo "error: bundle file ${BUNDLE_FILE} is empty" >&2; exit 1; }
[[ ! -f "${BUNDLE_SIG_FILE}" ]] && { echo "error: bundle signature file ${BUNDLE_SIG_FILE} does not exist" >&2; exit 1; }
[[ ! -s "${BUNDLE_SIG_FILE}" ]] && { echo "error: bundle signature file ${BUNDLE_SIG_FILE} is empty" >&2; exit 1; }

# get sha384sum of the bundle
bundlesha384sum=$( sha384sum "${BUNDLE_FILE}" | awk '{print $1}' )
: "${bundlesha384sum:?failed to calculate sha384sum of bundle file ${BUNDLE_FILE}}"

# validate gzip
gzip -t "${BUNDLE_FILE}" || { echo "error: invalid gzip"; exit 1; }
# validate tar validity (tests gzip too)
tar -tzf "${BUNDLE_FILE}" > /dev/null || { echo "error: invalid tar"; exit 1; }

# upload the bundle to s3 named by its sha384sum
bundle_upload_file="${bundlesha384sum}.tar.gz"
echo "==> Uploading site bundle to s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_upload_file}"
aws s3 cp "${BUNDLE_FILE}" "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_upload_file}"

# verify upload by re-downloading and checking sha384sum
echo "==> Verifying uploaded bundle by re-downloading and checking sha384sum"
verifys3hash "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_upload_file}" "${bundlesha384sum}"

# copy the sigstore bundle to s3
bundle_sig_upload_file="${bundlesha384sum}.sigstore.json"
echo "==> Uploading sigstore bundle to s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_sig_upload_file}"
aws s3 cp "${BUNDLE_SIG_FILE}" "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_sig_upload_file}"

# verify sigstore bundle upload by re-downloading and checking sha384sum
echo "==> Verifying uploaded sigstore bundle by re-downloading and checking sha384sum"
bundle_sig_hash=$( sha384sum "${BUNDLE_SIG_FILE}" | awk '{print $1}' )
verifys3hash "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${bundle_sig_upload_file}" "${bundle_sig_hash}"

echo "${bundlesha384sum}" > .release-id

echo "==> store-s3-bundle done"