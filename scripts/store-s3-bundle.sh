#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

cd "${REPO_ROOT}"

verifys3hash()
{
  local s3uri="$1"
  local expectedhash="$2"
  local s3_tmp

  s3_tmp="$( mktemp )"
  aws s3 cp "${s3uri}" "${s3_tmp}"

  local download_sha384sum
  download_sha384sum="$( sha384sum "${s3_tmp}" | awk '{print $1}' )"

  rm -f "${s3_tmp}"

  if [[ "${download_sha384sum}" != "${expectedhash}" ]]; then
    echo "error: uploaded s3 object sha384sum ${download_sha384sum} does not match original ${expectedhash}" >&2
    exit 1
  fi
}

require_file()
{
  local file="$1"
  local desc="$2"

  [[ -f "${file}" ]] || { echo "error: ${desc} ${file} does not exist" >&2; exit 1; }
  [[ -s "${file}" ]] || { echo "error: ${desc} ${file} is empty" >&2; exit 1; }
}

upload_and_verify()
{
  local local_file="$1"
  local s3_file="$2"
  local desc="$3"

  local file_hash
  file_hash="$( sha384sum "${local_file}" | awk '{print $1}' )"
  : "${file_hash:?failed to calculate sha384sum of ${local_file}}"

  echo "==> Uploading ${desc} to s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${s3_file}"
  aws s3 cp "${local_file}" "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${s3_file}"

  echo "==> Verifying uploaded ${desc} by re-downloading and checking sha384sum"
  verifys3hash "s3://${RELEASE_BUCKET}/${RELEASE_PREFIX}/${s3_file}" "${file_hash}"
}

echo "==> Starting store-s3-bundle"

: "${RELEASE_BUCKET:?RELEASE_BUCKET must be set in release.conf}"
: "${RELEASE_PREFIX:?RELEASE_PREFIX must be set in release.conf}"
: "${BUNDLE_FILE:?BUNDLE_FILE must be set in release.conf}"
: "${BUNDLE_SIG_FILE_KMS:?BUNDLE_SIG_FILE_KMS must be set in release.conf}"
: "${BUNDLE_SIG_FILE_KEYLESS:?BUNDLE_SIG_FILE_KEYLESS must be set in release.conf}"
: "${BUNDLE_SIG_FILE_OLD:?BUNDLE_SIG_FILE_OLD must be set in release.conf}"

# sanity checks
require_file "${BUNDLE_FILE}" "bundle file"
require_file "${BUNDLE_SIG_FILE_KMS}" "KMS sigstore bundle file"
require_file "${BUNDLE_SIG_FILE_KEYLESS}" "keyless sigstore bundle file"
require_file "${BUNDLE_SIG_FILE_OLD}" "legacy sigstore bundle file"

# validate gzip
gzip -t "${BUNDLE_FILE}" || { echo "error: invalid gzip"; exit 1; }

# validate tar validity, this also tests gzip
tar -tzf "${BUNDLE_FILE}" > /dev/null || { echo "error: invalid tar"; exit 1; }

# get sha384sum of the bundle
bundlesha384sum="$( sha384sum "${BUNDLE_FILE}" | awk '{print $1}' )"
: "${bundlesha384sum:?failed to calculate sha384sum of bundle file ${BUNDLE_FILE}}"

# upload names are keyed by bundle content hash
bundle_upload_file="sha384/${bundlesha384sum}.tar.gz"
bundle_sig_upload_file_kms="${bundle_upload_file}.kms.bundle.sigstore.json"
bundle_sig_upload_file_keyless="${bundle_upload_file}.keyless.bundle.sigstore.json"

# legacy remote name for backwards compatibility with existing deploy consumers
bundle_sig_upload_file_old="${bundle_upload_file}.sigstore.json"

# upload the bundle to s3 named by its sha384sum
upload_and_verify "${BUNDLE_FILE}" "${bundle_upload_file}" "site bundle"

# upload both new sigstore bundles
upload_and_verify "${BUNDLE_SIG_FILE_KMS}" "${bundle_sig_upload_file_kms}" "KMS sigstore bundle"
upload_and_verify "${BUNDLE_SIG_FILE_KEYLESS}" "${bundle_sig_upload_file_keyless}" "keyless sigstore bundle"

# upload the temporary backwards-compatible sigstore bundle name
upload_and_verify "${BUNDLE_SIG_FILE_OLD}" "${bundle_sig_upload_file_old}" "legacy sigstore bundle"

echo "${bundlesha384sum}" > .release-id

echo "==> store-s3-bundle done"