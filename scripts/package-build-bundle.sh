#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

echo "==> Starting package-build-bundle"

[[ ! -d "${CONTENT_DIR}/" ]] && { echo "error: missing ${CONTENT_DIR}/ directory - build the site first" >&2; exit 1; }

# remove any existing bundle file
[[ -f "${BUNDLE_FILE}" ]] && { echo "==> Removing existing bundle file ${BUNDLE_FILE}" ; rm -f "${BUNDLE_FILE}"; }

# create the site bundle
echo "==> Bundling ${BUNDLE_FILE} from ${CONTENT_DIR}/ directory"
curdate="$( date -u +"%Y-%m-%dT%H:%M:%SZ" )"
curcommit="$( git rev-parse --short HEAD )"

tar -zcf "${BUNDLE_FILE}" -C "${CONTENT_DIR}/" --label="linnemanlabs.com ${curdate} commit ${curcommit}" .

# sanity checks
[[ ! -f "${BUNDLE_FILE}" ]] && { echo "error: failed to create ${BUNDLE_FILE}" >&2; exit 1; }
[[ ! -s "${BUNDLE_FILE}" ]] && { echo "error: created ${BUNDLE_FILE} is empty" >&2; exit 1; }
tar -tzf "${BUNDLE_FILE}" > /dev/null || { echo "error: invalid tar"; exit 1; }

# calculate size of the bundle
bundle_size=$( stat -c%s "${BUNDLE_FILE}" || stat -f%z "${BUNDLE_FILE}" )
echo "==> Bundle created file=${BUNDLE_FILE} size=${bundle_size}"

# sign the bundle with cosign
: "${BUNDLE_KMS_KEYID_PARAM:?BUNDLE_KMS_KEYID_PARAM must be set in release.conf}"

BUNDLE_KMS_KEYID="$( aws ssm get-parameter --name "${BUNDLE_KMS_KEYID_PARAM}" --query 'Parameter.Value' --output text )"
: "${BUNDLE_KMS_KEYID:?failed to get BUNDLE_KMS_KEYID from SSM param ${BUNDLE_KMS_KEYID_PARAM}}"
COSIGN_KEY="kms://${BUNDLE_KMS_KEYID}"

echo "==> Signing bundle with cosign using KMS key ${BUNDLE_KMS_KEYID}"
cosign sign-blob --yes --key "${COSIGN_KEY}" --bundle "${BUNDLE_SIG_FILE}" --signing-config <( echo '{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","rekorTlogConfig":{},"tsaConfig":{}}' ) "${BUNDLE_FILE}"
if [[ ! -f "${BUNDLE_SIG_FILE}" ]]; then
  echo "error: failed to create signature file ${BUNDLE_SIG_FILE}" >&2
  exit 1
fi

# verify the signature by checking the bundle with cosign
echo "==> Verifying bundle signature with cosign"
cosign verify-blob --key "${COSIGN_KEY}" --bundle "${BUNDLE_SIG_FILE}" "${BUNDLE_FILE}" || { echo "error: failed to verify bundle signature with cosign" >&2; exit 1; }

echo "==> package-build-bundle done"