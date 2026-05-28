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

echo "==> Starting package-build-bundle"

: "${CONTENT_DIR:?CONTENT_DIR must be set in release.conf}"
: "${BUNDLE_FILE:?BUNDLE_FILE must be set in release.conf}"
: "${BUNDLE_SIG_FILE_KMS:?BUNDLE_SIG_FILE_KMS must be set in release.conf}"
: "${BUNDLE_SIG_FILE_KEYLESS:?BUNDLE_SIG_FILE_KEYLESS must be set in release.conf}"
: "${BUNDLE_SIG_FILE_OLD:?BUNDLE_SIG_FILE_OLD must be set in release.conf}"
: "${COSIGN_TRUSTED_ROOT:?COSIGN_TRUSTED_ROOT must be set in release.conf}"
: "${COSIGN_SIGNING_CONFIG:?COSIGN_SIGNING_CONFIG must be set in release.conf}"
: "${BUNDLE_KMS_KEYID_PARAM:?BUNDLE_KMS_KEYID_PARAM must be set in release.conf}"

[[ ! -d "${CONTENT_DIR}/" ]] && { echo "error: missing ${CONTENT_DIR}/ directory - build the site first" >&2; exit 1; }
[[ -f "${COSIGN_TRUSTED_ROOT}" ]] || { echo "error: missing ${COSIGN_TRUSTED_ROOT}" >&2; exit 1; }
[[ -f "${COSIGN_SIGNING_CONFIG}" ]] || { echo "error: missing ${COSIGN_SIGNING_CONFIG}" >&2; exit 1; }

# remove any existing bundle
echo "==> Removing any existing bundle/signature files"
rm -f "${BUNDLE_FILE}" \
       "${BUNDLE_SIG_FILE_KMS}" \
       "${BUNDLE_SIG_FILE_KEYLESS}" \
       "${BUNDLE_SIG_FILE_OLD}"

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

# sign the bundle with cosign using both KMS and Fulcio keyless
# kms flow
BUNDLE_KMS_KEYID="$( aws ssm get-parameter --name "${BUNDLE_KMS_KEYID_PARAM}" --query 'Parameter.Value' --output text )"
: "${BUNDLE_KMS_KEYID:?failed to get BUNDLE_KMS_KEYID from SSM param ${BUNDLE_KMS_KEYID_PARAM}}"
COSIGN_KEY="awskms:///${BUNDLE_KMS_KEYID}"

echo "==> Signing bundle with cosign using KMS key ${BUNDLE_KMS_KEYID}"
cosign sign-blob --yes --key "${COSIGN_KEY}" --bundle "${BUNDLE_SIG_FILE_KMS}" --signing-config "${COSIGN_SIGNING_CONFIG}" --trusted-root "${COSIGN_TRUSTED_ROOT}" "${BUNDLE_FILE}"
if [[ ! -f "${BUNDLE_SIG_FILE_KMS}" ]]; then
  echo "error: failed to create signature file ${BUNDLE_SIG_FILE_KMS}" >&2
  exit 1
fi

# verify the signature by checking the kms bundle with cosign
echo "==> Verifying kms bundle signature with cosign"
cosign verify-blob --key "${COSIGN_KEY}" --bundle "${BUNDLE_SIG_FILE_KMS}" --trusted-root "${COSIGN_TRUSTED_ROOT}" "${BUNDLE_FILE}" || { echo "error: failed to verify kms bundle signature with cosign" >&2; exit 1; }

# fulcio keyless flow
echo "==> Signing bundle with cosign using Fulcio keyless"
cosign sign-blob --yes --bundle "${BUNDLE_SIG_FILE_KEYLESS}" --signing-config "${COSIGN_SIGNING_CONFIG}" --trusted-root "${COSIGN_TRUSTED_ROOT}" "${BUNDLE_FILE}"
if [[ ! -f "${BUNDLE_SIG_FILE_KEYLESS}" ]]; then
  echo "error: failed to create signature file ${BUNDLE_SIG_FILE_KEYLESS}" >&2
  exit 1
fi

# verify the signature by checking the keyless bundle with cosign
echo "==> Verifying keyless bundle signature with cosign"
cosign verify-blob \
  --bundle "${BUNDLE_SIG_FILE_KEYLESS}" \
  --trusted-root "${COSIGN_TRUSTED_ROOT}" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp="^https://github\.com/keithlinneman/linnemanlabs-site/\.github/workflows/build\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$" \
  --certificate-github-workflow-trigger="push" \
  --certificate-github-workflow-repository="keithlinneman/linnemanlabs-site" \
  --certificate-github-workflow-name="Build Site" \
  "${BUNDLE_FILE}" || { echo "error: failed to verify keyless bundle signature with cosign" >&2; exit 1; }

# copy the kms bundle to the old name also for temporary backwards compatibility while transitioning
cp "${BUNDLE_SIG_FILE_KMS}" "${BUNDLE_SIG_FILE_OLD}"

echo "==> package-build-bundle done"
