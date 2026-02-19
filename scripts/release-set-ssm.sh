#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

echo "==> Starting release-set-ssm"

if [[ -z "${RELEASE_ID:-}" && -f .release-id ]]; then
  RELEASE_ID="$( cat .release-id )"
fi
: "${RELEASE_ID:?RELEASE_ID must be set}"
rel_len="$( wc -c <<< "${RELEASE_ID}" )"
# 97 because of newline
if [[ "${rel_len}" != 97 ]]; then
  echo "error: RELEASE_ID length is ${rel_len} expected 97" >&2
  exit 1
fi

: "${DEPLOY_ROLE_ARN_PARAM:?DEPLOY_ROLE_ARN_PARAM must be set in release.conf}"
: "${DEPLOY_SSM_PARAM:?DEPLOY_SSM_PARAM must be set in release.conf}"

DEPLOY_ROLE_ARN="$( aws ssm get-parameter --name "${DEPLOY_ROLE_ARN_PARAM}" --query 'Parameter.Value' --output text )"
: "${DEPLOY_ROLE_ARN:?failed to get DEPLOY_ROLE_ARN from SSM param ${DEPLOY_ROLE_ARN_PARAM}}"

# validate the file in s3
s3_metadata="$( aws s3api head-object --bucket "${RELEASE_BUCKET}" --key "${RELEASE_PREFIX}/${RELEASE_ID}.tar.gz" )"
s3_size="$( jq -r '.ContentLength' <<< "${s3_metadata}" )"
[[ -z "${s3_size}" || "${s3_size}" == "null" ]] && { echo "error: ${RELEASE_PREFIX}/${RELEASE_ID}.tar.gz size: not in S3 bucket ${RELEASE_BUCKET}"; exit 1; }
[[ "${s3_size}" -le 1024 ]] && { echo "error: ${RELEASE_PREFIX}/${RELEASE_ID}.tar.gz size is <1kb in S3 bucket ${RELEASE_BUCKET}"; exit 1; }
s3_contenttype="$( jq -r '.ContentType' <<< "${s3_metadata}" )"
[[ "${s3_contenttype}" != "application/x-tar" ]] && { echo "error: ${RELEASE_PREFIX}/${RELEASE_ID}.tar.gz in S3 bucket ${RELEASE_BUCKET} has invalid content-type ${s3_contenttype} expected application/x-tar"; exit 1; }

# assume role in workload account in a subshell for cred isolation
(
  echo "==> assuming role=${DEPLOY_ROLE_ARN}"
  # 15min is the shortest aws will allow
  credentials="$( aws sts assume-role --role-arn "${DEPLOY_ROLE_ARN}" --role-session-name "release-site-${RELEASE_ID:0:8}" --duration-seconds 900 )"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  AWS_ACCESS_KEY_ID="$(jq -r '.Credentials.AccessKeyId' <<< "$credentials")"
  AWS_SECRET_ACCESS_KEY="$(jq -r '.Credentials.SecretAccessKey' <<< "$credentials")"
  AWS_SESSION_TOKEN="$(jq -r '.Credentials.SessionToken' <<< "$credentials")"

  ssm_value="sha384:${RELEASE_ID}"

  echo "==> setting workload ssm param ${DEPLOY_SSM_PARAM} to ${ssm_value}"
  aws ssm put-parameter --name "${DEPLOY_SSM_PARAM}" --type String --value "${ssm_value}" --overwrite
)

echo "==> release-set-ssm done"