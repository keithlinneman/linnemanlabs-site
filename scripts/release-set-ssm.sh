#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
# shellcheck source=release.conf
source "${SCRIPT_DIR}/../release.conf"

if [[ -z "${RELEASE_ID:-}" && -f .release-id ]]; then
  RELEASE_ID="$( cat .release-id )"
fi
: "${RELEASE_ID:?RELEASE_ID must be set}"

: "${DEPLOY_ROLE_ARN_PARAM:?DEPLOY_ROLE_ARN_PARAM must be set in release.conf}"
: "${DEPLOY_SSM_PARAM:?DEPLOY_SSM_PARAM must be set in release.conf}"

DEPLOY_ROLE_ARN="$( aws ssm get-parameter --name "${DEPLOY_ROLE_ARN_PARAM}" --query 'Parameter.Value' --output text )"
: "${DEPLOY_ROLE_ARN:?failed to get DEPLOY_ROLE_ARN from SSM param ${DEPLOY_ROLE_ARN_PARAM}}"

# assume role in workload account in a subshell
(
  echo "==> assuming role=${DEPLOY_ROLE_ARN}"
  credentials="$( aws sts assume-role --role-arn "${DEPLOY_ROLE_ARN}" --role-session-name "release-site-${RELEASE_ID:0:8}" --duration-seconds 900 )"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  AWS_ACCESS_KEY_ID="$(jq -r '.Credentials.AccessKeyId' <<< "$credentials")"
  AWS_SECRET_ACCESS_KEY="$(jq -r '.Credentials.SecretAccessKey' <<< "$credentials")"
  AWS_SESSION_TOKEN="$(jq -r '.Credentials.SessionToken' <<< "$credentials")"

  echo "==> setting workload ssm param=${DEPLOY_SSM_PARAM} to ${RELEASE_ID}"
  aws ssm put-parameter --name "${DEPLOY_SSM_PARAM}" --type String --value "${RELEASE_ID}" --overwrite
)

echo "==> release-set-ssm done"