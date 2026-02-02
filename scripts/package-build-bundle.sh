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

echo "==> package-build-bundle done"