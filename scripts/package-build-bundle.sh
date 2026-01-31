#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
# shellcheck source=release.conf
source "${SCRIPT_DIR}/../release.conf"

[[ ! -d public/ ]] && { echo "error: missing public/ directory - build the site first" >&2; exit 1; }

# remove any existing bundle files
echo "==> Cleaning up any existing ${BUNDLE_FILE} and ${BUNDLE_FILE}.sha256"
rm -f "${BUNDLE_FILE}" "${BUNDLE_FILE}.sha256"

# create the site bundle
echo "==> Bundling ${BUNDLE_FILE} from public/ directory"
tar -zcf "${BUNDLE_FILE}" -C public/ .

# create the sha256 checksum file
echo "==> Hashing ${BUNDLE_FILE}.sha256"
sha256sum "${BUNDLE_FILE}" | awk '{ print $1 }' > "${BUNDLE_FILE}.sha256"

bundle_size=$( stat -c%s "${BUNDLE_FILE}" || stat -f%z "${BUNDLE_FILE}" )
bundle_sha256sum=$( cat "${BUNDLE_FILE}.sha256" )
echo "==> Bundle created file=${BUNDLE_FILE} size=${bundle_size} sha256=${bundle_sha256sum}"

echo "==> package-build-bundle done"