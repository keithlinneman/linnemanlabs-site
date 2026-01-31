#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
# shellcheck source=release.conf
source "${SCRIPT_DIR}/../release.conf"

[[ ! -d "${CONTENT_DIR}/" ]] && { echo "error: missing ${CONTENT_DIR}/ directory - build the site first" >&2; exit 1; }

# remove any existing bundle files
#echo "==> Cleaning up any existing ${bundle_file} and ${bundle_file}.sha256"
#rm -f "${bundle_file}" "${bundle_file}.sha256"

# setup temp file for the bundle
bundle_file="$( mktemp -u site-bundle-XXXXXX.tar.gz )"

# create the site bundle
echo "==> Bundling ${bundle_file} from ${CONTENT_DIR}/ directory"
tar -zcf "${bundle_file}" -C "${CONTENT_DIR}/" .

# calculate sha256 sum and size of the bundle
bundle_sha256sum=$( sha256sum "${bundle_file}" | awk '{ print $1 }' )
bundle_size=$( stat -c%s "${bundle_file}" || stat -f%z "${bundle_file}" )

# sanity checks
[[ ! -f "${bundle_file}" ]] && { echo "error: failed to create ${bundle_file}" >&2; exit 1; }
[[ ! -s "${bundle_file}" ]] && { echo "error: created ${bundle_file} is empty" >&2; exit 1; }
[[ "${bundle_size}" -eq 0 ]] && { echo "error: created ${bundle_file} has size 0" >&2; exit 1; }
echo "==> Bundle created file=${bundle_file} size=${bundle_size} sha256=${bundle_sha256sum}"

# rename bundle to sha256 sum
echo "==> Renaming bundle to ${bundle_sha256sum}.tar.gz"
mv "${bundle_file}" "${bundle_sha256sum}.tar.gz"

# create sha256 file for independent step execution
echo "${bundle_sha256sum}" > .release-id

echo "==> package-build-bundle done"