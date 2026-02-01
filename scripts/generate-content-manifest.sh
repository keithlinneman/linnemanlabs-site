#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

# output file
MANIFEST_FILE="${REPO_ROOT}/${CONTENT_DIR}/manifest.json"

# verify content directory exists
[[ ! -d "${REPO_ROOT}/${CONTENT_DIR}/" ]] && { echo "error: missing ${CONTENT_DIR}/ directory - build the site first" >&2; exit 1; }

echo "==> Starting generate-content-manifest"

# create temporary array to store file info
files_json="[]"

# Counters for summary
total_files=0
total_size=0
html_files=0
css_files=0
js_files=0
font_files=0
image_files=0
xml_files=0
txt_files=0
json_files=0
other_files=0

# per-file manifest
echo "==> Scanning files in ${CONTENT_DIR}/"
# loop through files in public/
while IFS= read -r -d '' file; do
  rel_path="${file#"${REPO_ROOT}"/"${CONTENT_DIR}/"}"
  
  # skip manifest.json, release.json if they exist from previous runs
  [[ "${rel_path}" == "manifest.json" || "${rel_path}" == "release.json" ]] && continue
  
  # file metadata
  file_size="$( stat -c%s "${file}" 2>/dev/null || stat -f%z "${file}" 2>/dev/null || echo "0" )"
  file_hash="$( sha256sum "${file}" | awk '{ print $1 }' )"
  file_modified="$( stat -c%Y "${file}" 2>/dev/null || stat -f%m "${file}" 2>/dev/null || echo "0" )"
  file_modified_iso="$( date -u -d @"${file_modified}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -r "${file_modified}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown" )"
  
  # determine file type
  extension="${rel_path##*.}"
  case "${extension}" in
    html|htm) 
        file_type="html"
        ((html_files++)) || true
        ;;
    css) 
        file_type="css"
        ((css_files++)) || true
        ;;
    js) 
        file_type="javascript"
        ((js_files++)) || true
        ;;
    woff|woff2|ttf|otf|eot) 
        file_type="font"
        ((font_files++)) || true
        ;;
    png|jpg|jpeg|gif|svg|webp|ico) 
        file_type="image"
        ((image_files++)) || true
        ;;
    xml) 
        file_type="xml"
        ((xml_files++)) || true
        ;;
    txt) 
        file_type="txt"
        ((txt_files++)) || true
        ;;
    json) 
        file_type="json"
        ((json_files++)) || true
        ;;
    *)
        file_type="other"
        ((other_files++)) || true
        ;;
  esac
  
  # build JSON object for this file
  file_json="$( jq -n \
    --arg path "${rel_path}" \
    --arg sha256 "${file_hash}" \
    --arg size "${file_size}" \
    --arg type "${file_type}" \
    --arg modified "${file_modified_iso}" \
    '{
      "path": $path,
      "sha256": $sha256,
      "size": ($size | tonumber),
      "type": $type,
      "modified": $modified
    }'
  )"

  # append to files array
  files_json="$( jq -n --argjson arr "${files_json}" --argjson newfile "${file_json}" '$arr + [$newfile]' )"

  ((total_files++)) || true
  total_size=$((total_size + file_size))
    
done < <( find "${REPO_ROOT}/${CONTENT_DIR}" -type f -print0 | sort -z )
echo "==> Scanned ${total_files} files (${total_size} bytes)"

# calculate bundle hash (content directory, excluding manifest, reproducible hash of file names/hashes)
echo "==> Calculating content hash (reproducible)"
content_hash="$( find "${REPO_ROOT}/${CONTENT_DIR}" -type f ! -name 'manifest.json' ! -name 'release.json' -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{ print $1 }' )"
echo "==> Content hash: sha256:${content_hash}"

# inventory time
inventory_time="$( date -u +"%Y-%m-%dT%H:%M:%SZ" )"

echo "==> Writing manifest to ${MANIFEST_FILE}"
# assemble final manifest
jq -n \
  --arg content_hash "${content_hash}" \
  --argjson total_files "${total_files}" \
  --argjson total_size "${total_size}" \
  --argjson html_files "${html_files}" \
  --argjson css_files "${css_files}" \
  --argjson js_files "${js_files}" \
  --argjson font_files "${font_files}" \
  --argjson image_files "${image_files}" \
  --argjson xml_files "${xml_files}" \
  --argjson txt_files "${txt_files}" \
  --argjson json_files "${json_files}" \
  --argjson other_files "${other_files}" \
  --argjson files "${files_json}" \
  --arg created_at "${inventory_time}" \
  '{
    "schema": "com.linnemanlabs.manifest.site.content.bundle.v1",
    "type": "content-bundle",
    "created_at": $created_at,
    "content_hash": $content_hash,
    
    "summary": {
      "total_files": $total_files,
      "total_size": $total_size,
      "file_types": {
        "html": $html_files,
        "css": $css_files,
        "javascript": $js_files,
        "font": $font_files,
        "image": $image_files,
        "xml": $xml_files,
        "txt": $txt_files,
        "json": $json_files,
        "other": $other_files
      } | map_values(select(. > 0))
    },
      
      "files": $files
  }' \
> "${MANIFEST_FILE}"

# validate JSON
if ! jq empty "${MANIFEST_FILE}" 2>/dev/null; then
  echo "error: generated manifest is not valid JSON" >&2
  exit 1
fi

manifest_size="$( stat -c%s "${MANIFEST_FILE}" 2>/dev/null )"
manifest_sha256="$( sha256sum "${MANIFEST_FILE}" | awk '{ print $1 }' )"
echo "==> Manifest generated: ${MANIFEST_FILE} (${manifest_size} bytes) sha256:${manifest_sha256}"
echo "==> generate-content-manifest done"