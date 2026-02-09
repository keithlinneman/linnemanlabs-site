#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

echo "==> Starting generate-provenance-manifest"

# output file
PROVENANCE_FILE="${REPO_ROOT}/${CONTENT_DIR}/provenance.json"

# verify content directory exists
[[ ! -d "${REPO_ROOT}/${CONTENT_DIR}/" ]] && { echo "error: missing ${CONTENT_DIR}/ directory - build the site first" >&2; exit 1; }

# build metadata
build_time="$( date -u +"%Y-%m-%dT%H:%M:%SZ" )"
build_host="$( hostname -f 2>/dev/null || hostname )"
build_user="${USER:-unknown}"

# git information
git_commit="$( git -C "${REPO_ROOT}" rev-parse HEAD )"
git_commit_short="$( git -C "${REPO_ROOT}" rev-parse --short HEAD )"
git_commit_date="$( TZ=UTC git -C "${REPO_ROOT}" log -1 --format="%cd" --date="format-local:%Y-%m-%dT%H:%M:%SZ" HEAD )"
git_branch="$( git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached" )"
git_dirty="false"
if [[ -n "$( git -C "${REPO_ROOT}" status --porcelain 2>/dev/null )" ]]; then
  git_dirty="true"
fi
git_remote="$( git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || echo "unknown" )"

# tool versions and checksum (content SBOM) - use PATH same as build does
# hugo (static html generation)
if command -v hugo &>/dev/null; then
  hugo_version="$( hugo version 2>/dev/null | head -1 | awk '{ print $2 }' | awk -F '-' '{ print $1 }' || echo "unknown" )"
  # hugo_verbose="$( hugo version 2>/dev/null || echo "" )"
  hugo_path="$( command -v hugo )"
  hugo_checksum="$( sha256sum "${hugo_path}" 2>/dev/null | awk '{ print $1 }' || echo "unknown" )"
else
  hugo_version="unknown"
  hugo_checksum="unknown"
fi

# tailwindcss (css generation)
if command -v tailwindcss &>/dev/null; then
  tailwind_version="$( NO_COLOR=1 tailwindcss --help | head -1 | awk '{ print $3 }' || echo "unknown" )"
  # tailwind_verbose="$( tailwindcss --help | head -1 || echo "" )"
  tailwind_path="$( command -v tailwindcss )"
  tailwind_checksum="$( sha256sum "${tailwind_path}" 2>/dev/null | awk '{ print $1 }' || echo "unknown" )"
else
  tailwind_version="unknown"
  tailwind_checksum="unknown"
fi

# tidy (html validation)
if command -v tidy &>/dev/null; then
  tidy_version="$( tidy --version | head -1 | awk '{ print $NF }' || echo "unknown" )"
  # tidy_verbose="$( tidy --version || echo "" )"
  tidy_path="$( command -v tidy )"
  tidy_checksum="$( sha256sum "${tidy_path}" 2>/dev/null | awk '{ print $1 }' || echo "unknown" )"
else
  tidy_version="unknown"
  tidy_checksum="unknown"
fi

# git (source control)
if command -v git &>/dev/null; then
  git_tool_version="$( git --version | awk '{ print $NF }' )"
else
  git_tool_version="unknown"
fi

# bash version
bash_version="${BASH_VERSION:-unknown}"

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

# content release version - sha256sum and short commit
release_version="$( date "+%Y.%m.%d" ).${git_commit_short:-unknown}"

# assemble final release manifest
echo "==> Writing provenance manifest to ${PROVENANCE_FILE}"

jq -n \
  --arg version "${release_version:-unknown}" \
  --arg content_id "sha256:${content_hash}" \
  --arg content_hash "${content_hash}" \
  --arg created_at "${build_time}" \
  --arg git_repo "${git_remote}" \
  --arg git_commit "${git_commit}" \
  --arg git_commit_short "${git_commit_short}" \
  --arg git_commit_date "${git_commit_date}" \
  --arg git_branch "${git_branch}" \
  --argjson git_dirty "${git_dirty}" \
  --arg hugo_version "${hugo_version}" \
  --arg hugo_checksum "${hugo_checksum}" \
  --arg tailwind_version "${tailwind_version}" \
  --arg tailwind_checksum "${tailwind_checksum}" \
  --arg tidy_version "${tidy_version}" \
  --arg tidy_checksum "${tidy_checksum}" \
  --arg git_tool_version "${git_tool_version}" \
  --arg bash_version "${bash_version}" \
  --arg build_host "${build_host}" \
  --arg build_user "${build_user}" \
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
  '{
    "schema": "com.linnemanlabs.manifest.site.content.bundle.v1",
    "type": "content-bundle",
    "version": $version,
    "content_id": $content_id,
    "content_hash": $content_hash,
    "created_at": $created_at,
      
    "source": {
      "repository": $git_repo,
      "commit": $git_commit,
      "commit_short": $git_commit_short,
      "commit_date": $git_commit_date,
      "branch": $git_branch,
      "dirty": $git_dirty
    },

    "build": {
      "host": $build_host,
      "user": $build_user,
      "timestamp": $created_at
    },

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
      
    "files": $files,
    
    "tooling": {
      "hugo": {
        "version": $hugo_version,
        "sha256": $hugo_checksum
      },
      "tailwindcss": {
        "version": $tailwind_version,
        "sha256": $tailwind_checksum
      },
      "tidy": {
        "version": $tidy_version,
        "sha256": $tidy_checksum
      },
      "git": {
        "version": $git_tool_version
      },
      "bash": {
        "version": $bash_version
      }
    }
  }' >  \
"${PROVENANCE_FILE}"

# validate release json
if ! jq empty "${PROVENANCE_FILE}" 2>/dev/null; then
  echo "error: generated manifest is not valid JSON" >&2
  exit 1
fi

release_size="$( stat -c%s "${PROVENANCE_FILE}" 2>/dev/null )"
echo "==> Provenance manifest generated: ${PROVENANCE_FILE} (${release_size} bytes)"
echo "==> generate-provenance-manifest done"