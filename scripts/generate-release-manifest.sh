#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
REPO_ROOT="${SCRIPT_DIR}/.."
# shellcheck source=release.conf
source "${REPO_ROOT}/release.conf"

echo "==> Starting generate-release-manifest"

# output file
RELEASE_FILE="${REPO_ROOT}/${CONTENT_DIR}/release.json"
# manifest file
MANIFEST_FILE="${REPO_ROOT}/${CONTENT_DIR}/manifest.json"

# verify content directory exists
[[ ! -d "${REPO_ROOT}/${CONTENT_DIR}/" ]] && { echo "error: missing ${CONTENT_DIR}/ directory - build the site first" >&2; exit 1; }
# verify manifest.json exists
[[ ! -f "${MANIFEST_FILE}" ]] && { echo "error: missing ${MANIFEST_FILE} file - generate content manifest first" >&2; exit 1; }

# build metadata
build_time="$( date -u +"%Y-%m-%dT%H:%M:%SZ" )"
build_host="$( hostname -f 2>/dev/null || hostname )"
build_user="${USER:-unknown}"

# git information
git_commit="$( git -C "${REPO_ROOT}" rev-parse HEAD )"
git_commit_short="$( git -C "${REPO_ROOT}" rev-parse --short HEAD )"
git_commit_date="$( git -C "${REPO_ROOT}" log -1 --format=%cI HEAD )"
git_branch="$( git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached" )"
git_dirty="false"
if [[ -n "$( git -C "${REPO_ROOT}" status --porcelain 2>/dev/null )" ]]; then
  git_dirty="true"
fi
git_remote="$( git -C "${REPO_ROOT}" remote get-url origin 2>/dev/null || echo "unknown" )"

# tool versions and checksum (content SBOM) - use PATH same as build does
# hugo (static html generation)
if command -v hugo &>/dev/null; then
  hugo_version="$( hugo version 2>/dev/null | head -1 | awk '{ print $2 }' || echo "unknown" )"
  # hugo_verbose="$( hugo version 2>/dev/null || echo "" )"
  hugo_path="$( command -v hugo )"
  hugo_checksum="$( sha256sum "${hugo_path}" 2>/dev/null | awk '{ print $1 }' || echo "unknown" )"
else
  hugo_version="unknown"
  hugo_checksum="unknown"
fi

# tailwindcss (css generation)
if command -v tailwindcss &>/dev/null; then
  tailwind_version="$( tailwindcss --help | head -1 | awk '{ print $3 }' || echo "unknown" )"
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

# manifest.json data
manifest_sha256="$( sha256sum "${MANIFEST_FILE}" | awk '{ print $1 }' )"
manifest_rel="$( basename "${MANIFEST_FILE}" )"

# get content_id from content manifest
content_hash="$( jq -r '.content_hash' "${MANIFEST_FILE}" )"
: "${content_hash:?failed to get content_hash from ${MANIFEST_FILE}}"

# content release version - sha256sum and short commit
release_version="$( date "+%Y.%m.%d" ).${git_commit_short:-unknown}"

# assemble final release manifest
echo "==> Writing release manifest to ${RELEASE_FILE}"

jq -n \
  --arg version "${release_version:-unknown}" \
  --arg content_id "sha256:${content_hash}" \
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
  --arg manifest_rel "${manifest_rel}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  '{
    "schema": "com.linnemanlabs.manifest.site.content.release.v1",
    "type": "content-bundle",
    "version": $version,
    "content_id": $content_id,
    "created_at": $created_at,
      
    "source": {
      "repository": $git_repo,
      "commit": $git_commit,
      "commit_short": $git_commit_short,
      "commit_date": $git_commit_date,
      "branch": $git_branch,
      "dirty": $git_dirty
    },
    
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
    },
    
    "build": {
      "host": $build_host,
      "user": $build_user,
      "timestamp": $created_at
    },
    
    "artifacts": {
      "manifest": {
        "path": $manifest_rel,
        "sha256": $manifest_sha256
      }
    }
  }' >  \
"${RELEASE_FILE}"

# validate release json
if ! jq empty "${RELEASE_FILE}" 2>/dev/null; then
  echo "error: generated manifest is not valid JSON" >&2
  exit 1
fi

release_size="$( stat -c%s "${RELEASE_FILE}" 2>/dev/null )"
echo "==> Release manifest generated: ${RELEASE_FILE} (${release_size} bytes)"
echo "==> Content hash: sha256:${content_hash}"
echo "==> generate-release-manifest done"