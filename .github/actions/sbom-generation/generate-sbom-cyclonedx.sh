#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-sbom-cyclonedx.sh <source> <output_prefix>
# Example:
#   generate-sbom-cyclonedx.sh "dir:." "sbom/filesystem"
# Produces:
#   sbom/filesystem.cyclonedx.json
#   sbom/filesystem.spdx.json

SOURCE="${1:?source is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source_directory() {
  case "$SOURCE" in
    dir:*) printf '%s\n' "${SOURCE#dir:}" ;;
    *) return 1 ;;
  esac
}

has_python_dependency_manifest() {
  local project_dir="$1"

  [ -f "$project_dir/poetry.lock" ] ||
    [ -f "$project_dir/requirements.txt" ] ||
    grep -q "\[tool.poetry\]" "$project_dir/pyproject.toml" 2>/dev/null
}

if project_dir="$(source_directory)" && has_python_dependency_manifest "$project_dir"; then
  bash "$SCRIPT_DIR/generate-python-sbom-cyclonedx.sh" "$project_dir" "$OUTPUT_PREFIX"
else
  syft "${SOURCE}" \
    --output "cyclonedx-json=${OUTPUT_PREFIX}.cyclonedx.json" \
    --output "spdx-json=${OUTPUT_PREFIX}.spdx.json"
fi
