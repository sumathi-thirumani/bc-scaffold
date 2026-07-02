#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-python-sbom-cyclonedx.sh <project_dir> <output_prefix>

PROJECT_DIR="${1:?project directory is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"

CYCLONEDX_BOM_VERSION="${CYCLONEDX_BOM_VERSION:-7.3.0}"
POETRY_VERSION="${POETRY_VERSION:-2.2.1}"

log() {
  echo "[python-sbom] $*"
}

die() {
  echo "[python-sbom] ERROR: $*" >&2
  exit 1
}

is_poetry_project() {
  [ -f "poetry.lock" ] || grep -q '^\[tool\.poetry\]' pyproject.toml 2>/dev/null
}

ensure_poetry_lock() {
  if [ ! -f "poetry.lock" ]; then
    log "poetry.lock not found; generating lock file"
    "$TOOL_POETRY" lock --no-interaction
  fi
}

verify_sbom() {
  local sbom_file="$1"
  local python_bin="$2"

  [ -f "$sbom_file" ] || die "SBOM output missing: $sbom_file"

  local component_count
  component_count="$("$python_bin" - "$sbom_file" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

print(len(data.get("components") or []))
PY
)"

  if [ "$component_count" -eq 0 ]; then
    die "SBOM contains zero components: $sbom_file"
  fi

  log "SBOM contains $component_count components"
}

[ -d "$PROJECT_DIR" ] || die "Project directory does not exist: $PROJECT_DIR"

mkdir -p "$(dirname "$OUTPUT_PREFIX")"

OUTPUT_FILE="$(cd "$(dirname "$OUTPUT_PREFIX")" && pwd)/$(basename "$OUTPUT_PREFIX").cyclonedx.json"
SPDX_FILE="$(cd "$(dirname "$OUTPUT_PREFIX")" && pwd)/$(basename "$OUTPUT_PREFIX").spdx.json"

TOOL_VENV="$(mktemp -d)"
PROJECT_VENV=""

cleanup() {
  rm -rf "$TOOL_VENV"
  [ -n "${PROJECT_VENV}" ] && rm -rf "$PROJECT_VENV"
}
trap cleanup EXIT

log "Installing SBOM tooling"

python -m venv "$TOOL_VENV"
TOOL_PYTHON="$TOOL_VENV/bin/python"

"$TOOL_PYTHON" -m pip install --disable-pip-version-check --quiet \
  "cyclonedx-bom==$CYCLONEDX_BOM_VERSION" \
  "poetry==$POETRY_VERSION"

TOOL_POETRY="$TOOL_VENV/bin/poetry"

pushd "$PROJECT_DIR" >/dev/null

if is_poetry_project; then
  log "Detected Poetry project"

  ensure_poetry_lock

  PROJECT_VENV="$(mktemp -d)"

  log "Installing Poetry dependencies"

  export POETRY_VIRTUALENVS_CREATE=true
  export POETRY_VIRTUALENVS_PATH="$PROJECT_VENV"
  "$TOOL_POETRY" install --no-interaction --no-root

  PROJECT_PYTHON="$("$TOOL_POETRY" env info --executable)"

  log "Generating SBOM from installed Poetry environment"

  "$TOOL_PYTHON" -m cyclonedx_py environment \
    "$PROJECT_PYTHON" \
    --output-format JSON \
    --output-file "$OUTPUT_FILE"

elif [ -f "requirements.txt" ]; then
  log "Detected requirements.txt project"

  PROJECT_VENV="$(mktemp -d)"
  python -m venv "$PROJECT_VENV"

  PROJECT_PYTHON="$PROJECT_VENV/bin/python"

  log "Installing requirements"

  "$PROJECT_PYTHON" -m pip install --disable-pip-version-check --quiet --upgrade pip
  "$PROJECT_PYTHON" -m pip install --disable-pip-version-check --quiet -r requirements.txt

  log "Generating SBOM from installed environment"

  "$TOOL_PYTHON" -m cyclonedx_py environment \
    "$PROJECT_PYTHON" \
    --output-format JSON \
    --output-file "$OUTPUT_FILE"
else
  die "No supported dependency manifest found (poetry.lock, pyproject.toml, or requirements.txt)"
fi

log "Generating SPDX SBOM for dependency graph submission"

syft "dir:." \
  --output "spdx-json=$SPDX_FILE"

popd >/dev/null

verify_sbom "$OUTPUT_FILE" "$TOOL_PYTHON"

log "SBOM written to: $OUTPUT_FILE"