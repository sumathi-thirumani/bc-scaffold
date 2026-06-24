#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-sbom.sh <source> <output_prefix>
#
# Example:
#   generate-sbom.sh "dir:." "filesystem"
#
# Produces:
#   filesystem.cyclonedx.json
#   filesystem.spdx.json

SOURCE="${1:?source is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"

log() {
	echo "[sbom] $*"
}

generate_cyclonedx_sbom() {
	local source="$1"

	log "Generating CycloneDX SBOM with Syft"

	syft "$source" \
		--output "cyclonedx-json=${OUTPUT_PREFIX}.cyclonedx.json"
}

generate_spdx_sbom() {
	local source="$1"

	log "Generating SPDX JSON 2.2 SBOM with Syft"

	syft "$source" \
		--output "spdx-json@2.2=${OUTPUT_PREFIX}.spdx.json"
}

generate_cyclonedx_sbom "$SOURCE"
generate_spdx_sbom "$SOURCE"

log "SBOM generation completed"

ls -lh \
	"${OUTPUT_PREFIX}.cyclonedx.json" \
	"${OUTPUT_PREFIX}.spdx.json" 2>/dev/null || true


log "Validating SPDX package metadata"

jq '
[
	.packages[]
	| {
		name,
		versionInfo,
		purl: [
			.externalRefs[]?
			| select(.referenceType=="purl")
			| .referenceLocator
		]
	}
]
| .[0:10]
' "${OUTPUT_PREFIX}.spdx.json"