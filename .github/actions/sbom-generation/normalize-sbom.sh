#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   normalize-sbom.sh <output_prefix> <created_at> <serial>
# Example:
#   normalize-sbom.sh "filesystem" "2026-01-01T00:00:00Z" "urn:uuid:..."

OUTPUT_PREFIX="${1:?output_prefix is required}"
CREATED_AT="${2:?created_at is required}"
SERIAL="${3:?serial is required}"

CDX_FILE="${OUTPUT_PREFIX}.cyclonedx.json"

# Fail clearly if generation did not create the expected CycloneDX file.
if [ ! -f "$CDX_FILE" ]; then
	echo "Expected file missing: $CDX_FILE" >&2
	exit 1
fi

# Stabilize metadata used for reproducible artifacts and comparisons.
jq --sort-keys '. as $root | if $root.metadata then .metadata.timestamp = $createdAt else . end | .serialNumber = $serial' \
	--arg createdAt "$CREATED_AT" \
	--arg serial "$SERIAL" \
	"$CDX_FILE" >"${CDX_FILE}.tmp"
mv "${CDX_FILE}.tmp" "$CDX_FILE"
