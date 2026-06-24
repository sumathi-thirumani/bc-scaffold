#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   build-ecosystem-matrix.sh <mode> <source_path> [supported_ecosystems_csv]
# Modes:
#   audit - emits matrix entries like {"ecosystem":"node"}
#   sbom  - emits filesystem matrix entries for unique detected ecosystem directories, like
#           {"scan_kind":"filesystem","scan_label":"filesystem-node-src-app","source":"dir:src/app","output_prefix":"filesystem-node-src-app"}
#
# Output JSON shape:
# {
#   "detected": ["node", "python"],
#   "targets": ["filesystem-node-src-app"],
#   "count": 1,
#   "matrix": {"include": [...]}
# }

MODE="${1:?mode is required (audit|sbom)}"
SOURCE_PATH="${2:-.}"
SUPPORTED_CSV="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect ecosystems once so all modes use the same scan results.
ecosystem_json="$(bash "$SCRIPT_DIR/detect-ecosystems.sh" "$SOURCE_PATH")"
detected="$(jq -c '.list' <<<"$ecosystem_json")"

# Convert a comma-separated ecosystem allowlist to JSON.
build_supported_json() {
	local csv="$1"
	jq -cn --arg supported "$csv" '
    $supported
    | split(",")
    | map(gsub("^\\s+|\\s+$"; ""))
    | map(select(length > 0))
  '
}

case "$MODE" in
audit)
	# Audit jobs run per supported ecosystem.
	supported_json="$(build_supported_json "${SUPPORTED_CSV:-node,python}")"
	entries="$(jq -c --argjson supported "$supported_json" '
      [.list[] | select(. as $e | $supported | index($e) != null) | {ecosystem:.}]
    ' <<<"$ecosystem_json")"
	# Targets summarize the selected ecosystems.
	targets="$(jq -c '[.[].ecosystem]' <<<"$entries")"
	;;

sbom)
	# SBOM jobs run per manifest directory.
	entries="$(jq -c --arg sourcePath "$SOURCE_PATH" '
      # Create workflow-safe label segments.
      def slug:
        if . == "." then "root"
        else
          gsub("^\\./"; "")
          | gsub("[^A-Za-z0-9._-]+"; "-")
          | gsub("^-+|-+$"; "")
          | if length == 0 then "root" else . end
        end;
      # Keep labels relative to the configured scan root.
      def relative_to_root($root):
        if . == $root then "."
        elif ($root != "." and startswith($root + "/")) then ltrimstr($root + "/")
        else gsub("^\\./"; "")
        end;

      if .any then
        [.findings
          # group_by requires adjacent keys, so sort by path before grouping.
          | sort_by(.path)
          | group_by(.path)[]
          | {
              path: .[0].path,
              label_path: (.[0].path | relative_to_root($sourcePath)),
              ecosystems: (map(.ecosystem) | unique)
            }
          # Include ecosystem names and path to avoid label collisions.
          | .label = ("filesystem-" + (.ecosystems | join("-")) + "-" + (.label_path | slug))
          | {
              scan_kind: "filesystem",
              scan_label: .label,
              source: ("dir:" + .path),
              output_prefix: .label,
              ecosystems: .ecosystems
            }]
      else
        # Fall back to one generic filesystem scan when no manifests match.
        [{
          scan_kind: "filesystem",
          scan_label: "filesystem-generic",
          source: ("dir:" + $sourcePath),
          output_prefix: "filesystem-generic",
          ecosystems: []
        }]
      end
    ' <<<"$ecosystem_json")"
	# Targets summarize generated scan labels.
	targets="$(jq -c '[.[].scan_label]' <<<"$entries")"
	;;

*)
	echo "Unsupported mode: $MODE (expected audit or sbom)" >&2
	exit 1
	;;
esac

count="$(jq -r 'length' <<<"$entries")"
matrix="$(jq -c --argjson include "$entries" '{include:$include}' <<<'{}')"

# Emit the normalized GitHub Actions output payload.
jq -cn \
	--argjson detected "$detected" \
	--argjson targets "$targets" \
	--argjson count "$count" \
	--argjson matrix "$matrix" \
	'{detected:$detected, targets:$targets, count:$count, matrix:$matrix}'
