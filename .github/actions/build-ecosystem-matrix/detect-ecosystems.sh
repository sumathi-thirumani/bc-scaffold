#!/usr/bin/env bash
set -euo pipefail

ROOT_PATH="${1:-.}"

# Fail fast on an invalid scan root.
if [ ! -d "$ROOT_PATH" ]; then
	echo "Filesystem scan path does not exist: $ROOT_PATH" >&2
	exit 1
fi

# Track whether anything was found and collect manifest directories.
any="false"
detected=()
findings_file="$(mktemp)"

# Ignore generated, vendored, cached, and workflow-only folders.
excluded_dirs=(
	.git
	.github
	.gradle
	.mypy_cache
	.nox
	.pytest_cache
	.tox
	.venv
	__pycache__
	build
	coverage
	dist
	env
	node_modules
	out
	target
	vendor
	venv
)
excluded_dir_find_args=()

# Build a safe reusable `find` name expression for ignored directories.
for dir in "${excluded_dirs[@]}"; do
	if [ "${#excluded_dir_find_args[@]}" -gt 0 ]; then
		excluded_dir_find_args+=(-o)
	fi
	excluded_dir_find_args+=(-name "$dir")
done

cleanup() {
	rm -f "$findings_file"
}
trap cleanup EXIT

# Scan one ecosystem using the provided manifest name predicates.
detect_one() {
	local ecosystem="$1"
	shift
	local matches
	# Prune ignored folders before matching ecosystem manifests.
	matches="$(
		find "$ROOT_PATH" \
			\( -type d \( "${excluded_dir_find_args[@]}" \) -prune \) -o \
			\( -type f \( "$@" \) -print \)
	)"
	if [ -n "$matches" ]; then
		any="true"
		detected+=("$ecosystem")
		while IFS= read -r match; do
			[ -n "$match" ] || continue
			# Store the manifest directory for downstream ecosystem tools.
			printf '%s\t%s\n' "$ecosystem" "$(dirname "$match")" >>"$findings_file"
		done <<<"$matches"
	fi
}

# Manifest-based ecosystem definitions.
detect_one node -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name package.json
detect_one python -name 'requirements*.txt' -o -name pyproject.toml -o -name poetry.lock -o -name Pipfile.lock -o -name setup.py
detect_one java -name pom.xml -o -name build.gradle -o -name build.gradle.kts -o -name settings.gradle -o -name settings.gradle.kts
detect_one dotnet -name '*.sln' -o -name '*.csproj' -o -name '*.fsproj' -o -name '*.vbproj' -o -name Directory.Packages.props

# Emit stable JSON with unique findings and ecosystem names.
jq -Rn \
	--argjson any "$any" \
	--slurpfile findings <(sort -u "$findings_file" | jq -R 'split("\t") | {ecosystem: .[0], path: .[1]}') '
  {
    any: $any,
    list: ($findings | map(.ecosystem) | unique),
    findings: $findings
  }
'
