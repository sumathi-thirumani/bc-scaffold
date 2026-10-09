#!/usr/bin/env bash
set -euo pipefail

base_branch="${INPUT_BASE_BRANCH:-}"
if [ -z "${base_branch}" ]; then
	base_branch="$(gh repo view "${GITHUB_REPOSITORY}" --json defaultBranchRef --jq '.defaultBranchRef.name')"
fi

echo "base_branch=${base_branch}" >>"$GITHUB_OUTPUT"
echo "Base branch: ${base_branch}"
