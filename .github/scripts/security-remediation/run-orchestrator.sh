#!/usr/bin/env bash
set -euo pipefail

python ./octo-gha-tools/security-remediation-agent/main.py \
	--owner "${GITHUB_REPOSITORY_OWNER}" \
	--repo "${GITHUB_REPOSITORY#*/}" \
	>orchestrator-output.json

if [ ! -s orchestrator-output.json ]; then
	echo "::error::Orchestrator produced no JSON. main.py must serialize the result to stdout, including empty remediation plans." >&2
	exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
node "$script_dir/prepare-workflow-output.js"
total_plans="$(jq '[.groups[].plans? // [] | length] | add // 0' workflow-plans.json)"
if [ "${total_plans}" -gt 0 ]; then
	echo "has_work=true" >>"$GITHUB_OUTPUT"
else
	echo "has_work=false" >>"$GITHUB_OUTPUT"
fi
echo "Total plans: ${total_plans}"
