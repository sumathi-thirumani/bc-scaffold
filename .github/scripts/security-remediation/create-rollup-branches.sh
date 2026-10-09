#!/usr/bin/env bash
set -euo pipefail

# NOTE: This script no longer creates, merges, or pushes any branches.
# It only summarizes which rollup/standalone/placeholder PR candidates
# would have been grouped together, for reporting purposes in
# rollup-results.json and the workflow step summary.

OUTPUT_FILE="workflow-plans.json"
RESULTS_FILE="rollup-results.json"
echo '{"branches":{},"stubs":{}}' >"$RESULTS_FILE"

# Collect all unique categories from the orchestrator output
# category = "<ecosystem>--<non-breaking|breaking>-<rollup|standalone>"
# Only rollup_pr and standalone_pr plans have real branches to merge.
categories="$(jq -r '
  (.groups // .) |
  [
    to_entries[] |
    .value.plans[]? |
    select(.action.action_type == "rollup_pr" or .action.action_type == "standalone_pr") |
    (if .fix.fix_class == "BREAKING_BUMP" then "breaking" else "non-breaking" end) as $imp |
    (if .action.action_type == "rollup_pr" then "rollup" else "standalone" end) as $act |
    "\((.package.ecosystem // "unknown") | @uri)--\($imp)-\($act)"
  ] | unique[]
' "$OUTPUT_FILE")"

for category in $categories; do
	# category format: <ecosystem>--<imp>-<act>, e.g. npm--non-breaking-rollup
	act="$(echo "$category" | rev | cut -d'-' -f1 | rev)"
	ecosystem_key="${category%%--*}"
	impact_action="${category#*--}"
	imp="${impact_action%-*}"

	# Extract PR numbers already matched for this category (no branch resolution/merging).
	pr_numbers_json="$(jq --arg ecosystem "$ecosystem_key" --arg imp "$imp" --arg act "$act" '
    (.groups // .) |
    [
      to_entries[] |
      .value.plans[]? |
      select(
        ((.package.ecosystem // "unknown") | @uri) == $ecosystem and
        (.action.action_type == "rollup_pr" or .action.action_type == "standalone_pr") and
        (if .fix.fix_class == "BREAKING_BUMP" then "breaking" else "non-breaking" end) == $imp and
        (if .action.action_type == "rollup_pr" then "rollup" else "standalone" end) == $act and
        .action.pr_number != null
      ) |
      .action.pr_number
    ] | unique
  ' "$OUTPUT_FILE")"

	count="$(echo "$pr_numbers_json" | jq 'length')"
	if [ "$count" -eq 0 ]; then continue; fi

	branch_name="security-remediation/${category}"
	echo "::notice::${branch_name} - ${count} candidate PR(s) grouped (no branch created)"

	tmp="$(mktemp)"
	jq \
		--arg cat "${category}" \
		--arg branch "${branch_name}" \
		--argjson included "${pr_numbers_json}" \
		'.branches[$cat] = {
      branch:       $branch,
      included_prs: $included,
      excluded_prs: [],
      pushed:       false,
      note:         "summary only - no branch created or merged"
    }' "$RESULTS_FILE" >"$tmp"
	mv "$tmp" "$RESULTS_FILE"
done

echo "Rollup branch summary complete (no branches created)."

# Placeholder plans are grouped by ecosystem and impact for reporting only.
echo "Summarizing placeholder PR groups..."

placeholder_plans="$(jq -r '
  (.groups // .) |
  to_entries[] |
  .value.plans[]? |
  select(.action.action_type == "placeholder_pr") |
  [
    (if .fix.fix_class == "BREAKING_BUMP" then "breaking" else "non-breaking" end),
    ((.package.ecosystem // "unknown") | @uri),
    .plan_id
  ] | @tsv
' "$OUTPUT_FILE")"

declare -A group_plan_count

while IFS=$'\t' read -r imp ecosystem plan_id; do
	[ -z "$plan_id" ] && continue
	group_key="${ecosystem}--${imp}"
	stub_branch="security-remediation/placeholder/${group_key}"
	group_plan_count[$group_key]=$((${group_plan_count[$group_key]:-0} + 1))

	tmp="$(mktemp)"
	jq \
		--arg plan_id "${plan_id}" \
		--arg branch "${stub_branch}" \
		'.stubs[$plan_id] = { branch: $branch, note: "summary only - no branch created" }' \
		"$RESULTS_FILE" >"$tmp"
	mv "$tmp" "$RESULTS_FILE"
done <<<"$placeholder_plans"

for group_key in "${!group_plan_count[@]}"; do
	echo "::notice::security-remediation/placeholder/${group_key} - ${group_plan_count[$group_key]} placeholder plan(s) grouped (no branch created)"
done

echo "Placeholder summary complete (no branches created)."
cat "$RESULTS_FILE"
