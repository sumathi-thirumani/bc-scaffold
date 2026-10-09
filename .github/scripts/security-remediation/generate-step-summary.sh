#!/usr/bin/env bash
set -euo pipefail

{
	echo "## Security Vulnerability Remediation"
	echo
} >>"$GITHUB_STEP_SUMMARY"

if [ ! -f orchestrator-output.json ]; then
	echo "Orchestration did not complete." >>"$GITHUB_STEP_SUMMARY"
	exit 0
fi

base_branch="${BASE_BRANCH}"
# SummaryContext contains repository-wide totals, before severity filtering.
open_security_alerts="$(jq '.summary.context.total_vulnerabilities // 0' orchestrator-output.json)"
open_code_scanning_alerts="$(jq '.summary.context.total_code_scanning_alerts // 0' orchestrator-output.json)"
open_prs_reviewed="$(jq '.summary.total_reviewed_prs // 0' orchestrator-output.json)"
prs_matched="$(jq '.summary.context.total_remediation_prs // 0' orchestrator-output.json)"
prs_ignored="$(jq '.summary.context.total_ignored_prs // 0' orchestrator-output.json)"
auto_created_issues=0
if [ -f rollup-output.json ]; then
	auto_created_issues="$(jq '.stats.total_issues_created // 0' rollup-output.json)"
fi

{
	echo "| Metric | Value |"
	echo "|--------|-------|"
	echo "| Base branch | \`${base_branch}\` |"
	echo "| Open security alerts | ${open_security_alerts} |"
	echo "| Open code scanning alerts | ${open_code_scanning_alerts} |"
	echo "| Open PRs reviewed | ${open_prs_reviewed} |"
	echo "| PRs matched (used as remediation) | ${prs_matched} |"
	echo "| PRs ignored (no matching finding) | ${prs_ignored} |"
	echo "| Tracking issues created/updated | ${auto_created_issues} |"
	echo
} >>"$GITHUB_STEP_SUMMARY"

if [ -f rollup-output.json ]; then
	dry_run="$(jq -r '.dry_run' rollup-output.json)"
	if [ "$dry_run" = "true" ]; then
		{
			echo "> ℹ️ **Dry run mode** - no branches, PRs, or issues were created."
			echo
		} >>"$GITHUB_STEP_SUMMARY"
	fi

	pr_count="$(jq '.created_prs | length' rollup-output.json)"
	if [ "$pr_count" -gt 0 ]; then
		{
			echo "### Remediation Pull Requests"
			echo
		} >>"$GITHUB_STEP_SUMMARY"
		jq -r '
      .created_prs | to_entries[] |
      .key as $cat |
      (if (.value | type) == "array"
       then .value | unique_by(.number) | .[]
       else .value
       end) |
      "- **\($cat)**: [\(.title)](\(.url))"
    ' rollup-output.json >>"$GITHUB_STEP_SUMMARY"
		echo >>"$GITHUB_STEP_SUMMARY"
	fi

	issue_count="$(jq '.created_issues | length' rollup-output.json 2>/dev/null || echo 0)"
	if [ "$issue_count" -gt 0 ]; then
		{
			echo "### Tracking Issues"
			echo
		} >>"$GITHUB_STEP_SUMMARY"
		jq -r '.created_issues | to_entries[] | "- **\(.key)**: [\(.value.title)](\(.value.url))"' \
			rollup-output.json >>"$GITHUB_STEP_SUMMARY"
		echo >>"$GITHUB_STEP_SUMMARY"
	fi
fi

# Category counts describe the selected workflow plans, when available.
if [ ! -f workflow-plans.json ]; then
	exit 0
fi
critical="$(jq '.vulnerabilities_summary.critical // 0' workflow-plans.json)"
high="$(jq '.vulnerabilities_summary.high // 0' workflow-plans.json)"
medium="$(jq '.vulnerabilities_summary.medium // 0' workflow-plans.json)"
low="$(jq '.vulnerabilities_summary.low // 0' workflow-plans.json)"
others="$(jq '.vulnerabilities_summary.others // 0' workflow-plans.json)"

{
	echo "### Vulnerability Categories"
	echo
	echo "| Critical | High | Medium | Low | Others |"
	echo "|:--------:|:----:|:------:|:---:|:------:|"
	echo "| $critical | $high | $medium | $low | $others |"

} >>"$GITHUB_STEP_SUMMARY"
