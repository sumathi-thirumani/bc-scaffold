// Assembles the tracking issue body from its independent sections.

const { buildAcceptanceCriteriaSection } = require('./acceptance-criteria');
const { footerSection, mergeOrderSection, truncateForGitHub } = require('./footer');
const { buildCategoryDetailSections } = require('./package-details');
const { buildPackageSummarySection } = require('./package-summary');
const { buildReconciliationNotesSection } = require('./reconciliation-notes');
const { buildRemediationPRsSection } = require('./remediation-prs');
const { getCategory, getImpact, isTransitivePlan } = require('./plan-helpers');
const { buildUpgradeOptionsSection } = require('./upgrade-options');
const { repositorySummaryMarkdown } = require('./repository-summary');

// run: { id, url } of the workflow run; remediationPlan: parsed orchestrator output.
function buildIssueBody({
  ecosystem, upgradeGroup, group, categoryMap, groupPRs, baseBranch, run, remediationPlan,
}) {
  const groupPlansSet = new Set(group.plans);
  const sourceBundle = (remediationPlan.remediation_plan_bundles || []).find(bundle =>
    bundle.ecosystem === ecosystem && bundle.groupName === upgradeGroup);

  let body = `# [${ecosystem}] [${upgradeGroup}]\n\n`;
  body += `**Base Branch**: \`${baseBranch}\`\n`;
  body += `**Workflow Run**: [#${run.id}](${run.url})\n\n`;
  body += repositorySummaryMarkdown(group.plans);
  body += buildPackageSummarySection(ecosystem, group.plans);
  body += buildAcceptanceCriteriaSection(group.plans, sourceBundle?.upgrade_targets);
  body += buildRemediationPRsSection(ecosystem, categoryMap, groupPlansSet, groupPRs);
  body += buildUpgradeOptionsSection(group.plans, sourceBundle?.upgrade_targets);
  body += buildReconciliationNotesSection(ecosystem, remediationPlan.reconciliation_info);
  body += buildCategoryDetailSections(ecosystem, categoryMap, groupPlansSet, groupPRs);
  body += mergeOrderSection();
  body += footerSection(run.url);

  return truncateForGitHub(body, run.url);
}

module.exports = { buildIssueBody, getCategory, getImpact, isTransitivePlan };
