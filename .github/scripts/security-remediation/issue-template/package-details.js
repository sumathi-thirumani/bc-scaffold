// Per-package detail sections grouped by impact and action.

const { buildAlerts, vulnerabilityTableRows } = require('./alerts');
const { IMP_LABEL, ACT_LABEL, isTransitivePlan, forEachCategory } = require('./plan-helpers');
const { prLinks } = require('./remediation-prs');

function planStatus(plan) {
  if (plan.action.action_type === 'open_issue') return 'Manual/agent review - tracking issue opened';
  if (plan.action.action_type === 'placeholder_pr') return 'Placeholder - awaiting agent/manual fix';
  return plan.action.pr_number ? 'Remediation PR matched' : 'Awaiting remediation PR';
}

function buildTransitiveDetails(plan) {
  let details = '';
  for (const occurrence of plan.package.dependency_occurrences || []) {
    details += `\nTransitive dependency **${occurrence.package} ${occurrence.version || 'unknown'}** is introduced via\n\n`;
    for (const parent of occurrence.introducers || []) {
      details += `- ${parent.package} ${parent.version || 'unknown'} → ${occurrence.package} ${occurrence.version || 'unknown'}\n`;
    }
    if (!(occurrence.introducers || []).length) details += '_No declared parent found in the lockfile._\n';
    details += '\n';
  }
  const mdNote = plan.action.placeholder_markdown || '';
  const undershoot = mdNote.match(/Existing PR #(\d+) is insufficient[^)]*\(([^)]+)\)/);
  if (undershoot) details += `- **Existing PR**: #${undershoot[1]} undershoots required version - [view](${undershoot[2]})\n`;
  return details;
}

function buildPlanDetailSection(plan) {
  const alerts = buildAlerts(plan);

  let section = `<details>\n<summary><code>${plan.package.name}</code>: <code>${plan.package.current_version_range}</code> -> <code>${plan.fix.upgrade_version || 'N/A'}</code></summary>\n\n`;
  section += `- **Remediation Status**: ${planStatus(plan)}\n`;
  if (isTransitivePlan(plan)) section += buildTransitiveDetails(plan);

  if (plan.action.pr_number) {
    section += `- **Remediation PR**: #${plan.action.pr_number} ([view](${plan.action.pull_url}))\n`;
  }
  if (plan.state.issue_id) {
    section += `- **Tracking Issue**: #${plan.state.issue_id} ([view](${plan.state.issue_url}))\n`;
  }

  if (alerts.length > 0) {
    section += `**Vulnerabilities**:\n\n| ID | Summary | CVSS | Affected Versions | Fixed In |\n|---|---|---|---|---|\n`;
    section += vulnerabilityTableRows(alerts).join('\n') + '\n\n';
  }

  return section + '</details>\n\n';
}

function buildCategoryDetailSections(ecosystem, categoryMap, groupPlansSet, groupPRs) {
  let body = '';
  forEachCategory(ecosystem, categoryMap, groupPlansSet, (category, plans, impact, action) => {
    if (!body) body = '## Vulnerability Findings & Dependency Graph\n\n';
    body += `**${IMP_LABEL[impact]} - ${ACT_LABEL[action]} Updates**\n\n`;

    if (action === 'placeholder') {
      const placeholderPRs = groupPRs(category) || [];
      if (placeholderPRs.length > 0) {
        body += `**Placeholder PR**: ${prLinks(placeholderPRs)} _(draft - push fixes or assign to agent)_\n\n`;
      }
    }

    for (const plan of plans) body += buildPlanDetailSection(plan);
  });
  return body;
}

module.exports = { buildCategoryDetailSections };
