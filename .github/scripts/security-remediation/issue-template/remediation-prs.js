// Remediation pull requests overview table.

const { IMP_LABEL, ACT_LABEL, forEachCategory } = require('./plan-helpers');

const prLinks = prs => [...new Map(prs.map(pr => [pr.number, pr])).values()]
  .map(pr => `[#${pr.number}](${pr.url})`).join(', ');

function remediationStatusFor(act, categoryPRs) {
  if (act === 'open-issue') {
    return { link: (categoryPRs || []).map(pr => `[#${pr.number}](${pr.url})`).join(', ') || '—',
      status: 'Manual/agent review - issue tracking only' };
  }
  if (act === 'placeholder') {
    if (categoryPRs && categoryPRs.length > 0) {
      return { link: prLinks(categoryPRs), status: 'Draft - awaiting agent/manual fix' };
    }
    return { link: '—', status: 'Stub branch creation failed' };
  }
  if (categoryPRs) return { link: prLinks(categoryPRs), status: 'Open' };
  return { link: '—', status: 'No remediation PR matched' };
}

function buildRemediationPRsSection(ecosystem, categoryMap, groupPlansSet, groupPRs) {
  const rows = [];
  forEachCategory(ecosystem, categoryMap, groupPlansSet, (category, plans, impact, action) => {
    const { link, status } = remediationStatusFor(action, groupPRs(category));
    const pkgList = plans.map(p => `\`${p.package.name}\``).join(', ');
    rows.push(`| ${IMP_LABEL[impact]} | ${ACT_LABEL[action] || action} | ${pkgList} | ${link} | ${status} |`);
  });

  let section = `## Remediation Pull Requests\n\n`;
  section += rows.length > 0
    ? `| Impact | Action | Package | Pull Request | Status |\n|---|---|---|---|---|\n${rows.join('\n')}\n\n`
    : '_No remediation PRs matched._\n\n';
  return section;
}

module.exports = { buildRemediationPRsSection, prLinks };
