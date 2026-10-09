// Creates/updates GitHub tracking issues for security remediation plans.
// PR creation is handled elsewhere (create-rollup-branches.sh); this script
// only reads already-matched PR/issue references from workflow-plans.json
// and builds one tracking issue per (ecosystem, upgrade-group) bucket.

const fs = require('fs');
const { owner, repo } = context.repo;
core.info(`Operating on caller repository: ${owner}/${repo}`);

// ── Inputs ───────────────────────────────────────────────────────────────────

const raw = JSON.parse(fs.readFileSync('workflow-plans.json', 'utf8'));
const output = raw.groups || raw;
const remediationPlan = JSON.parse(fs.readFileSync('orchestrator-output.json', 'utf8'));
const summary = remediationPlan.summary || {};
const summaryContext = summary.context || {};
const BASE_BRANCH = process.env.BASE_BRANCH;
const GITHUB_BODY_MAX = 65536;

// ── Labels ───────────────────────────────────────────────────────────────────

const IMP_LABEL = { 'non-breaking': 'Non-Breaking', breaking: 'Breaking' };
const ACT_LABEL = { rollup: 'Rollup', standalone: 'Standalone', placeholder: 'Placeholder', 'open-issue': 'Open Issue' };

const ACTION_LABELS = {
  'non-breaking-rollup': { color: '2da44e', description: 'Non-breaking fix included in a rollup PR' },
  'non-breaking-standalone': { color: '6fdd8b', description: 'Non-breaking fix with its own standalone PR' },
  'non-breaking-placeholder': { color: 'a8f0bc', description: 'Non-breaking fix - placeholder PR, needs manual attention' },
  'non-breaking-open-issue': { color: 'd4f5e2', description: 'Non-breaking finding - no fix available, issue opened' },
  'breaking-rollup': { color: 'e85e2b', description: 'Breaking bump included in a rollup PR' },
  'breaking-standalone': { color: 'f5854a', description: 'Breaking bump with its own standalone PR' },
  'breaking-placeholder': { color: 'f8b48a', description: 'Breaking bump - placeholder PR, needs manual attention' },
  'breaking-open-issue': { color: 'fbd9c5', description: 'Breaking finding - no fix available, issue opened' },
  'security-rollup': { color: 'e11d48', description: 'Security vulnerability rollup' },
};

const ACTION_TYPE_TO_SUFFIX = {
  rollup_pr: 'rollup',
  standalone_pr: 'standalone',
  placeholder_pr: 'placeholder',
  open_issue: 'open-issue',
};

// ── Plan helpers ─────────────────────────────────────────────────────────────

function getImpact(plan) {
  return plan.fix.fix_class === 'BREAKING_BUMP' ? 'breaking' : 'non-breaking';
}

function isTransitivePlan(plan) {
  return (plan.package.relationship || '').toLowerCase() === 'transitive' || plan.package.is_transitive === true;
}

// Strips scope/subpath noise from a package name for grouping purposes.
// e.g. "@vue/cli-service" -> "@vue", "some-pkg/sub" -> "some-pkg".
function normalizeGroupingName(name) {
  if (!name) return name;
  return name.includes('/') ? name.slice(0, name.indexOf('/')) : name;
}

// Determines the package name used for issue grouping: for transitive
// packages, always use a parent/introducer package; otherwise use the
// package's own name. When multiple introducers exist, pick deterministically
// (alphabetically) so packages sharing the same introducer set always group
// together, regardless of array ordering in the source data.
function getGroupingPackageName(plan) {
  if (!isTransitivePlan(plan)) return plan.package.name;

  const occurrences = plan.package.dependency_occurrences || [];
  const introducerNames = [...new Set(occurrences.flatMap(occ => (occ.introducers || []).map(i => i.package)))]
    .map(normalizeGroupingName).sort();
  if (introducerNames.length > 0) return introducerNames[0];

  const sources = plan.package.transitive_source_packages || plan.package.transitive_source_package || [];
  if (sources.length > 0) {
    const names = sources
      .map(s => (s.includes('@') && s.lastIndexOf('@') > 0 ? s.slice(0, s.lastIndexOf('@')) : s))
      .map(normalizeGroupingName)
      .sort();
    return names[0];
  }

  return normalizeGroupingName(plan.package.name);
}

function getActionSuffix(plan) {
  return ACTION_TYPE_TO_SUFFIX[plan.action.action_type] || 'open-issue';
}

function getCategory(plan) {
  return `${encodeURIComponent(plan.package.ecosystem || 'unknown')}--${getImpact(plan)}-${getActionSuffix(plan)}`;
}

function getActionLabel(plan) {
  return `${getImpact(plan)}-${getActionSuffix(plan)}`;
}

function buildAlerts(plan) {
  if (plan.package.vulnerabilities) return plan.package.vulnerabilities;
  const mdSummaries = {};
  const md = plan.action.placeholder_markdown || '';
  for (const m of md.matchAll(/- \*\*(GHSA-[\w-]+)\*\* \(CVSS ([\d.]+)\) - (.+)/g)) {
    mdSummaries[m[1]] = { cvss: parseFloat(m[2]), summary: m[3].trim() };
  }
  return plan.package.unique_ghsas.map(id => ({
    ghsa_id: id,
    cve_id: null,
    summary: mdSummaries[id]?.summary || `Vulnerability in ${plan.package.name}`,
    cvss: mdSummaries[id]?.cvss ?? null,
    url: `https://github.com/advisories/${id}`,
    vulnerable_range: plan.package.current_version_range,
    first_patched: plan.fix.upgrade_version || '—',
  }));
}

function vulnerabilityTableRows(alerts) {
  return alerts.map(a => {
    const id = a.ghsa_id || a.cve_id || '?';
    const cvss = a.cvss != null ? String(a.cvss) : '—';
    return `| [${id}](${a.url}) | ${a.summary || '—'} | ${cvss} | ${a.vulnerable_range || '—'} | ${a.first_patched || '—'} |`;
  });
}

function transitiveChildrenOf(plan, allPlans) {
  return allPlans.filter(p => {
    if (!isTransitivePlan(p)) return false;
    const sources = p.package.transitive_source_packages || p.package.transitive_source_package || [];
    return sources.some(src => src.split('@')[0].toLowerCase() === plan.package.name.toLowerCase());
  });
}

// ── GitHub helpers ───────────────────────────────────────────────────────────

async function ensureAllLabels() {
  for (const [name, { color, description }] of Object.entries(ACTION_LABELS)) {
    try {
      await github.rest.issues.getLabel({ owner, repo, name });
    } catch {
      await github.rest.issues.createLabel({ owner, repo, name, color, description });
      core.info(`Created label: ${name}`);
    }
  }
}

async function findIssue(title) {
  const q = `repo:${owner}/${repo} is:issue is:open in:title "${title}"`;
  const res = await github.rest.search.issuesAndPullRequests({ q, per_page: 10 });
  return res.data.items.find(i => i.title === title) || null;
}

// ── Repository summary section ──────────────────────────────────────────────

const SEVERITY_BUCKETS = ['Critical', 'High', 'Medium', 'Low'];

// Same CVSS thresholds used by severityLabel(), applied per-alert so counts
// bucket consistently with the per-package Severity column below.
function severityBucketOf(alert) {
  const cvss = alert.cvss;
  if (cvss == null) return null;
  return cvss >= 9 ? 'Critical' : cvss >= 7 ? 'High' : cvss >= 4 ? 'Medium' : 'Low';
}

function severityCounts(plans) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const plan of plans) {
    for (const alert of buildAlerts(plan)) {
      const bucket = severityBucketOf(alert);
      if (bucket) counts[bucket] += 1;
    }
  }
  return counts;
}

function repositorySummaryMarkdown(plans) {
  const counts = severityCounts(plans);
  return '## Summary\n\n' +
    `| ${SEVERITY_BUCKETS.join(' | ')} |\n` +
    `|${SEVERITY_BUCKETS.map(() => '---').join('|')}|\n` +
    `| ${SEVERITY_BUCKETS.map(bucket => counts[bucket]).join(' | ')} |\n\n`;
}

// ── Issue group summary section (per-package overview table) ───────────────

function severityLabel(alerts) {
  const cvssValues = alerts.map(a => a.cvss).filter(v => v != null);
  if (cvssValues.length === 0) return '—';
  const maxCvss = Math.max(...cvssValues);
  const bucket = maxCvss >= 9 ? 'Critical' : maxCvss >= 7 ? 'High' : maxCvss >= 4 ? 'Medium' : 'Low';
  return `${bucket} (${maxCvss})`;
}

// Parent (introducer) packages for a specific vulnerable package, scoped to
// only the transitive_dependency_occurrences whose `package` matches it -
// not every occurrence across the whole bundle/plan.
function parentPackagesOf(plan, packageName) {
  const occurrences = (plan.package.dependency_occurrences || []).filter(occ =>
    !packageName || (occ.package || '').toLowerCase() === packageName.toLowerCase());
  const introducerNames = [...new Set(occurrences.flatMap(occ => (occ.introducers || []).map(i => i.package)))];
  const parents = introducerNames.length
    ? introducerNames
    : (plan.package.transitive_source_packages || plan.package.transitive_source_package || []);
  return Array.isArray(parents) && parents.length ? parents.join(', ') : '—';
}

// The vulnerable package name(s) as reported by the underlying vulnerability
// alerts, rather than the remediation/bundle package name (which for
// transitive plans is the resolved upgrade target, not the vulnerable one).
// Deduplicated case-insensitively since the same package can be reported
// with inconsistent casing across alerts (e.g. "starlette" vs "Starlette").
function vulnerablePackageNamesOf(plan, alerts) {
  const seen = new Map();
  for (const alert of alerts) {
    if (!alert.package) continue;
    const key = alert.package.toLowerCase();
    if (!seen.has(key)) seen.set(key, alert.package);
  }
  const names = [...seen.values()];
  return names.length ? names : [plan.package.name];
}

// Splits a plan's alerts by the vulnerable package they were reported
// against, so each distinct vulnerable package gets its own summary row
// instead of being merged into one comma-separated cell.
function alertsByVulnerablePackage(plan, alerts) {
  const names = vulnerablePackageNamesOf(plan, alerts);
  if (names.length <= 1) return [[names[0], alerts]];
  const byKey = new Map(names.map(name => [name.toLowerCase(), []]));
  for (const alert of alerts) {
    const key = (alert.package || '').toLowerCase();
    (byKey.get(key) || byKey.get(names[0].toLowerCase())).push(alert);
  }
  return names.map(name => [name, byKey.get(name.toLowerCase())]);
}

function buildIssueGroupSummarySection(ecosystem, plans) {
  const vulnerablePlans = plans.filter(plan => buildAlerts(plan).length > 0);
  let section = `\n## Package Vulnerability Summary (${ecosystem})\n\n`;
  section += `| Package | No. of Vulnerabilities | Severity | Direct/Transitive | Parent Packages |\n|---|---|---|---|---|\n`;

  if (vulnerablePlans.length === 0) {
    section += `| _No vulnerable packages in this group_ | | | | |\n\n`;
    return section;
  }

  for (const plan of vulnerablePlans) {
    const alerts = buildAlerts(plan);
    const depType = isTransitivePlan(plan) ? 'Transitive' : 'Direct';
    for (const [packageName, packageAlerts] of alertsByVulnerablePackage(plan, alerts)) {
      section += `| \`${packageName}\` | ${packageAlerts.length} | ${severityLabel(packageAlerts)} | ${depType} | ${parentPackagesOf(plan, packageName)} |\n`;
    }
  }
  return section + '\n';
}

// ── Acceptance criteria section (checkbox per bundle package) ───────────────

function buildAcceptanceCriteriaSection(plans) {
  const vulnerablePlans = plans.filter(plan => buildAlerts(plan).length > 0);
  let section = `## Acceptance Criteria\n\n`;

  if (vulnerablePlans.length === 0) {
    section += `_No vulnerable packages in this group_\n\n`;
    return section;
  }

  for (const plan of vulnerablePlans) {
    const currentVersion = plan.package.current_version || 'unknown';
    const remediationVersion = plan.fix.upgrade_version || '—';
    const minimumVersion = plan.package.minimum_upgradable_version;
    const versionNoteLabel = minimumVersion
      && remediationVersion !== '—'
      && compareVersions(minimumVersion, remediationVersion) > 0
      ? 'upgrade candidate'
      : 'minimum version';
    const minimumVersionNote = minimumVersion && minimumVersion !== remediationVersion
      ? ` [${versionNoteLabel}: ${minimumVersion}]`
      : '';
    section += `- [ ] Upgrade \`${plan.package.name}\` from \`${currentVersion}\` to \`${remediationVersion}\`${minimumVersionNote}\n`;
  }

  function compareVersions(left, right) {
    const parts = version => version.replace(/^[vV]/, '').split(/[.+-]/)
      .map(part => /^\d+$/.test(part) ? Number(part) : part);
    const leftParts = parts(left);
    const rightParts = parts(right);
    const length = Math.max(leftParts.length, rightParts.length);
    for (let i = 0; i < length; i++) {
      const a = leftParts[i] ?? 0;
      const b = rightParts[i] ?? 0;
      if (a === b) continue;
      if (typeof a === 'number' && typeof b === 'number') return a - b;
      return String(a).localeCompare(String(b));
    }
    return 0;
  }
  return section + '\n';
}

// ── Remediation pull requests overview table ────────────────────────────────

function remediationStatusFor(act, cPlans, categoryPRs) {
  if (act === 'open-issue') {
    return { link: '—', status: 'No fix available - issue tracking only' };
  }
  if (act === 'placeholder') {
    if (categoryPRs && categoryPRs.length > 0) {
      const uniq = [...new Map(categoryPRs.map(p => [p.number, p])).values()];
      return { link: uniq.map(p => `[#${p.number}](${p.url})`).join(', '), status: 'Draft - awaiting agent/manual fix' };
    }
    return { link: '—', status: 'Stub branch creation failed' };
  }
  if (categoryPRs) {
    if (Array.isArray(categoryPRs)) {
      const links = [...new Map(categoryPRs.map(p => [p.number, p])).values()]
        .map(p => `[#${p.number}](${p.url})`).join(', ');
      return { link: links, status: 'Open' };
    }
    return { link: `[${categoryPRs.title}](${categoryPRs.url})`, status: 'Open' };
  }
  return { link: '—', status: 'No remediation PR matched' };
}

function buildRemediationPRsSection(ecosystem, categoryMap, groupPlansSet, groupPRs) {
  const rows = [];
  for (const imp of ['non-breaking', 'breaking']) {
    for (const act of ['rollup', 'standalone', 'placeholder', 'open-issue']) {
      const cat = `${encodeURIComponent(ecosystem)}--${imp}-${act}`;
      const cPlans = (categoryMap[cat] || []).filter(plan => groupPlansSet.has(plan));
      if (cPlans.length === 0) continue;
      const { link, status } = remediationStatusFor(act, cPlans, groupPRs(cat));
      const pkgList = cPlans.map(p => `\`${p.package.name}\``).join(', ');
      rows.push(`| ${IMP_LABEL[imp]} | ${ACT_LABEL[act] || act} | ${pkgList} | ${link} | ${status} |`);
    }
  }

  let section = `## Remediation Pull Requests\n\n`;
  section += rows.length > 0
    ? `| Impact | Action | Package | Pull Request | Status |\n|---|---|---|---|---|\n${rows.join('\n')}\n\n`
    : '_No remediation PRs matched._\n\n';
  return section;
}

function buildReconciliationNotesSection(ecosystem) {
  if (!['npm', 'npm_and_yarn', 'yarn'].includes((ecosystem || '').toLowerCase())) {
    return '';
  }
  const notes = (remediationPlan.reconciliation_info || [])
    .filter(info => ['npm', 'npm_and_yarn', 'yarn']
      .includes((info.ecosystem || '').toLowerCase()))
    .map(info => (info.reconciliation_notes || '').trim())
    .filter(Boolean);
  if (notes.length === 0) return '';

  const indentedNotes = notes.join('\n\n').split('\n')
    .map(line => `    ${line}`)
    .join('\n');
  return `## Reconciliation Notes\n\n${indentedNotes}\n\n`;
}

// ── Per-package detail sections ──────────────────────────────────────────────

function planStatus(plan) {
  if (plan.action.action_type === 'open_issue') return 'No fix available - tracking issue opened';
  if (plan.action.action_type === 'placeholder_pr') return 'Placeholder - awaiting agent/manual fix';
  return plan.action.pr_number ? 'Remediation PR matched' : 'Awaiting remediation PR';
}

function buildTransitiveDetails(plan) {
  let details = '';
  const parentPRs = plan.package.introducer_pull_requests || [];
  if (parentPRs.length) {
    details += '\n**Introducer upgrade PRs** (verify the resulting transitive version):\n\n';
    for (const candidate of parentPRs) {
      details += `- [#${candidate.pr_number}](${candidate.pull_url}): ${candidate.package} ${candidate.from_version} → ${candidate.to_version}\n`;
    }
    details += '\n';
  }
  for (const occurrence of plan.package.dependency_occurrences || []) {
    details += `\nTransitive dependency **${occurrence.package} ${occurrence.version || 'unknown'}** is introduced via\n\n`;
    for (const parent of occurrence.introducers || []) {
      details += `- ${parent.package} ${parent.version || 'unknown'} → ${occurrence.package} ${occurrence.version || 'unknown'}\n`;
    }
    if (!(occurrence.introducers || []).length) details += '_No declared parent found in the lockfile._\n';
    details += '\n';
  }
  const transitiveOf = plan.package.transitive_source_packages || plan.package.transitive_source_package || [];
  const srcList = Array.isArray(transitiveOf) ? transitiveOf.join(', ') : String(transitiveOf);
  const mdNote = plan.action.placeholder_markdown || '';
  const undershoot = mdNote.match(/Existing PR #(\d+) is insufficient[^)]*\(([^)]+)\)/);
  if (undershoot) details += `- **Existing PR**: #${undershoot[1]} undershoots required version - [view](${undershoot[2]})\n`;
  return details;
}

function buildDirectDetails(plan, transitiveChildren) {
  let details = '';
  if (transitiveChildren.length > 0) {
    details += `- **Transitive Vulnerabilities Resolved**: ${transitiveChildren.map(t => `\`${t.package.name}\``).join(', ')}\n`;
  }
  return details;
}

function buildTransitiveChildrenSection(transitiveChildren) {
  let section = `**Transitive Vulnerabilities Resolved by This Upgrade**:\n\n`;
  for (const child of transitiveChildren) {
    const childAlerts = buildAlerts(child);
    const childSrc = (child.package.transitive_source_packages || child.package.transitive_source_package || []).join(', ');
    section += `<details><summary><code>${child.package.name}</code> (transitive via <code>${childSrc}</code>)</summary>\n\n`;
    if (childAlerts.length > 0) {
      section += `| ID | Summary | CVSS | Affected Versions | Fixed In |\n|---|---|---|---|---|\n`;
      section += vulnerabilityTableRows(childAlerts).join('\n') + '\n';
    } else {
      section += '_No individual vulnerability details available._\n';
    }
    section += `\n</details>\n\n`;
  }
  return section;
}

function buildPlanDetailSection(plan, allPlans) {
  const alerts = buildAlerts(plan);
  const isTransitive = isTransitivePlan(plan);
  const transitiveChildren = transitiveChildrenOf(plan, allPlans);

  let section = `### \`${plan.package.name}\`: \`${plan.package.current_version_range}\` -> \`${plan.fix.upgrade_version || plan.fix.non_breaking_fix || 'N/A'}\`\n\n`;
  section += `- **Remediation Status**: ${planStatus(plan)}\n`;
  section += isTransitive ? buildTransitiveDetails(plan) : buildDirectDetails(plan, transitiveChildren);

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

  if (!isTransitive && transitiveChildren.length > 0) {
    section += buildTransitiveChildrenSection(transitiveChildren);
  }

  return section;
}

function buildCategoryDetailSections(ecosystem, categoryMap, groupPlansSet, groupPRs, allPlans) {
  let body = '';
  for (const imp of ['non-breaking', 'breaking']) {
    for (const act of ['rollup', 'standalone', 'placeholder', 'open-issue']) {
      const cat = `${encodeURIComponent(ecosystem)}--${imp}-${act}`;
      const cPlans = (categoryMap[cat] || []).filter(plan => groupPlansSet.has(plan));
      if (cPlans.length === 0) continue;

      body += `## ${IMP_LABEL[imp]} - ${ACT_LABEL[act]} Updates\n\n`;

      if (act === 'placeholder') {
        const phPRs = groupPRs(cat) || [];
        const uniqPRs = [...new Map(phPRs.map(p => [p.number, p])).values()];
        if (uniqPRs.length > 0) {
          body += `**Placeholder PR**: ${uniqPRs.map(p => `[#${p.number}](${p.url})`).join(', ')} _(draft - push fixes or assign to agent)_\n\n`;
        }
      }

      for (const plan of cPlans) {
        body += buildPlanDetailSection(plan, allPlans);
      }
    }
  }
  return body;
}

// ── Footer sections ──────────────────────────────────────────────────────────

function mergeOrderSection() {
  return `## Recommended Merge Order\n\n` +
    `1. **Non-breaking updates first** - lower risk, no API changes expected\n` +
    `2. **Validate** in a staging or test environment before merging\n` +
    `3. **Breaking updates** - review dependent code for API or behavior changes\n` +
    `4. **Re-run** this workflow after each merge to refresh the tracking issue\n\n`;
}

function footerSection() {
  return `---\n_Generated by [Security Vulnerability Remediation](${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId})_`;
}

function truncateForGitHub(body) {
  if (body.length <= GITHUB_BODY_MAX) return body;
  const runLink = `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;
  const notice = `\n\n---\n> ⚠️ **Content truncated**: this tracking issue exceeded GitHub's ${GITHUB_BODY_MAX}-character body limit. ` +
    `See the full details in the [workflow run](${runLink}) artifacts.\n`;
  return body.slice(0, GITHUB_BODY_MAX - notice.length) + notice;
}

// ── Issue body assembly ──────────────────────────────────────────────────────

function buildIssueBody(ecosystem, upgradeGroup, group, categoryMap, groupPRs) {
  let body = `# [${ecosystem}] [${upgradeGroup}]\n\n`;
  body += `**Base Branch**: \`${BASE_BRANCH}\`\n`;
  body += `**Workflow Run**: [#${context.runId}](${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId})\n\n`;
  body += repositorySummaryMarkdown(group.plans);
  body += buildIssueGroupSummarySection(ecosystem, group.plans);
  body += buildAcceptanceCriteriaSection(group.plans);

  const groupPlansSet = new Set(group.plans);
  body += buildRemediationPRsSection(ecosystem, categoryMap, groupPlansSet, groupPRs);
  body += buildReconciliationNotesSection(ecosystem);
  body += buildCategoryDetailSections(ecosystem, categoryMap, groupPlansSet, groupPRs, group.plans);
  body += mergeOrderSection();
  body += footerSection();

  return truncateForGitHub(body);
}

// ── Grouping ─────────────────────────────────────────────────────────────────

function buildCategoryMap() {
  const categoryMap = {};
  for (const sourceGroup of Object.values(output)) {
    for (const plan of sourceGroup.plans || []) {
      const cat = getCategory(plan);
      (categoryMap[cat] ||= []).push(plan);
    }
  }
  return categoryMap;
}

// Groups plans into one tracking issue per package bundle, using the
// bundle metadata (groupName/ecosystem) attached by prepare-workflow-output.js
// from the orchestrator's RemeditionPackageBundle. Falls back to the
// ecosystem/impact heuristic for plans without bundle metadata (e.g. older
// workflow-plans.json artifacts or hand-authored test fixtures).
function buildIssueGroups() {
  const issueGroups = new Map();
  for (const sourceGroup of Object.values(output)) {
    for (const plan of sourceGroup.plans || []) {
      const bundle = plan.bundle;
      const ecosystem = (bundle && bundle.ecosystem) || plan.package.ecosystem || 'unknown';
      const upgradeGroup = bundle && bundle.groupName
        ? bundle.groupName
        : (getImpact(plan) === 'breaking' ? `Major(${getGroupingPackageName(plan)})` : 'Minor-Patch');
      const key = JSON.stringify([ecosystem, upgradeGroup]);
      if (!issueGroups.has(key)) {
        issueGroups.set(key, { ecosystem, upgradeGroup, plans: [] });
      }
      issueGroups.get(key).plans.push(plan);
    }
  }
  return issueGroups;
}

// Matches already-created PRs (from prior workflow runs, tracked via
// plan.action.pr_number) to a category, restricted to the plans in this
// issue group. Since this script no longer creates PRs itself, this is
// sourced entirely from the plan data prepared upstream.
function makeGroupPRsResolver(group) {
  const prsByCategory = {};
  for (const plan of group.plans) {
    if (!plan.action.pr_number) continue;
    const cat = getCategory(plan);
    (prsByCategory[cat] ||= []).push({
      number: plan.action.pr_number,
      url: plan.action.pull_url,
      package: plan.package.name,
    });
  }
  return cat => prsByCategory[cat];
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function createOrUpdateTrackingIssues() {
  await ensureAllLabels();

  const categoryMap = buildCategoryMap();
  const issueGroups = buildIssueGroups();
  const createdIssues = {};

  for (const [issueKey, group] of issueGroups) {
    const { ecosystem, upgradeGroup } = group;
    const title = `[Security Remediation] [${ecosystem}] [${upgradeGroup}]`;
    const groupPRs = makeGroupPRsResolver(group);
    const body = buildIssueBody(ecosystem, upgradeGroup, group, categoryMap, groupPRs);

    const issueLabels = ['security-rollup'];
    const seenIssueLabels = new Set();
    for (const plan of group.plans) {
      const al = getActionLabel(plan);
      if (!seenIssueLabels.has(al)) {
        seenIssueLabels.add(al);
        issueLabels.push(al);
      }
    }

    try {
      const existing = await findIssue(title);
      if (existing) {
        await github.rest.issues.update({ owner, repo, issue_number: existing.number, body });
        await github.rest.issues.setLabels({ owner, repo, issue_number: existing.number, labels: issueLabels }).catch(() => {});
        core.info(`Updated tracking issue #${existing.number}: ${title}`);
        createdIssues[issueKey] = { number: existing.number, url: existing.html_url, title };
      } else {
        const issue = await github.rest.issues.create({ owner, repo, title, body, labels: issueLabels });
        core.info(`Created tracking issue #${issue.data.number}: ${title}`);
        createdIssues[issueKey] = { number: issue.data.number, url: issue.data.html_url, title };
      }
    } catch (err) {
      core.warning(`Failed to create/update tracking issue for ${title}: ${err.message}`);
    }
  }

  return createdIssues;
}

const createdIssues = await createOrUpdateTrackingIssues();

const totalPlans = Object.values(output).reduce((n, g) => n + (g.plans || []).length, 0);
fs.writeFileSync('rollup-output.json', JSON.stringify({
  summary,
  stats: {
    ...summaryContext,
    total_plans: totalPlans,
    total_rollup_prs_created: 0,
    total_issues_created: Object.keys(createdIssues).length,
  },
  created_prs: {},
  created_issues: createdIssues,
  base_branch: BASE_BRANCH,
  dry_run: false,
}, null, 2));
