// Creates/updates GitHub tracking issues for security remediation plans.
// This script does not create PRs; it only reads already-matched PR/issue
// references from workflow-plans.json
// and builds one tracking issue per (ecosystem, upgrade-group) bucket.
// Issue body sections live in ./issue-template (located via ISSUE_TEMPLATE_DIR).

const fs = require('fs');
const { buildIssueBody, getCategory, getImpact, isTransitivePlan } = require(process.env.ISSUE_TEMPLATE_DIR);
const { owner, repo } = context.repo;
core.info(`Operating on caller repository: ${owner}/${repo}`);

// ── Inputs ───────────────────────────────────────────────────────────────────

const raw = JSON.parse(fs.readFileSync('workflow-plans.json', 'utf8'));
const output = raw.groups || raw;
const remediationPlan = JSON.parse(fs.readFileSync('orchestrator-output.json', 'utf8'));
const summary = remediationPlan.summary || {};
const summaryContext = summary.context || summary;
const BASE_BRANCH = process.env.BASE_BRANCH;
const RUN_URL = `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;

const SECURITY_REMEDIATION_LABEL = 'Security Remediation';

// ── Grouping helpers ─────────────────────────────────────────────────────────

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

  return normalizeGroupingName(plan.package.name);
}

// ── GitHub helpers ───────────────────────────────────────────────────────────

async function ensureSecurityRemediationLabel() {
  const name = SECURITY_REMEDIATION_LABEL;
  try {
    await github.rest.issues.getLabel({ owner, repo, name });
  } catch (error) {
    if (error.status !== 404) throw error;
    await github.rest.issues.createLabel({
      owner, repo, name, color: 'e11d48', description: 'Security vulnerability remediation',
    });
    core.info(`Created label: ${name}`);
  }
}

async function findIssue(title) {
  const q = `repo:${owner}/${repo} is:issue is:open in:title "${title}"`;
  const res = await github.rest.search.issuesAndPullRequests({ q, per_page: 10 });
  return res.data.items.find(i => i.title === title) || null;
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
  await ensureSecurityRemediationLabel();

  const categoryMap = buildCategoryMap();
  const issueGroups = buildIssueGroups();
  const createdIssues = {};

  for (const [issueKey, group] of issueGroups) {
    const { ecosystem, upgradeGroup } = group;
    const title = `[Security Remediation] [${ecosystem}] [${upgradeGroup}]`;
    const groupPRs = makeGroupPRsResolver(group);
    const body = buildIssueBody({
      ecosystem,
      upgradeGroup,
      group,
      categoryMap,
      groupPRs,
      baseBranch: BASE_BRANCH,
      run: { id: context.runId, url: RUN_URL },
      remediationPlan,
    });

    const issueLabels = [SECURITY_REMEDIATION_LABEL];

    try {
      const existing = await findIssue(title);
      if (existing) {
        await github.rest.issues.update({ owner, repo, issue_number: existing.number, body });
        await github.rest.issues.setLabels({ owner, repo, issue_number: existing.number, labels: issueLabels });
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
