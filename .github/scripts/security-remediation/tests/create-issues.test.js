const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const scriptsDir = path.join(__dirname, '..');
const issueTemplateDir = path.join(scriptsDir, 'issue-template');
const source = fs.readFileSync(path.join(scriptsDir, 'create-issues.js'), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

test('current triage output produces verified parent criteria, unresolved tracking, and flat totals', async () => {
  const { prepareOutput } = require('../prepare-workflow-output');
  const remediationPlan = {
    summary: { total_vulnerabilities: 3, total_reviewed_prs: 5 },
    remediation_plan_bundles: [{ ecosystem: 'npm', groupName: 'current', packages: [
      { package: 'child', istransitive: true,
        vulnerabilities: [{ package: 'child', severity: 'high', cvss: 0, ghsa_id: 'GHSA-child' }],
        package_upgrade_recommendations: [{ package: 'parent', from_version: '1.0.0',
          minimum_patched_version: '1.1.0', highest_stable_version: '3.0.0' }],
        compatible_versions: { parent: '1.5.0' }, verified_versions: { parent: '2.0.0' } },
      { package: 'unverified', vulnerabilities: [{ severity: 'moderate', cvss: 0 }],
        package_upgrade_recommendations: [{ package: 'unverified', highest_stable_version: '9.0.0' }] },
      { package: 'unresolved', vulnerabilities: [{ severity: 'high', cvss: 0 }] },
      { package: 'minimatch', current_version: '3.0.4', vulnerablility_fixed_version: '3.1.2',
        vulnerabilities: [{ severity: 'high', cvss: 0 }] },
      { package: 'candidate', current_version: '1.0.0', vulnerabilities: [{ severity: 'high', cvss: 0 }],
        package_upgrade_recommendations: [{ package: 'candidate', from_version: '1.0.0',
          minimum_patched_version: '1.1.0', highest_stable_version: '2.0.0' }],
        compatible_versions: { candidate: '1.2.0' } },
      { package: 'fast-uri', vulnerabilities: [{ severity: 'high', cvss: 0 }],
        package_upgrade_recommendations: [{ package: 'orval', minimum_patched_version: '99.0.0' }] },
      { package: 'undici', vulnerabilities: [{ severity: 'high', cvss: 0 }],
        package_upgrade_recommendations: [{ package: 'orval', minimum_patched_version: '100.0.0' }] },
    ] }],
  };
  remediationPlan.remediation_plan_bundles[0].upgrade_targets = [
    { package: 'parent', current_version: '1.0.0', minimum_fixed_version: '1.1.0',
      compatible_version: '1.5.0', highest_fixed_version: '3.0.0', affected_packages: ['child'] },
    { package: 'minimatch', current_version: '3.0.4', minimum_fixed_version: '3.1.2', affected_packages: ['minimatch'] },
    { package: 'candidate', current_version: '1.0.0', minimum_fixed_version: '1.1.0',
      compatible_version: '1.2.0', highest_fixed_version: '2.0.0', affected_packages: ['candidate'] },
    { package: 'orval', affected_packages: ['unverified'] },
    { package: 'unresolved', affected_packages: ['unresolved'] },
    { package: 'orval', current_version: '7.0.0', minimum_fixed_version: '7.2.0',
      compatible_version: '7.2.0', highest_fixed_version: '8.0.0', affected_packages: ['fast-uri', 'undici'] },
  ];
  const raw = prepareOutput(remediationPlan);
  const created = [];
  let output;
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [] } }) },
    issues: {
      getLabel: async () => ({}),
      create: async args => { created.push(args); return { data: { number: 1, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => (name === 'fs' ? fakeFs : require(name)), { env: { BASE_BRANCH: 'main', ISSUE_TEMPLATE_DIR: issueTemplateDir } }, console,
  );
  assert.equal(created.length, 1);
  const body = created[0].body;
  assert.doesNotMatch(body, /and run the project tests/);
  assert.match(body, /Upgrade `parent` from `1\.0\.0` to `1\.1\.0` \[compatible: `1\.5\.0`, highest fixed: `3\.0\.0`\]\./);
  assert.match(body, /Upgrade `minimatch` from `3\.0\.4` to `3\.1\.2` \[compatible: `unknown`, highest fixed: `unknown`\]/);
  assert.match(body, /Upgrade `candidate` from `1\.0\.0` to `1\.1\.0` \[compatible: `1\.2\.0`, highest fixed: `2\.0\.0`\]/);
  assert.doesNotMatch(body, /Investigate remediation for `minimatch`/);
  assert.doesNotMatch(body, /Review and validate an upgrade/);
  assert.equal((body.match(/- \[ \] Upgrade `orval`/g) || []).length, 1);
  assert.match(body, /Upgrade `orval` from `7\.0\.0` to `7\.2\.0` \[compatible: `7\.2\.0`, highest fixed: `8\.0\.0`\]\.\n/);
  const acceptanceCriteria = body.split('## Acceptance Criteria\n')[1].split('\n## ')[0];
  assert.doesNotMatch(acceptanceCriteria, /to resolve/);
  assert.doesNotMatch(body, /to `99\.0\.0`|to `100\.0\.0`/);
  assert.doesNotMatch(body, /9\.0\.0|Stub branch creation failed|Upgrade `child`/);
  assert.match(body, /\| 0 \| 6 \| 1 \| 0 \|/);
  assert.match(body, /\| High \| Transitive \|/);
  assert.equal(output.stats.total_reviewed_prs, 5);
  assert.equal(output.stats.total_vulnerabilities, 3);
});

test('tracking issues group by ecosystem and major package or minor-patch, across severities', async () => {
  const plan = (name, ecosystem, major = false) => ({
    package: { name, ecosystem, effective_severity: 'medium', unique_ghsas: [], current_version_range: '1.0.0' },
    fix: { fix_class: major ? 'BREAKING_BUMP' : 'NON_BREAKING_BUMP' },
    action: { action_type: 'open_issue' }, state: {},
  });
  const raw = { groups: {
    medium: { plans: [plan('axios', 'npm', true), plan('vite', 'npm', true),
      plan('postcss', 'npm'), plan('nanoid', 'npm'), plan('cryptography', 'pip')] },
    high: { plans: [plan('postcss', 'npm')] },
  } };
  raw.groups.high.plans[0].package.effective_severity = 'high';
  const starlette = plan('starlette', 'pip');
  starlette.package.relationship = 'transitive';
  starlette.package.dependency_occurrences = [{ package: 'starlette', version: '0.50.0',
    introducers: [{ package: 'fastapi', version: '0.125.0' },
      { package: 'fastapi-sqlalchemy', version: '0.2.1' }] }];
  raw.groups.medium.plans.push(starlette);
  raw.groups.medium.plans.push(plan('System.Linq.Dynamic.Core', 'nuget'));
  // Pre-existing PRs matched upstream (not created by this script).
  raw.groups.medium.plans[2].action = { action_type: 'rollup_pr', pr_number: 10, pull_url: 'https://example.test/10' };
  raw.groups.high.plans[0].action = { action_type: 'rollup_pr', pr_number: 11, pull_url: 'https://example.test/11' };
  raw.groups.medium.plans[4].action = { action_type: 'rollup_pr', pr_number: 20, pull_url: 'https://example.test/20' };

  const remediationPlan = {
    reconciliation_info: [
      { ecosystem: 'npm', reconciliation_notes: 'Manifest: package.json\nExit code: 0\naxios 1.0.0 → 2.0.0' },
      { ecosystem: 'nuget', reconciliation_notes: 'DotnetSecurityFailures/App.csproj: candidate 1.9.0' },
    ],
    summary: { context: {
      total_vulnerabilities: 61, total_code_scanning_alerts: 3,
      total_reviewed_prs: 9, total_ignored_prs: 8, total_remediation_prs: 1,
    }, ecosystem_summary: [] },
  };

  const created = [];
  const updated = [];
  const labelUpdates = [];
  const checkedLabels = [];
  const createdLabels = [];
  let output;
  const existingTitle = '[Security Remediation] [npm] [Major(axios)]';
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [
      { title: existingTitle, number: 42, html_url: 'https://example.test/42' },
    ] } }) },
    issues: {
      getLabel: async args => { checkedLabels.push(args.name); throw { status: 404 }; },
      createLabel: async args => { createdLabels.push(args.name); },
      setLabels: async args => { labelUpdates.push(args.labels); },
      update: async args => { updated.push(args); },
      create: async args => { created.push(args); return { data: { number: created.length, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    existsSync: () => true,
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => (name === 'fs' ? fakeFs : require(name)), { env: { BASE_BRANCH: 'main', ISSUE_TEMPLATE_DIR: issueTemplateDir } }, console,
  );

  assert.deepEqual(checkedLabels, ['Security Remediation']);
  assert.deepEqual(createdLabels, ['Security Remediation']);
  assert.deepEqual(labelUpdates, [['Security Remediation']]);
  assert.ok(created.every(issue => JSON.stringify(issue.labels) === JSON.stringify(['Security Remediation'])));
  assert.equal(updated.length, 1);
  assert.equal(updated[0].issue_number, 42);
  assert.equal(created.length, 4);
  assert.equal(output.stats.total_issues_created, 5);
  assert.equal(Object.keys(output.created_issues).length, 5);
  assert.equal(output.stats.total_rollup_prs_created, 0);
  assert.deepEqual(output.created_prs, {});

  const minor = created.find(i => i.title === '[Security Remediation] [npm] [Minor-Patch]');
  assert.ok(minor);
  assert.match(minor.body, /<details>\n<summary>Summary<\/summary>\n/);
  assert.doesNotMatch(minor.body, /Open security alerts|Open code scanning alerts/);
  assert.match(minor.body, /`postcss`/);
  assert.match(minor.body, /`nanoid`/);
  assert.doesNotMatch(minor.body, /### `(?:axios|vite|cryptography)`/);
  assert.match(minor.body, /\[#10\]\(https:\/\/example\.test\/10\)/);
  assert.match(minor.body, /<details>\n<summary>Reconciliation Notes<\/summary>\n\n    Manifest: package\.json/);
  assert.doesNotMatch(minor.body, /DotnetSecurityFailures/);
  assert.match(minor.body, /<summary>Reconciliation Notes<\/summary>[\s\S]*axios 1\.0\.0 \u2192 2\.0\.0[\s\S]*?<\/details>/);
  assert.match(minor.body, /<details>\n<summary>Recommended Merge Order<\/summary>\n\nValidate updates before merging;[^\n]+\n\n<\/details>/);
  assert.doesNotMatch(minor.body, /<details open|## Recommended Merge Order|## Reconciliation Notes/);
  assert.ok(minor.body.indexOf('<summary>Reconciliation Notes</summary>') >
    minor.body.indexOf('## Remediation Pull Requests'));

  const pipIssue = created.find(i => i.title.includes('[pip]'));
  assert.ok(pipIssue.body.includes('Transitive dependency **starlette 0.50.0** is introduced via'));
  assert.ok(pipIssue.body.includes('- fastapi 0.125.0 → starlette 0.50.0'));
  assert.ok(pipIssue.body.includes('- fastapi-sqlalchemy 0.2.1 → starlette 0.50.0'));
  assert.match(pipIssue.body, /\[#20\]\(https:\/\/example\.test\/20\)/);
  assert.doesNotMatch(pipIssue.body, /<summary>Reconciliation Notes<\/summary>/);

  const nugetIssue = created.find(i => i.title.includes('[nuget]'));
  assert.doesNotMatch(nugetIssue.body, /<summary>Reconciliation Notes<\/summary>|DotnetSecurityFailures/);

  assert.deepEqual(output.summary, remediationPlan.summary);
  assert.equal(output.stats.total_reviewed_prs, 9);
  assert.doesNotMatch(updated[0].body, /vite|postcss|nanoid|cryptography/);
});

test('creates one tracking issue per package bundle when bundle metadata is present', async () => {
  const planWithBundle = (name, ecosystem, groupName) => ({
    package: { name, ecosystem, effective_severity: 'medium', unique_ghsas: [], current_version_range: '1.0.0' },
    fix: { fix_class: 'NON_BREAKING_BUMP' },
    action: { action_type: 'open_issue' }, state: {},
    bundle: { groupName, ecosystem, severity: 'medium' },
  });
  const raw = { groups: {
    medium: { plans: [
      planWithBundle('underscore', 'npm', 'default'),
      planWithBundle('moment-timezone', 'npm', 'default'),
      planWithBundle('node-sass', 'npm', 'css-tools'),
    ] },
  } };

  const remediationPlan = { summary: { context: {
    total_vulnerabilities: 3, total_code_scanning_alerts: 0,
    total_reviewed_prs: 0, total_ignored_prs: 0, total_remediation_prs: 0,
  } } };

  const created = [];
  let output;
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}), addLabels: async () => ({}),
      update: async () => {},
      create: async args => { created.push(args); return { data: { number: created.length, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    existsSync: () => true,
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => (name === 'fs' ? fakeFs : require(name)), { env: { BASE_BRANCH: 'main', ISSUE_TEMPLATE_DIR: issueTemplateDir } }, console,
  );

  assert.equal(created.length, 2);
  const defaultIssue = created.find(i => i.title === '[Security Remediation] [npm] [default]');
  const cssToolsIssue = created.find(i => i.title === '[Security Remediation] [npm] [css-tools]');
  assert.ok(defaultIssue);
  assert.ok(cssToolsIssue);
  assert.match(defaultIssue.body, /`underscore`/);
  assert.match(defaultIssue.body, /`moment-timezone`/);
  assert.doesNotMatch(defaultIssue.body, /node-sass/);
  assert.match(cssToolsIssue.body, /`node-sass`/);
  assert.equal(output.stats.total_issues_created, 2);
});

test('Summary section is collapsed and preserves severity counts', async () => {
  const alert = (cvss, ghsaSuffix) => ({
    ghsa_id: `GHSA-${ghsaSuffix}`, cve_id: null, url: `https://github.com/advisories/GHSA-${ghsaSuffix}`,
    summary: 'test vuln', cvss, vulnerable_range: '<1.0.0', first_patched: '1.0.0',
  });
  const plan = {
    package: {
      name: 'lodash', ecosystem: 'npm', effective_severity: 'critical',
      unique_ghsas: [], current_version_range: '1.0.0',
      vulnerabilities: [
        alert(9.8, 'aaaa-1111-1111'), // Critical
        alert(7.5, 'bbbb-2222-2222'), // High
        alert(7.2, 'cccc-3333-3333'), // High
        alert(4.0, 'dddd-4444-4444'), // Medium
        alert(2.0, 'eeee-5555-5555'), // Low
      ],
    },
    fix: { fix_class: 'NON_BREAKING_BUMP' },
    action: { action_type: 'open_issue' }, state: {},
  };
  const raw = { groups: { critical: { plans: [plan] } } };
  const remediationPlan = { summary: { context: {
    total_vulnerabilities: 5, total_code_scanning_alerts: 0,
    total_reviewed_prs: 0, total_ignored_prs: 0, total_remediation_prs: 0,
  } } };
  const created = [];
  let output;
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}), addLabels: async () => ({}),
      update: async () => {},
      create: async args => { created.push(args); return { data: { number: created.length, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    existsSync: () => true,
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => (name === 'fs' ? fakeFs : require(name)), { env: { BASE_BRANCH: 'main', ISSUE_TEMPLATE_DIR: issueTemplateDir } }, console,
  );

  const body = created[0].body;
  assert.match(body, /<details>\n<summary>Summary<\/summary>\n/);
  assert.doesNotMatch(body, /## Repository Summary|## Summary|<details open/);
  assert.match(body, /<summary>Summary<\/summary>\n\n\| Critical \| High \| Medium \| Low \|\n[^\n]+\n\| 1 \| 2 \| 1 \| 1 \|\n\n<\/details>/);
  assert.match(body, /\| Critical \| High \| Medium \| Low \|/);
  assert.match(body, /\| 1 \| 2 \| 1 \| 1 \|/);
});

test('AC labels higher minimum as upgrade candidate and omits matching minimum', async () => {
  const plan = (name, minimumVersion, targetVersion) => ({
    package: {
      name, ecosystem: 'npm', effective_severity: 'high',
      unique_ghsas: [], current_version: '1.0.0', current_version_range: '1.0.0',
      vulnerabilities: [{ ghsa_id: `GHSA-${name}`, summary: 'test vulnerability', cvss: 7.5 }],
      minimum_upgradable_version: minimumVersion,
    },
    fix: { upgrade_version: targetVersion, fix_class: 'NON_BREAKING_BUMP' },
    action: { action_type: 'open_issue' },
    state: {},
  });
  const raw = { groups: { high: { plans: [
    plan('sass', '1.99.0', '1.105.1'),
    plan('bootstrap-vue', '2.23.1', '2.23.1'),
    plan('@vue/cli-plugin-typescript', '5.1.0', '5.0.9'),
  ] } } };
  const remediationPlan = { summary: { context: {} } };
  const created = [];
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}), addLabels: async () => ({}),
      update: async () => {},
      create: async args => { created.push(args); return { data: { number: 1, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    existsSync: () => true,
    writeFileSync: () => {},
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => (name === 'fs' ? fakeFs : require(name)), { env: { BASE_BRANCH: 'main', ISSUE_TEMPLATE_DIR: issueTemplateDir } }, console,
  );

  const body = created[0].body;
  assert.match(body, /Upgrade `sass` from `1\.0\.0` to `1\.105\.1` \[minimum version: 1\.99\.0\]/);
  assert.match(body, /Upgrade `bootstrap-vue` from `1\.0\.0` to `2\.23\.1`/);
  assert.doesNotMatch(body, /minimum version: 2\.23\.1/);
  assert.match(body, /Upgrade `@vue\/cli-plugin-typescript` from `1\.0\.0` to `5\.0\.9` \[upgrade candidate: 5\.1\.0\]/);
});
