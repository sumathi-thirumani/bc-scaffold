const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'create-issues.js'), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

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
  let output;
  const existingTitle = '[Security Remediation] [npm] [Major(axios)]';
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [
      { title: existingTitle, number: 42, html_url: 'https://example.test/42' },
    ] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}), addLabels: async () => ({}),
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
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
  );

  assert.equal(updated.length, 1);
  assert.equal(updated[0].issue_number, 42);
  assert.equal(created.length, 4);
  assert.equal(output.stats.total_issues_created, 5);
  assert.equal(Object.keys(output.created_issues).length, 5);
  assert.equal(output.stats.total_rollup_prs_created, 0);
  assert.deepEqual(output.created_prs, {});

  const minor = created.find(i => i.title === '[Security Remediation] [npm] [Minor-Patch]');
  assert.ok(minor);
  assert.match(minor.body, /## Summary\n/);
  assert.doesNotMatch(minor.body, /Open security alerts|Open code scanning alerts/);
  assert.match(minor.body, /`postcss`/);
  assert.match(minor.body, /`nanoid`/);
  assert.doesNotMatch(minor.body, /### `(?:axios|vite|cryptography)`/);
  assert.match(minor.body, /\[#10\]\(https:\/\/example\.test\/10\)/);
  assert.match(minor.body, /## Reconciliation Notes\n\n    Manifest: package\.json/);
  assert.doesNotMatch(minor.body, /DotnetSecurityFailures/);
  assert.ok(minor.body.indexOf('## Reconciliation Notes') >
    minor.body.indexOf('## Remediation Pull Requests'));

  const pipIssue = created.find(i => i.title.includes('[pip]'));
  assert.ok(pipIssue.body.includes('Transitive dependency **starlette 0.50.0** is introduced via'));
  assert.ok(pipIssue.body.includes('- fastapi 0.125.0 → starlette 0.50.0'));
  assert.ok(pipIssue.body.includes('- fastapi-sqlalchemy 0.2.1 → starlette 0.50.0'));
  assert.match(pipIssue.body, /\[#20\]\(https:\/\/example\.test\/20\)/);
  assert.doesNotMatch(pipIssue.body, /## Reconciliation Notes/);

  const nugetIssue = created.find(i => i.title.includes('[nuget]'));
  assert.doesNotMatch(nugetIssue.body, /## Reconciliation Notes|DotnetSecurityFailures/);

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
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
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

test('Summary section is renamed and shows a severity count table (critical/high/medium/low)', async () => {
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
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
  );

  const body = created[0].body;
  assert.match(body, /## Summary\n/);
  assert.doesNotMatch(body, /## Repository Summary/);
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
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
  );

  const body = created[0].body;
  assert.match(body, /Upgrade `sass` from `1\.0\.0` to `1\.105\.1` \[minimum version: 1\.99\.0\]/);
  assert.match(body, /Upgrade `bootstrap-vue` from `1\.0\.0` to `2\.23\.1`/);
  assert.doesNotMatch(body, /minimum version: 2\.23\.1/);
  assert.match(body, /Upgrade `@vue\/cli-plugin-typescript` from `1\.0\.0` to `5\.0\.9` \[upgrade candidate: 5\.1\.0\]/);
});
