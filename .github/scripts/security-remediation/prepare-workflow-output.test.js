const { test } = require('node:test');
const assert = require('node:assert/strict');
const { prepareOutput } = require('./prepare-workflow-output');

test('normalizes moderate and medium in filters, alerts, and issue severity', () => {
  const raw = { plan_id: 'alias', remediation_plan_bundles: [
    { groupName: 'group-a', ecosystem: 'npm', packages: [
      { remediation_package: 'a', ecosystem: 'npm', packages: [{ vulnerabilities: [{ severity: 'medium' }] }] },
      { remediation_package: 'b', ecosystem: 'npm', packages: [{ vulnerabilities: [{ severity: 'Moderate' }, { severity: 'low' }] }] },
    ] },
    { groupName: 'group-b', ecosystem: 'npm', severity: 'moderate', packages: [
      { remediation_package: 'c', ecosystem: 'npm', packages: [{}] },
    ] },
  ] };
  for (const filter of ['moderate', 'medium', ' Medium, MODERATE ']) {
    const result = prepareOutput(raw, filter);
    assert.deepEqual(Object.keys(result.groups), ['medium']);
    assert.equal(result.groups.medium.plans.length, 3);
    assert.ok(result.groups.medium.plans.every(p => p.package.effective_severity === 'medium'));
  }
});

test('adapts ecosystem packages, chooses highest severity and routes actions', () => {
  const basePkg = (overrides = {}) => ({
    remediation_package: 'example',
    ecosystem: 'pip',
    current_version: '1.0',
    remediation_version: '1.2',
    packages: [{ vulnerabilities: [{ severity: 'low' }, { severity: 'high', ghsa_id: 'GHSA-example' }] }],
    remediation_prs: [{ pr_number: 12, version_bumps: [{ package: 'example', to_version: '1.2' }] }],
    ...overrides,
  });
  const raw = { plan_id: 'plan', remediation_plan_bundles: [{ groupName: 'default', ecosystem: 'pip', packages: [
    basePkg(),
    basePkg({ packages: [{ vulnerabilities: [{ severity: 'low' }, { severity: 'high', ghsa_id: 'GHSA-example' }], isbreakable: true }] }),
    basePkg({ remediation_prs: [] }),
    basePkg({ remediation_version: '', remediation_prs: [] }),
    basePkg({ remediation_prs: [{ pr_number: 13, version_bumps: [{ package: 'example', to_version: '1.1' }] }] }),
  ] }] };
  const plans = prepareOutput(raw).groups.high.plans;
  assert.deepEqual(plans.map(p => p.action.action_type),
    ['rollup_pr', 'standalone_pr', 'placeholder_pr', 'open_issue', 'placeholder_pr']);
  assert.equal(plans[0].action.pr_number, 12);
  assert.equal(plans[0].package.ecosystem, 'pip');
  assert.equal(plans[1].fix.fix_class, 'BREAKING_BUMP');
  assert.equal(new Set(plans.map(p => p.plan_id)).size, 5);
  assert.match(plans[2].action.placeholder_markdown, /GHSA-example/);
  assert.deepEqual(prepareOutput(raw, 'critical').groups, {});
  assert.ok(plans.every(p => p.bundle.groupName === 'default' && p.bundle.ecosystem === 'pip'));
});

test('uses the lower version as the minimum and omits the note when both versions match', () => {
  const raw = { remediation_plan_bundles: [{ groupName: 'versions', ecosystem: 'npm', packages: [
    { remediation_package: '@vue/cli-plugin-typescript', current_version: '4.5.19',
      remediation_version: '5.0.9', upgrade_to_version: '5.1.0', minimum_upgradable_version: '5.0.9',
      packages: [{ vulnerabilities: [{ severity: 'high' }] }] },
    { remediation_package: 'same-version', current_version: '1.0.0',
      remediation_version: '2.0.0', upgrade_to_version: '2.0.0',
      packages: [{ vulnerabilities: [{ severity: 'high' }] }] },
    { remediation_package: 'only-remediation-version', current_version: '1.0.0',
      remediation_version: '3.0.0',
      packages: [{ vulnerabilities: [{ severity: 'high' }] }] },
  ] }] };
  const plans = prepareOutput(raw).groups.high.plans;
  assert.match(plans[0].action.placeholder_markdown,
    /to `5\.1\.0` \[minimum version: 5\.0\.9\]/);
  assert.equal(plans[0].package.minimum_upgradable_version, '5.0.9');
  assert.match(plans[1].action.placeholder_markdown, /to `2\.0\.0` \(direct,/);
  assert.doesNotMatch(plans[1].action.placeholder_markdown, /\[minimum version:/);
  assert.match(plans[2].action.placeholder_markdown, /to `3\.0\.0` \(direct,/);
  assert.doesNotMatch(plans[2].action.placeholder_markdown, /\[minimum version:/);
});

test('marks a package transitive when any underlying PackageContext is non-root', () => {
  const raw = { plan_id: 'plan', remediation_plan_bundles: [{ groupName: 'grp', ecosystem: 'npm', packages: [
    { remediation_package: 'child', ecosystem: 'npm', current_version: '1.0', remediation_version: '1.1',
      packages: [{ relationship: 'transitive', vulnerabilities: [{ severity: 'high' }],
        transitive_dependency_occurrences: [{ package: 'child', version: '1.0', introducers: [{ package: 'parent', version: '2.0' }] }] }] },
  ] }] };
  const [plan] = prepareOutput(raw).groups.high.plans;
  assert.equal(plan.package.relationship, 'transitive');
  assert.equal(plan.package.dependency_occurrences.length, 1);
});

test('a direct package stays direct even when it also introduces an unrelated transitive vulnerability', () => {
  // Reproduces the axios scenario: axios is a direct dependency, but it also
  // introduces follow-redirects transitively. The remediation planner keys
  // the follow-redirects fix recommendation by the introducer's name
  // ("axios"), so RemeditionPackage("axios").packages ends up containing
  // BOTH axios's own (direct) PackageContext and follow-redirects's
  // (transitive) PackageContext. Only axios's own context should determine
  // axios's relationship.
  const raw = { plan_id: 'plan', remediation_plan_bundles: [{ groupName: 'grp', ecosystem: 'npm', packages: [
    { remediation_package: 'axios', ecosystem: 'npm', current_version: '0.28.0', remediation_version: '1.7.9',
      packages: [
        { name: 'axios', relationship: 'direct', vulnerabilities: [{ severity: 'high', package: 'axios' }] },
        { name: 'follow-redirects', relationship: 'transitive', vulnerabilities: [{ severity: 'high', package: 'follow-redirects' }],
          transitive_dependency_occurrences: [{ package: 'follow-redirects', version: '1.15.6',
            introducers: [{ package: 'axios', version: '0.28.0' }] }] },
      ] },
  ] }] };
  const [plan] = prepareOutput(raw).groups.high.plans;
  assert.equal(plan.package.relationship, 'direct');
});

test('accepts empty plans and rejects missing output or invalid severity', () => {
  assert.deepEqual(prepareOutput({ remediation_plan_bundles: [] }),
    { groups: {}, vulnerabilities_summary: { critical: 0, high: 0, medium: 0, low: 0, others: 0 } });
  assert.throws(() => prepareOutput(null), /RemediationPlan/);
  assert.throws(() => prepareOutput({ remediation_plan_bundles: [] }, 'invalid'), /Invalid severity/);
});

test('surfaces the orchestrator vulnerabilities_summary instead of re-deriving counts from plan arrays', () => {
  // The orchestrator's SecurityRemediationContext.vulnerabilities_summary
  // tallies each unique Dependabot alert exactly once. It must be passed
  // through as-is rather than recomputed by summing plan.package.vulnerabilities,
  // which can double-count alerts that appear on multiple PackageContext
  // entries for the same package (e.g. multiple lockfile locations).
  const raw = {
    plan_id: 'plan',
    remediation_plan_bundles: [],
    summary: { vulnerabilities_summary: { critical: 358, high: 120, medium: 0, low: 0, others: 3 } },
  };
  const result = prepareOutput(raw);
  assert.deepEqual(result.vulnerabilities_summary, { critical: 358, high: 120, medium: 0, low: 0, others: 3 });
});
