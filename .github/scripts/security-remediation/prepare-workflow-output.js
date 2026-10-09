// Adapt the orchestrator's RemediationPlan to the workflow presentation model.
const fs = require('fs');
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

function normalizeSeverity(value) {
  const severity = value?.trim().toLowerCase();
  return severity === 'moderate' ? 'medium' : severity;
}

// A RemeditionPackage is direct when none of its OWN PackageContext entries
// (i.e. those describing this exact package, not a transitive child it
// happens to introduce/fix) are marked transitive. RemeditionPackage.packages
// can contain PackageContext entries for other vulnerable packages this
// package introduces as a parent - those must not affect this package's own
// direct/transitive classification.
function ownPackageContexts(remediationPackage) {
  const name = (remediationPackage.remediation_package || '').toLowerCase();
  const own = (remediationPackage.packages || []).filter(pkg => (pkg.name || '').toLowerCase() === name);
  return own.length ? own : (remediationPackage.packages || []);
}

function isTransitivePackage(remediationPackage) {
  return ownPackageContexts(remediationPackage).some(pkg => (pkg.relationship || '').toLowerCase() === 'transitive'
    || pkg.is_direct === false);
}

// A bundle package is breakable if any of its OWN PackageContext entries say so.
function isBreakablePackage(remediationPackage) {
  return ownPackageContexts(remediationPackage).some(pkg => pkg.isbreakable === true);
}

function compareVersions(left, right) {
  const leftParts = left.replace(/^[vV]/, '').split(/[.+-]/).map(part => /^\d+$/.test(part) ? Number(part) : part);
  const rightParts = right.replace(/^[vV]/, '').split(/[.+-]/).map(part => /^\d+$/.test(part) ? Number(part) : part);
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

function prepareOutput(raw, severities = 'critical,high,medium,low') {
  if (!raw || !Array.isArray(raw.remediation_plan_bundles)) {
    throw new Error('Expected orchestrator RemediationPlan.remediation_plan_bundles array');
  }
  const selected = new Set(severities.split(',').map(normalizeSeverity));
  for (const severity of selected) {
    if (!SEVERITIES.includes(severity)) throw new Error(`Invalid severity: ${severity}`);
  }
  const groups = {};
  for (const [bundleIndex, bundle] of raw.remediation_plan_bundles.entries()) {
    const bundleEcosystem = bundle.ecosystem || 'unknown';
    for (const [packageIndex, pkg] of (bundle.packages || []).entries()) {
      const vulnerabilities = (pkg.packages || []).flatMap(p => p.vulnerabilities || []);
      const severity = SEVERITIES.find(s => vulnerabilities.some(v => normalizeSeverity(v.severity) === s))
        || normalizeSeverity(bundle.severity) || 'unknown';
      if (!selected.has(severity)) continue;
      const name = pkg.remediation_package;
      const ecosystem = pkg.ecosystem || bundleEcosystem;
      const remediationVersion = pkg.remediation_version || '';
      const upgradeToVersion = pkg.upgrade_to_version || '';
      const minimumUpgradableVersion = pkg.minimum_upgradable_version || '';
      const versions = [remediationVersion, upgradeToVersion].filter(Boolean);
      versions.sort(compareVersions);
      const target = versions.at(-1) || '';
      const minimumVersion = minimumUpgradableVersion || versions[0] || '';
      const hasDistinctMinimum = minimumVersion && target
        && compareVersions(minimumVersion, target) !== 0;
      const isbreakable = isBreakablePackage(pkg);
      const relationship = isTransitivePackage(pkg) ? 'transitive' : 'direct';
      // Only reuse a PR whose package and target match the planned upgrade.
      const pr = target && (pkg.remediation_prs || []).find(p => p.pr_number &&
        (p.version_bumps || []).some(b => b.package.toLowerCase() === name.toLowerCase() && b.to_version === target));
      const action = bundle.action_type || (target
        ? (pr ? (isbreakable ? 'standalone_pr' : 'rollup_pr') : 'placeholder_pr')
        : 'open_issue');
      const actionType = ['rollup_pr', 'standalone_pr'].includes(action) && !pr ? 'placeholder_pr' : action;
      const advisories = [...new Set(vulnerabilities.map(v => v.ghsa_id).filter(Boolean))];
      const dependencyOccurrences = (pkg.packages || []).flatMap(p => p.transitive_dependency_occurrences || []);
      const minimumVersionNote = hasDistinctMinimum
        ? ` [minimum version: ${minimumVersion}]`
        : '';
      const markdown = `### ${name} (${ecosystem})\n\n` +
        `- [ ] **AC:** Upgrade \`${name}\` from \`${pkg.current_version || 'unknown'}\` to \`${target || 'no known fix'}\`${minimumVersionNote} ` +
        `(${relationship}, ${isbreakable ? 'breaking' : 'non-breaking'}). Resolve ${advisories.join(', ') || 'the reported vulnerabilities'} and run the project tests.\n`;
      const plan = {
        plan_id: `${raw.plan_id || 'plan'}-${bundleIndex}-${packageIndex}`,
        package: {
          name,
          ecosystem,
          relationship,
          current_version: pkg.current_version,
          current_version_range: pkg.current_version || 'unknown',
          minimum_upgradable_version: minimumVersion,
          vulnerabilities,
          pull_requests: pkg.remediation_prs || [],
          dependency_occurrences: dependencyOccurrences,
          effective_severity: severity,
          unique_ghsas: advisories,
          isbreakable,
        },
        fix: { fix_class: isbreakable ? 'BREAKING_BUMP' : (target ? 'NON_BREAKING_BUMP' : 'NO_FIX_AVAILABLE'), upgrade_version: target },
        action: { action_type: actionType, pr_number: pr?.pr_number || null,
          pull_url: pr?.pull_url || '', target_package: name, placeholder_markdown: markdown },
        state: {},
        // Bundle metadata so create-issues.js can create one tracking
        // issue per package bundle (grouped by bundle.groupName) instead
        // of by ecosystem/impact heuristics.
        bundle: { groupName: bundle.groupName || 'default', ecosystem: bundleEcosystem, severity: bundle.severity || null },
      };
      (groups[severity] ||= { plans: [] }).plans.push(plan);
    }
  }
  // Authoritative severity counts come from the orchestrator's
  // SecurityRemediationContext.vulnerabilities_summary (RemediationPlan.summary),
  // which tallies each unique Dependabot alert exactly once. Re-deriving
  // counts from plan.package.vulnerabilities double-counts alerts that
  // appear on multiple PackageContext entries (e.g. a package resolved at
  // several lockfile locations), so callers should prefer this field for
  // the "Vulnerability Categories" table instead of summing per-plan arrays.
  const summaryCounts = raw.summary?.vulnerabilities_summary || {};
  const vulnerabilities_summary = {
    critical: summaryCounts.critical || 0,
    high: summaryCounts.high || 0,
    medium: summaryCounts.medium || 0,
    low: summaryCounts.low || 0,
    others: summaryCounts.others || 0,
  };
  return { groups, vulnerabilities_summary };
}

if (require.main === module) {
  const raw = JSON.parse(fs.readFileSync('orchestrator-output.json', 'utf8'));
  fs.writeFileSync('workflow-plans.json', JSON.stringify(prepareOutput(raw, process.env.SEVERITIES), null, 2));
}
module.exports = { prepareOutput };
