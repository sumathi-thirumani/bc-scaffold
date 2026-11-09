// Per-package vulnerability overview table.

const { SEVERITY_BUCKETS, buildAlerts, severityBucketOf } = require('./alerts');
const { isTransitivePlan } = require('./plan-helpers');

function severityLabel(alerts) {
  const severity = SEVERITY_BUCKETS.find(bucket => alerts.some(alert => severityBucketOf(alert) === bucket));
  if (alerts.some(alert => alert.severity) && severity) return severity;
  const cvssValues = alerts.map(a => a.cvss).filter(v => v != null);
  if (cvssValues.length === 0) return '—';
  const maxCvss = Math.max(...cvssValues);
  const bucket = maxCvss >= 9 ? 'Critical' : maxCvss >= 7 ? 'High' : maxCvss >= 4 ? 'Medium' : 'Low';
  return `${bucket} (${maxCvss})`;
}

// Parent (introducer) packages for a specific vulnerable package, scoped to
// only the occurrences whose `package` matches it.
function parentPackagesOf(plan, packageName) {
  const occurrences = (plan.package.dependency_occurrences || []).filter(occ =>
    !packageName || (occ.package || '').toLowerCase() === packageName.toLowerCase());
  const introducerNames = [...new Set(occurrences.flatMap(occ => (occ.introducers || []).map(i => i.package)))];
  return introducerNames.length ? introducerNames.join(', ') : '—';
}

// Vulnerable package name(s) as reported by the alerts (not the bundle's
// upgrade-target name), deduplicated case-insensitively.
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

// Splits a plan's alerts by vulnerable package so each gets its own row.
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

function buildPackageSummarySection(ecosystem, plans) {
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

module.exports = { buildPackageSummarySection };
