// Vulnerability alert helpers shared by issue sections.

const SEVERITY_BUCKETS = ['Critical', 'High', 'Medium', 'Low'];

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

// Buckets an alert by its severity, falling back to CVSS thresholds.
function severityBucketOf(alert) {
  const severity = (alert.severity || '').toLowerCase();
  const normalized = severity === 'moderate' ? 'medium' : severity;
  const bucket = SEVERITY_BUCKETS.find(value => value.toLowerCase() === normalized);
  if (bucket) return bucket;
  const cvss = alert.cvss;
  if (cvss == null) return null;
  return cvss >= 9 ? 'Critical' : cvss >= 7 ? 'High' : cvss >= 4 ? 'Medium' : 'Low';
}

module.exports = { SEVERITY_BUCKETS, buildAlerts, vulnerabilityTableRows, severityBucketOf };
