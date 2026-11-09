// Upgrade options table for packages needing an upgrade, with collapsed column definitions.


const COLUMN_DETAILS = [
  ['Package', 'Package requiring an upgrade (a direct dependency, or the parent of a vulnerable transitive dependency)'],
  ['Current', 'Currently declared or resolved version'],
  ['Minimum Fix', 'Lowest candidate expected to address the vulnerability'],
  ['Compatible Version', 'Highest version satisfying the existing version/compatibility policy, whether patched or not'],
  ['Verified Version', 'Version that passed dependency resolution during verification; blank when not verified'],
  ['Latest Available', 'Newest published stable version, regardless of compatibility'],
  ['Is Optional Update', 'Yes when this is an optional non-vulnerable update rather than a vulnerability fix; blank otherwise'],
  ['Verification Status', 'SUCCESS, FAILED (candidates conflicted) or NOT VERIFIED (no candidate or the runner could not verify, e.g. missing tool or timeout); details are listed under the table'],
];

const cell = value => (value ? `\`${value}\`` : '—');
const escapeAttribute = text => String(text).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
  .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r?\n/g, '&#10;');

function verificationCell(target) {
  if (!target.verification_status) return '—';
  if (target.verification_status === 'SUCCESS' || !target.verification_notes) return target.verification_status;
  return `<abbr title="${escapeAttribute(target.verification_notes)}">${target.verification_status}</abbr>`;
}

function row(target) {
  return `| \`${target.package}\` | ${cell(target.current_version)} | ${cell(target.minimum_fixed_version)} ` +
    `| ${cell(target.compatible_version)} | ${cell(target.verified_version)} | ${cell(target.latest_available || target.highest_fixed_version)} ` +
    `| ${target.is_update ? 'Yes' : ''} | ${verificationCell(target)} |`;
}

function failureNotes(targets) {
  const failed = targets.filter(target => ['FAILED', 'NOT VERIFIED'].includes(target.verification_status));
  if (failed.length === 0) return '';
  const lines = failed.map(target => {
    const notes = (target.verification_notes || '').split('\n').filter(Boolean).join('; ');
    return `- \`${target.package}\` (${target.verification_status}): ${notes || 'no details were captured.'}`;
  });
  return `**Verification notes**\n\n${lines.join('\n')}\n\n`;
}

function buildUpgradeOptionsSection(plans, bundleTargets) {
  if (!Array.isArray(bundleTargets)) return '';
  const selectedPackages = new Set(plans.map(plan => plan.package.name.toLowerCase()));
  // Same selection as the acceptance criteria, so parent upgrades for transitive findings are included.
  const targets = bundleTargets.filter(target => (target.affected_packages || [])
    .some(name => selectedPackages.has(name.toLowerCase())));
  if (targets.length === 0) return '';

  return '## Dependency Compatibility Analysis\n\n' +
    'The following upgrade options are identified for each package that needs an upgrade (direct dependencies and parents of transitive ones). ' +
    'Recommendations prioritize the minimum version that resolves the identified vulnerabilities and passes dependency compatibility validation.\n\n' +
    '| Package | Current | Minimum Fix | Compatible Version | Verified Version | Latest Available | Is Optional Update | Verification Status |\n' +
    '|---|---|---|---|---|---|---|---|\n' +
    `${targets.map(row).join('\n')}\n\n` +
    failureNotes(targets) +
    '<details>\n<summary>Column reference</summary>\n\n' +
    '| Column | Meaning |\n|---|---|\n' +
    `${COLUMN_DETAILS.map(([name, meaning]) => `| ${name} | ${meaning} |`).join('\n')}\n\n</details>\n\n`;
}

module.exports = { buildUpgradeOptionsSection };
