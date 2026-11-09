// Upgrade options table for packages needing an upgrade, with collapsed column definitions.


const COLUMN_DETAILS = [
  ['Package', 'Package requiring an upgrade (a direct dependency, or the parent of a vulnerable transitive dependency)'],
  ['Current', 'Currently declared or resolved version'],
  ['Minimum Fix', 'Lowest candidate expected to address the vulnerability'],
  ['Compatible Upgrade', 'Highest upgrade satisfying the existing version/compatibility policy, whether patched or not'],
  ['Latest Available', 'Newest published stable version, regardless of compatibility'],
  ['Is Update', 'Yes when this is an additional non-vulnerable update rather than a vulnerability fix'],
  ['Verification Status', 'Resolver verification outcome; hover over a failed status to see the notes'],
];

const cell = value => (value ? `\`${value}\`` : '—');
const escapeAttribute = text => String(text).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
  .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r?\n/g, '&#10;');

function verificationCell(target) {
  if (!target.verification_status) return '—';
  if (target.verification_status !== 'FAILED' || !target.verification_notes) return target.verification_status;
  return `<abbr title="${escapeAttribute(target.verification_notes)}">FAILED</abbr>`;
}

function row(target) {
  return `| \`${target.package}\` | ${cell(target.current_version)} | ${cell(target.minimum_fixed_version)} ` +
    `| ${cell(target.compatible_upgrade)} | ${cell(target.latest_available || target.highest_fixed_version)} ` +
    `| ${target.is_update ? 'Yes' : 'No'} | ${verificationCell(target)} |`;
}

function buildUpgradeOptionsSection(plans, bundleTargets) {
  if (!Array.isArray(bundleTargets)) return '';
  const selectedPackages = new Set(plans.map(plan => plan.package.name.toLowerCase()));
  // Same selection as the acceptance criteria, so parent upgrades for transitive findings are included.
  const targets = bundleTargets.filter(target => (target.affected_packages || [])
    .some(name => selectedPackages.has(name.toLowerCase())));
  if (targets.length === 0) return '';

  return '<details>\n<summary>Dependency Compatibility Analysis</summary>\n\n' +
    'The following upgrade options are identified for each package that needs an upgrade (direct dependencies and parents of transitive ones). ' +
    'Recommendations prioritize the minimum version that resolves the identified vulnerabilities and passes dependency compatibility validation.\n\n' +
    '| Package | Current | Minimum Fix | Compatible Upgrade | Latest Available | Is Update | Verification Status |\n' +
    '|---|---|---|---|---|---|---|\n' +
    `${targets.map(row).join('\n')}\n\n` +
    '| Column | Meaning |\n|---|---|\n' +
    `${COLUMN_DETAILS.map(([name, meaning]) => `| ${name} | ${meaning} |`).join('\n')}\n\n</details>\n\n`;
}

module.exports = { buildUpgradeOptionsSection };
