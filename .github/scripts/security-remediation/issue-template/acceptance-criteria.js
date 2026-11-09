// Acceptance criteria: one checkbox per upgrade target in the bundle.

const { buildAlerts } = require('./alerts');
const { compareVersions } = require('./versions');

// Preferred path: the bundle's consolidated upgrade_targets.
function targetCriteria(plans, bundleTargets) {
  const selectedPackages = new Set(plans.map(plan => plan.package.name.toLowerCase()));
  const targets = bundleTargets.filter(target => (target.affected_packages || [])
    .some(name => selectedPackages.has(name.toLowerCase())));
  let section = '';
  for (const target of targets) {
    section += target.minimum_fixed_version
      ? `- [ ] Upgrade \`${target.package}\` from \`${target.current_version || 'unknown'}\` to \`${target.minimum_fixed_version}\` [compatible: \`${target.compatible_version || 'unknown'}\`, highest fixed: \`${target.highest_fixed_version || 'unknown'}\`].\n`
      : `- [ ] Review and validate an upgrade for \`${target.package}\`; no fixed upgrade version has been identified.\n`;
  }
  return section + (targets.length ? '\n' : '_No upgrade targets identified in this bundle._\n\n');
}

// Fallback for plans without upgrade_targets (older orchestrator output).
function planCriteria(vulnerablePlans) {
  let section = '';
  for (const plan of vulnerablePlans) {
    const recommendations = plan.package.package_upgrade_recommendations || [];
    if (recommendations.length > 0) {
      for (const recommendation of recommendations) {
        const minimumFixedVersion = recommendation.minimum_patched_version
          || (recommendation.package === plan.package.name ? plan.package.minimum_fixed_version : '');
        section += minimumFixedVersion
          ? `- [ ] Upgrade \`${recommendation.package}\` from \`${recommendation.from_version || plan.package.current_version || 'unknown'}\` to \`${minimumFixedVersion}\` [compatible: \`${recommendation.compatible_version || 'unknown'}\`, highest fixed: \`${recommendation.highest_stable_version || 'unknown'}\`].\n`
          : `- [ ] Review and validate an upgrade for \`${recommendation.package}\`.\n`;
      }
      continue;
    }
    if (plan.package.minimum_fixed_version) {
      section += `- [ ] Upgrade \`${plan.package.name}\` from \`${plan.package.current_version || 'unknown'}\` to \`${plan.package.minimum_fixed_version}\` [compatible: \`unknown\`, highest fixed: \`unknown\`].\n`;
      continue;
    }
    if (plan.fix.fix_class === 'NO_FIX_AVAILABLE') {
      section += `- [ ] Investigate remediation for \`${plan.package.name}\`; no verified upgrade is available.\n`;
      continue;
    }
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
  return section + '\n';
}

function buildAcceptanceCriteriaSection(plans, bundleTargets) {
  const heading = '## Acceptance Criteria\n\n';
  if (Array.isArray(bundleTargets)) return heading + targetCriteria(plans, bundleTargets);

  const vulnerablePlans = plans.filter(plan => buildAlerts(plan).length > 0);
  if (vulnerablePlans.length === 0) return `${heading}_No vulnerable packages in this group_\n\n`;
  return heading + planCriteria(vulnerablePlans);
}

module.exports = { buildAcceptanceCriteriaSection };
