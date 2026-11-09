// Shared plan classification and category naming used by issue sections.

const IMP_LABEL = { 'non-breaking': 'Non-Breaking', breaking: 'Breaking' };
const ACT_LABEL = { rollup: 'Rollup', standalone: 'Standalone', placeholder: 'Placeholder', 'open-issue': 'Open Issue' };
const IMPACTS = ['non-breaking', 'breaking'];
const ACTIONS = ['rollup', 'standalone', 'placeholder', 'open-issue'];

const ACTION_TYPE_TO_SUFFIX = {
  rollup_pr: 'rollup',
  standalone_pr: 'standalone',
  placeholder_pr: 'placeholder',
  open_issue: 'open-issue',
};

function getImpact(plan) {
  return plan.fix.fix_class === 'BREAKING_BUMP' ? 'breaking' : 'non-breaking';
}

function isTransitivePlan(plan) {
  return (plan.package.relationship || '').toLowerCase() === 'transitive' || plan.package.is_transitive === true;
}

function getActionSuffix(plan) {
  return ACTION_TYPE_TO_SUFFIX[plan.action.action_type] || 'open-issue';
}

function categoryKey(ecosystem, impact, action) {
  return `${encodeURIComponent(ecosystem || 'unknown')}--${impact}-${action}`;
}

function getCategory(plan) {
  return categoryKey(plan.package.ecosystem, getImpact(plan), getActionSuffix(plan));
}

// Calls visit(category, plans, impact, action) for each non-empty category
// of this ecosystem, restricted to the plans in the current issue group.
function forEachCategory(ecosystem, categoryMap, groupPlansSet, visit) {
  for (const impact of IMPACTS) {
    for (const action of ACTIONS) {
      const category = categoryKey(ecosystem, impact, action);
      const plans = (categoryMap[category] || []).filter(plan => groupPlansSet.has(plan));
      if (plans.length > 0) visit(category, plans, impact, action);
    }
  }
}

module.exports = {
  IMP_LABEL, ACT_LABEL, getImpact, isTransitivePlan, getCategory, forEachCategory,
};
