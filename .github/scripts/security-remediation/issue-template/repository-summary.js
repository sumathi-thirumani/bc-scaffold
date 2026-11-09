// Collapsible severity count table at the top of the issue.

const { SEVERITY_BUCKETS, buildAlerts, severityBucketOf } = require('./alerts');

function severityCounts(plans) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const plan of plans) {
    for (const alert of buildAlerts(plan)) {
      const bucket = severityBucketOf(alert);
      if (bucket) counts[bucket] += 1;
    }
  }
  return counts;
}

function repositorySummaryMarkdown(plans) {
  const counts = severityCounts(plans);
  return '<details>\n<summary>Summary</summary>\n\n' +
    `| ${SEVERITY_BUCKETS.join(' | ')} |\n` +
    `|${SEVERITY_BUCKETS.map(() => '---').join('|')}|\n` +
    `| ${SEVERITY_BUCKETS.map(bucket => counts[bucket]).join(' | ')} |\n\n</details>\n\n`;
}

module.exports = { repositorySummaryMarkdown };
