// Collapsible npm reconciliation notes taken from the orchestrator output.

const NPM_ECOSYSTEMS = ['npm', 'npm_and_yarn', 'yarn'];

function isNpmEcosystem(ecosystem) {
  return NPM_ECOSYSTEMS.includes((ecosystem || '').toLowerCase());
}

function buildReconciliationNotesSection(ecosystem, reconciliationInfo) {
  if (!isNpmEcosystem(ecosystem)) return '';
  const notes = (reconciliationInfo || [])
    .filter(info => isNpmEcosystem(info.ecosystem))
    .map(info => (info.reconciliation_notes || '').trim())
    .filter(Boolean);
  if (notes.length === 0) return '';

  const indentedNotes = notes.join('\n\n').split('\n')
    .map(line => `    ${line}`)
    .join('\n');
  return `<details>\n<summary>Reconciliation Notes</summary>\n\n${indentedNotes}\n\n</details>\n\n`;
}

module.exports = { buildReconciliationNotesSection };
