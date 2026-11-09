// Loose version comparison for display decisions (not for semver validation).

function compareVersions(left, right) {
  const parts = version => version.replace(/^[vV]/, '').split(/[.+-]/)
    .map(part => /^\d+$/.test(part) ? Number(part) : part);
  const leftParts = parts(left);
  const rightParts = parts(right);
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

module.exports = { compareVersions };
