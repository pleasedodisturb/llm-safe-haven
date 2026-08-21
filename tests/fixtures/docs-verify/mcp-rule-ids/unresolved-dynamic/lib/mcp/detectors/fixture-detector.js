'use strict';

// Fixture detector whose only rule-id interpolation variable has no
// resolvable finite alternative set anywhere in this module (no strict
// equality comparison against a string literal appears anywhere in this
// file) — proves lib/docs-verify/mcp-rule-ids.js's run() forces an
// incomplete sweep (exit 2) instead of silently skipping the site or
// guessing at a value.

const id = 'unresolved-detector';

function run(servers) {
  const findings = [];
  for (const server of Array.isArray(servers) ? servers : []) {
    const suffix = server.dynamicSuffix;
    findings.push({
      id: `${id}/${suffix}-thing`,
    });
  }
  return findings;
}

module.exports = { id, run };
