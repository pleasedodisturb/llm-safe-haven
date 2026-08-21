'use strict';

// Shared cross-check satisfier (G-1570, 21-04). This root is swept by the
// REAL registry via `node scripts/docs-verify.js --root <this dir>`, which
// runs EVERY registered check, not just Check 6 (commands) this fixture
// root exists to exercise. Without a detector tree + matching
// docs/mcp-security.md, Check 2 (mcp-rule-ids) throws on a missing
// `lib/mcp/detectors` dir and forces the sweep incomplete (exit 2)
// regardless of what Check 6 finds. This is a byte-for-byte copy of the
// shape already proven clean by tests/fixtures/docs-verify/identifiers/clean
// (21-02) and tests/fixtures/docs-verify/links/clean (21-03).

const id = 'fixture-detector';

function run(servers) {
  const findings = [];

  for (const server of Array.isArray(servers) ? servers : []) {
    const bin = server.bin;
    if (bin === 'npx' || bin === 'uvx') {
      findings.push({
        id: `${id}/${bin}-no-version`,
      });
    }
  }

  findings.push({ id: `${id}/inlined-secret` });
  findings.push({ id: `${id}/broad-inheritance` });

  return findings;
}

module.exports = { id, run };
