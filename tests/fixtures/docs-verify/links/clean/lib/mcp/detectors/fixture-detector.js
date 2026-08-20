'use strict';

// Shared cross-check satisfier (G-1570, 21-03), byte-for-byte copy of the
// shape tests/fixtures/docs-verify/identifiers/clean/lib/mcp/detectors/
// fixture-detector.js already proves clean. This root is swept by the
// REAL registry via `node scripts/docs-verify.js --root <this dir>`,
// which runs every registered check, not just Check 3 (links) this
// fixture root exists to exercise. Without this detector tree and its
// matching docs/mcp-security.md row, Check 2 (mcp-rule-ids) throws on a
// missing lib/mcp/detectors dir and forces the sweep incomplete (exit 2)
// regardless of what Check 3 finds.

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
