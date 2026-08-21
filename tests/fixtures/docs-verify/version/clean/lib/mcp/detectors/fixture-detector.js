'use strict';

// Shared cross-check satisfier (G-1570, 21-02). This root is swept by the
// REAL registry via `node scripts/docs-verify.js --root <this dir>`, which
// runs EVERY registered check, not just the one this fixture root exists to
// exercise. Without a detector tree + matching docs/mcp-security.md, Check 2
// (mcp-rule-ids) throws on a missing `lib/mcp/detectors` dir and forces the
// sweep incomplete (exit 2) regardless of what this plan's own check finds
// -- verified empirically against a throwaway fixture before this file was
// written. This is a byte-for-byte copy of the shape
// tests/fixtures/docs-verify/mcp-rule-ids/clean/lib/mcp/detectors/fixture-detector.js
// already proves clean; it exists here purely so Check 2 reports zero
// findings against this root, leaving Check 1's own result as the only
// signal in the CLI-level exit code.

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
