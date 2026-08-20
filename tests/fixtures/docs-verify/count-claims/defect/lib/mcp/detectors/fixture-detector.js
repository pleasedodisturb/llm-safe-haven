'use strict';

// Shared cross-check satisfier (G-1570, 21-04) -- see the identical comment
// in tests/fixtures/docs-verify/commands/{clean,defect}/lib/mcp/detectors/
// fixture-detector.js for why this file exists. This root's own docs/
// mcp-security.md documents every rule ID emitted here, so Check 2
// (mcp-rule-ids) reports zero findings against this root, leaving Check 7
// (count-claims)'s own result as the only signal in the CLI-level exit
// code. This file ALSO IS the canonical source for the mcp-detectors count
// (exactly one file here) that Check 7's own claims are graded against.
//
// The `const bin = server.bin` extraction (rather than an inline
// `server.bin` reference inside the template literal) matters: Check 2
// resolves a `${var}` rule-id template only via a finite-alternative-set
// found from strict-equality comparisons against that SAME local variable
// name in this module -- an inline `${server.bin}` is not resolvable.

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

  return findings;
}

module.exports = { id, run };
