'use strict';

// Fixture detector whose `const id` declaration uses double quotes, which
// ID_CONST_RE (single-quote only, lib/docs-verify/mcp-rule-ids.js:48) does
// not match -- proves run() forces an incomplete sweep (exit 2) instead of
// fabricating a nonsensical "null/<suffix>" finding when the detector id
// cannot be parsed (G-1570, 21-REVIEW.md WR-01). This row IS documented in
// this fixture's docs/mcp-security.md, so without the WR-01 guard the bug
// reports it as MISSING documentation anyway -- the exact defect the
// review reproduced.

const id = "double-quoted-detector";

function run(servers) {
  const findings = [];
  for (const server of Array.isArray(servers) ? servers : []) {
    findings.push({ id: `${id}/some-suffix` });
  }
  return findings;
}

module.exports = { id, run };
