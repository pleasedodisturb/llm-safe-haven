'use strict';

// Fixture detector module from which zero rule IDs can be extracted --
// proves lib/docs-verify/mcp-rule-ids.js's per-detector non-vacuity guard
// forces an incomplete sweep (exit 2) rather than presenting a clean pass
// when the emission shape yields nothing at all.

const id = 'no-rules-detector';

function run() {
  return [];
}

module.exports = { id, run };
