'use strict';

// Shared console.log capture helper (Phase 11 / TESTQ-02, D-05 — generalizes
// the local `quiet(fn)` prototype in tests/supply-chain-scan.test.js and the
// beforeEach/afterEach console.log-swap idiom duplicated across
// install.test.js, audit.test.js, scan.test.js, update.test.js,
// scorecard.test.js, cli.test.js, and tests/mcp/scan-mcp.test.js).
//
// Lives under tests/helpers/ (NOT matching the package.json test glob
// `tests/*.test.js`), so the test runner never picks it up as a test file.
//
// Callback-wrapper shape: swaps console.log before calling fn, restores it
// in a finally block (so a throw inside fn never leaves console.log
// swapped for a later test in the same process), and returns { logs,
// result }. Declared async and awaits fn() so both sync and async callers
// are supported transparently.

const util = require('util');

async function captureLog(fn) {
  const orig = console.log;
  const logs = [];
  // util.format matches real console.log semantics ('%d' etc.) — a plain
  // args.join(' ') would capture format specifiers literally.
  console.log = (...args) => logs.push(util.format(...args));
  try {
    const result = await fn();
    return { logs, result };
  } finally {
    console.log = orig;
  }
}

module.exports = { captureLog };
