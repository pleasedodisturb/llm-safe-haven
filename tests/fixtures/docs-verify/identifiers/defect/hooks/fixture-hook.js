'use strict';

// Fixture source for tests/docs-verify/identifiers.test.js -- declares the
// identifiers the defect root's scoped doc claims. `MISSING_IDENTIFIER`
// (the planted defect) deliberately does NOT appear anywhere in this file
// or in lib/fixture-lib.js.

const REAL_IDENTIFIER = 'fixture';

function realFunction(x) {
  return x;
}

module.exports = { REAL_IDENTIFIER, realFunction };
