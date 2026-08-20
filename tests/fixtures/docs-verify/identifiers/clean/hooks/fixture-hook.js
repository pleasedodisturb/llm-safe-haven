'use strict';

// Fixture source for tests/docs-verify/identifiers.test.js -- declares the
// identifiers the clean root's scoped doc claims, all of which are real.

const REAL_IDENTIFIER = 'fixture';

function realFunction(x) {
  return x;
}

module.exports = { REAL_IDENTIFIER, realFunction };
