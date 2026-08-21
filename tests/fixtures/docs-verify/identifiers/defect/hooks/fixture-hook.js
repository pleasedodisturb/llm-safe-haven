'use strict';

// Fixture source for tests/docs-verify/identifiers.test.js. The scoped
// doc's planted-defect identifier (see docs/hardening/fixture-agent.md)
// deliberately does not appear anywhere in this file or in
// lib/fixture-lib.js -- not even inside a comment, since Check 1's
// "exists" test is raw source-text presence and would find it there too.

const REAL_IDENTIFIER = 'fixture';

function realFunction(x) {
  return x;
}

module.exports = { REAL_IDENTIFIER, realFunction };
