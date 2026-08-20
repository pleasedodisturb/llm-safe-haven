'use strict';

// STUB -- RED phase (G-1570). Parse-valid, deliberately wrong answers so
// tests/docs-verify/identifiers.test.js fails on its assertions, not on a
// missing export or a throw. Real implementation lands in the GREEN commit.

const id = 'identifiers';
const SCOPED_DOCS = [];

function extractClaims() {
  return [];
}

function identifierExistsInSource() {
  return false;
}

function run() {
  return [];
}

module.exports = { id, run, SCOPED_DOCS, extractClaims, identifierExistsInSource };
