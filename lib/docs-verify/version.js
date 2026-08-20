'use strict';

// STUB -- RED phase (G-1570). Parse-valid, deliberately wrong answers so
// tests/docs-verify/version.test.js fails on its assertions, not on a
// missing export or a throw. Real implementation lands in the GREEN commit.

const id = 'version';
const SELF_VERSION_PATTERNS = [];

function extractVersionClaims() {
  return [];
}

function run() {
  return [];
}

module.exports = { id, run, SELF_VERSION_PATTERNS, extractVersionClaims };
