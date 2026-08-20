'use strict';

// RED-phase stub (G-1570, 21-03 Task 3). Parse-valid, deliberately wrong
// answer so tests/docs-verify/anchors.test.js fails on assertions, not on
// a module-resolution error. Replaced with the real implementation in the
// GREEN commit.

const id = 'anchors';

function run() {
  return [];
}

module.exports = { id, run };
