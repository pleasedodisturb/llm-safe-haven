'use strict';

// RED-phase stub (G-1570, 21-03 Task 2). Parse-valid, deliberately wrong
// answers so tests/docs-verify/links.test.js fails on assertions, not on a
// module-resolution error. Replaced with the real implementation in the
// GREEN commit.

const id = 'links';

function run() {
  return [];
}

function extractLinks() {
  return [];
}

function isExternal() {
  return false;
}

function decodeTargetOrNull(raw) {
  return raw;
}

function statPath() {
  return { exists: true, isDirectory: false };
}

module.exports = { id, run, extractLinks, isExternal, decodeTargetOrNull, statPath };
