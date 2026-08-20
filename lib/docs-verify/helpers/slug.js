'use strict';

// RED-phase stub (G-1570, 21-03 Task 1). Parse-valid, deliberately wrong
// answers so tests/docs-verify/slug.test.js fails on assertions, not on a
// module-resolution error. Replaced with the real implementation in the
// GREEN commit.

function slugify() {
  return '';
}

function headingSlugs() {
  return [];
}

module.exports = { slugify, headingSlugs };
