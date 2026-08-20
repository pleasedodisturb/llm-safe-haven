'use strict';

// STUB (RED phase, G-1570) -- parse-valid, deliberately wrong output so
// the new tests fail on their assertions rather than on a missing module.
// Real implementation lands in the GREEN commit.

const STATIC_SKIP_DIRS = Object.freeze(new Set());

function gitignoreDirEntries() {
  return new Set();
}

function discoverMarkdown() {
  return { files: [], errors: [] };
}

module.exports = { discoverMarkdown, gitignoreDirEntries, STATIC_SKIP_DIRS };
