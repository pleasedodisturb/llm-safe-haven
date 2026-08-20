'use strict';

// STUB (RED phase, G-1570, 21-04, Check 6). Parse-valid, deliberately wrong
// answers -- replaced by the real implementation before the GREEN commit.

const id = 'commands';

const INTERNAL_PATH_PREFIXES = Object.freeze([]);

function isDateShapedSegment() {
  return false;
}

function isPlaceholderSegment() {
  return false;
}

function tokenizeFencedLine() {
  return [];
}

function extractPathTokens() {
  return [];
}

function run() {
  return [];
}

module.exports = {
  id,
  run,
  extractPathTokens,
  INTERNAL_PATH_PREFIXES,
  isPlaceholderSegment,
  isDateShapedSegment,
  tokenizeFencedLine,
};
