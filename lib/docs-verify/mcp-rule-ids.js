'use strict';

// STUB (RED phase, G-1570) -- see helpers/discover-md.js stub header.

const id = 'mcp-rule-ids';

function run() {
  return [];
}

function splitTableRow(line) {
  return [line];
}

function expandBraceAlternation(token) {
  return [token];
}

function documentedRuleSuffixes() {
  return new Map();
}

function emittedRuleSuffixes() {
  return { detectorId: null, suffixes: [], unresolved: [] };
}

module.exports = { id, run, splitTableRow, expandBraceAlternation, documentedRuleSuffixes, emittedRuleSuffixes };
