'use strict';

// STUB (RED phase, G-1570) -- see helpers/discover-md.js stub header.

const EXIT = Object.freeze({ CLEAN: 0, FINDINGS: 1, INCOMPLETE: 2 });

function loadChecks() {
  return { checks: [], errors: [] };
}

function runAll() {
  return { findings: [], incomplete: [] };
}

function tallySeverities() {
  return { fail: 0, warn: 0 };
}

function computeExit() {
  return EXIT.CLEAN;
}

function formatReport() {
  return '';
}

module.exports = { loadChecks, runAll, tallySeverities, computeExit, formatReport, EXIT };
