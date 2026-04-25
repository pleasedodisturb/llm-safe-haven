'use strict';

const { vscodeExtensionExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = vscodeExtensionExists('continue.continue');
  return { found, version: null, path: found ? 'VS Code extension' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .continueignore
  const ignoreResult = writeIgnoreFile(projectDir, '.continueignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .continueignore');
  } else if (ignoreResult.written) {
    actions.push('.continueignore — created');
  } else {
    actions.push('.continueignore — ' + ignoreResult.reason);
  }

  warnings.push('Review Continue config at ~/.continue/config.json for API key exposure');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Continue.dev',
  id: 'continue-dev',
  tier: 2,
  detect,
  harden,
  audit,
};
