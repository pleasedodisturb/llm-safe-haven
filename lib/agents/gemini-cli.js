'use strict';

const { commandExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = commandExists('gemini');
  return { found, version: null, path: found ? 'gemini' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .geminiignore
  const ignoreResult = writeIgnoreFile(projectDir, '.geminiignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .geminiignore');
  } else if (ignoreResult.written) {
    actions.push('.geminiignore — created');
  } else {
    actions.push('.geminiignore — ' + ignoreResult.reason);
  }

  // 2. Advise on config
  warnings.push('Review ~/.gemini/settings.json for model and permission settings');
  warnings.push('Gemini CLI sends context to Google servers — avoid sensitive repos without .geminiignore');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Gemini CLI',
  id: 'gemini-cli',
  tier: 3,
  detect,
  harden,
  audit,
};
