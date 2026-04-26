'use strict';

const { vscodeExtensionExists } = require('./base.js');

function detect() {
  const found = vscodeExtensionExists('augment.augment-vscode');
  return { found, version: null, path: found ? 'VS Code extension' : null };
}

function harden(_projectDir, _flags) {
  const actions = [];
  const warnings = [];

  warnings.push('Augment indexes your entire workspace for context — sensitive files are included');
  warnings.push('Review which repositories Augment has access to in extension settings');
  warnings.push('No ignore-file mechanism — use .gitignore to limit indexed files where possible');
  warnings.push('Audit Augment workspace connections periodically for stale project access');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Augment',
  id: 'augment',
  tier: 3,
  detect,
  harden,
  audit,
};
