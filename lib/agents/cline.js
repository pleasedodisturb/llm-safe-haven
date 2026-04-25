'use strict';

const { vscodeExtensionExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = vscodeExtensionExists('saoudrizwan.claude-dev');
  return { found, version: null, path: found ? 'VS Code extension' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .clineignore
  const ignoreResult = writeIgnoreFile(projectDir, '.clineignore', SENSITIVE_PATTERNS);
  if (flags.dryRun) {
    actions.push('[dry-run] Would create .clineignore');
  } else if (ignoreResult.written) {
    actions.push('.clineignore — created');
  } else {
    actions.push('.clineignore — ' + ignoreResult.reason);
  }

  // 2. Advise
  warnings.push('Review auto-approve settings in Cline extension configuration');
  warnings.push('Cline was target of Clinejection supply chain attack (Feb 2026) — keep updated');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Cline',
  id: 'cline',
  tier: 2,
  detect,
  harden,
  audit,
};
