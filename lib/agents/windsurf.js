'use strict';

const { commandExists, macAppExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const cliFound = commandExists('windsurf');
  const appPath = macAppExists('Windsurf');
  const found = cliFound || !!appPath;
  return { found, version: null, path: appPath || (cliFound ? 'windsurf' : null) };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .codeiumignore
  const ignoreResult = writeIgnoreFile(projectDir, '.codeiumignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .codeiumignore');
  } else if (ignoreResult.written) {
    actions.push('.codeiumignore — created');
  } else {
    actions.push('.codeiumignore — ' + ignoreResult.reason);
  }

  // 2. Warn about fundamental limitations
  warnings.push('Windsurf has NO native sandbox — Cascade runs with full user permissions');
  warnings.push('No hook system available — cannot intercept tool calls');
  warnings.push('Never auto-approve commands — read every command before approving');
  warnings.push('Consider using Claude Code or Cursor for sensitive projects');

  return { actions, warnings };
}

function audit() {
  const checks = [];

  checks.push({
    name: 'Sandbox',
    pass: false,
    detail: 'Windsurf has no native sandbox — fundamental limitation',
  });

  checks.push({
    name: 'Hooks',
    pass: false,
    detail: 'No hook system available',
  });

  return { checks, level: 0 };
}

module.exports = {
  name: 'Windsurf',
  id: 'windsurf',
  tier: 2,
  detect,
  harden,
  audit,
};
