'use strict';

const fs = require('fs');
const path = require('path');
const { commandExists, getVersion, macAppExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const cliFound = commandExists('cursor');
  const appPath = macAppExists('Cursor');
  const found = cliFound || !!appPath;
  const version = cliFound ? getVersion('cursor', '--version') : null;
  return { found, version, path: appPath || (cliFound ? 'cursor' : null) };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .cursorignore (blocks files from AI context entirely)
  const ignoreResult = writeIgnoreFile(projectDir, '.cursorignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .cursorignore');
  } else if (ignoreResult.written) {
    actions.push('.cursorignore — created');
  } else {
    actions.push('.cursorignore — ' + ignoreResult.reason);
  }

  // 2. Advise on workspace trust
  warnings.push('Enable workspace trust: Settings → security.workspace.trust.enabled = true');
  warnings.push('Cursor disables workspace trust by default — malicious repos can auto-execute code');

  // 3. Advise on auto-run mode
  warnings.push('Review Auto-Run Mode allowlist — shell builtins bypass it (CVE-2026-22708)');

  return { actions, warnings };
}

function audit() {
  const checks = [];

  // No programmatic way to check Cursor settings from CLI
  checks.push({
    name: 'Workspace trust',
    pass: false,
    detail: 'Cannot verify from CLI — check Settings → security.workspace.trust.enabled',
  });

  return { checks, level: 0 };
}

module.exports = {
  name: 'Cursor',
  id: 'cursor',
  tier: 2,
  detect,
  harden,
  audit,
};
