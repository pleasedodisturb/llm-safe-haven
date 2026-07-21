'use strict';

const { commandExists, macAppExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  // The exact CLI binary name is unconfirmed (RESEARCH.md Open Question 3);
  // 'antigravity' is the primary guess, used only as an OR-fallback
  // alongside the .app bundle check — mirrors windsurf.js's precedent.
  const cliFound = commandExists('antigravity');
  const appPath = macAppExists('Antigravity');
  const found = cliFound || !!appPath;
  return { found, version: null, path: appPath || (cliFound ? 'antigravity' : null) };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create ignore file
  const ignoreResult = writeIgnoreFile(projectDir, '.antigravityignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .antigravityignore');
  } else if (ignoreResult.written) {
    actions.push('.antigravityignore — created');
  } else {
    actions.push('.antigravityignore — ' + ignoreResult.reason);
  }

  // 2. Advise on lack of native sandbox / MCP review
  warnings.push('Antigravity has no documented native sandbox — review agent permissions before granting workspace access');
  warnings.push('Review ~/.gemini/config/mcp_config.json and <project>/.agents/mcp_config.json for unexpected MCP servers');
  warnings.push('Never auto-approve commands — read every command before approving');

  return { actions, warnings };
}

function audit() {
  const checks = [];

  checks.push({
    name: 'Sandbox',
    pass: false,
    detail: 'Antigravity has no documented native sandbox — review agent permissions manually',
  });

  return { checks, level: 0 };
}

module.exports = {
  name: 'Antigravity',
  id: 'antigravity',
  tier: 2,
  detect,
  harden,
  audit,
};
