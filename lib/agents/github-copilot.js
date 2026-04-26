'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { vscodeExtensionExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = vscodeExtensionExists('github.copilot');
  return { found, version: null, path: found ? 'VS Code extension' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .copilotignore
  const ignoreResult = writeIgnoreFile(projectDir, '.copilotignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .copilotignore');
  } else if (ignoreResult.written) {
    actions.push('.copilotignore — created');
  } else {
    actions.push('.copilotignore — ' + ignoreResult.reason);
  }

  // 2. Advise on agent mode and workspace trust
  warnings.push('Enable VS Code workspace trust: security.workspace.trust.enabled = true');
  warnings.push('Review Copilot agent mode settings — agents can execute terminal commands');
  warnings.push('Audit github.copilot.chat.agent.enabled and auto-run permissions');
  warnings.push('Consider disabling Copilot for specific file types via editor.inlineSuggest settings');

  return { actions, warnings };
}

function audit() {
  // BUG-4: Use platform-correct path for VS Code settings
  const settingsPath = process.platform === 'darwin'
    ? path.join(os.homedir(), 'Library', 'Application Support', 'Code', 'User', 'settings.json')
    : path.join(os.homedir(), '.config', 'Code', 'User', 'settings.json');
  let trust = null;
  try {
    trust = JSON.parse(fs.readFileSync(settingsPath, 'utf8'))['security.workspace.trust.enabled'];
  } catch { /* settings may not exist */ }

  const pass = trust === true;
  const detail = trust === true ? 'VS Code workspace trust is enabled'
    : trust === false ? 'Workspace trust explicitly disabled — malicious repos can auto-execute'
    : 'Cannot verify — check Settings → security.workspace.trust.enabled';

  return { checks: [{ name: 'Workspace trust', pass, detail }], level: 0 };
}

module.exports = {
  name: 'GitHub Copilot',
  id: 'github-copilot',
  tier: 3,
  detect,
  harden,
  audit,
};
