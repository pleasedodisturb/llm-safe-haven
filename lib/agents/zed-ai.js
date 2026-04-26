'use strict';

const { commandExists, macAppExists } = require('./base.js');

function detect() {
  const cliFound = commandExists('zed');
  const appPath = macAppExists('Zed');
  const found = cliFound || !!appPath;
  return { found, version: null, path: appPath || (cliFound ? 'zed' : null) };
}

function harden(_projectDir, _flags) {
  const actions = [];
  const warnings = [];

  warnings.push('Review Zed AI settings: Settings → Features → Assistant');
  warnings.push('Zed sends file context to configured LLM provider — review which provider is active');
  warnings.push('Disable inline completions for sensitive files if not needed');
  warnings.push('Zed has no ignore-file for AI context — be cautious with secrets in open buffers');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Zed AI',
  id: 'zed-ai',
  tier: 3,
  detect,
  harden,
  audit,
};
