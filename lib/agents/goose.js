'use strict';

const { commandExists, getVersion, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = commandExists('goose');
  const version = found ? getVersion('goose', '--version') : null;
  return { found, version, path: found ? 'goose' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create ignore file
  const ignoreResult = writeIgnoreFile(projectDir, '.gooseignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .gooseignore');
  } else if (ignoreResult.written) {
    actions.push('.gooseignore — created');
  } else {
    actions.push('.gooseignore — ' + ignoreResult.reason);
  }

  // 2. Advise on Goose's extension/secrets model
  warnings.push('Review the `extensions:` block in ~/.config/goose/config.yaml before enabling new MCP servers');
  warnings.push('Goose resolves secrets via env_keys against your OS keyring — never commit resolved values to config.yaml');
  warnings.push('Disabled extensions (enabled: false) are still a supply-chain surface if re-enabled later — audit them too');

  return { actions, warnings };
}

function audit() {
  const checks = [];

  checks.push({
    name: 'Config review',
    pass: true,
    detail: 'Review ~/.config/goose/config.yaml extensions: block for unexpected MCP servers',
  });

  return { checks, level: 1 };
}

module.exports = {
  name: 'Goose',
  id: 'goose',
  tier: 2,
  detect,
  harden,
  audit,
};
