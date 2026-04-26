'use strict';

const { commandExists, macAppExists } = require('./base.js');

function detect() {
  const cliFound = commandExists('replit');
  const appPath = macAppExists('Replit');
  const found = cliFound || !!appPath;
  return { found, version: null, path: appPath || (cliFound ? 'replit' : null) };
}

function harden(_projectDir, _flags) {
  const actions = [];
  const warnings = [];

  warnings.push('Replit Agent executes code on Replit servers — your code leaves your machine');
  warnings.push('Never paste secrets or credentials into Replit Agent prompts');
  warnings.push('Use Replit Secrets manager instead of .env files — but understand they are server-side');
  warnings.push('Review Replit workspace visibility settings (public/private) before adding sensitive code');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Replit Agent',
  id: 'replit-agent',
  tier: 3,
  detect,
  harden,
  audit,
};
