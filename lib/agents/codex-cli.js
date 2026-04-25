'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { commandExists, getVersion, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = commandExists('codex');
  const version = found ? getVersion('codex', '--version') : null;
  return { found, version, path: found ? 'codex' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create ignore file (Codex uses AGENTS.md conventions, but .gitignore-style exclusions help)
  const ignoreResult = writeIgnoreFile(projectDir, '.codexignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .codexignore');
  } else if (ignoreResult.written) {
    actions.push('.codexignore — created');
  } else {
    actions.push('.codexignore — ' + ignoreResult.reason);
  }

  // 2. Advise on sandbox
  warnings.push('Codex CLI has built-in network-disabled sandbox by default');
  warnings.push('Use "suggest" approval mode (not "auto-edit" or "full-auto") for sensitive projects');
  warnings.push('Review AGENTS.md if present in cloned repos — it can override agent behavior');

  return { actions, warnings };
}

function audit() {
  const checks = [];

  checks.push({
    name: 'Sandbox',
    pass: true,
    detail: 'Codex CLI sandbox is on by default (network-disabled)',
  });

  return { checks, level: 1 };
}

module.exports = {
  name: 'Codex CLI',
  id: 'codex-cli',
  tier: 2,
  detect,
  harden,
  audit,
};
