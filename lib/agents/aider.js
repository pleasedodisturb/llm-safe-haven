'use strict';

const fs = require('fs');
const path = require('path');
const { commandExists, getVersion, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = commandExists('aider');
  const version = found ? getVersion('aider', '--version') : null;
  return { found, version, path: found ? 'aider' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .aiderignore
  const ignoreResult = writeIgnoreFile(projectDir, '.aiderignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .aiderignore');
  } else if (ignoreResult.written) {
    actions.push('.aiderignore — created');
  } else {
    actions.push('.aiderignore — ' + ignoreResult.reason);
  }

  // 2. Check for .env with API keys
  const envPath = path.join(projectDir, '.env');
  if (fs.existsSync(envPath)) {
    try {
      const content = fs.readFileSync(envPath, 'utf8');
      if (/OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY/i.test(content)) {
        warnings.push('.env contains API keys — Aider reads these directly. Move to env vars or credential manager');
      }
    } catch { /* ignore */ }
  }

  // 3. Advise
  warnings.push('Aider has no sandbox, no hooks, and no permission model');
  warnings.push('Consider running Aider in a Docker container for isolation');
  warnings.push('Use --no-auto-commits to review changes before committing');

  return { actions, warnings };
}

function audit() {
  const checks = [];

  checks.push({
    name: 'Sandbox',
    pass: false,
    detail: 'Aider has no sandbox — runs with full user permissions',
  });

  return { checks, level: 0 };
}

module.exports = {
  name: 'Aider',
  id: 'aider',
  tier: 2,
  // Effectively unmaintained: no PyPI release in ~12 months, no repo activity in
  // 30+ days, maintainer absent (issues #4613/#4648/#4751). Still ~190k dl/wk, so
  // we keep hardening it — but users should not expect upstream security fixes.
  deprecated: 'Effectively unmaintained: no release in ~12 months and no repo activity in 30+ days (as of 2026-08). Still widely used, so hardening remains useful — but do not expect upstream security fixes.',
  detect,
  harden,
  audit,
};
