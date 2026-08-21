'use strict';

const { commandExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = commandExists('gemini');
  return { found, version: null, path: found ? 'gemini' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .geminiignore
  const ignoreResult = writeIgnoreFile(projectDir, '.geminiignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .geminiignore');
  } else if (ignoreResult.written) {
    actions.push('.geminiignore — created');
  } else {
    actions.push('.geminiignore — ' + ignoreResult.reason);
  }

  // 2. Advise on config
  warnings.push('Review ~/.gemini/settings.json for model and permission settings');
  warnings.push('Gemini CLI sends context to Google servers — avoid sensitive repos without .geminiignore');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Gemini CLI',
  id: 'gemini-cli',
  // Re-tiered 3 -> 2 (G-1661, plan 21-06/21-07, D-01-fixed / ROADMAP
  // criterion 6, anticipated). Cited: Gemini CLI's own docs confirm
  // .geminiignore is honored by tools that respect it.
  tier: 2,
  installsEnforcedHooks: false,
  writesIgnoreFile: true,
  ignoreFileHonored: true,
  ignoreFileCitation: {
    url: 'https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/gemini-ignore.md',
    retrievedAt: '2026-08-20',
    claim: 'Tools that respect .geminiignore exclude matching files and directories from their operations (e.g. the @ command excludes paths listed there), though they remain visible to other services such as Git.',
  },
  detect,
  harden,
  audit,
};
