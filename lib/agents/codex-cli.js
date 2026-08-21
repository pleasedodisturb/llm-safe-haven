'use strict';

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
  // Re-tiered 2 -> 3 (G-1661, plan 21-06/21-07, apply-all disposition,
  // unanticipated by ROADMAP criterion 6). no-citation-found: exhaustive
  // search of openai/codex (174 docs/**/*.md files, 3403 .rs/.toml source
  // files, plus developers.openai.com/codex/{cli,local-config,security})
  // found zero mentions of a .codexignore mechanism anywhere -- the file
  // this harden() writes appears to correspond to nothing the vendor
  // documents or implements.
  tier: 3,
  installsEnforcedHooks: false,
  writesIgnoreFile: true,
  ignoreFileHonored: false,
  ignoreFileCitation: {
    url: 'https://github.com/openai/codex/blob/main/codex-rs/config.md',
    retrievedAt: '2026-08-20',
    claim: 'No .codexignore mechanism documented anywhere in openai/codex -- the canonical config reference (codex-rs/config.md) contains zero mentions of "ignore" or "exclude" of any kind (no-citation-found).',
  },
  detect,
  harden,
  audit,
};
