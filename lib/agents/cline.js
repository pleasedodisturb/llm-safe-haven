'use strict';

const { vscodeExtensionExists, writeIgnoreFile, SENSITIVE_PATTERNS } = require('./base.js');

function detect() {
  const found = vscodeExtensionExists('saoudrizwan.claude-dev');
  return { found, version: null, path: found ? 'VS Code extension' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  // 1. Create .clineignore
  const ignoreResult = writeIgnoreFile(projectDir, '.clineignore', SENSITIVE_PATTERNS, flags.dryRun);
  if (ignoreResult.reason === 'dry-run') {
    actions.push('[dry-run] Would create .clineignore');
  } else if (ignoreResult.written) {
    actions.push('.clineignore — created');
  } else {
    actions.push('.clineignore — ' + ignoreResult.reason);
  }

  // 2. Advise
  warnings.push('Review auto-approve settings in Cline extension configuration');
  warnings.push('Cline was target of Clinejection supply chain attack (Feb 2026) — keep updated');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Cline',
  id: 'cline',
  tier: 2,
  // Declared capabilities (G-1661, plan 21-06/21-07). Caveat: Cline's own
  // docs state .clineignore "is not a security or access-control boundary"
  // and will be deprecated -- flagged here, but the implied tier is
  // unaffected because the file still filters automatic loading today.
  installsEnforcedHooks: false,
  writesIgnoreFile: true,
  ignoreFileHonored: true,
  ignoreFileCitation: {
    url: 'https://docs.cline.bot/customization/clineignore',
    retrievedAt: '2026-08-20',
    claim: '.clineignore filters what Cline loads automatically when analyzing the codebase; vendor caveat: not a security/access-control boundary, ignored files still reachable via explicit @ mentions or shell commands, and the feature is being deprecated.',
  },
  detect,
  harden,
  audit,
};
