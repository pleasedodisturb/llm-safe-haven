'use strict';

const { commandExists, vscodeExtensionExists } = require('./base.js');

function detect() {
  const cliFound = commandExists('q');
  const extFound = vscodeExtensionExists('amazonwebservices.amazon-q-vscode');
  const found = cliFound || extFound;
  return {
    found,
    version: null,
    path: extFound ? 'VS Code extension' : (cliFound ? 'q' : null),
  };
}

function harden(_projectDir, _flags) {
  const actions = [];
  const warnings = [];

  warnings.push('Amazon Q has access to AWS credentials in your environment — scope IAM roles tightly');
  warnings.push('Use least-privilege IAM policies when Q is active — avoid AdministratorAccess');
  warnings.push('Review Amazon Q data sharing settings in VS Code extension preferences');
  warnings.push('Consider using AWS SSO with session tokens instead of long-lived access keys');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Amazon Q',
  id: 'amazon-q',
  tier: 3,
  // AWS published an end-of-support schedule: new sign-ups blocked 2026-05-15,
  // full EOS 2027-04-30, superseded by Kiro. We still detect + advise for the
  // decaying installed base, but flag the sunset so users plan a migration.
  deprecated: 'End-of-support: AWS has published an EOS schedule (new sign-ups blocked 2026-05-15, full end-of-support 2027-04-30) and is steering users to Kiro. Hardening still applies while you run it — plan your migration.',
  detect,
  harden,
  audit,
};
