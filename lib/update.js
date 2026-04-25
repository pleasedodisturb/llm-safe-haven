'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { C, PASS, WARN } = require('./scorecard.js');

const HOOKS_DIR = path.join(os.homedir(), '.claude', 'hooks');
const HOOK_FILES = ['bash-firewall.js', 'secret-guard.js', 'audit-logger.js'];

function update(flags) {
  console.log('');
  console.log(`  ${C.bold}${C.cyan}Updating hooks...${C.reset}`);
  console.log('');

  const hooksSource = path.join(__dirname, '..', 'hooks');

  if (!fs.existsSync(hooksSource)) {
    console.log(`  ${C.red}Hook source not found at ${hooksSource}${C.reset}`);
    process.exit(1);
  }

  for (const hook of HOOK_FILES) {
    const src = path.join(hooksSource, hook);
    const dest = path.join(HOOKS_DIR, hook);

    if (!fs.existsSync(src)) {
      console.log(`  ${WARN} ${hook} — source not found, skipped`);
      continue;
    }

    if (!fs.existsSync(dest)) {
      console.log(`  ${WARN} ${hook} — not installed, skipped (run install first)`);
      continue;
    }

    if (flags.dryRun) {
      console.log(`  [dry-run] Would update ${hook}`);
      continue;
    }

    const srcContent = fs.readFileSync(src, 'utf8');
    const destContent = fs.readFileSync(dest, 'utf8');

    if (srcContent === destContent) {
      console.log(`  ${PASS} ${hook} — already up to date`);
    } else {
      fs.copyFileSync(src, dest);
      fs.chmodSync(dest, 0o755);
      console.log(`  ${PASS} ${hook} — updated`);
    }
  }

  console.log('');
  console.log(`  ${C.dim}Hooks source: ${hooksSource}${C.reset}`);
  console.log('');
}

module.exports = { update };
