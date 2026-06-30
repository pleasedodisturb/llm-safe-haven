'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const SCAN_DIRS = [
  path.join(os.homedir(), 'Projects'),
  path.join(os.homedir(), 'Developer'),
  path.join(os.homedir(), 'Code'),
  path.join(os.homedir(), 'src'),
  path.join(os.homedir(), 'repos'),
  path.join(os.homedir(), 'workspace'),
];

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', '__pycache__', '.venv', 'venv']);

function findEnvFiles(startDir, maxDepth) {
  const results = [];
  if (!fs.existsSync(startDir)) return results;

  function walk(dir, depth) {
    if (depth > (maxDepth || 4)) return;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // Permission denied or other error
    }

    for (const entry of entries) {
      // M-6: Skip symlinks to prevent symlink-following attacks
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        walk(path.join(dir, entry.name), depth + 1);
      } else if (entry.isFile()) {
        if (entry.name === '.env' || (entry.name.startsWith('.env.') && !entry.name.endsWith('.example') && !entry.name.endsWith('.template') && !entry.name.endsWith('.sample'))) {
          results.push(path.join(dir, entry.name));
        }
      }
    }
  }

  walk(startDir, 0);
  return results;
}

function scanForEnvFiles() {
  const allFiles = [];

  for (const dir of SCAN_DIRS) {
    const found = findEnvFiles(dir);
    allFiles.push(...found);
  }

  // Deduplicate
  return [...new Set(allFiles)].sort();
}

// Bundled IOC scanners (shipped in the package via package.json "files").
// The newest one covers the most vectors; it is the default for --supply-chain.
const SUPPLY_CHAIN_SCANNER = 'scan-miasma-june2026.sh';

/**
 * Runs the bundled supply-chain IOC scanner (a POSIX shell script) and streams
 * its output. Network-free: sets LSH_NO_NETWORK so the scanner skips its only
 * optional network call (the `gh repo list` dead-drop audit).
 *
 * opts (for testing): { platform, spawnSync, scriptsDir }.
 * Returns { ran, code, script?, reason? } — never throws.
 * Exit-code convention: 0 = clean, 1 = findings, 2 = error/could-not-complete.
 * A could-not-run or interrupted scan is NEVER reported as 0 ("clean") — a
 * security gate must distinguish "no IOCs found" from "the scan did not finish".
 */
function runSupplyChainScan(flags, opts = {}) {
  const { printHeader, C } = require('./scorecard.js');
  const platform = opts.platform || process.platform;
  const spawnSync = opts.spawnSync || require('child_process').spawnSync;
  const scriptsDir = opts.scriptsDir || path.join(__dirname, '..', 'scripts');
  const script = path.join(scriptsDir, SUPPLY_CHAIN_SCANNER);

  printHeader();
  console.log(`  ${C.bold}Supply-chain IOC scan (Miasma / Mini Shai-Hulud)...${C.reset}`);
  console.log('');

  if (platform === 'win32') {
    console.log(`  ${C.yellow}◆${C.reset} The supply-chain scanner is a POSIX shell script (macOS/Linux).`);
    console.log(`     On Windows, run it under WSL or Git Bash:`);
    console.log(`       bash "${script}"`);
    return { ran: false, reason: 'win32', code: 2 };
  }

  if (!fs.existsSync(script)) {
    console.log(`  ${C.yellow}◆${C.reset} Scanner not found at ${script}`);
    return { ran: false, reason: 'missing', code: 2 };
  }

  // Honor the no-network posture: skip the scanner's optional gh dead-drop audit.
  const env = Object.assign({}, process.env, { LSH_NO_NETWORK: '1' });
  const result = spawnSync('bash', [script], { stdio: 'inherit', env });

  if (result.error) {
    console.log(`  ${C.yellow}◆${C.reset} Could not run the scanner (is bash installed?): ${result.error.message}`);
    return { ran: false, reason: 'spawn-error', code: 2 };
  }
  // result.status is null when the child was killed by a signal (e.g. SIGKILL
  // from the OOM killer, or SIGINT). Treat that as code 2 (incomplete) — never
  // 0, or an interrupted scan would falsely read as "clean".
  if (result.status === null) {
    console.log(`  ${C.yellow}◆${C.reset} Scan did not complete (killed by ${result.signal || 'a signal'}) — treating as incomplete, not clean.`);
    return { ran: false, reason: 'killed', code: 2 };
  }
  return { ran: true, code: result.status, script };
}

function scan(flags, opts) {
  if (flags && flags.supplyChain) {
    return runSupplyChainScan(flags, opts);
  }

  const { printHeader, printEnvScan, printNextSteps, C } = require('./scorecard.js');

  printHeader();
  console.log(`  ${C.bold}Scanning for exposed secrets...${C.reset}`);
  console.log('');

  const envFiles = scanForEnvFiles();
  printEnvScan(envFiles);

  // Check for common dangerous files in home dir
  const dangerousFiles = [
    '.aws/credentials',
    '.config/gcloud/application_default_credentials.json',
    '.kube/config',
    '.npmrc',
  ].map(f => path.join(os.homedir(), f)).filter(f => fs.existsSync(f));

  if (dangerousFiles.length > 0) {
    console.log('');
    console.log(`  ${C.bold}Credential files accessible to agents:${C.reset}`);
    for (const f of dangerousFiles) {
      console.log(`    ${C.yellow}\u25c6${C.reset} ${C.dim}${f}${C.reset}`);
    }
  }

  printNextSteps(envFiles.length === 0 ? 2 : 1);
}

module.exports = { scan, scanForEnvFiles, findEnvFiles, runSupplyChainScan, SUPPLY_CHAIN_SCANNER };
