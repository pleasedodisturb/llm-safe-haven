'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const { Traversal } = require('./traverse/engine.js');

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', '__pycache__', '.venv', 'venv']);

/**
 * D-23/D-03: `.env` discovery is now a thin wrapper over the shared
 * traversal engine's `env-secrets` class instead of a hand-rolled
 * recursive fs.readdirSync walk. `maxDepth`/`skipDirs`/`skipDotDirs` are
 * the per-consumer enumeration SHAPE the engine reserves exactly for this
 * caller (lib/traverse/index.js's normalizeOptions IMPORTANT note) --
 * `maxDepth || 4` reproduces the OLD walk's exact falsy-zero-coerces-to-4
 * quirk byte-for-byte, since `maxDepth` was never validated as a positive
 * integer before this change either.
 *
 * `classes: ['env-secrets']` alone means no `spec` is needed (env-secrets
 * membership needs no spec DATA -- see EMPTY_SPEC in engine.js) and
 * `bulk-content` is never requested, so `enumerateSync()` never
 * constructs a real ignore resolver and spawns zero subprocesses -- `.env`
 * files are deliberately gitignored, and the whole point of this class
 * being TARGETED tier is that gitignore is never consulted for it.
 *
 * Returns `{ files, skips }` -- `files` is the SAME plain path array
 * `findEnvFiles()` always returned (see below); `skips` is the engine's
 * new counted-skip inventory (symlinks, permission-denied directories,
 * etc.) that the old hand-rolled walk silently swallowed.
 */
function findEnvFilesDetailed(startDir, maxDepth) {
  const result = new Traversal({
    roots: [startDir],
    classes: ['env-secrets'],
    maxDepth: maxDepth || 4,
    skipDirs: SKIP_DIRS,
    skipDotDirs: true,
  }).enumerateSync();

  return { files: result.byClass.get('env-secrets') || [], skips: result.skips };
}

function findEnvFiles(startDir, maxDepth) {
  return findEnvFilesDetailed(startDir, maxDepth).files;
}

function scanForEnvFiles() {
  // D-08: scan.js now honours LSH_ROOTS, which it previously ignored
  // entirely (tests/roots.test.js's pre-change pin, flipped in plan
  // 17-13) -- an intentional capability addition, not a regression. Roots
  // now come from the SAME lib/roots.js module the traversal engine and
  // the bash scanner share, instead of a hand-synced, LSH_ROOTS-blind
  // SCAN_DIRS array.
  //
  // getRoots() is required and called HERE, at point-of-use, rather than
  // cached in a module-level const -- so a caller that re-requires this
  // module against a stubbed os.homedir() always sees roots computed
  // against the CURRENT homedir. `homedir: os.homedir` is passed
  // explicitly, using THIS module's own `os` binding (fresh on every
  // re-require), because lib/roots.js captures its own `os` reference at
  // ITS OWN module top level -- a stub installed after roots.js was first
  // required elsewhere in the process would otherwise never reach it.
  const { getRoots } = require('./roots.js');
  const allFiles = [];

  for (const dir of getRoots({ homedir: os.homedir })) {
    const found = findEnvFiles(dir);
    allFiles.push(...found);
  }

  // Deduplicate
  return [...new Set(allFiles)].sort();
}

// Bundled IOC scanners (shipped in the package via package.json "files").
// The newest one covers the most vectors; it is the default for --supply-chain.
// scan-chaindrop-aug2026.sh is a superset of the June Miasma scanner's general
// agent-persistence/workflow/tasks vectors plus the Aug 2026 ChainDrop IOCs.
const SUPPLY_CHAIN_SCANNER = 'scan-chaindrop-aug2026.sh';

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
  console.log(`  ${C.bold}Supply-chain IOC scan (ChainDrop / Mini Shai-Hulud)...${C.reset}`);
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
  if (flags && flags.mcp) {
    return require('./scan-mcp.js').scanMcp(flags, opts);
  }

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

module.exports = { scan, scanForEnvFiles, findEnvFiles, findEnvFilesDetailed, runSupplyChainScan, SUPPLY_CHAIN_SCANNER };
