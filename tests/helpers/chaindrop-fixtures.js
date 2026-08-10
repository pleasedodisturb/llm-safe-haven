'use strict';

// Shared ChainDrop (Aug 2026) scanner fixture builders (Phase 17 / TRAV-07,
// D-XX — promoted from the locally-defined `write`/`newHome`/`runScanner`
// trio in tests/chaindrop-scanner.test.js:27-54 so tests/chaindrop-parity.test.js
// and tests/traverse/*.test.js can reuse them without duplicating ~25 lines).
//
// Lives under tests/helpers/ (NOT matching the package.json test glob
// `tests/*.test.js`), so the test runner never picks it up as a test file.
//
// Fixtures are built at RUNTIME in an isolated HOME and never committed — a
// file literally named Math_Symbol.js or a real poisoned lockfile committed
// under tests/ is a self-scan hazard and would break the SELF_ROOT
// false-positive guard at tests/chaindrop-scanner.test.js:285-292 (the
// scanner is pointed at its own repo and must come back clean because the
// repo legitimately contains every IOC string as detection data).
//
// tests/chaindrop-scanner.test.js itself is NOT migrated to this helper in
// this plan — plan 17-14 owns that file and performs the migration.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const DEFAULT_SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'scan-chaindrop-aug2026.sh');
const hasBash = spawnSync('bash', ['-c', 'true']).status === 0;

// Write `contents` to `file`, creating parent directories as needed.
function write(file, contents) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

// Build a throwaway HOME, hand it to `build`, return its path. `built` is an
// array the caller registers for cleanup (typically in an `after` hook):
// `built.forEach((h) => fs.rmSync(h, { recursive: true, force: true }))`.
function newHome(built, build) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-'));
  built.push(home);
  build(home, (rel) => path.join(home, rel));
  return home;
}

// Run the real bash scanner against an isolated HOME (+ clean TMPDIR),
// network disabled. extraEnv lets a test flip LSH_NO_NETWORK off or set
// LSH_ROOTS. `scriptPath` defaults to the bundled ChainDrop scanner but can
// be overridden so parity tests can name the script explicitly. `opts.tmpSeed`
// (Phase 17 / TRAV-05, plan 17-05, the bun-staging corpus case) is an
// optional `(tmpDir) => void` callback invoked AFTER the isolated TMPDIR is
// created but BEFORE the scanner runs, so a case can seed TMPDIR content
// (e.g. a bun-dl-* staging directory) that the scanner's own mkdtemp'd
// TMPDIR would otherwise make unreachable from the case's `build(home, p)`.
function runScanner(home, extraEnv = {}, scriptPath = DEFAULT_SCRIPT, opts = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-tmp-'));
  if (typeof opts.tmpSeed === 'function') opts.tmpSeed(tmp);
  const res = spawnSync('bash', [scriptPath], {
    encoding: 'utf8',
    timeout: 60_000, // non-functional: a run must terminate well within this
    env: { HOME: home, TMPDIR: tmp, PATH: process.env.PATH, LSH_NO_NETWORK: '1', ...extraEnv },
  });
  fs.rmSync(tmp, { recursive: true, force: true });
  return res;
}

module.exports = { write, newHome, runScanner, hasBash };
