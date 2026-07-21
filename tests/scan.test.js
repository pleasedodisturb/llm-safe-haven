'use strict';

// TQ-04 (locked D-07): coverage for lib/scan.js's two uncovered branch
// families —
//   (1) findEnvFiles(startDir, maxDepth) directory-walk branches, exercised
//       directly against fs.mkdtempSync fixture trees (no stubbing needed —
//       findEnvFiles is a pure exported walk; per RESEARCH's correction,
//       '.git' in SKIP_DIRS is only a skip-list string, not git-command
//       dependent), and
//   (2) scan()'s dangerous-file block (~137-151), exercised with
//       os.homedir() stubbed to mkdtemp HOME sandboxes (empty vs seeded)
//       per the WR-01 top-level-const ordering rule, since lib/scan.js
//       captures `os` at module top level (SCAN_DIRS is computed from
//       os.homedir() at load time too).

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { stubHomedir } = require('./helpers/module-stub.js');
const { captureLog } = require('./helpers/capture-log.js');

const { findEnvFiles } = require('../lib/scan.js');

function mkFixture() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'scan-fixture-'));
}

// Root portability: mode bits do not block uid 0, so permission-denied
// tests can only pass as non-root (containers/CI sometimes run as root).
const runningAsRoot = typeof process.getuid === 'function' && process.getuid() === 0;

// ---------------------------------------------------------------------------
// findEnvFiles — directory-walk branch families
// ---------------------------------------------------------------------------
describe('findEnvFiles', () => {
  let fixtureDir;

  beforeEach(() => {
    fixtureDir = mkFixture();
  });

  afterEach(() => {
    // Restore perms so rmSync cleanup of the readdirSync-throws test doesn't
    // itself fail on a still-locked-down subdirectory.
    try {
      fs.chmodSync(path.join(fixtureDir, 'locked'), 0o755);
    } catch {
      // Directory may not exist in every test — fine.
    }
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it('nonexistent startDir returns []', () => {
    const missing = path.join(fixtureDir, 'does-not-exist');
    assert.deepEqual(findEnvFiles(missing, 4), []);
  });

  it('finds an exact .env file at the root', () => {
    fs.writeFileSync(path.join(fixtureDir, '.env'), 'SECRET=1\n');
    const found = findEnvFiles(fixtureDir, 4);
    assert.deepEqual(found, [path.join(fixtureDir, '.env')]);
  });

  it('finds .env.local and .env.production (dotted-suffix variants)', () => {
    fs.writeFileSync(path.join(fixtureDir, '.env.local'), 'A=1\n');
    fs.writeFileSync(path.join(fixtureDir, '.env.production'), 'B=1\n');
    const found = findEnvFiles(fixtureDir, 4).sort();
    assert.deepEqual(found, [
      path.join(fixtureDir, '.env.local'),
      path.join(fixtureDir, '.env.production'),
    ].sort());
  });

  it('does NOT report .env.example/.template/.sample (allowlisted suffixes)', () => {
    fs.writeFileSync(path.join(fixtureDir, '.env.example'), 'A=1\n');
    fs.writeFileSync(path.join(fixtureDir, '.env.template'), 'B=1\n');
    fs.writeFileSync(path.join(fixtureDir, '.env.sample'), 'C=1\n');
    assert.deepEqual(findEnvFiles(fixtureDir, 4), []);
  });

  it('does not recurse into SKIP_DIRS (node_modules, .git)', () => {
    const nodeModules = path.join(fixtureDir, 'node_modules');
    fs.mkdirSync(nodeModules);
    fs.writeFileSync(path.join(nodeModules, '.env'), 'HIDDEN=1\n');

    // lib/scan.js never invokes git — SKIP_DIRS.has('.git') is a plain
    // string match on the directory NAME, so a bare mkdir'd .git/ (no git
    // binary, no real repo) exercises the branch identically. Seeding a
    // .env inside strengthens the assertion: if the walk ever recursed
    // into .git/, it would be found.
    const gitDir = path.join(fixtureDir, '.git');
    fs.mkdirSync(gitDir, { recursive: true });
    fs.writeFileSync(path.join(gitDir, '.env'), 'HIDDEN=1\n');

    assert.deepEqual(findEnvFiles(fixtureDir, 4), [],
      'neither node_modules/.env nor .git/.env must be found — SKIP_DIRS must not be recursed into');
  });

  it('does not recurse into dot-prefixed directories other than the walk root', () => {
    const dotDir = path.join(fixtureDir, '.hidden');
    fs.mkdirSync(dotDir);
    fs.writeFileSync(path.join(dotDir, '.env'), 'HIDDEN=1\n');
    assert.deepEqual(findEnvFiles(fixtureDir, 4), []);
  });

  it('skips a symlinked .env entry unconditionally (M-6)', () => {
    const realEnv = path.join(fixtureDir, 'real.env.target');
    fs.writeFileSync(realEnv, 'SECRET=1\n');
    const linkPath = path.join(fixtureDir, '.env');
    fs.symlinkSync(realEnv, linkPath);

    assert.deepEqual(findEnvFiles(fixtureDir, 4), [], 'a symlinked .env must be skipped, not followed/reported');
  });

  it('readdirSync throws (permission-denied subdir): caught, walk continues, other .env still found', { skip: runningAsRoot }, () => {
    const locked = path.join(fixtureDir, 'locked');
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, '.env'), 'LOCKED=1\n');
    fs.chmodSync(locked, 0o000);

    fs.writeFileSync(path.join(fixtureDir, '.env'), 'ROOT=1\n');

    const found = findEnvFiles(fixtureDir, 4);
    assert.deepEqual(found, [path.join(fixtureDir, '.env')], 'the permission-denied subdir must be skipped, not crash the walk');
  });

  it('depth boundary: a default maxDepth (4) finds a .env within range', () => {
    // Build nested/1/2/3/.env (depth 4 — within default bound).
    let dir = fixtureDir;
    for (let i = 1; i <= 3; i++) {
      dir = path.join(dir, `d${i}`);
      fs.mkdirSync(dir);
    }
    fs.writeFileSync(path.join(dir, '.env'), 'A=1\n');
    const found = findEnvFiles(fixtureDir, 4);
    assert.deepEqual(found, [path.join(dir, '.env')]);
  });

  it('depth boundary: a custom smaller maxDepth stops recursion before reaching a deep .env', () => {
    let dir = fixtureDir;
    for (let i = 1; i <= 3; i++) {
      dir = path.join(dir, `d${i}`);
      fs.mkdirSync(dir);
    }
    fs.writeFileSync(path.join(dir, '.env'), 'A=1\n');
    // maxDepth=1 stops recursion after the first level — the depth-3 .env
    // must NOT be found.
    const found = findEnvFiles(fixtureDir, 1);
    assert.deepEqual(found, []);
  });

  it('security regression (V5): a maliciously deep tree confirms the maxDepth guard bounds recursion (DoS)', () => {
    let dir = fixtureDir;
    const depth = 50;
    for (let i = 0; i < depth; i++) {
      dir = path.join(dir, `level${i}`);
      fs.mkdirSync(dir);
    }
    fs.writeFileSync(path.join(dir, '.env'), 'DEEP=1\n');

    // Default maxDepth (4) must bound the walk — a .env 50 levels deep must
    // not be reached, proving recursion does not walk unboundedly.
    const found = findEnvFiles(fixtureDir, 4);
    assert.deepEqual(found, [], 'recursion must stop at the maxDepth guard, not walk all 50 levels');
  });
});

// ---------------------------------------------------------------------------
// scan() dangerous-file block (REQUIRED per D-07) — os.homedir sandboxed
// ---------------------------------------------------------------------------
describe('scan() dangerous-file block', () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');

  let sandboxHome;
  let originalOsEntry;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-dangerous-home-'));
    originalOsEntry = require.cache[osPath];
  });

  afterEach(() => {
    // Restore the real os module and evict the stub-bound scan.js so later
    // suites in this process never see the sandboxed homedir.
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];

    fs.rmSync(sandboxHome, { recursive: true, force: true });
  });

  it('dangerous-file block: zero found (empty sandbox HOME, header absent)', async () => {
    const { scan } = stubHomedir(sandboxHome, scanPath);

    const { logs } = await captureLog(() => scan({}, {}));

    const output = logs.join('\n');
    assert.ok(!output.includes('Credential files accessible to agents:'), 'the dangerous-file header must NOT print when nothing is found');
  });

  it('dangerous-file block: one or more found (seeded sandbox HOME, header + both paths present)', async () => {
    const { scan } = stubHomedir(sandboxHome, scanPath);

    const awsDir = path.join(sandboxHome, '.aws');
    fs.mkdirSync(awsDir, { recursive: true });
    const awsCreds = path.join(awsDir, 'credentials');
    fs.writeFileSync(awsCreds, '[default]\naws_access_key_id = FAKE\naws_secret_access_key = FAKE\n');

    const npmrc = path.join(sandboxHome, '.npmrc');
    fs.writeFileSync(npmrc, '//registry.npmjs.org/:_authToken=FAKE\n');

    const { logs } = await captureLog(() => scan({}, {}));

    const output = logs.join('\n');
    assert.ok(output.includes('Credential files accessible to agents:'), 'the dangerous-file header must print when seeded files are found');
    assert.ok(output.includes(awsCreds), 'the seeded .aws/credentials path must be listed');
    assert.ok(output.includes(npmrc), 'the seeded .npmrc path must be listed');
  });

  it('scanForEnvFiles() also resolves deterministically against the sandbox (SCAN_DIRS do not exist there)', () => {
    const { scanForEnvFiles } = stubHomedir(sandboxHome, scanPath);
    assert.deepEqual(scanForEnvFiles(), [], 'none of the six SCAN_DIRS exist in an empty sandbox HOME');
  });
});
