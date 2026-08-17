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

const { stubHomedir, installStub } = require('./helpers/module-stub.js');
const { captureLog } = require('./helpers/capture-log.js');

const { findEnvFiles, findEnvFilesDetailed, scanForEnvFiles, scan, buildCauseClauses, remedyForCause } = require('../lib/scan.js');

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
  let cwdSandbox;
  let originalOsEntry;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-dangerous-home-'));
    // G-1621: an explicit, independent, non-project cwd sandbox. Once the
    // zero-default-root cwd fallback (D-20-01) lands, an empty sandbox HOME
    // resolves zero default roots — without this, these tests would run
    // with the REAL llm-safe-haven repo as `process.cwd()` (it has both
    // .git and package.json) and silently start scanning the actual
    // working tree instead of the fixture this describe block controls
    // (research Pitfall 1). Neither marker exists here, so the fallback
    // does not fire and the run reports incomplete/no-root instead.
    cwdSandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-dangerous-cwd-'));
    originalOsEntry = require.cache[osPath];
  });

  afterEach(() => {
    // Restore the real os module and evict the stub-bound scan.js so later
    // suites in this process never see the sandboxed homedir.
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];

    fs.rmSync(sandboxHome, { recursive: true, force: true });
    fs.rmSync(cwdSandbox, { recursive: true, force: true });
  });

  it('dangerous-file block: zero found (empty sandbox HOME, header absent) [G-1621: pins an explicit non-project cwd — the prior pin let a naive zero-root fallback silently scan the real repo]', async () => {
    const { scan } = stubHomedir(sandboxHome, scanPath);

    const { logs } = await captureLog(() => scan({}, { cwd: cwdSandbox }));

    const output = logs.join('\n');
    assert.ok(!output.includes('Credential files accessible to agents:'), 'the dangerous-file header must NOT print when nothing is found');
  });

  it('dangerous-file block: one or more found (seeded sandbox HOME, header + both paths present) [G-1621: same explicit non-project cwd as the previous case]', async () => {
    const { scan } = stubHomedir(sandboxHome, scanPath);

    const awsDir = path.join(sandboxHome, '.aws');
    fs.mkdirSync(awsDir, { recursive: true });
    const awsCreds = path.join(awsDir, 'credentials');
    fs.writeFileSync(awsCreds, '[default]\naws_access_key_id = FAKE\naws_secret_access_key = FAKE\n');

    const npmrc = path.join(sandboxHome, '.npmrc');
    fs.writeFileSync(npmrc, '//registry.npmjs.org/:_authToken=FAKE\n');

    const { logs } = await captureLog(() => scan({}, { cwd: cwdSandbox }));

    const output = logs.join('\n');
    assert.ok(output.includes('Credential files accessible to agents:'), 'the dangerous-file header must print when seeded files are found');
    assert.ok(output.includes(awsCreds), 'the seeded .aws/credentials path must be listed');
    assert.ok(output.includes(npmrc), 'the seeded .npmrc path must be listed');
  });

  it('scanForEnvFiles() also resolves deterministically against the sandbox (SCAN_DIRS do not exist there) [G-1621: the [] this returns is no longer readable as "clean" on its own — asserted alongside scanForEnvFilesDetailed() in the same case, which now reports incomplete]', () => {
    const { scanForEnvFiles, scanForEnvFilesDetailed } = stubHomedir(sandboxHome, scanPath);
    assert.deepEqual(scanForEnvFiles({ cwd: cwdSandbox }), [], 'none of the six SCAN_DIRS exist in an empty sandbox HOME');

    const detail = scanForEnvFilesDetailed({ cwd: cwdSandbox });
    assert.deepEqual(detail.files, [], 'the detailed accessor agrees on the empty file list');
    assert.equal(detail.incomplete, true, 'G-1621: zero default roots plus a non-project cwd must be incomplete, never silently clean');
    assert.equal(detail.rootResolution.unresolved, true, 'the run must record that no scan root could be resolved');
  });
});

// ---------------------------------------------------------------------------
// Engine adoption (plan 17-13, D-23) — findEnvFiles/scanForEnvFiles are now
// thin wrappers over the shared traversal engine's `env-secrets` class
// instead of a hand-rolled recursive fs.readdirSync walk. These tests are
// ADDITIVE — every describe block above this comment is unmodified from the
// pre-adoption implementation and is the semantic oracle these prove against.
// ---------------------------------------------------------------------------
describe('findEnvFilesDetailed — additive export (D-23 engine adoption)', () => {
  let fixtureDir;

  beforeEach(() => {
    fixtureDir = mkFixture();
  });

  afterEach(() => {
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it('is exported as a function, additive to findEnvFiles (same shape it always returned)', () => {
    assert.equal(typeof findEnvFilesDetailed, 'function');
  });

  it('returns { files, skips } — files matches findEnvFiles() exactly for the same inputs', () => {
    fs.writeFileSync(path.join(fixtureDir, '.env'), 'SECRET=1\n');
    const detailed = findEnvFilesDetailed(fixtureDir, 4);
    assert.deepEqual(detailed.files, [path.join(fixtureDir, '.env')]);
    assert.deepEqual(detailed.files, findEnvFiles(fixtureDir, 4));
    assert.equal(typeof detailed.skips.total, 'function', 'skips is a SkipInventory (add/counts/paths/total)');
  });

  // Guard 1 (G-1511, TRAV-14): findEnvFilesDetailed() both directions —
  // incomplete === false for an ordinary small fixture, incomplete === true
  // when the underlying engine enumeration truncates.
  it('incomplete is false for an ordinary small fixture', () => {
    fs.writeFileSync(path.join(fixtureDir, '.env'), 'SECRET=1\n');
    const detailed = findEnvFilesDetailed(fixtureDir, 4);
    assert.equal(detailed.incomplete, false);
  });

  it('incomplete is true when LSH_MAX_FILES truncates the enumeration; truncated files is a subset of the complete run (G-1511, TRAV-14)', () => {
    for (let i = 0; i < 5; i++) {
      fs.writeFileSync(path.join(fixtureDir, `.env.variant${i}`), `SECRET_${i}=1\n`);
    }
    for (let i = 0; i < 10; i++) {
      fs.writeFileSync(path.join(fixtureDir, `noise-${i}.txt`), 'not a secret\n');
    }

    const complete = findEnvFilesDetailed(fixtureDir, 4);
    assert.equal(complete.incomplete, false, 'precondition: the untruncated run over this small fixture must itself be complete');
    assert.equal(complete.files.length, 5, 'precondition: all 5 planted .env variants must be found in the untruncated run');

    const originalMaxFiles = process.env.LSH_MAX_FILES;
    try {
      process.env.LSH_MAX_FILES = '3';
      const truncated = findEnvFilesDetailed(fixtureDir, 4);
      assert.equal(truncated.incomplete, true, 'LSH_MAX_FILES=3 over 15 entries must truncate the enumeration');
      assert.ok(
        truncated.files.length < complete.files.length,
        `truncated run must find strictly fewer files than the complete run (${truncated.files.length} vs ${complete.files.length})`
      );
      assert.ok(
        truncated.files.every((f) => complete.files.includes(f)),
        'every truncated-run file must also appear in the complete run — a genuine subset, not a different set'
      );
    } finally {
      if (originalMaxFiles === undefined) delete process.env.LSH_MAX_FILES;
      else process.env.LSH_MAX_FILES = originalMaxFiles;
    }
  });
});

// ---------------------------------------------------------------------------
// Guard 2 (G-1511, TRAV-14): scanForEnvFiles() is unchanged — pinned as a
// thin wrapper over scanForEnvFilesDetailed().files, the frozen accessor's
// signature and return type provably untouched by the additive export.
// ---------------------------------------------------------------------------
describe('scanForEnvFiles / scanForEnvFilesDetailed — the frozen accessor is a thin wrapper over the additive one (G-1511, TRAV-14)', () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');

  let sandboxHome;
  let originalOsEntry;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-frozen-accessor-'));
    originalOsEntry = require.cache[osPath];
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];
    fs.rmSync(sandboxHome, { recursive: true, force: true });
  });

  it('scanForEnvFilesDetailed().files deep-equals scanForEnvFiles() for the same sandbox', () => {
    const projectsDir = path.join(sandboxHome, 'Projects');
    fs.mkdirSync(projectsDir, { recursive: true });
    fs.writeFileSync(path.join(projectsDir, '.env'), 'SECRET=1\n');

    const { scanForEnvFiles: sef, scanForEnvFilesDetailed: sefd } = stubHomedir(sandboxHome, scanPath);
    assert.deepEqual(sefd().files, sef(), 'the additive accessor\'s .files and the frozen accessor\'s return value must be identical');
  });

  it('scanForEnvFiles() still returns a bare Array (not an object)', () => {
    const { scanForEnvFiles: sef } = stubHomedir(sandboxHome, scanPath);
    assert.ok(Array.isArray(sef()), 'scanForEnvFiles() must still return a bare array — every existing consumer depends on this shape');
  });
});

describe('scan.js spawns zero subprocesses (env-secrets is TARGETED tier — T-17-02)', () => {
  const cpPath = require.resolve('child_process');
  const scanPath = require.resolve('../lib/scan.js');
  const realChildProcess = require('child_process');

  let callCount;
  let preStubEntry;

  beforeEach(() => {
    callCount = 0;
    preStubEntry = Object.prototype.hasOwnProperty.call(require.cache, cpPath) ? require.cache[cpPath] : undefined;
    installStub(cpPath, {
      ...realChildProcess,
      spawnSync: (...args) => {
        callCount += 1;
        return realChildProcess.spawnSync(...args);
      },
    });
  });

  afterEach(() => {
    if (preStubEntry === undefined) delete require.cache[cpPath];
    else require.cache[cpPath] = preStubEntry;
  });

  it('scanForEnvFiles() never calls spawnSync — count is exactly 0', () => {
    // lib/traverse/index.js's normalizeOptions() calls require('child_process')
    // lazily, per Traversal call, so the stub installed above is picked up
    // without needing to evict/re-require lib/scan.js itself.
    scanForEnvFiles();
    assert.equal(callCount, 0, 'the env-secrets class must never consult git — no subprocess should be spawned');
  });
});

// ---------------------------------------------------------------------------
// Semantic identity (plan 17-13 Task 3, T-17-05) — one fixture tree exercising
// every suffix/skip/symlink/depth branch at once, asserted with an EXACT
// expected array (not a subset or a length). This is the oracle: the
// pre-adoption implementation, exercised branch-by-branch in every describe
// block above, produced exactly this same array for this same tree.
// ---------------------------------------------------------------------------
describe('semantic identity — engine-backed findEnvFiles matches pre-adoption byte-for-byte (T-17-05)', () => {
  let fixtureDir;

  beforeEach(() => {
    fixtureDir = mkFixture();
  });

  afterEach(() => {
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it('exact expected array across suffix/skip/symlink/depth cases combined, including sorted+deduplicated', () => {
    // exact .env and dotted-suffix variants -- must be found.
    fs.writeFileSync(path.join(fixtureDir, '.env'), 'A=1\n');
    fs.writeFileSync(path.join(fixtureDir, '.env.local'), 'A=1\n');
    fs.writeFileSync(path.join(fixtureDir, '.env.production'), 'A=1\n');

    // allowlisted suffixes -- must NOT be found.
    fs.writeFileSync(path.join(fixtureDir, '.env.example'), 'A=1\n');
    fs.writeFileSync(path.join(fixtureDir, '.env.template'), 'A=1\n');
    fs.writeFileSync(path.join(fixtureDir, '.env.sample'), 'A=1\n');

    // node_modules -- SKIP_DIRS, must NOT be found.
    const nodeModules = path.join(fixtureDir, 'node_modules');
    fs.mkdirSync(nodeModules);
    fs.writeFileSync(path.join(nodeModules, '.env'), 'HIDDEN=1\n');

    // dot-directory -- blanket skip, must NOT be found.
    const hiddenDir = path.join(fixtureDir, '.hidden');
    fs.mkdirSync(hiddenDir);
    fs.writeFileSync(path.join(hiddenDir, '.env'), 'HIDDEN=1\n');

    // a symlinked .env -- never followed, must NOT be found.
    const symDir = path.join(fixtureDir, 'symdir');
    fs.mkdirSync(symDir);
    const symTarget = path.join(symDir, 'real.env.target');
    fs.writeFileSync(symTarget, 'SECRET=1\n');
    fs.symlinkSync(symTarget, path.join(symDir, '.env'));

    // within the default maxDepth(4) bound (3 nested dirs -- same shape as
    // the pre-existing depth-boundary pin) -- must be found.
    let withinDir = fixtureDir;
    for (let i = 1; i <= 3; i++) {
      withinDir = path.join(withinDir, `d${i}`);
      fs.mkdirSync(withinDir);
    }
    fs.writeFileSync(path.join(withinDir, '.env'), 'DEEP=1\n');

    // five levels deep -- exceeds the default maxDepth(4) bound, must NOT be
    // found (the 5th-level directory itself is never readdir'd).
    let tooDeepDir = fixtureDir;
    for (let i = 1; i <= 5; i++) {
      tooDeepDir = path.join(tooDeepDir, `x${i}`);
      fs.mkdirSync(tooDeepDir);
    }
    fs.writeFileSync(path.join(tooDeepDir, '.env'), 'TOO_DEEP=1\n');

    const expected = [
      path.join(fixtureDir, '.env'),
      path.join(fixtureDir, '.env.local'),
      path.join(fixtureDir, '.env.production'),
      path.join(withinDir, '.env'),
    ].sort();

    const found = findEnvFiles(fixtureDir, 4).sort();
    assert.deepEqual(found, expected);

    // Sorted-and-deduplicated property: seed a duplicate path through two
    // roots (the same fixture directory used twice, mirroring
    // scanForEnvFiles()'s own combine-then-dedupe-then-sort step over
    // multiple SCAN_DIRS/getRoots() entries).
    const combined = [...findEnvFiles(fixtureDir, 4), ...findEnvFiles(fixtureDir, 4)];
    const deduped = [...new Set(combined)].sort();
    assert.deepEqual(deduped, expected, 'duplicate discovery across two roots collapses to one sorted, deduplicated entry per path');
  });
});

// ---------------------------------------------------------------------------
// Skip accounting (new capability, T-17-11) — findEnvFilesDetailed() now
// counts skips the pre-adoption walk silently swallowed.
// ---------------------------------------------------------------------------
describe('skip accounting (new capability) — findEnvFilesDetailed counts symlink/unreadable skips', () => {
  let fixtureDir;

  beforeEach(() => {
    fixtureDir = mkFixture();
  });

  afterEach(() => {
    try {
      fs.chmodSync(path.join(fixtureDir, 'locked'), 0o755);
    } catch {
      // Directory may not exist in every test — fine.
    }
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it('counts at least one symlink skip', () => {
    const realTarget = path.join(fixtureDir, 'real.env.target');
    fs.writeFileSync(realTarget, 'SECRET=1\n');
    fs.symlinkSync(realTarget, path.join(fixtureDir, '.env'));

    const { files, skips } = findEnvFilesDetailed(fixtureDir, 4);
    assert.deepEqual(files, [], 'the symlinked .env must not be reported as found');
    assert.ok(skips.counts().symlink >= 1, 'the symlinked .env must be counted as a symlink skip');
  });

  it('counts one unreadable skip on a permission-denied subdirectory', { skip: runningAsRoot }, () => {
    const locked = path.join(fixtureDir, 'locked');
    fs.mkdirSync(locked);
    fs.chmodSync(locked, 0o000);

    const { skips } = findEnvFilesDetailed(fixtureDir, 4);
    assert.ok(skips.counts().unreadable >= 1, 'the permission-denied subdirectory must be counted as an unreadable skip');
  });
});

// ---------------------------------------------------------------------------
// Guard 3 (G-1511, TRAV-14): scan()'s return contract — a truncated .env
// enumeration returns { code: 2 } (never undefined/implicit exit 0); a
// complete, clean enumeration still returns undefined exactly as before.
// LSH_ROOTS is pinned to a fixture directory inside a stubbed sandbox
// homedir (D-08's override, not merge) so this is fast and deterministic —
// the six real default roots are never touched.
// ---------------------------------------------------------------------------
describe("scan()'s return contract — a truncated .env scan returns { code: 2 }, a complete clean scan returns undefined (G-1511, TRAV-14)", () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');

  let sandboxHome;
  let fixtureDir;
  let originalOsEntry;
  let originalLshRoots;
  let originalLshMaxFiles;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-return-contract-'));
    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-return-contract-root-'));
    originalOsEntry = require.cache[osPath];
    originalLshRoots = process.env.LSH_ROOTS;
    originalLshMaxFiles = process.env.LSH_MAX_FILES;
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];
    if (originalLshRoots === undefined) delete process.env.LSH_ROOTS;
    else process.env.LSH_ROOTS = originalLshRoots;
    if (originalLshMaxFiles === undefined) delete process.env.LSH_MAX_FILES;
    else process.env.LSH_MAX_FILES = originalLshMaxFiles;
    fs.rmSync(sandboxHome, { recursive: true, force: true });
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it('a truncated enumeration (LSH_MAX_FILES small) returns { code: 2 } and prints the diagnostic to stderr only, never stdout', async () => {
    for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(fixtureDir, `noise-${i}.txt`), 'x\n');
    process.env.LSH_ROOTS = fixtureDir;
    process.env.LSH_MAX_FILES = '2';

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      const { logs, result } = await captureLog(() => sandboxedScan({}, {}));
      assert.deepEqual(result, { code: 2 }, 'a truncated .env enumeration must return { code: 2 }, never undefined');
      assert.ok(
        stderrLines.some((l) => l.includes('did not finish') && l.includes('incomplete')),
        `expected an incomplete-scan diagnostic on stderr, got: ${stderrLines}`
      );
      assert.ok(
        !logs.some((l) => l.includes('did not finish')),
        'the incomplete-scan diagnostic must go to stderr, never stdout — the scorecard owns stdout'
      );
    } finally {
      console.error = originalError;
    }
  });

  it('paired control: the same fixture with no LSH_MAX_FILES override returns undefined (implicit exit 0), no stderr diagnostic', async () => {
    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      const { result } = await captureLog(() => sandboxedScan({}, {}));
      assert.strictEqual(result, undefined, 'a complete, clean .env enumeration must return undefined, exactly as before G-1511');
      assert.equal(stderrLines.length, 0, 'a complete, clean scan must print no incomplete-scan diagnostic');
    } finally {
      console.error = originalError;
    }
  });
});

// ---------------------------------------------------------------------------
// G-1504 / D-03 (17.1-CONTEXT.md): scanForEnvFilesDetailed() must fold a
// configured-but-missing LSH_ROOTS entry into `incomplete`, mirroring
// lib/traverse/run.js's own onMissingRoot wiring (found missing here by
// cross-model review — B3/G-1504). Same fixture-plus-sandbox-HOME pattern
// as the return-contract describe block above: LSH_ROOTS is pinned so the
// six real default roots are never touched.
// ---------------------------------------------------------------------------
describe("scan()'s return contract — a missing configured LSH_ROOTS entry also returns { code: 2 } with a stderr warning (G-1504, D-03)", () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');

  let sandboxHome;
  let fixtureDir;
  let originalOsEntry;
  let originalLshRoots;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-missing-root-'));
    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-missing-root-existing-'));
    originalOsEntry = require.cache[osPath];
    originalLshRoots = process.env.LSH_ROOTS;
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];
    if (originalLshRoots === undefined) delete process.env.LSH_ROOTS;
    else process.env.LSH_ROOTS = originalLshRoots;
    fs.rmSync(sandboxHome, { recursive: true, force: true });
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it('a missing configured root (LSH_ROOTS) returns { code: 2 } and prints a stderr warning naming the path, never on stdout', async () => {
    const missingRoot = path.join(fixtureDir, 'definitely-does-not-exist-xyz');
    process.env.LSH_ROOTS = missingRoot;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      const { logs, result } = await captureLog(() => sandboxedScan({}, {}));
      assert.deepEqual(result, { code: 2 }, 'a missing configured root must return { code: 2 }, never undefined');
      assert.ok(
        stderrLines.some((l) => l.includes('configured scan root does not exist') && l.includes(missingRoot)),
        `expected a stderr warning naming ${missingRoot}, got: ${stderrLines}`
      );
      assert.ok(
        stderrLines.some((l) => l.includes('did not finish') && l.includes('incomplete')),
        `expected the incomplete-scan diagnostic on stderr too, got: ${stderrLines}`
      );
      assert.ok(
        !logs.some((l) => l.includes(missingRoot) || l.includes('did not finish')),
        'neither the missing-root warning nor the incomplete-scan diagnostic must reach stdout'
      );
    } finally {
      console.error = originalError;
    }
  });

  it('paired control: LSH_ROOTS pointing at an existing, empty directory returns undefined (implicit exit 0), no missing-root warning', async () => {
    process.env.LSH_ROOTS = fixtureDir;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      const { result } = await captureLog(() => sandboxedScan({}, {}));
      assert.strictEqual(result, undefined, 'a fully-present, clean root set must return undefined, exactly as before G-1504');
      assert.equal(stderrLines.length, 0, 'a fully-present root set must print no missing-root warning and no incomplete diagnostic');
    } finally {
      console.error = originalError;
    }
  });

  it('a missing root listed twice in LSH_ROOTS prints the stderr warning exactly once (dedup, mirroring run.js)', async () => {
    const missingRoot = path.join(fixtureDir, 'definitely-does-not-exist-xyz');
    process.env.LSH_ROOTS = `${missingRoot}:${missingRoot}`;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      await captureLog(() => sandboxedScan({}, {}));
      const warningLines = stderrLines.filter((l) => l.includes('configured scan root does not exist') && l.includes(missingRoot));
      assert.equal(warningLines.length, 1, `expected exactly one deduped warning line, got: ${warningLines}`);
    } finally {
      console.error = originalError;
    }
  });
});

// ---------------------------------------------------------------------------
// D-07a (G-1545, worst defect in the phase) — a `.env` behind an unreadable
// directory must never render as a green check and must never exit 0. This
// block makes the reproduction permanent, pins review C-1's next-steps fix
// (an incomplete scan that found no .env files must not tell the operator to
// remove .env files), and pins review C-4's cause-branching (budget,
// unreadable and root causes must never render as the same sentence).
// Sandbox-HOME + LSH_ROOTS idiom copied from the return-contract describe
// block above (:507-580).
// ---------------------------------------------------------------------------
describe('D-07a — an unreadable directory can no longer render a green check or exit 0 (G-1545, review C-1/C-4)', () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');
  const skipUnreadableFixtures = process.platform === 'win32' || runningAsRoot;

  let sandboxHome;
  let fixtureDir;
  let originalOsEntry;
  let originalLshRoots;
  let originalLshMaxFiles;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-d07a-home-'));
    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-d07a-root-'));
    originalOsEntry = require.cache[osPath];
    originalLshRoots = process.env.LSH_ROOTS;
    originalLshMaxFiles = process.env.LSH_MAX_FILES;
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];
    if (originalLshRoots === undefined) delete process.env.LSH_ROOTS;
    else process.env.LSH_ROOTS = originalLshRoots;
    if (originalLshMaxFiles === undefined) delete process.env.LSH_MAX_FILES;
    else process.env.LSH_MAX_FILES = originalLshMaxFiles;
    fs.rmSync(sandboxHome, { recursive: true, force: true });
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  async function runScanWithStderr(sandboxedScan) {
    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      const { logs, result } = await captureLog(() => sandboxedScan({}, {}));
      return { logs, result, stderrLines };
    } finally {
      console.error = originalError;
    }
  }

  it('the D-07a reproduction: a .env behind a mode-000 directory returns { code: 2 }, prints NO green line, and reports the could-not-verify state', { skip: skipUnreadableFixtures }, async () => {
    const locked = path.join(fixtureDir, 'locked-secret');
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, '.env'), 'SECRET_TOKEN=abc123\n');
    fs.chmodSync(locked, 0o000);

    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    try {
      const { logs, result, stderrLines } = await runScanWithStderr(sandboxedScan);
      assert.deepEqual(result, { code: 2 }, 'a .env behind an unreadable directory must return { code: 2 }, never undefined');
      assert.ok(!logs.some((l) => l.includes('No .env files found')), 'no captured stdout line may print the green "No .env files found" check');
      assert.ok(logs.some((l) => l.includes('could not verify')), `expected a could-not-verify line on stdout, got: ${logs}`);
      assert.ok(
        stderrLines.some((l) => l.includes('did not finish') && l.includes('incomplete')),
        `expected an incomplete-scan diagnostic on stderr, got: ${stderrLines}`
      );
      assert.ok(!logs.some((l) => l.includes('did not finish')), 'the incomplete-scan diagnostic must stay on stderr, never stdout — the scorecard owns stdout');
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });

  it('review C-1: the next-steps block names the unreadable remedy, never the "remove .env files" sentence, for an incomplete scan that found none', { skip: skipUnreadableFixtures }, async () => {
    const locked = path.join(fixtureDir, 'locked-secret');
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, '.env'), 'SECRET_TOKEN=abc123\n');
    fs.chmodSync(locked, 0o000);

    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    try {
      const { logs } = await runScanWithStderr(sandboxedScan);
      // Negative needle FIRST (review C-1's own break-proof reverts the
      // dedicated block back to printNextSteps(1) -- that must fail THIS
      // assertion, not merely leave the positive one unmatched, so the two
      // are asserted independently rather than short-circuiting together).
      assert.ok(
        !logs.some((l) => l.includes('Set up audit logging and remove .env files')),
        'an incomplete scan which found no .env files must NEVER tell the operator to remove .env files — that is review C-1\'s whole point'
      );
      assert.ok(
        logs.some((l) => l.includes('Restore read access to the paths the scan could not read, then re-run npx llm-safe-haven scan')),
        `expected the pinned unreadable-cause remedy sentence verbatim, got: ${logs.join('\n')}`
      );
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });

  it('review C-4: the unreadable cause renders its own clause, never the budget or root wording', { skip: skipUnreadableFixtures }, async () => {
    const locked = path.join(fixtureDir, 'locked-secret');
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, '.env'), 'SECRET_TOKEN=abc123\n');
    fs.chmodSync(locked, 0o000);

    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    try {
      const { logs } = await runScanWithStderr(sandboxedScan);
      const output = logs.join('\n');
      assert.ok(output.includes('path(s) could not be read'), `expected the unreadable clause, got: ${output}`);
      assert.ok(!output.includes('stopped early'), 'a counter that sums several reasons must not render the budget clause when only unreadable fired');
      assert.ok(!output.includes('configured scan root(s) could not be resolved'), 'a counter that sums several reasons must not render the root clause when only unreadable fired');
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });

  it('review C-4: the budget cause renders its own clause, never the unreadable or root wording', async () => {
    for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(fixtureDir, `noise-${i}.txt`), 'x\n');
    process.env.LSH_ROOTS = fixtureDir;
    process.env.LSH_MAX_FILES = '2';

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const { logs } = await runScanWithStderr(sandboxedScan);
    const output = logs.join('\n');
    assert.ok(output.includes('stopped early'), `expected the budget clause, got: ${output}`);
    assert.ok(!output.includes('path(s) could not be read'), 'a counter that sums several reasons must not render the unreadable clause when only budget fired');
    assert.ok(!output.includes('configured scan root(s) could not be resolved'), 'a counter that sums several reasons must not render the root clause when only budget fired');
  });

  it('review C-4: the root cause renders its own clause, never the budget or unreadable wording', async () => {
    process.env.LSH_ROOTS = path.join(fixtureDir, 'does-not-exist-xyz');
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const { logs } = await runScanWithStderr(sandboxedScan);
    const output = logs.join('\n');
    assert.ok(output.includes('configured scan root(s) could not be resolved'), `expected the root clause, got: ${output}`);
    assert.ok(!output.includes('stopped early'), 'a counter that sums several reasons must not render the budget clause when only a missing root fired');
    assert.ok(!output.includes('path(s) could not be read'), 'a counter that sums several reasons must not render the unreadable clause when only a missing root fired');
  });

  it('PAIRED CONTROL: the same fixture, readable, finds the .env and prints no could-not-verify line', { skip: skipUnreadableFixtures }, async () => {
    const readable = path.join(fixtureDir, 'readable-secret');
    fs.mkdirSync(readable);
    fs.writeFileSync(path.join(readable, '.env'), 'SECRET_TOKEN=abc123\n');
    fs.chmodSync(readable, 0o755);

    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const { logs } = await runScanWithStderr(sandboxedScan);
    assert.ok(logs.some((l) => l.includes('.env file(s) found')), `expected the .env to be found, got: ${logs.join('\n')}`);
    assert.ok(!logs.some((l) => l.includes('could not verify')), 'a fully readable tree must never print the could-not-verify line');
  });

  it('PAIRED CONTROL: a readable, complete, empty root stays green — undefined result, standard next steps, no could-not-verify line', async () => {
    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const { logs, result } = await runScanWithStderr(sandboxedScan);
    assert.strictEqual(result, undefined, 'a complete, clean scan must return undefined, byte-identical to before this plan');
    assert.ok(logs.some((l) => l.includes('No .env files found')), 'the green line must still print for a clean, complete scan');
    assert.ok(logs.some((l) => l.includes('Next steps:')), 'the standard next-steps block must still render');
    assert.ok(!logs.some((l) => l.includes('could not verify')), 'a clean, complete scan must never print the could-not-verify line');
  });

  it('PAIRED CONTROL: findings AND incomplete both render — the middle branch of the shared renderer', { skip: skipUnreadableFixtures }, async () => {
    fs.writeFileSync(path.join(fixtureDir, '.env'), 'SECRET_TOKEN=abc123\n');
    const lockedSibling = path.join(fixtureDir, 'locked-sibling');
    fs.mkdirSync(lockedSibling);
    fs.chmodSync(lockedSibling, 0o000);

    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    try {
      const { logs } = await runScanWithStderr(sandboxedScan);
      assert.ok(logs.some((l) => l.includes('.env file(s) found')), `expected the readable .env to be found and reported, got: ${logs.join('\n')}`);
      assert.ok(logs.some((l) => l.includes('could not verify')), `expected the could-not-verify line alongside the findings, got: ${logs.join('\n')}`);
    } finally {
      fs.chmodSync(lockedSibling, 0o755);
    }
  });
});

// ---------------------------------------------------------------------------
// EXIT-01 (G-1545, D-04) — scan()'s exit code is now produced by
// computeExit(), not a hand-rolled ladder: a `.env` finding exits 1, a
// clean/complete scan still returns `undefined`, an incomplete-with-findings
// scan exits 1 (D-18: findings beat incompleteness), an incomplete-with-no-
// findings scan still exits 2 (Task 1's case, unchanged), and the
// credential-file list can never drive the exit code (Pitfall 3 / D-02b).
// Sandbox-HOME + LSH_ROOTS idiom copied from the return-contract describe
// block above (:507-580).
// ---------------------------------------------------------------------------
describe('EXIT-01 — scan() routes its exit code through computeExit() (G-1545, D-04, D-18)', () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');
  const skipUnreadableFixtures = process.platform === 'win32' || runningAsRoot;

  let sandboxHome;
  let fixtureDir;
  let originalOsEntry;
  let originalLshRoots;
  let originalLshMaxFiles;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-exit01-home-'));
    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-exit01-root-'));
    originalOsEntry = require.cache[osPath];
    originalLshRoots = process.env.LSH_ROOTS;
    originalLshMaxFiles = process.env.LSH_MAX_FILES;
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];
    if (originalLshRoots === undefined) delete process.env.LSH_ROOTS;
    else process.env.LSH_ROOTS = originalLshRoots;
    if (originalLshMaxFiles === undefined) delete process.env.LSH_MAX_FILES;
    else process.env.LSH_MAX_FILES = originalLshMaxFiles;
    fs.rmSync(sandboxHome, { recursive: true, force: true });
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it('findings -> exit 1: a fixture root with a .env returns { code: 1 } and prints the red findings line', async () => {
    fs.writeFileSync(path.join(fixtureDir, '.env'), 'SECRET_TOKEN=abc123\n');
    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result } = await captureLog(() => sandboxedScan({}, {}));

    assert.deepEqual(result, { code: 1 }, 'a .env finding must return { code: 1 }, never undefined (implicit 0)');
    assert.ok(logs.some((l) => l.includes('.env file(s) found')), 'the red findings line must still print');
  });

  it('PAIRED CONTROL: clean -> undefined (re-confirms tests/scan.test.js:573/:654 still hold, unedited)', async () => {
    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { result } = await captureLog(() => sandboxedScan({}, {}));

    assert.strictEqual(result, undefined, 'a clean, complete scan must still return undefined, byte-identical to before this plan');
  });

  it('D-18 precedence: findings AND an incomplete enumeration -> exit 1, not 2', { skip: skipUnreadableFixtures }, async () => {
    fs.writeFileSync(path.join(fixtureDir, '.env'), 'SECRET_TOKEN=abc123\n');
    const lockedSibling = path.join(fixtureDir, 'locked-sibling');
    fs.mkdirSync(lockedSibling);
    fs.chmodSync(lockedSibling, 0o000);

    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    try {
      const { result } = await captureLog(() => sandboxedScan({}, {}));
      assert.deepEqual(result, { code: 1 }, 'D-18: a real .env finding must beat incompleteness — exit 1, not 2');
    } finally {
      fs.chmodSync(lockedSibling, 0o755);
    }
  });

  it('no findings AND incomplete -> exit 2, unchanged from Task 1', { skip: skipUnreadableFixtures }, async () => {
    const locked = path.join(fixtureDir, 'locked-secret');
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, '.env'), 'SECRET_TOKEN=abc123\n');
    fs.chmodSync(locked, 0o000);

    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    try {
      const { result } = await captureLog(() => sandboxedScan({}, {}));
      assert.deepEqual(result, { code: 2 }, 'zero findings plus incompleteness must still exit 2');
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });

  it('CRYING-WOLF CONTROL (Pitfall 3): a sandbox HOME with .npmrc and no .env still returns undefined', async () => {
    fs.writeFileSync(path.join(sandboxHome, '.npmrc'), '//registry.npmjs.org/:_authToken=FAKE\n');
    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result } = await captureLog(() => sandboxedScan({}, {}));

    assert.strictEqual(result, undefined, 'mapping dangerousFiles to fail would exit 1 on nearly every real developer machine — a D-02b-class regression');
    assert.ok(logs.some((l) => l.includes('Credential files accessible to agents:')), 'the credential-file block must still print (detected, just not fail-severity)');
  });

  it('CRYING-WOLF CONTROL (Pitfall 3): a sandbox HOME with .aws/credentials and no .env still returns undefined', async () => {
    const awsDir = path.join(sandboxHome, '.aws');
    fs.mkdirSync(awsDir, { recursive: true });
    fs.writeFileSync(path.join(awsDir, 'credentials'), '[default]\naws_access_key_id = FAKE\n');
    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result } = await captureLog(() => sandboxedScan({}, {}));

    assert.strictEqual(result, undefined, 'mapping dangerousFiles to fail would exit 1 on nearly every real developer machine — a D-02b-class regression');
    assert.ok(logs.some((l) => l.includes('Credential files accessible to agents:')), 'the credential-file block must still print (detected, just not fail-severity)');
  });

  it('synchronous-return guard: the env path never returns a thenable (lib/cli.js:122-127\'s requirement)', async () => {
    process.env.LSH_ROOTS = fixtureDir;
    delete process.env.LSH_MAX_FILES;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    let rawReturn;
    await captureLog(() => { rawReturn = sandboxedScan({}, {}); return rawReturn; });

    assert.strictEqual(rawReturn, undefined, 'a clean fixture returns undefined synchronously');
    assert.ok(
      !(rawReturn && typeof rawReturn.then === 'function'),
      'scan()\'s return value must never be a thenable — pins the sync-return contract so this path is never made async'
    );
  });
});

// ---------------------------------------------------------------------------
// EXIT-02 (G-1542, D-07b) — a configured root that exists but could not be
// READ (the parent lacks +x) is surfaced distinctly from a missing one, at
// the scan() caller level. Sandbox-HOME + LSH_ROOTS idiom copied from the
// return-contract describe block above (:507-580).
// ---------------------------------------------------------------------------
describe('EXIT-02 — an unreadable configured root is surfaced, distinctly from a missing one (G-1542, D-07b)', () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');
  const runningAsRootLocal = typeof process.getuid === 'function' && process.getuid() === 0;
  const skip = process.platform === 'win32' || runningAsRootLocal;

  let sandboxHome;
  let parentDir;
  let childDir;
  let originalOsEntry;
  let originalLshRoots;

  beforeEach(() => {
    sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-exit02-home-'));
    originalOsEntry = require.cache[osPath];
    originalLshRoots = process.env.LSH_ROOTS;
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];
    if (originalLshRoots === undefined) delete process.env.LSH_ROOTS;
    else process.env.LSH_ROOTS = originalLshRoots;
    fs.rmSync(sandboxHome, { recursive: true, force: true });
    if (parentDir) {
      try { fs.chmodSync(parentDir, 0o755); } catch { /* may not exist */ }
      fs.rmSync(parentDir, { recursive: true, force: true });
    }
    parentDir = childDir = undefined;
  });

  it('LSH_ROOTS under a mode-000 parent returns { code: 2 }, names the path and the errno, and never claims the root "does not exist"', { skip }, async () => {
    parentDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-exit02-parent-'));
    childDir = path.join(parentDir, 'child');
    fs.mkdirSync(childDir);
    fs.chmodSync(parentDir, 0o000);

    process.env.LSH_ROOTS = childDir;

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      const { result } = await captureLog(() => sandboxedScan({}, {}));
      assert.deepEqual(result, { code: 2 }, 'an unreadable configured root must return { code: 2 }');
      assert.ok(
        stderrLines.some((l) => l.includes(childDir) && l.includes('EACCES')),
        `expected a stderr line naming the path and the EACCES errno, got: ${stderrLines}`
      );
      assert.ok(
        !stderrLines.some((l) => l.includes(childDir) && l.includes('does not exist')),
        'the unreadable-root warning must NEVER claim the root "does not exist" — that wording is reserved for a genuinely absent root'
      );
    } finally {
      fs.chmodSync(parentDir, 0o755);
      console.error = originalError;
    }
  });

  it('PAIRED CONTROL: a readable root prints no unreadable-root warning and returns undefined', async () => {
    const readable = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-exit02-readable-'));
    try {
      process.env.LSH_ROOTS = readable;
      const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

      const originalError = console.error;
      const stderrLines = [];
      console.error = (msg) => { stderrLines.push(String(msg)); };
      try {
        const { result } = await captureLog(() => sandboxedScan({}, {}));
        assert.strictEqual(result, undefined, 'a fully readable root set must return undefined');
        assert.equal(stderrLines.length, 0, 'a fully readable root set must print no warning at all');
      } finally {
        console.error = originalError;
      }
    } finally {
      fs.rmSync(readable, { recursive: true, force: true });
    }
  });

  it('rootFailures.unreadable is non-zero on the unreadable-root fixture and zero on the readable control', { skip }, () => {
    parentDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-exit02-rf-parent-'));
    childDir = path.join(parentDir, 'child');
    fs.mkdirSync(childDir);
    fs.chmodSync(parentDir, 0o000);

    process.env.LSH_ROOTS = childDir;
    const { scanForEnvFilesDetailed } = stubHomedir(sandboxHome, scanPath);

    const originalError = console.error;
    console.error = () => {};
    let detailUnreadable;
    let detailReadable;
    try {
      detailUnreadable = scanForEnvFilesDetailed();
    } finally {
      fs.chmodSync(parentDir, 0o755);
      console.error = originalError;
    }

    const readable = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-exit02-rf-readable-'));
    try {
      process.env.LSH_ROOTS = readable;
      delete require.cache[scanPath];
      const { scanForEnvFilesDetailed: sefd2 } = stubHomedir(sandboxHome, scanPath);
      detailReadable = sefd2();
    } finally {
      fs.rmSync(readable, { recursive: true, force: true });
    }

    assert.ok(detailUnreadable.rootFailures.unreadable > 0, `expected rootFailures.unreadable > 0, got ${detailUnreadable.rootFailures.unreadable}`);
    assert.equal(detailReadable.rootFailures.unreadable, 0, 'a readable root must report rootFailures.unreadable === 0');
  });
});

// ---------------------------------------------------------------------------
// scan() zero default roots (EXIT-04, G-1621)
//
// D-20-01: when explicit LSH_ROOTS is NOT set and none of the six default
// root names exist, `scan` either scans `process.cwd()` (if it looks like a
// project — `.git` dir/file OR `package.json`) with exactly one stderr
// note, or reports incomplete/exit 2 through the EXISTING computeExit()
// plumbing. D-20-02: a HOME with 1..5 of 6 default roots present stays
// byte-identical to before this phase (mandatory paired control below).
//
// Structural rule (research Pitfall 1): every case here builds TWO
// independent fs.mkdtempSync sandboxes — one for HOME, one for cwd — so the
// project heuristic is controlled by the test, never by wherever this test
// PROCESS happens to run (the real repo has both .git and package.json, so
// an implicit cwd would silently start scanning it the moment the fallback
// lands).
// ---------------------------------------------------------------------------
describe('scan() zero default roots (EXIT-04, G-1621)', () => {
  const osPath = require.resolve('os');
  const scanPath = require.resolve('../lib/scan.js');

  let sandboxHome;
  let cwdSandbox;
  let originalOsEntry;

  function mkSandbox(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }

  beforeEach(() => {
    sandboxHome = mkSandbox('scan-nodefault-home-');
    originalOsEntry = require.cache[osPath];
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[scanPath];

    fs.rmSync(sandboxHome, { recursive: true, force: true });
    if (cwdSandbox) fs.rmSync(cwdSandbox, { recursive: true, force: true });
    cwdSandbox = undefined;
  });

  // Mirrors the existing local `runScanWithStderr` idiom at :721-731
  // (snapshot console.error, replace, restore in finally), parameterized
  // with the opts object so `cwd` can be threaded through per case.
  async function runScanWithStderr(sandboxedScan, opts) {
    const originalError = console.error;
    const stderrLines = [];
    console.error = (msg) => { stderrLines.push(String(msg)); };
    try {
      const { logs, result } = await captureLog(() => sandboxedScan({}, opts));
      return { logs, result, stderrLines };
    } finally {
      console.error = originalError;
    }
  }

  it('scanForEnvFilesDetailed({ cwd }) against a non-project cwd, empty sandbox HOME: [], incomplete, rootResolution.unresolved', () => {
    cwdSandbox = mkSandbox('scan-nodefault-nonproject-');
    const { scanForEnvFilesDetailed } = stubHomedir(sandboxHome, scanPath);

    const detail = scanForEnvFilesDetailed({ cwd: cwdSandbox });

    assert.deepEqual(detail.files, []);
    assert.equal(detail.incomplete, true);
    assert.deepEqual(detail.rootResolution, { unresolved: true, cwdFallback: null });
  });

  it('scanForEnvFilesDetailed({ cwd }) against a project cwd (package.json), empty sandbox HOME: reports the seeded .env, not incomplete', () => {
    cwdSandbox = mkSandbox('scan-nodefault-project-pkg-');
    fs.writeFileSync(path.join(cwdSandbox, 'package.json'), '{}\n');
    fs.writeFileSync(path.join(cwdSandbox, '.env'), 'SECRET=1\n');

    const { scanForEnvFilesDetailed } = stubHomedir(sandboxHome, scanPath);
    const detail = scanForEnvFilesDetailed({ cwd: cwdSandbox });

    assert.deepEqual(detail.files, [path.join(cwdSandbox, '.env')]);
    assert.equal(detail.incomplete, false);
    assert.deepEqual(detail.rootResolution, { unresolved: false, cwdFallback: path.resolve(cwdSandbox) });
  });

  it('scan({}, { cwd }) against a non-project cwd, empty sandbox HOME: no green check, "could not verify" + the D-20-01(2) cause text, exit 2, exactly one matching stderr line', async () => {
    cwdSandbox = mkSandbox('scan-nodefault-nonproject-cmd-');
    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);

    const { logs, result, stderrLines } = await runScanWithStderr(sandboxedScan, { cwd: cwdSandbox });

    const output = logs.join('\n');
    assert.ok(!output.includes('No .env files found'), 'a run that examined zero roots must never print the green check');
    assert.ok(output.includes('could not verify'), `expected a could-not-verify line, got: ${output}`);
    assert.ok(output.includes('no scan root could be resolved'), `expected the D-20-01(2) cause text verbatim, got: ${output}`);
    // review C-4 twin: the no-root cause must render its own clause, never
    // the budget/unreadable/root wording that fires from unrelated causes.
    assert.ok(!output.includes('configured scan root(s) could not be resolved'), 'must not render the existing root-clause wording for a zero-default-root cause');
    assert.ok(!output.includes('stopped early'), 'must not render the budget clause');
    assert.ok(!output.includes('path(s) could not be read'), 'must not render the unreadable clause');
    assert.deepEqual(result, { code: 2 }, 'zero roots resolved and no project cwd fallback must exit 2 through computeExit()');
    assert.equal(stderrLines.length, 1, `expected exactly one stderr line, got: ${stderrLines}`);
    assert.ok(stderrLines[0].includes('no scan root could be resolved'), `expected the stderr diagnostic to name the same cause, got: ${stderrLines[0]}`);
  });

  it('scan({}, { cwd }) against a project cwd (package.json, seeded .env), empty sandbox HOME: exactly one stderr note verbatim, the .env is reported, exit 1', async () => {
    cwdSandbox = mkSandbox('scan-nodefault-project-cmd-');
    fs.writeFileSync(path.join(cwdSandbox, 'package.json'), '{}\n');
    fs.writeFileSync(path.join(cwdSandbox, '.env'), 'SECRET=1\n');

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result, stderrLines } = await runScanWithStderr(sandboxedScan, { cwd: cwdSandbox });

    assert.equal(stderrLines.length, 1, `expected exactly one stderr line, got: ${stderrLines}`);
    assert.equal(stderrLines[0], 'llm-safe-haven: scanning current directory (no default scan root found)');
    assert.ok(logs.some((l) => l.includes(path.join(cwdSandbox, '.env'))), `expected the seeded .env to be reported, got: ${logs.join('\n')}`);
    assert.deepEqual(result, { code: 1 }, 'a .env found via the cwd fallback must exit 1 — findings beat incompleteness');
  });

  it('scan({}, { cwd }) against a project cwd with NO .env, empty sandbox HOME: green check prints, returns undefined, one stderr note still present', async () => {
    cwdSandbox = mkSandbox('scan-nodefault-project-clean-');
    fs.writeFileSync(path.join(cwdSandbox, 'package.json'), '{}\n');

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result, stderrLines } = await runScanWithStderr(sandboxedScan, { cwd: cwdSandbox });

    assert.ok(logs.some((l) => l.includes('No .env files found')), `expected the green check, got: ${logs.join('\n')}`);
    assert.equal(result, undefined, 'a clean cwd-fallback scan must return undefined, exactly like a clean default-root scan');
    assert.equal(stderrLines.length, 1, `expected exactly one stderr line, got: ${stderrLines}`);
    assert.equal(stderrLines[0], 'llm-safe-haven: scanning current directory (no default scan root found)');
  });

  it('cwd containing a .git DIRECTORY (no package.json) is also recognised as a project', async () => {
    cwdSandbox = mkSandbox('scan-nodefault-project-gitdir-');
    fs.mkdirSync(path.join(cwdSandbox, '.git'));
    fs.writeFileSync(path.join(cwdSandbox, '.env'), 'SECRET=1\n');

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result, stderrLines } = await runScanWithStderr(sandboxedScan, { cwd: cwdSandbox });

    assert.equal(stderrLines.length, 1);
    assert.equal(stderrLines[0], 'llm-safe-haven: scanning current directory (no default scan root found)');
    assert.ok(logs.some((l) => l.includes(path.join(cwdSandbox, '.env'))));
    assert.deepEqual(result, { code: 1 });
  });

  it('cwd containing a .git FILE (worktree/submodule shape, no package.json) is also recognised as a project — distinct from the directory case', async () => {
    cwdSandbox = mkSandbox('scan-nodefault-project-gitfile-');
    fs.writeFileSync(path.join(cwdSandbox, '.git'), 'gitdir: /somewhere/else/.git/worktrees/foo\n');
    fs.writeFileSync(path.join(cwdSandbox, '.env'), 'SECRET=1\n');

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result, stderrLines } = await runScanWithStderr(sandboxedScan, { cwd: cwdSandbox });

    assert.equal(stderrLines.length, 1);
    assert.equal(stderrLines[0], 'llm-safe-haven: scanning current directory (no default scan root found)');
    assert.ok(logs.some((l) => l.includes(path.join(cwdSandbox, '.env'))));
    assert.deepEqual(result, { code: 1 });
  });

  it('PAIRED CONTROL (D-20-02): a HOME with exactly one default root (Projects), non-project cwd — byte-identical to the pre-phase render, undefined, zero stderr lines', async () => {
    // Captured against commit c62301f0800b58dbf93a0c2a0c6897d1a5a0f56e (the
    // phase-19 head, immediately pre-phase-20) via:
    //   node -e "... stubHomedir(sandboxHome-with-only-Projects/, scanPath) ...
    //     captureLog(() => scan({}, {}))"
    // A control that RE-DERIVES this render from the code under test would
    // agree with whatever ships and detect nothing — this is a hardcoded
    // literal compared with deepEqual, not a smoke test.
    const EXPECTED_PRE_PHASE_RENDER = [
      '',
      '  \u{1F512} LLM Safe Haven — Security Scorecard',
      '',
      '  Scanning for exposed secrets...',
      '',
      '',
      '  Project scan:',
      '    ✓ No .env files found',
      '',
      '  Next steps:',
      '    Set up a credential proxy (see docs/credential-management.md)',
      '    Docs: https://github.com/pleasedodisturb/llm-safe-haven',
      '',
    ];

    fs.mkdirSync(path.join(sandboxHome, 'Projects'));
    cwdSandbox = mkSandbox('scan-nodefault-paired-control-cwd-');

    const { scan: sandboxedScan } = stubHomedir(sandboxHome, scanPath);
    const { logs, result, stderrLines } = await runScanWithStderr(sandboxedScan, { cwd: cwdSandbox });

    assert.deepEqual(logs, EXPECTED_PRE_PHASE_RENDER, 'D-20-02: 1..5-of-6 default roots present must render byte-identically to before this phase');
    assert.equal(result, undefined);
    assert.equal(stderrLines.length, 0, 'D-20-02: no new stderr line for the 1..5-of-6 case');
  });
});

// ---------------------------------------------------------------------------
// buildCauseClauses — the 'no-root' clause (EXIT-04, G-1621, D-20-01(2))
// ---------------------------------------------------------------------------
describe("buildCauseClauses — the 'no-root' clause (EXIT-04, G-1621)", () => {
  it("a detail with rootResolution.unresolved=true produces exactly one clause, id 'no-root', the D-20-01(2) text verbatim — never the existing 'root' wording", () => {
    const clauses = buildCauseClauses({
      anomalyReasons: {},
      rootFailures: { missing: 0, unreadable: 0 },
      rootResolution: { unresolved: true, cwdFallback: null },
    });
    assert.equal(clauses.length, 1);
    assert.equal(clauses[0].id, 'no-root');
    assert.equal(clauses[0].text, 'no scan root could be resolved');
  });

  it('MUST-STILL-PASS TWIN (G-1617): a detail with NO rootResolution field behaves exactly as today — the no-root clause never fires on its absence', () => {
    const withRootFailure = buildCauseClauses({ anomalyReasons: {}, rootFailures: { missing: 1, unreadable: 0 } });
    assert.equal(withRootFailure.length, 1);
    assert.equal(withRootFailure[0].id, 'root', 'a detail with no rootResolution field must default to the non-firing shape, never the unresolved one');

    const withNothing = buildCauseClauses({ anomalyReasons: {}, rootFailures: { missing: 0, unreadable: 0 } });
    assert.equal(withNothing.length, 1);
    assert.equal(withNothing[0].id, 'unknown', 'the G-1617 fallback must still be the only clause when nothing fired and rootResolution is absent');
  });
});

// ---------------------------------------------------------------------
// G-1617: every ANOMALY_SKIP_REASONS member must be EXPLAINABLE, not just
// classifiable.
//
// `incomplete` is derived generically by iterating the frozen
// ANOMALY_SKIP_REASONS set, but buildCauseClauses() names its causes by
// hand. Those are two sources of truth. The engine's partition test forces
// a new reason to be CLASSIFIED as ANOMALY or SCOPE; nothing forced it to
// be EXPLAINED, so a seventh reason would set `incomplete`, produce no
// clause, and make the caller's `clauses[0].id` throw in the operator-
// facing next-steps block of a scan that already could not finish.
//
// This is the mechanism that replaces the convention. It is derived FROM
// the frozen set, so it covers reasons nobody has written yet -- a test
// listing today's six by hand would pass forever and prove nothing.
// ---------------------------------------------------------------------
describe('buildCauseClauses — ANOMALY reason coverage (G-1617)', () => {
  const { ANOMALY_SKIP_REASONS } = require('../lib/traverse/engine.js');

  it('the frozen ANOMALY set is non-empty and readable — this test cannot pass vacuously', () => {
    const members = [...ANOMALY_SKIP_REASONS];
    assert.ok(
      members.length >= 3,
      `expected at least the 3 known ANOMALY reasons, got ${members.length}: ${members.join(', ')} — ` +
      'if this set became unreadable or empty, every assertion below would iterate nothing and pass silently'
    );
  });

  it('EVERY ANOMALY_SKIP_REASONS member produces a named clause — a 7th reason without one FAILS here', () => {
    const uncovered = [];
    for (const reason of ANOMALY_SKIP_REASONS) {
      // One anomaly present, everything else zero: the clause list must
      // name THIS reason and never fall through to the `unknown` fallback.
      const detail = {
        anomalyReasons: { [reason]: 1 },
        rootFailures: { missing: 0, unreadable: 0 },
      };
      const clauses = buildCauseClauses(detail);
      // G-1619 (Kimi-K3, review round 2): asserting merely that SOME clause
      // exists is too weak -- a reason could produce a clause belonging to a
      // DIFFERENT reason and still pass. With exactly one anomaly set, the
      // clause list must name THAT reason and nothing else.
      if (clauses.length !== 1 || clauses[0].id !== reason) {
        uncovered.push(`${reason} -> ${clauses.map((c) => c.id).join(',') || '(none)'}`);
      }
    }
    assert.deepEqual(
      uncovered, [],
      `ANOMALY_SKIP_REASONS member(s) with no clause in buildCauseClauses(): ${uncovered.join(', ')} — ` +
      'they would set `incomplete` and leave the operator with no stated cause. Add a clause AND a ' +
      'remedy in remedyForCause() for each.'
    );
  });

  it('every clause id also has a REMEDY that is not the generic fallback', () => {
    const generic = remedyForCause('definitely-not-a-real-clause-id', 'scan', {});
    const missing = [];
    for (const reason of ANOMALY_SKIP_REASONS) {
      const clauses = buildCauseClauses({
        anomalyReasons: { [reason]: 1 },
        rootFailures: { missing: 0, unreadable: 0 },
      });
      if (clauses.length && remedyForCause(clauses[0].id, 'scan', {}) === generic) {
        missing.push(`${reason} (clause '${clauses[0].id}')`);
      }
    }
    assert.deepEqual(missing, [], `clause(s) falling through to the generic remedy: ${missing.join(', ')}`);
  });

  // The fallback exists so the caller can never throw. It must stay
  // UNREACHABLE in practice -- these two assertions pin both halves.
  it('the unknown fallback exists (so clauses[0] never throws) but is not reachable via any real reason', () => {
    const empty = buildCauseClauses({ anomalyReasons: {}, rootFailures: { missing: 0, unreadable: 0 } });
    assert.equal(empty.length, 1, 'an empty cause set must still yield one clause, never []');
    assert.equal(empty[0].id, 'unknown');
    assert.ok(remedyForCause(empty[0].id, 'scan', {}).length > 0, 'the fallback must still render a remedy');
  });

  it('PAIRED CONTROL: a root failure alone still names the root cause, not the fallback', () => {
    const clauses = buildCauseClauses({ anomalyReasons: {}, rootFailures: { missing: 1, unreadable: 0 } });
    assert.equal(clauses[0].id, 'root');
  });
});

// ---------------------------------------------------------------------
// G-1619 (Kimi-K3, cross-AI review round 2): the invariant that G-1617's
// "the unknown fallback is unreachable" claim actually rests on.
//
// `incomplete` is `result.stopped === true || anomalyCount > 0`. The
// anomaly half is covered by the coverage test above. The `stopped` half
// is NOT: if the walk could ever report `stopped: true` while recording
// ZERO budget skips, `incomplete` would be true with an empty cause list
// and the fallback would be reachable today -- making the comment that
// calls it unreachable false.
//
// Probed and held on every budget-exhaustion shape (maxFiles 0/1,
// budgetSeconds 0, multi-root), but held-when-probed is not the same as
// enforced. This pins it.
// ---------------------------------------------------------------------
describe('walk invariant: stopped implies at least one budget skip (G-1619)', () => {
  const { Traversal } = require('../lib/traverse/engine.js');
  const fsMod = require('fs');
  const osMod = require('os');
  const pathMod = require('path');

  function tree() {
    const dir = fsMod.mkdtempSync(pathMod.join(osMod.tmpdir(), 'lsh-stopped-'));
    for (const sub of ['r1/a', 'r2/b']) {
      fsMod.mkdirSync(pathMod.join(dir, sub), { recursive: true });
      for (let i = 0; i < 3; i += 1) {
        fsMod.writeFileSync(pathMod.join(dir, sub, `f${i}.txt`), 'x\n');
      }
    }
    return dir;
  }

  const SHAPES = [
    { name: 'maxFiles: 0', opts: { maxFiles: 0 } },
    { name: 'maxFiles: 1', opts: { maxFiles: 1 } },
    { name: 'budgetSeconds: 0', opts: { budgetSeconds: 0 } },
  ];

  for (const shape of SHAPES) {
    it(`${shape.name} — stopped is true AND a budget skip is recorded, never one without the other`, () => {
      const dir = tree();
      try {
        const result = new Traversal({
          roots: [pathMod.join(dir, 'r1'), pathMod.join(dir, 'r2')],
          classes: ['env-secrets'],
          ...shape.opts,
        }).enumerateSync();

        assert.equal(result.stopped, true, `${shape.name} should exhaust the budget`);
        assert.ok(
          (result.skips.counts().budget || 0) > 0,
          `stopped === true with ZERO budget skips: buildCauseClauses() would return an empty ` +
          `list while incomplete is true, making the 'unknown' fallback reachable and the ` +
          `"unreachable" comment in lib/scan.js false. counts=${JSON.stringify(result.skips.counts())}`
        );
      } finally {
        fsMod.rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  it('PAIRED CONTROL: an unconstrained walk of the same tree is not stopped and records no budget skip', () => {
    const dir = tree();
    try {
      const result = new Traversal({
        roots: [pathMod.join(dir, 'r1'), pathMod.join(dir, 'r2')],
        classes: ['env-secrets'],
      }).enumerateSync();
      assert.equal(result.stopped, false);
      assert.equal(result.skips.counts().budget || 0, 0);
    } finally {
      fsMod.rmSync(dir, { recursive: true, force: true });
    }
  });
});
