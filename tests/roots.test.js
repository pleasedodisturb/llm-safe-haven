'use strict';

// Coverage for lib/roots.js (17-03, D-08) — the single source of the
// default code-root list and LSH_ROOTS parsing. Includes a deliberate
// "pre-change pin" (RESEARCH.md A3) recording that lib/scan.js today
// IGNORES LSH_ROOTS entirely — plan 17-13 flips this when scan.js adopts
// lib/roots.js; the flip is an intentional capability addition, not a
// regression.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { stubHomedir, restoreHomedir } = require('./helpers/module-stub.js');

const {
  getRoots, parseRootsEnv, DEFAULT_ROOT_NAMES,
  looksLikeProject, resolveZeroRootFallback,
} = require('../lib/roots.js');

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------------------
// default list identity — existence filter proven in both branches
// ---------------------------------------------------------------------------
describe('getRoots — default list identity', () => {
  let sandboxHome;

  afterEach(() => {
    if (sandboxHome) fs.rmSync(sandboxHome, { recursive: true, force: true });
    sandboxHome = undefined;
  });

  it('with a sandbox homedir containing all six directories, returns them in DEFAULT_ROOT_NAMES order', () => {
    sandboxHome = mkTmp('roots-full-');
    for (const name of DEFAULT_ROOT_NAMES) {
      fs.mkdirSync(path.join(sandboxHome, name));
    }

    const roots = getRoots({ env: {}, homedir: () => sandboxHome });
    assert.deepEqual(roots, DEFAULT_ROOT_NAMES.map((name) => path.resolve(sandboxHome, name)));
  });

  it('with only Projects and src present, returns exactly those two, in that order', () => {
    sandboxHome = mkTmp('roots-partial-');
    fs.mkdirSync(path.join(sandboxHome, 'Projects'));
    fs.mkdirSync(path.join(sandboxHome, 'src'));

    const roots = getRoots({ env: {}, homedir: () => sandboxHome });
    assert.deepEqual(roots, [
      path.resolve(sandboxHome, 'Projects'),
      path.resolve(sandboxHome, 'src'),
    ]);
  });

  it('with none of the six present, returns []', () => {
    sandboxHome = mkTmp('roots-empty-');
    const roots = getRoots({ env: {}, homedir: () => sandboxHome });
    assert.deepEqual(roots, []);
  });
});

// ---------------------------------------------------------------------------
// LSH_ROOTS override — proves override, not merge
// ---------------------------------------------------------------------------
describe('getRoots — LSH_ROOTS override', () => {
  let sandboxHome;
  let realA;
  let realB;

  afterEach(() => {
    if (sandboxHome) fs.rmSync(sandboxHome, { recursive: true, force: true });
    if (realA) fs.rmSync(realA, { recursive: true, force: true });
    if (realB) fs.rmSync(realB, { recursive: true, force: true });
    sandboxHome = realA = realB = undefined;
  });

  it('returns only the real LSH_ROOTS dirs and IGNORES the six defaults entirely', () => {
    // Seed a sandbox homedir with all six defaults present — if LSH_ROOTS
    // merged instead of overrode, these would leak into the result.
    sandboxHome = mkTmp('roots-lsh-home-');
    for (const name of DEFAULT_ROOT_NAMES) {
      fs.mkdirSync(path.join(sandboxHome, name));
    }

    realA = mkTmp('roots-lsh-a-');
    realB = mkTmp('roots-lsh-b-');
    const nonexistent = path.join(os.tmpdir(), 'roots-lsh-does-not-exist-xyz');

    const lshRoots = [realA, nonexistent, realB].join(':');
    const roots = getRoots({ env: { LSH_ROOTS: lshRoots }, homedir: () => sandboxHome });

    assert.deepEqual(roots, [path.resolve(realA), path.resolve(realB)]);
    for (const name of DEFAULT_ROOT_NAMES) {
      assert.ok(
        !roots.includes(path.resolve(sandboxHome, name)),
        `default root ${name} must be absent when LSH_ROOTS is set`
      );
    }
  });
});

// ---------------------------------------------------------------------------
// parseRootsEnv edge cases
// ---------------------------------------------------------------------------
describe('parseRootsEnv', () => {
  it('empty string returns []', () => {
    assert.deepEqual(parseRootsEnv(''), []);
  });

  it('undefined returns []', () => {
    assert.deepEqual(parseRootsEnv(undefined), []);
  });

  it('null returns []', () => {
    assert.deepEqual(parseRootsEnv(null), []);
  });

  it('single path returns a one-element array', () => {
    assert.deepEqual(parseRootsEnv('/a/b/c'), ['/a/b/c']);
  });

  it('trailing colon drops the empty trailing segment', () => {
    assert.deepEqual(parseRootsEnv('/a:/b:'), ['/a', '/b']);
  });

  it('leading colon drops the empty leading segment', () => {
    assert.deepEqual(parseRootsEnv(':/a:/b'), ['/a', '/b']);
  });

  it('repeated colons drop every empty segment they produce', () => {
    assert.deepEqual(parseRootsEnv('/a:::/b'), ['/a', '/b']);
  });
});

// ---------------------------------------------------------------------------
// deduplication
// ---------------------------------------------------------------------------
describe('getRoots — deduplication', () => {
  let realDir;

  afterEach(() => {
    if (realDir) fs.rmSync(realDir, { recursive: true, force: true });
    realDir = undefined;
  });

  it('the same directory listed twice yields one entry', () => {
    realDir = mkTmp('roots-dedup-');
    const roots = getRoots({ env: { LSH_ROOTS: `${realDir}:${realDir}` }, homedir: () => os.tmpdir() });
    assert.deepEqual(roots, [path.resolve(realDir)]);
  });
});

// ---------------------------------------------------------------------------
// symlinked root — both branches
// ---------------------------------------------------------------------------
describe('getRoots — symlinked root', () => {
  let parentDir;
  let realTarget;
  let goodLink;
  let brokenLink;
  let brokenTarget;

  afterEach(() => {
    if (parentDir) fs.rmSync(parentDir, { recursive: true, force: true });
    parentDir = realTarget = goodLink = brokenLink = brokenTarget = undefined;
  });

  it('a symlink pointing at a real directory is accepted', () => {
    parentDir = mkTmp('roots-symlink-good-');
    realTarget = path.join(parentDir, 'real-target');
    fs.mkdirSync(realTarget);
    goodLink = path.join(parentDir, 'good-link');
    fs.symlinkSync(realTarget, goodLink, 'dir');

    const roots = getRoots({ env: { LSH_ROOTS: goodLink }, homedir: () => os.tmpdir() });
    assert.deepEqual(roots, [path.resolve(goodLink)]);
  });

  it('a broken symlink is dropped', () => {
    parentDir = mkTmp('roots-symlink-broken-');
    brokenTarget = path.join(parentDir, 'never-created');
    brokenLink = path.join(parentDir, 'broken-link');
    fs.symlinkSync(brokenTarget, brokenLink, 'dir');

    const roots = getRoots({ env: { LSH_ROOTS: brokenLink }, homedir: () => os.tmpdir() });
    assert.deepEqual(roots, []);
  });
});

// ---------------------------------------------------------------------------
// getRoots — onMissingRoot (G-1504)
// ---------------------------------------------------------------------------
describe('getRoots — onMissingRoot (G-1504)', () => {
  let sandboxHome;
  let realDir;

  afterEach(() => {
    if (sandboxHome) fs.rmSync(sandboxHome, { recursive: true, force: true });
    if (realDir) fs.rmSync(realDir, { recursive: true, force: true });
    sandboxHome = realDir = undefined;
  });

  it('an LSH_ROOTS entry that does not exist fires onMissingRoot exactly once and is dropped from the result', () => {
    realDir = mkTmp('roots-missing-real-');
    const missing = path.join(os.tmpdir(), 'roots-missing-xyz-does-not-exist');

    const calls = [];
    const roots = getRoots({
      env: { LSH_ROOTS: `${realDir}:${missing}` },
      homedir: () => os.tmpdir(),
      onMissingRoot: (candidate) => calls.push(candidate),
    });

    assert.deepEqual(roots, [path.resolve(realDir)]);
    assert.deepEqual(calls, [missing]);
  });

  it('a default-root-list (probe) miss calls onMissingRoot ZERO times', () => {
    sandboxHome = mkTmp('roots-missing-probe-');
    fs.mkdirSync(path.join(sandboxHome, 'Projects'));
    // Deliberately leave the other five DEFAULT_ROOT_NAMES absent.

    const calls = [];
    const roots = getRoots({
      env: {},
      homedir: () => sandboxHome,
      onMissingRoot: (candidate) => calls.push(candidate),
    });

    assert.deepEqual(roots, [path.resolve(sandboxHome, 'Projects')]);
    assert.deepEqual(calls, [], 'the default probe must never fire onMissingRoot — noise on every ordinary machine');
  });

  it('getRoots() with NO onMissingRoot supplied behaves byte-identically to today (no throw, same return value)', () => {
    realDir = mkTmp('roots-missing-noop-');
    const missing = path.join(os.tmpdir(), 'roots-missing-noop-does-not-exist');

    assert.doesNotThrow(() => {
      const roots = getRoots({ env: { LSH_ROOTS: `${realDir}:${missing}` }, homedir: () => os.tmpdir() });
      assert.deepEqual(roots, [path.resolve(realDir)]);
    });
  });

  it('an LSH_ROOTS entry that exists but is a FILE, not a directory, also fires onMissingRoot', () => {
    sandboxHome = mkTmp('roots-missing-file-');
    const filePath = path.join(sandboxHome, 'not-a-directory.txt');
    fs.writeFileSync(filePath, 'x');

    const calls = [];
    const roots = getRoots({
      env: { LSH_ROOTS: filePath },
      homedir: () => os.tmpdir(),
      onMissingRoot: (candidate) => calls.push(candidate),
    });

    assert.deepEqual(roots, []);
    assert.deepEqual(calls, [filePath]);
  });

  it('LSH_ROOTS listing the same missing path twice fires onMissingRoot exactly TWICE — once per occurrence, not per unique path', () => {
    const missing = path.join(os.tmpdir(), 'roots-missing-dup-does-not-exist');

    const calls = [];
    const roots = getRoots({
      env: { LSH_ROOTS: `${missing}:${missing}` },
      homedir: () => os.tmpdir(),
      onMissingRoot: (candidate) => calls.push(candidate),
    });

    assert.deepEqual(roots, []);
    assert.equal(calls.length, 2, 'the seen dedup only applies to surviving directories — a missing candidate reaches the drop path on every occurrence');
    assert.deepEqual(calls, [missing, missing]);
  });
});

// ---------------------------------------------------------------------------
// FLIPPED 2026-08-07 by plan 17-13 (D-08): lib/scan.js now honours
// LSH_ROOTS, since scanForEnvFiles() sources its root list from THIS
// module's getRoots() instead of a hand-synced, LSH_ROOTS-blind SCAN_DIRS
// array. This is an INTENTIONAL CAPABILITY ADDITION, not a regression — the
// previous version of this describe block (RESEARCH.md A3) pinned the OLD
// LSH_ROOTS-blind behaviour; a future reader must not mistake this flip for
// a silent behaviour change.
// ---------------------------------------------------------------------------
describe('LSH_ROOTS override — lib/scan.js now honours LSH_ROOTS (D-08, flipped by plan 17-13)', () => {
  const scanPath = require.resolve('../lib/scan.js');

  let sandboxHome;
  let lshDir;
  let originalLshRoots;

  afterEach(() => {
    restoreHomedir(scanPath);
    if (sandboxHome) fs.rmSync(sandboxHome, { recursive: true, force: true });
    if (lshDir) fs.rmSync(lshDir, { recursive: true, force: true });
    if (originalLshRoots === undefined) delete process.env.LSH_ROOTS;
    else process.env.LSH_ROOTS = originalLshRoots;
    sandboxHome = lshDir = undefined;
  });

  it('scanForEnvFiles() finds a .env inside an LSH_ROOTS directory AND does not scan the six default roots', () => {
    originalLshRoots = process.env.LSH_ROOTS;

    // Seed every DEFAULT_ROOT_NAMES directory with its own .env — if
    // LSH_ROOTS merged instead of overrode, these would leak into the
    // result.
    sandboxHome = mkTmp('roots-flip-home-');
    for (const name of DEFAULT_ROOT_NAMES) {
      const dir = path.join(sandboxHome, name);
      fs.mkdirSync(dir);
      fs.writeFileSync(path.join(dir, '.env'), `DEFAULT_${name}=1\n`);
    }

    lshDir = mkTmp('roots-flip-lsh-');
    fs.writeFileSync(path.join(lshDir, '.env'), 'SECRET=1\n');
    process.env.LSH_ROOTS = lshDir;

    const { scanForEnvFiles } = stubHomedir(sandboxHome, scanPath);
    const found = scanForEnvFiles();

    assert.deepEqual(found, [path.join(lshDir, '.env')], 'the LSH_ROOTS directory must be scanned and only its .env reported');
    for (const name of DEFAULT_ROOT_NAMES) {
      assert.ok(
        !found.some((f) => f.startsWith(path.join(sandboxHome, name) + path.sep) || f === path.join(sandboxHome, name)),
        `default root ${name} must NOT be scanned when LSH_ROOTS is set`
      );
    }
  });
});

// ---------------------------------------------------------------------------
// getRoots — onUnreadableRoot (EXIT-02 / D-07b, G-1542, plan 18-04 Task 3)
// ---------------------------------------------------------------------------
describe('getRoots — onUnreadableRoot (EXIT-02, D-07b)', () => {
  function statSyncThrowing(code) {
    return (candidate) => {
      const err = new Error(`simulated ${code}`);
      err.code = code;
      throw err;
    };
  }

  it('EACCES on a DEFAULT-probe candidate fires onUnreadableRoot(candidate, "EACCES") and does NOT fire onMissingRoot', () => {
    const missingCalls = [];
    const unreadableCalls = [];
    const roots = getRoots({
      env: {},
      homedir: () => '/home/fake',
      fs: { statSync: statSyncThrowing('EACCES') },
      onMissingRoot: (candidate) => missingCalls.push(candidate),
      onUnreadableRoot: (candidate, code) => unreadableCalls.push([candidate, code]),
    });

    assert.deepEqual(roots, []);
    assert.deepEqual(missingCalls, [], 'onMissingRoot must never fire for an unreadable candidate');
    assert.equal(unreadableCalls.length, DEFAULT_ROOT_NAMES.length, 'onUnreadableRoot must fire once per default-probe candidate');
    for (const [, code] of unreadableCalls) assert.equal(code, 'EACCES');
  });

  it('ENOENT on a DEFAULT-probe candidate fires NEITHER callback — D-17.1-B silence preserved', () => {
    const missingCalls = [];
    const unreadableCalls = [];
    const roots = getRoots({
      env: {},
      homedir: () => '/home/fake',
      fs: { statSync: statSyncThrowing('ENOENT') },
      onMissingRoot: (candidate) => missingCalls.push(candidate),
      onUnreadableRoot: (candidate, code) => unreadableCalls.push([candidate, code]),
    });

    assert.deepEqual(roots, []);
    assert.deepEqual(missingCalls, [], 'ENOENT on the default probe must stay silent (D-17.1-B)');
    assert.deepEqual(unreadableCalls, [], 'ENOENT means absent, not unreadable — must not fire onUnreadableRoot');
  });

  it('ENOTDIR fires neither callback on the default probe, and fires onMissingRoot (not onUnreadableRoot) when explicit', () => {
    const defaultMissing = [];
    const defaultUnreadable = [];
    getRoots({
      env: {},
      homedir: () => '/home/fake',
      fs: { statSync: statSyncThrowing('ENOTDIR') },
      onMissingRoot: (c) => defaultMissing.push(c),
      onUnreadableRoot: (c, code) => defaultUnreadable.push([c, code]),
    });
    assert.deepEqual(defaultMissing, [], 'ENOTDIR on the default probe must stay silent (D-17.1-B)');
    assert.deepEqual(defaultUnreadable, [], 'ENOTDIR means absent (not a directory), not unreadable');

    const explicitMissing = [];
    const explicitUnreadable = [];
    getRoots({
      env: { LSH_ROOTS: '/some/explicit/path' },
      homedir: () => '/home/fake',
      fs: { statSync: statSyncThrowing('ENOTDIR') },
      onMissingRoot: (c) => explicitMissing.push(c),
      onUnreadableRoot: (c, code) => explicitUnreadable.push([c, code]),
    });
    assert.deepEqual(explicitMissing, ['/some/explicit/path'], 'ENOTDIR on an explicit root must fire onMissingRoot');
    assert.deepEqual(explicitUnreadable, [], 'ENOTDIR must never fire onUnreadableRoot');
  });

  it('a SUCCESSFUL statSync whose isDirectory() is false fires onMissingRoot when explicit and NOTHING on the default probe', () => {
    const fakeFs = { statSync: () => ({ isDirectory: () => false }) };

    const explicitMissing = [];
    const explicitUnreadable = [];
    getRoots({
      env: { LSH_ROOTS: '/some/file-not-dir' },
      homedir: () => '/home/fake',
      fs: fakeFs,
      onMissingRoot: (c) => explicitMissing.push(c),
      onUnreadableRoot: (c, code) => explicitUnreadable.push([c, code]),
    });
    assert.deepEqual(explicitMissing, ['/some/file-not-dir']);
    assert.deepEqual(explicitUnreadable, [], 'a regular file is a scope fact, never an anomaly');

    const defaultMissing = [];
    const defaultUnreadable = [];
    getRoots({
      env: {},
      homedir: () => '/home/fake',
      fs: fakeFs,
      onMissingRoot: (c) => defaultMissing.push(c),
      onUnreadableRoot: (c, code) => defaultUnreadable.push([c, code]),
    });
    assert.deepEqual(defaultMissing, [], 'the default probe never fires onMissingRoot regardless of cause');
    assert.deepEqual(defaultUnreadable, []);
  });

  it('EACCES on an EXPLICIT LSH_ROOTS entry fires onUnreadableRoot, not onMissingRoot', () => {
    const missingCalls = [];
    const unreadableCalls = [];
    const roots = getRoots({
      env: { LSH_ROOTS: '/some/locked/path' },
      homedir: () => '/home/fake',
      fs: { statSync: statSyncThrowing('EACCES') },
      onMissingRoot: (c) => missingCalls.push(c),
      onUnreadableRoot: (c, code) => unreadableCalls.push([c, code]),
    });
    assert.deepEqual(roots, []);
    assert.deepEqual(missingCalls, [], 'an unreadable explicit root must never be reported as missing');
    assert.deepEqual(unreadableCalls, [['/some/locked/path', 'EACCES']]);
  });

  it('getRoots() with NO onUnreadableRoot supplied behaves byte-identically to today (no throw, same bare string[] return)', () => {
    assert.doesNotThrow(() => {
      const roots = getRoots({
        env: { LSH_ROOTS: '/some/locked/path' },
        homedir: () => '/home/fake',
        fs: { statSync: statSyncThrowing('EACCES') },
      });
      assert.deepEqual(roots, []);
    });
  });

  // Real-filesystem paired control: the stub's errno is the one the kernel
  // actually produces. Measured this session: statSync on a child UNDER a
  // mode-000 parent throws EACCES (statSync on the mode-000 directory
  // itself SUCCEEDS -- isDirectory() is true -- which is exactly why the
  // gap is confined to "statSync itself throws", per 18-CONTEXT.md D-07b).
  describe('real filesystem: a child under a mode-000 parent', () => {
    const runningAsRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const skip = process.platform === 'win32' || runningAsRoot;

    let parentDir;
    let childDir;

    afterEach(() => {
      if (parentDir) {
        try { fs.chmodSync(parentDir, 0o755); } catch { /* may not exist */ }
        fs.rmSync(parentDir, { recursive: true, force: true });
      }
      parentDir = childDir = undefined;
    });

    it('a real mode-000 parent makes statSync on the child throw EACCES, and getRoots() fires onUnreadableRoot for it', { skip }, () => {
      parentDir = mkTmp('roots-real-eacces-parent-');
      childDir = path.join(parentDir, 'child');
      fs.mkdirSync(childDir);
      fs.chmodSync(parentDir, 0o000);

      const unreadableCalls = [];
      const missingCalls = [];
      try {
        const roots = getRoots({
          env: { LSH_ROOTS: childDir },
          homedir: () => os.tmpdir(),
          onMissingRoot: (c) => missingCalls.push(c),
          onUnreadableRoot: (c, code) => unreadableCalls.push([c, code]),
        });
        assert.deepEqual(roots, []);
        assert.deepEqual(missingCalls, []);
        assert.equal(unreadableCalls.length, 1);
        assert.equal(unreadableCalls[0][0], childDir);
        assert.equal(unreadableCalls[0][1], 'EACCES');
      } finally {
        fs.chmodSync(parentDir, 0o755);
      }
    });

    it('PAIRED CONTROL: statSync on the mode-000 directory ITSELF succeeds — isDirectory() is true, no callback fires', { skip }, () => {
      parentDir = mkTmp('roots-real-eacces-self-');
      fs.chmodSync(parentDir, 0o000);

      const unreadableCalls = [];
      const missingCalls = [];
      try {
        const roots = getRoots({
          env: { LSH_ROOTS: parentDir },
          homedir: () => os.tmpdir(),
          onMissingRoot: (c) => missingCalls.push(c),
          onUnreadableRoot: (c, code) => unreadableCalls.push([c, code]),
        });
        assert.deepEqual(roots, [path.resolve(parentDir)], 'statSync itself succeeds on a mode-000 directory — the gap is confined to a child beneath it');
        assert.deepEqual(missingCalls, []);
        assert.deepEqual(unreadableCalls, []);
      } finally {
        fs.chmodSync(parentDir, 0o755);
      }
    });
  });
});

// ---------------------------------------------------------------------------
// getRoots — onNoDefaultRoots (EXIT-04, G-1621)
//
// D-20-05: the third additive callback sibling of onMissingRoot/
// onUnreadableRoot above — fires ONLY when the DEFAULT probe (not explicit
// LSH_ROOTS) resolves to zero roots. It reports the FACT that zero default
// roots resolved; it never decides what to do about it (that decision, the
// cwd fallback, lives in the CALLER — see tests/scan.test.js "scan() zero
// default roots"). Mirrors the onMissingRoot describe above case for case.
// ---------------------------------------------------------------------------
describe('getRoots — onNoDefaultRoots (EXIT-04, G-1621)', () => {
  function statSyncThrowing(code) {
    return () => {
      const err = new Error(`simulated ${code}`);
      err.code = code;
      throw err;
    };
  }

  let sandboxHome;

  afterEach(() => {
    if (sandboxHome) fs.rmSync(sandboxHome, { recursive: true, force: true });
    sandboxHome = undefined;
  });

  it('fires onNoDefaultRoots exactly ONCE, with no arguments (arity 0), when none of the six default roots exist', () => {
    sandboxHome = mkTmp('roots-nodefault-empty-');
    const calls = [];
    const roots = getRoots({
      env: {},
      homedir: () => sandboxHome,
      onNoDefaultRoots: (...args) => calls.push(args),
    });

    assert.deepEqual(roots, []);
    assert.equal(calls.length, 1, 'onNoDefaultRoots must fire exactly once');
    assert.deepEqual(calls[0], [], 'onNoDefaultRoots is arity-0 — it must be called with no arguments');
  });

  it('PAIRED CONTROL (D-20-02): a HOME with exactly one default root (Projects) fires onNoDefaultRoots ZERO times', () => {
    sandboxHome = mkTmp('roots-nodefault-onepresent-');
    fs.mkdirSync(path.join(sandboxHome, 'Projects'));

    const calls = [];
    const roots = getRoots({
      env: {},
      homedir: () => sandboxHome,
      onNoDefaultRoots: () => calls.push(true),
    });

    assert.deepEqual(roots, [path.resolve(sandboxHome, 'Projects')]);
    assert.deepEqual(calls, [], 'a HOME with 1..5 of 6 default roots must never fire onNoDefaultRoots — D-20-02');
  });

  it('explicit LSH_ROOTS mode with every entry missing fires onNoDefaultRoots ZERO times, while still firing onMissingRoot per occurrence', () => {
    const missingA = path.join(os.tmpdir(), 'roots-nodefault-explicit-missing-a-does-not-exist');
    const missingB = path.join(os.tmpdir(), 'roots-nodefault-explicit-missing-b-does-not-exist');

    const noDefaultCalls = [];
    const missingCalls = [];
    const roots = getRoots({
      env: { LSH_ROOTS: `${missingA}:${missingB}` },
      homedir: () => '/home/fake',
      onMissingRoot: (candidate) => missingCalls.push(candidate),
      onNoDefaultRoots: () => noDefaultCalls.push(true),
    });

    assert.deepEqual(roots, []);
    assert.deepEqual(noDefaultCalls, [], 'explicit LSH_ROOTS mode must never fire onNoDefaultRoots, even when every entry is missing');
    assert.deepEqual(missingCalls, [missingA, missingB], 'onMissingRoot must still fire per occurrence in explicit mode, unchanged');
  });

  it('getRoots() with NO onNoDefaultRoots supplied behaves byte-identically to today (no throw, same bare string[] return)', () => {
    sandboxHome = mkTmp('roots-nodefault-noop-');
    assert.doesNotThrow(() => {
      const roots = getRoots({ env: {}, homedir: () => sandboxHome });
      assert.deepEqual(roots, []);
    });
  });

  it('all six default candidates throwing EACCES fires onNoDefaultRoots (the result IS empty) AND onUnreadableRoot six times — the callback reports the FACT, the caller partitions on WHY', () => {
    const noDefaultCalls = [];
    const unreadableCalls = [];
    const roots = getRoots({
      env: {},
      homedir: () => '/home/fake',
      fs: { statSync: statSyncThrowing('EACCES') },
      onNoDefaultRoots: () => noDefaultCalls.push(true),
      onUnreadableRoot: (candidate, code) => unreadableCalls.push([candidate, code]),
    });

    assert.deepEqual(roots, []);
    assert.equal(noDefaultCalls.length, 1, 'onNoDefaultRoots fires once even when every candidate failed as unreadable, not merely absent');
    assert.equal(unreadableCalls.length, DEFAULT_ROOT_NAMES.length, 'onUnreadableRoot must still fire once per unreadable default-probe candidate');
  });
});

// 20-REVIEW.md WR-02 (G-1621): `looksLikeProject()` / `resolveZeroRootFallback()`
// document an injectable `fs` seam "for testing" that nothing in the suite
// exercised -- only real-disk integration coverage existed. These cases drive
// the seam with a stub `fs` (the same DI convention `getRoots()`'s own tests
// use above), so the seam is load-bearing rather than decorative. What would
// make them fail: the helpers reading the real `fs` module instead of the
// injected one (a stub that reports `.git` present would then be ignored and
// `looksLikeProject` would answer from the real disk).
describe('looksLikeProject / resolveZeroRootFallback — injectable fs seam (WR-02)', () => {
  // A stub whose whole world is the set of paths passed in. Anything else
  // does not exist. Real fs is never consulted.
  function fsWithOnly(existingPaths) {
    const set = new Set(existingPaths.map((p) => path.normalize(p)));
    return { existsSync: (p) => set.has(path.normalize(p)) };
  }

  const dir = path.join(path.sep, 'nonexistent-fake-root', 'proj');

  it('`.git` present via the stub ⇒ project (a real-disk check would say NO — the dir does not exist)', () => {
    assert.equal(fs.existsSync(dir), false, 'precondition: the fake dir must NOT exist on the real disk, or this case proves nothing');
    assert.equal(looksLikeProject(dir, fsWithOnly([path.join(dir, '.git')])), true);
  });

  it('`.git` as a FILE (worktree/submodule `gitdir:` pointer) counts too — the seam is existsSync, not isDirectory', () => {
    // The stub has no isDirectory at all; if the helper ever started calling
    // statSync().isDirectory() this would throw rather than pass.
    assert.equal(looksLikeProject(dir, fsWithOnly([path.join(dir, '.git')])), true);
  });

  it('`package.json` alone ⇒ project', () => {
    assert.equal(looksLikeProject(dir, fsWithOnly([path.join(dir, 'package.json')])), true);
  });

  it('neither marker ⇒ not a project, even when the directory itself "exists" in the stub', () => {
    assert.equal(looksLikeProject(dir, fsWithOnly([dir])), false);
  });

  it('resolveZeroRootFallback returns the resolved cwd when the stub says project, null when it does not — real disk never consulted', () => {
    assert.equal(resolveZeroRootFallback({ cwd: dir, fs: fsWithOnly([path.join(dir, 'package.json')]) }), path.resolve(dir));
    assert.equal(resolveZeroRootFallback({ cwd: dir, fs: fsWithOnly([]) }), null);
  });
});
