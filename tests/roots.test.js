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

const { getRoots, parseRootsEnv, DEFAULT_ROOT_NAMES } = require('../lib/roots.js');

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
// Pre-change pin (RESEARCH A3): lib/scan.js today IGNORES LSH_ROOTS.
// Plan 17-13 flips this assertion when scan.js adopts lib/roots.js — the
// flip is an intentional capability addition, not a regression.
// ---------------------------------------------------------------------------
describe('pre-change pin — lib/scan.js ignores LSH_ROOTS (retired by plan 17-13)', () => {
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

  it('pre-change pin: scanForEnvFiles() returns [] while LSH_ROOTS points at a directory containing a .env', () => {
    originalLshRoots = process.env.LSH_ROOTS;

    sandboxHome = mkTmp('roots-pin-home-'); // empty — none of the six SCAN_DIRS exist here
    lshDir = mkTmp('roots-pin-lsh-');
    fs.writeFileSync(path.join(lshDir, '.env'), 'SECRET=1\n');
    process.env.LSH_ROOTS = lshDir;

    const { scanForEnvFiles } = stubHomedir(sandboxHome, scanPath);
    assert.deepEqual(
      scanForEnvFiles(),
      [],
      'lib/scan.js does not yet consume LSH_ROOTS — this assertion flips in plan 17-13'
    );
  });
});
