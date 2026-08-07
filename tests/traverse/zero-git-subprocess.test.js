'use strict';

// Committed proof (G-1482, plan 17-14, 2026-08-07 tiering-trade-off
// reversal) that a real traversal engine run spawns ZERO subprocesses of
// any kind. Before this file existed, an attempt to prove this by hand
// (constructing a `Traversal` directly with a hand-built spec) threw
// inside `computeHashCandidateNames` before ever reaching the code path
// that would have consulted git -- an unproven, worthless probe. This file
// fixes that by driving a REAL `Traversal.run()` against the REAL bundled
// wave spec (`manifests/waves/chaindrop-aug2026.json`), over a fixture
// shaped exactly like the one that used to exercise `bulk-content`'s
// gitignore consultation (nested git repos, a `.gitignore`, and files
// covering the full old `bulk-content` allowlist plus `.env`/`.npmrc`),
// with `child_process.spawnSync` stubbed at the MODULE level (not an
// injectable-option seam -- `lib/traverse/git-ignore.js`, the only module
// that ever called it, is deleted; there is no seam left to stub through).
// If any code anywhere in the traversal engine's dependency graph ever
// calls `child_process.spawnSync` again, this test fails with a non-zero
// count.
//
// Uses the SAME require.cache-stubbing technique as
// tests/scan.test.js's "scan.js spawns zero subprocesses" describe block.

const { describe, it, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { installStub } = require('../helpers/module-stub.js');
const { initRepo, hasGit } = require('../helpers/git-fixture.js');

const cpPath = require.resolve('child_process');
const realChildProcess = require('child_process');

let callCount;
let calls;
let preStubEntry;

beforeEach(() => {
  callCount = 0;
  calls = [];
  preStubEntry = Object.prototype.hasOwnProperty.call(require.cache, cpPath) ? require.cache[cpPath] : undefined;
  installStub(cpPath, {
    ...realChildProcess,
    spawnSync: (...args) => {
      callCount += 1;
      calls.push(args);
      return realChildProcess.spawnSync(...args);
    },
  });
  // Evict and re-require every lib/traverse/ module so their top-level
  // `require('child_process')` calls (if any survive a future regression)
  // rebind against the stub -- matching the WR-01 ordering rule in
  // tests/helpers/module-stub.js. None of them require it today; this
  // guards against a future accidental reintroduction just as much as it
  // proves today's absence.
  for (const rel of ['index.js', 'walk.js', 'classify.js', 'read-pool.js', 'budget.js', 'engine.js', 'wave-spec.js', 'results.js', 'progress.js', 'run.js']) {
    delete require.cache[require.resolve(`../../lib/traverse/${rel}`)];
  }
  delete require.cache[require.resolve('../../lib/roots.js')];
});

afterEach(() => {
  if (preStubEntry === undefined) delete require.cache[cpPath];
  else require.cache[cpPath] = preStubEntry;
  for (const rel of ['index.js', 'walk.js', 'classify.js', 'read-pool.js', 'budget.js', 'engine.js', 'wave-spec.js', 'results.js', 'progress.js', 'run.js']) {
    delete require.cache[require.resolve(`../../lib/traverse/${rel}`)];
  }
  delete require.cache[require.resolve('../../lib/roots.js')];
});

const dirs = [];
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function mkFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zero-git-subprocess-'));
  dirs.push(dir);
  return dir;
}

describe('traversal engine — zero git subprocesses (2026-08-07 tiering-trade-off reversal)', () => {
  it('a real Traversal.run() over a nested-git-repo, marker-string-shaped fixture spawns NO subprocess at all', { skip: !hasGit ? 'git unavailable' : false }, async () => {
    const { loadWaveSpec } = require('../../lib/traverse/wave-spec.js');
    const { Traversal } = require('../../lib/traverse/engine.js');
    const SPEC_PATH = path.join(__dirname, '..', '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
    const loaded = loadWaveSpec(SPEC_PATH);
    assert.equal(loaded.valid, true, `bundled wave spec failed to load: ${loaded.reason}`);

    const home = mkFixture();

    // A real, nested git repo with a .gitignore -- the exact shape that
    // used to exercise git-ignore.js's subprocess calls (git rev-parse,
    // git ls-files) when `bulk-content` was still gitignore-aware.
    initRepo(path.join(home, 'outer-repo'), {
      gitignore: 'hidden/\n',
      untracked: {
        // Every name from the OLD bulk-content allowlist, planted both
        // inside and outside the gitignored directory.
        'hidden/loader.js': 'const c2 = "npm-cache.com";\n',
        'loader.mjs': 'export const x = 1;\n',
        'notes.md': '# notes\n',
        'config.yml': 'key: value\n',
        'script.sh': '#!/bin/sh\necho hi\n',
        // The .env/.npmrc credential-file class -- always targeted, but
        // included here so the fixture is comprehensive.
        '.env': 'SECRET=1\n',
        '.npmrc': 'registry=https://registry.npmjs.org/\n',
      },
    });
    // A second, nested inner repo (its own .git), exercising D-26 repo
    // attribution across a boundary within the same walk.
    initRepo(path.join(home, 'outer-repo', 'sub', 'inner-repo'), {
      untracked: { 'nested.js': 'console.log("nested");\n' },
    });

    const t = new Traversal({ roots: [home], spec: loaded.spec });
    const result = await t.run();

    assert.equal(callCount, 0, `expected zero child_process.spawnSync calls, got ${callCount}: ${JSON.stringify(calls)}`);
    // Non-vacuity: the fixture actually produced classified work (proves
    // the walk did real work rather than short-circuiting on an empty
    // tree, which would make "zero spawnSync calls" trivially true for
    // the wrong reason).
    assert.ok(result.counts.filesWalked > 0, 'fixture produced no walked files -- the zero-spawnSync result would be vacuous');
  });

  it('enumerateSync() also spawns NO subprocess, requesting every FILE_CLASSES member including the (now-unreachable) bulk-content', () => {
    const { Traversal } = require('../../lib/traverse/engine.js');
    const { FILE_CLASSES } = require('../../lib/traverse/index.js');

    const home = mkFixture();
    fs.mkdirSync(path.join(home, 'proj'), { recursive: true });
    fs.writeFileSync(path.join(home, 'proj', 'loader.js'), 'console.log(1);\n');
    fs.writeFileSync(path.join(home, 'proj', '.env'), 'SECRET=1\n');

    const spec = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'manifests', 'waves', 'chaindrop-aug2026.json'), 'utf8'));
    const t = new Traversal({ roots: [home], classes: FILE_CLASSES, spec });
    const r = t.enumerateSync();

    assert.equal(callCount, 0, `expected zero child_process.spawnSync calls, got ${callCount}: ${JSON.stringify(calls)}`);
    assert.ok(r.byClass.get('marker-config').length > 0, 'fixture produced no marker-config matches -- the zero-spawnSync result would be vacuous');
  });
});
