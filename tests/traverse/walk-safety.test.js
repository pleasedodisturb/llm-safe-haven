'use strict';

// Safety-property tests for lib/traverse/walk.js -- the single-pass
// enumeration core (G-1482, TRAV-01/TRAV-04, D-06/D-12/D-23/D-26). Every
// property here is proven in BOTH directions (a positive and a negative
// case) so a guard cannot pass vacuously -- see 17-VALIDATION.md's Q-02
// non-vacuous-guard rule and the B1/B6 regression guards this plan's
// cross-AI review added.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { walk } = require('../../lib/traverse/walk.js');
const { hasGit, initRepo } = require('../helpers/git-fixture.js');

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function mkFixture(prefix = 'walk-safety-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeFile(file, contents = '') {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

function cleanup(...dirs) {
  for (const dir of dirs) {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Runs walk() and collects every emitted event into an array, alongside the
// returned { counts, skips, stopped }.
function runWalk(roots, options = {}) {
  const events = [];
  const result = walk(roots, options, (e) => events.push(e));
  return { events, result };
}

function absPaths(events) {
  return events.map((e) => e.absPath);
}

function has(events, absPath) {
  return events.some((e) => e.absPath === absPath);
}

// ---------------------------------------------------------------------------
// No-policy-prune (B1 regression guard)
// ---------------------------------------------------------------------------

describe('walk.js -- B1 no-policy-prune regression guard', () => {
  it('with DEFAULT options, node_modules/dist/build/.next/target/.cache are ALL walked (no directory-name prune)', () => {
    const root = mkFixture();
    try {
      const files = [
        path.join(root, 'node_modules', 'keyv', 'package.json'),
        path.join(root, 'dist', 'a.js'),
        path.join(root, 'build', 'b.js'),
        path.join(root, '.next', 'c.js'),
        path.join(root, 'target', 'd.js'),
        path.join(root, '.cache', 'e.js'),
      ];
      for (const f of files) writeFile(f, 'x');

      const { events } = runWalk([root]);
      for (const f of files) {
        assert.ok(has(events, f), `expected ${f} to be walked by default (B1: no IOC-policy prune)`);
      }
    } finally {
      cleanup(root);
    }
  });

  it('PAIRED: an explicit skipDirs option (not the default) skips node_modules and dist, but leaves the other four walked', () => {
    const root = mkFixture();
    try {
      const files = {
        nodeModules: path.join(root, 'node_modules', 'keyv', 'package.json'),
        dist: path.join(root, 'dist', 'a.js'),
        build: path.join(root, 'build', 'b.js'),
        next: path.join(root, '.next', 'c.js'),
        target: path.join(root, 'target', 'd.js'),
        cache: path.join(root, '.cache', 'e.js'),
      };
      for (const f of Object.values(files)) writeFile(f, 'x');

      const { events } = runWalk([root], { skipDirs: new Set(['node_modules', 'dist']) });
      assert.equal(has(events, files.nodeModules), false, 'node_modules must be skipped when explicitly named');
      assert.equal(has(events, files.dist), false, 'dist must be skipped when explicitly named');
      assert.ok(has(events, files.build), 'build must still be walked -- not in the explicit skipDirs set');
      assert.ok(has(events, files.next), '.next must still be walked -- not in the explicit skipDirs set');
      assert.ok(has(events, files.target), 'target must still be walked -- not in the explicit skipDirs set');
      assert.ok(has(events, files.cache), '.cache must still be walked -- not in the explicit skipDirs set');
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Depth (B2 regression guard) -- mirrors tests/scan.test.js:130-170
// ---------------------------------------------------------------------------

describe('walk.js -- maxDepth (B2 regression guard)', () => {
  function buildChain(root) {
    const deep = path.join(root, 'd1', 'd2', 'd3', '.env');
    writeFile(deep, 'A=1');
    return deep;
  }

  it('maxDepth: 4 reaches the deep file', () => {
    const root = mkFixture();
    try {
      const deep = buildChain(root);
      const { events } = runWalk([root], { maxDepth: 4 });
      assert.ok(has(events, deep));
    } finally {
      cleanup(root);
    }
  });

  it('PAIRED: maxDepth: 1 stops recursion before reaching the deep file', () => {
    const root = mkFixture();
    try {
      const deep = buildChain(root);
      const { events } = runWalk([root], { maxDepth: 1 });
      assert.equal(has(events, deep), false);
    } finally {
      cleanup(root);
    }
  });

  it('the default (no maxDepth set, Infinity) reaches the deep file', () => {
    const root = mkFixture();
    try {
      const deep = buildChain(root);
      const { events } = runWalk([root], {});
      assert.ok(has(events, deep));
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// skipDotDirs applies to DIRECTORIES only
// ---------------------------------------------------------------------------

describe('walk.js -- skipDotDirs applies to directories only', () => {
  it('a dot-prefixed FILE at the root is emitted; a file inside a dot-prefixed DIRECTORY is not', () => {
    const root = mkFixture();
    try {
      const dotFile = path.join(root, '.env');
      writeFile(dotFile, 'A=1');
      const hiddenDirFile = path.join(root, '.hidden', 'inner.txt');
      writeFile(hiddenDirFile, 'x');

      const { events } = runWalk([root], { skipDotDirs: true });
      assert.ok(has(events, dotFile), 'a dot-prefixed FILE must still be emitted -- the dot-skip is directory-only');
      assert.equal(has(events, hiddenDirFile), false, 'a file inside a dot-prefixed DIRECTORY must not be reached');
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Symlinks (D-06 / T-17-07)
// ---------------------------------------------------------------------------

describe('walk.js -- symlinks are never followed (D-06)', () => {
  it('symlink to a file inside the tree: the real file is reached directly; the symlink entry itself is skipped and counted', () => {
    const root = mkFixture();
    try {
      const realFile = path.join(root, 'real.txt');
      writeFile(realFile, 'hi');
      const linkPath = path.join(root, 'link.txt');
      fs.symlinkSync(realFile, linkPath);

      const { events, result } = runWalk([root]);
      assert.ok(has(events, realFile), 'the real file, reached directly, must be emitted');
      assert.equal(has(events, linkPath), false, 'the symlink entry itself must never be emitted');
      assert.equal(result.skips.counts().symlink, 1);
      assert.deepEqual(result.skips.paths('symlink'), [linkPath]);
    } finally {
      cleanup(root);
    }
  });

  it('symlink to a directory OUTSIDE the root (escape case): absent via the symlink, present via its real root', () => {
    const outside = mkFixture('walk-safety-outside-');
    const root = mkFixture();
    try {
      const secret = path.join(outside, 'secret.txt');
      writeFile(secret, 'shh');
      const escapeLink = path.join(root, 'escape');
      fs.symlinkSync(outside, escapeLink);

      const viaRoot = runWalk([root]);
      assert.equal(has(viaRoot.events, path.join(escapeLink, 'secret.txt')), false,
        'the file must never be reached through the illegal symlink path');
      assert.equal(viaRoot.result.skips.counts().symlink, 1);

      const viaRealRoot = runWalk([outside]);
      assert.ok(has(viaRealRoot.events, secret), 'the same file must be found when its real directory is passed as a root');
    } finally {
      cleanup(outside, root);
    }
  });

  it('symlink cycle (a/link -> a) terminates without stack overflow', () => {
    const root = mkFixture();
    try {
      const a = path.join(root, 'a');
      fs.mkdirSync(a);
      fs.symlinkSync(a, path.join(a, 'link'));

      const { result } = runWalk([root]);
      assert.equal(result.skips.counts().symlink, 1);
      assert.equal(result.stopped, false);
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Device boundaries (D-12 / T-17-08)
// ---------------------------------------------------------------------------

function makeDeviceStubFs(overridePrefixes, overriddenDev) {
  return {
    readdirSync: (p, opts) => fs.readdirSync(p, opts),
    lstatSync: (p) => {
      const real = fs.lstatSync(p);
      const isOverridden = overridePrefixes.some((prefix) => p === prefix || p.startsWith(prefix + path.sep));
      if (!isOverridden) return real;
      return {
        dev: overriddenDev,
        isDirectory: () => real.isDirectory(),
        isFile: () => real.isFile(),
        isSymbolicLink: () => real.isSymbolicLink(),
      };
    },
  };
}

describe('walk.js -- device boundaries (D-12)', () => {
  it('a subtree on a different device is not descended into (both branches: crossing refused, same-dev descends)', () => {
    const root = mkFixture();
    try {
      const normalFile = path.join(root, 'normal', 'normal-file.txt');
      writeFile(normalFile, 'x');
      const mountDir = path.join(root, 'mount');
      const mountFile = path.join(mountDir, 'mount-file.txt');
      const deepFile = path.join(mountDir, 'deep', 'deep-file.txt');
      writeFile(mountFile, 'x');
      writeFile(deepFile, 'x');

      const realDev = fs.lstatSync(root).dev;
      const stubFs = makeDeviceStubFs([mountDir], realDev + 1);

      const { events, result } = runWalk([root], { fs: stubFs });

      assert.ok(has(events, normalFile), 'same-dev branch: normal/ must be descended into normally');
      assert.equal(has(events, mountFile), false, 'crossing-refused branch: mount/ must not be descended into');
      assert.equal(has(events, deepFile), false, 'crossing-refused branch: mount/deep/ must never be reached');
      assert.ok(result.skips.counts()['other-device'] >= 1);
      assert.ok(result.skips.paths('other-device').includes(mountDir));
    } finally {
      cleanup(root);
    }
  });

  it('explicit-root opt-in: the same different-dev directory passed DIRECTLY as a root is walked in full', () => {
    const root = mkFixture();
    try {
      const mountDir = path.join(root, 'mount');
      const mountFile = path.join(mountDir, 'mount-file.txt');
      const deepFile = path.join(mountDir, 'deep', 'deep-file.txt');
      writeFile(mountFile, 'x');
      writeFile(deepFile, 'x');

      const realDev = fs.lstatSync(root).dev;
      const stubFs = makeDeviceStubFs([mountDir], realDev + 1);

      const { events } = runWalk([mountDir], { fs: stubFs });
      assert.ok(has(events, mountFile), 'an explicit root always enters regardless of its dev');
      assert.ok(has(events, deepFile), 'the whole opted-in subtree must be reachable, not just the root itself');
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Unreadable directories (T-17-11)
// ---------------------------------------------------------------------------

describe('walk.js -- unreadable directories are counted, not fatal', () => {
  it('a readdirSync throw on one directory yields an unreadable count; the sibling directory is still walked', () => {
    const root = mkFixture();
    try {
      const locked = path.join(root, 'locked');
      fs.mkdirSync(locked);
      const openFile = path.join(root, 'open', 'file.txt');
      writeFile(openFile, 'x');

      const stubFs = {
        readdirSync: (p, opts) => {
          if (p === locked) {
            const err = new Error('EACCES: permission denied');
            err.code = 'EACCES';
            throw err;
          }
          return fs.readdirSync(p, opts);
        },
        lstatSync: (p) => fs.lstatSync(p),
      };

      const { events, result } = runWalk([root], { fs: stubFs });
      assert.ok(has(events, openFile), 'the sibling directory must still be walked');
      assert.equal(result.skips.counts().unreadable, 1);
      assert.deepEqual(result.skips.paths('unreadable'), [locked]);
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// DT_UNKNOWN Dirent fallback (C2/C3)
// ---------------------------------------------------------------------------

describe('walk.js -- DT_UNKNOWN Dirent fallback', () => {
  it('a Dirent whose three type predicates are all false triggers exactly one lstatSync fallback and is classified from the Stats', () => {
    const root = mkFixture();
    try {
      const targetName = 'mystery.txt';
      const targetAbsPath = path.join(root, targetName);
      writeFile(targetAbsPath, 'x');

      let targetLstatCalls = 0;
      const stubFs = {
        readdirSync: (p, opts) => {
          const real = fs.readdirSync(p, opts);
          if (p !== root) return real;
          return real.map((e) => (e.name !== targetName ? e : {
            name: e.name,
            isDirectory: () => false,
            isFile: () => false,
            isSymbolicLink: () => false,
          }));
        },
        lstatSync: (p) => {
          if (p === targetAbsPath) targetLstatCalls += 1;
          return fs.lstatSync(p);
        },
      };

      const { events } = runWalk([root], { fs: stubFs });
      assert.equal(targetLstatCalls, 1, 'exactly one lstat fallback for the DT_UNKNOWN entry');
      const match = events.find((e) => e.absPath === targetAbsPath);
      assert.ok(match, 'the entry must still be emitted, classified via the lstat fallback');
      assert.equal(match.isDirectory, false);
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// DT_UNKNOWN wall-clock containment (T-17-04-04)
// ---------------------------------------------------------------------------

function makeSyntheticDirFs(dirPath, count, { known }) {
  const names = Array.from({ length: count }, (_, i) => `f${i}`);
  const state = { lstatCalls: 0 };
  const stubFs = {
    readdirSync: (p) => {
      if (p !== dirPath) return [];
      return names.map((name) => (known
        ? { name, isDirectory: () => false, isFile: () => true, isSymbolicLink: () => false }
        : { name, isDirectory: () => false, isFile: () => false, isSymbolicLink: () => false }));
    },
    lstatSync: () => {
      state.lstatCalls += 1;
      return { dev: 1, isDirectory: () => false, isFile: () => true, isSymbolicLink: () => false };
    },
  };
  return { stubFs, state };
}

describe('walk.js -- DT_UNKNOWN wall-clock containment (periodic clock re-check on the fallback path only)', () => {
  it('a 1200-entry all-DT_UNKNOWN directory stops mid-directory once an injected clock passes the budget', () => {
    const dirPath = mkFixture();
    try {
      const { stubFs, state } = makeSyntheticDirFs(dirPath, 1200, { known: false });
      // The clock only "advances" once enough lstat fallbacks have happened
      // to prove the periodic re-check (not a per-directory-only check) is
      // what trips it -- a threshold well under the 512-fallback interval
      // guarantees the FIRST periodic checkpoint (the 512th fallback) sees
      // it and trips there, mid-directory.
      const now = () => (state.lstatCalls >= 5 ? 2_000_000_000n : 0n);

      const { events, result } = runWalk([dirPath], { fs: stubFs, now, budgetSeconds: 1 });

      assert.ok(events.length < 1200, `expected fewer than 1200 entries emitted, got ${events.length}`);
      assert.ok(result.skips.counts().budget >= 1);
      assert.equal(result.stopped, true);
    } finally {
      cleanup(dirPath);
    }
  });

  it('PAIRED: the same 1200-entry directory with all Dirent types KNOWN emits every entry under the same clock behaviour', () => {
    const dirPath = mkFixture();
    try {
      const { stubFs, state } = makeSyntheticDirFs(dirPath, 1200, { known: true });
      const now = () => (state.lstatCalls >= 5 ? 2_000_000_000n : 0n);

      const { events, result } = runWalk([dirPath], { fs: stubFs, now, budgetSeconds: 1 });

      assert.equal(events.length, 1200, 'the common (known-type) path must stay clock-free per entry and emit everything');
      assert.equal(result.skips.counts().budget, 0);
      assert.equal(result.stopped, false);
    } finally {
      cleanup(dirPath);
    }
  });
});

// ---------------------------------------------------------------------------
// Repo attribution is readdir-order independent (B6 regression guard)
// ---------------------------------------------------------------------------

describe('walk.js -- repo attribution is readdir-order independent (D-26 / B6)', () => {
  it('real filesystem: siblings sorting before (.aaa-sibling) and after (zzz-sibling) .git both carry the correct repoRoot', { skip: !hasGit }, () => {
    const root = mkFixture();
    try {
      initRepo(root, { tracked: { 'zzz-sibling/f.txt': 'z', '.aaa-sibling/f.txt': 'a' } });

      const { events } = runWalk([root]);
      const zzz = events.find((e) => e.absPath === path.join(root, 'zzz-sibling', 'f.txt'));
      const aaa = events.find((e) => e.absPath === path.join(root, '.aaa-sibling', 'f.txt'));
      assert.ok(zzz);
      assert.ok(aaa);
      assert.equal(zzz.repoRoot, root);
      assert.equal(aaa.repoRoot, root);
    } finally {
      cleanup(root);
    }
  });

  it('deterministic: a stubbed readdir returning .git LAST still attributes every sibling to the correct repoRoot', { skip: !hasGit }, () => {
    const root = mkFixture();
    try {
      initRepo(root, { tracked: { 'first-sibling/f.txt': 'a', 'second-sibling/f.txt': 'b' } });

      const stubFs = {
        readdirSync: (p, opts) => {
          const real = fs.readdirSync(p, opts);
          if (p !== root) return real;
          const gitEntry = real.find((e) => e.name === '.git');
          const rest = real.filter((e) => e.name !== '.git');
          // Force .git to be the LAST entry regardless of real OS order.
          return gitEntry ? [...rest, gitEntry] : real;
        },
        lstatSync: (p) => fs.lstatSync(p),
      };

      const { events } = runWalk([root], { fs: stubFs });
      const first = events.find((e) => e.absPath === path.join(root, 'first-sibling', 'f.txt'));
      const second = events.find((e) => e.absPath === path.join(root, 'second-sibling', 'f.txt'));
      assert.ok(first);
      assert.ok(second);
      assert.equal(first.repoRoot, root, 'attribution must not depend on readdir order');
      assert.equal(second.repoRoot, root, 'attribution must not depend on readdir order');
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Nested repos (D-26)
// ---------------------------------------------------------------------------

describe('walk.js -- nested repos resolve to the innermost repo (D-26)', () => {
  it('a repo nested inside another repo: files under inner/ attribute to the inner repo; a sibling file attributes to the outer repo', { skip: !hasGit }, () => {
    const outerRoot = mkFixture();
    try {
      initRepo(outerRoot, {
        gitignore: 'inner/secrets/\n',
        tracked: { 'outer-file.txt': 'outer' },
      });
      const innerRoot = path.join(outerRoot, 'inner');
      initRepo(innerRoot, { tracked: { 'inner-file.txt': 'inner' } });

      const { events } = runWalk([outerRoot]);
      const outerFile = events.find((e) => e.absPath === path.join(outerRoot, 'outer-file.txt'));
      const innerFile = events.find((e) => e.absPath === path.join(innerRoot, 'inner-file.txt'));
      assert.ok(outerFile);
      assert.ok(innerFile);
      assert.equal(outerFile.repoRoot, outerRoot, 'a file outside inner/ carries the outer repo path');
      assert.equal(innerFile.repoRoot, innerRoot, 'a file under inner/ carries the INNER repo path, not the outer one');
    } finally {
      cleanup(outerRoot);
    }
  });
});

// ---------------------------------------------------------------------------
// Git worktree shape (.git as a FILE)
// ---------------------------------------------------------------------------

describe('walk.js -- a .git FILE (linked worktree) is recognised as a repo boundary', () => {
  it('a directory containing a .git file starting with "gitdir:" is a repo root; the .git file itself is not emitted', () => {
    const root = mkFixture();
    try {
      writeFile(path.join(root, '.git'), 'gitdir: /somewhere/else/.git/worktrees/wt\n');
      const sibling = path.join(root, 'sibling.txt');
      writeFile(sibling, 'x');

      const { events } = runWalk([root]);
      const gitFileEmitted = events.some((e) => e.absPath === path.join(root, '.git'));
      assert.equal(gitFileEmitted, false, 'the .git worktree-pointer file must never be emitted as a scannable file');

      const siblingEvent = events.find((e) => e.absPath === sibling);
      assert.ok(siblingEvent);
      assert.equal(siblingEvent.repoRoot, root, 'a .git FILE must be recognised as a repo boundary, same as a .git directory');
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Non-vacuity checks (Q-02) -- performed manually once during development,
// confirmed to fail, then reverted; documented here rather than left as
// permanent mutated code (same pattern as tests/traverse/budget.test.js's
// header comment).
//
// 1. Removed BOTH symlink guards -- the early `entry.isSymbolicLink()`
//    check in walkDirectory's main loop AND the `stat.isSymbolicLink()`
//    check inside `resolveEntryType`'s DT_UNKNOWN-fallback branch (the
//    latter is defense-in-depth: a real symlink Dirent reports
//    `isDirectory()`/`isFile()` both false, so it already falls into the
//    fallback branch and is caught there too -- removing only the
//    main-loop check alone is NOT a real regression and, correctly,
//    changed nothing). With both removed: 3 tests failed ("symlink to a
//    file", "symlink escape", "symlink cycle"). Restored.
// 2. Moved the `.git` detection from the two-phase pre-scan into the
//    per-entry loop (checking as each entry was visited, instead of
//    scanning the whole Dirent array first) -- FAILED the ".git-last"
//    stubbed-readdir case (siblings preceding `.git` in the forced order
//    were attributed to no repo instead of the correct inner one).
//    Restored.
// 3. Added an unconditional `entry.name === 'node_modules'` prune ahead of
//    the `skipDirs` check -- FAILED the no-prune default-options test
//    (B1). Restored.
// ---------------------------------------------------------------------------
