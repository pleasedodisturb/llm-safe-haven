'use strict';

// Structural tests for lib/traverse/walk.js -- the single-pass property,
// budget call cadence, and the maxFiles overshoot bound, machine-verified
// rather than asserted in prose (G-1482, TRAV-01, 17-CONTEXT.md decision
// Q-06: structural CI assertions only, no tight wall-clock asserts).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { walk } = require('../../lib/traverse/walk.js');
const { normalizeOptions } = require('../../lib/traverse/index.js');
const { createBudget } = require('../../lib/traverse/budget.js');

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function mkFixture(prefix = 'walk-structural-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeFile(file, contents = 'x') {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// Builds a fixture tree with a KNOWN directory count (including `root`
// itself) and a known file count -- two files per directory, so file count
// is deliberately larger than directory count. Returns { dirs, files },
// both arrays of absolute paths, `dirs[0] === root`.
function buildFixture(root, filesPerDir = 2) {
  const dirs = [root];
  const files = [];

  const structure = {
    d1: { d1a: {}, d1b: {} },
    d2: { d2a: { d2a1: {}, d2a2: {} }, d2b: {} },
    d3: {},
    d4: { d4a: { d4a1: { d4a1i: {} }, d4a2: {} } },
    d5: { d5a: {} },
    d6: {},
    d7: { d7a: {} },
  };

  function seedFiles(dirPath) {
    for (let i = 0; i < filesPerDir; i += 1) {
      const f = path.join(dirPath, `file${i}.txt`);
      fs.writeFileSync(f, 'x');
      files.push(f);
    }
  }

  function create(base, tree) {
    for (const [name, sub] of Object.entries(tree)) {
      const p = path.join(base, name);
      fs.mkdirSync(p);
      dirs.push(p);
      seedFiles(p);
      create(p, sub);
    }
  }

  seedFiles(root);
  create(root, structure);

  return { dirs, files };
}

// A counting decorator around a real budget -- forwards every call, but
// tallies how many times noteDirectory()/noteFile() were invoked. Used to
// prove the call-cadence claims without duplicating budget.js's own
// arithmetic (walk.js's `options.budget` injectable seam).
function makeCountingBudget(real) {
  let noteDirectoryCalls = 0;
  let noteFileCalls = 0;
  return {
    noteDirectory: (...args) => {
      noteDirectoryCalls += 1;
      return real.noteDirectory(...args);
    },
    noteFile: (...args) => {
      noteFileCalls += 1;
      return real.noteFile(...args);
    },
    noteFiles: (...args) => real.noteFiles(...args),
    exhausted: (...args) => real.exhausted(...args),
    reason: (...args) => real.reason(...args),
    elapsedMs: (...args) => real.elapsedMs(...args),
    remainingMs: (...args) => real.remainingMs(...args),
    snapshot: (...args) => real.snapshot(...args),
    enterTier: (...args) => real.enterTier(...args),
    tierComplete: (...args) => real.tierComplete(...args),
    counts: () => ({ noteDirectoryCalls, noteFileCalls }),
  };
}

// ---------------------------------------------------------------------------
// One readdir per directory -- exact count, no duplicate directory path
// ---------------------------------------------------------------------------

describe('walk.js -- exactly one readdir per directory', () => {
  it('onReaddir fires exactly once per directory; the total is EXACT and no directory path repeats', () => {
    const root = mkFixture();
    try {
      const { dirs } = buildFixture(root);
      const seen = [];
      walk([root], { onReaddir: (p) => seen.push(p) }, () => {});

      assert.equal(seen.length, dirs.length, 'onReaddir call count must equal the exact directory count');
      assert.equal(new Set(seen).size, seen.length, 'no directory path must appear twice');
      assert.deepEqual([...seen].sort(), [...dirs].sort());
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Budget call cadence -- noteDirectory once per directory, noteFile once
// per emitted entry
// ---------------------------------------------------------------------------

describe('walk.js -- budget call cadence', () => {
  it('noteDirectory is called once per directory and NOT once per file (directory count is strictly less than the file count)', () => {
    const root = mkFixture();
    try {
      const { dirs, files } = buildFixture(root);
      const normalized = normalizeOptions({});
      const countingBudget = makeCountingBudget(createBudget(normalized));

      walk([root], { budget: countingBudget }, () => {});

      const { noteDirectoryCalls } = countingBudget.counts();
      assert.equal(noteDirectoryCalls, dirs.length);
      assert.ok(dirs.length < files.length, 'fixture sanity: directory count must be smaller than file count');
      assert.ok(noteDirectoryCalls < files.length);
    } finally {
      cleanup(root);
    }
  });

  it('noteFile is called once per emitted ENTRY (directories + files, excluding the un-emitted root)', () => {
    const root = mkFixture();
    try {
      const { dirs, files } = buildFixture(root);
      const normalized = normalizeOptions({});
      const countingBudget = makeCountingBudget(createBudget(normalized));

      const events = [];
      walk([root], { budget: countingBudget }, (e) => events.push(e));

      const expectedEntryCount = (dirs.length - 1) + files.length; // root itself is never emitted
      const { noteFileCalls } = countingBudget.counts();
      assert.equal(events.length, expectedEntryCount);
      assert.equal(noteFileCalls, expectedEntryCount);
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Overshoot bound (T-17-04-04)
// ---------------------------------------------------------------------------

describe('walk.js -- maxFiles overshoot bound', () => {
  it('a single directory of 500 files with maxFiles:10 stops after at most 11 emitted entries', () => {
    const root = mkFixture();
    try {
      for (let i = 0; i < 500; i += 1) writeFile(path.join(root, `f${i}.txt`));

      const events = [];
      const result = walk([root], { maxFiles: 10 }, (e) => events.push(e));

      assert.ok(events.length <= 11, `expected <= 11 emitted entries, got ${events.length}`);
      assert.equal(result.stopped, true);
      assert.ok(result.skips.counts().budget >= 1);
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Exhaustion preserves partial results (D-20 / T-17-04)
// ---------------------------------------------------------------------------

describe('walk.js -- exhaustion stops the walk but preserves partial results', () => {
  it('an injected clock that exhausts mid-walk stops descending, records the budget skip reason, and keeps already-emitted entries', () => {
    const root = mkFixture();
    try {
      const { dirs, files } = buildFixture(root);
      const totalEntries = (dirs.length - 1) + files.length;

      let nowCalls = 0;
      const now = () => {
        nowCalls += 1;
        // The first few calls (createBudget's own startNs read, plus the
        // first couple of noteDirectory() checkpoints) see an unexhausted
        // clock; every call after that sees the budget blown -- guarantees
        // the walk gets partway through this multi-directory fixture
        // before stopping, rather than stopping on directory 1.
        return nowCalls > 3 ? 2_000_000_000n : 0n;
      };

      const events = [];
      const result = walk([root], { now, budgetSeconds: 1 }, (e) => events.push(e));

      assert.ok(events.length > 0, 'some entries must have been emitted before exhaustion');
      assert.ok(events.length < totalEntries, 'the walk must not have completed the whole fixture');
      assert.equal(result.stopped, true);
      assert.ok(result.skips.counts().budget >= 1);
    } finally {
      cleanup(root);
    }
  });

  it('maxFiles set below the fixture total stops with the same partial-result property', () => {
    const root = mkFixture();
    try {
      const { dirs, files } = buildFixture(root);
      const totalEntries = (dirs.length - 1) + files.length;

      const events = [];
      const result = walk([root], { maxFiles: 5 }, (e) => events.push(e));

      assert.ok(events.length > 0);
      assert.ok(events.length < totalEntries);
      assert.equal(result.stopped, true);
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Smoke test -- generous ceiling, no tight wall-clock assertion (Q-06)
// ---------------------------------------------------------------------------

describe('walk.js -- smoke', () => {
  it('2000 files in one directory walk well under a generous 10s ceiling', () => {
    const root = mkFixture();
    try {
      for (let i = 0; i < 2000; i += 1) writeFile(path.join(root, `f${i}.txt`));

      const start = Date.now();
      const events = [];
      walk([root], {}, (e) => events.push(e));
      const elapsedMs = Date.now() - start;

      assert.equal(events.length, 2000);
      assert.ok(elapsedMs < 10_000, `expected well under 10s, took ${elapsedMs}ms`);
    } finally {
      cleanup(root);
    }
  });
});

// ---------------------------------------------------------------------------
// Non-vacuity checks (Q-02) -- performed manually once during development,
// confirmed to fail, then reverted; documented here rather than left as
// permanent mutated code (same pattern as tests/traverse/budget.test.js
// and tests/traverse/walk-safety.test.js).
//
// 1. Duplicated the `ctx.options.onReaddir(dirPath)` call in `walkDirectory`
//    (simulating a second enumeration pass being observed) -- FAILED the
//    single-readdir test's exact-count assertion (40 calls recorded against
//    an expected 20). Restored.
// 2. Removed the per-entry `budget.noteFile()` enforcement from `emitEntry`
//    entirely and replaced it with ONE `budget.noteFiles(entries.length)`
//    call per directory (issued before the entries loop, matching the
//    documented non-enforcement tradeoff on `noteFiles` in budget.js) --
//    FAILED three tests: the noteFile-cadence test (0 noteFile() calls
//    recorded, since the method is never called), the overshoot test (500
//    files in one directory with maxFiles:10 emitted far more than 11
//    entries -- the batch check does not stop enumeration mid-directory),
//    and the maxFiles-partial-results test (the same overshoot let the
//    walk consume the whole fixture instead of stopping partway through).
//    A first attempt using `noteFiles(1)` per entry (semantically identical
//    to `noteFile()`, just a differently-named call) correctly did NOT fail
//    the overshoot test -- confirming that per-call batch SIZE (not the
//    method name) is what the overshoot test actually proves. Restored.
// ---------------------------------------------------------------------------
