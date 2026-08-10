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

const { walk, WALK_ENTRY_CLOCK_INTERVAL } = require('../../lib/traverse/walk.js');
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
  it('noteDirectory is called once per directory, PLUS one interval-cadence recheck per WALK_ENTRY_CLOCK_INTERVAL entries iterated (G-1513, TRAV-16)', () => {
    // Prior to G-1513, walkDirectory's entry loop never re-read the clock,
    // so noteDirectoryCalls was expected to equal dirs.length EXACTLY. Now
    // walkDirectory's entry loop also calls noteDirectory() every
    // WALK_ENTRY_CLOCK_INTERVAL Dirents iterated, walk-wide (G-1513 /
    // TRAV-16), so a per-directory-only expectation is no longer the
    // contract. The expected count is therefore DERIVED from the fixture
    // and the exported constant, not a bumped integer -- bumping the
    // literal until it passes was exactly the defect-B1 reasoning
    // (17.1-CONTEXT.md) this plan is required to avoid.
    const root = mkFixture();
    try {
      const { dirs, files } = buildFixture(root);
      const normalized = normalizeOptions({});
      const countingBudget = makeCountingBudget(createBudget(normalized));

      walk([root], { budget: countingBudget }, () => {});

      // Every directory is itself an entry of its parent EXCEPT the root
      // (root[0] is never iterated as a Dirent of anything) -- the same
      // formula the noteFile cadence test below already uses.
      const entriesIterated = (dirs.length - 1) + files.length;
      const expectedNoteDirectoryCalls = dirs.length + Math.floor(entriesIterated / WALK_ENTRY_CLOCK_INTERVAL);

      const { noteDirectoryCalls } = countingBudget.counts();
      assert.equal(noteDirectoryCalls, expectedNoteDirectoryCalls);
      // This fixture is far smaller than WALK_ENTRY_CLOCK_INTERVAL, so the
      // interval term is 0 -- confirm that explicitly so a future fixture
      // resize doesn't silently stop exercising the per-directory term.
      assert.equal(Math.floor(entriesIterated / WALK_ENTRY_CLOCK_INTERVAL), 0, 'fixture sanity: this small tree must not cross the interval');
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
// One flat directory cannot outrun the wall clock (G-1513, TRAV-16)
// ---------------------------------------------------------------------------

describe('walk.js -- one flat directory cannot outrun the wall clock (G-1513, TRAV-16)', () => {
  const FLAT_COUNT = WALK_ENTRY_CLOCK_INTERVAL + 100;

  function buildFlatFixture(root, count) {
    for (let i = 0; i < count; i += 1) writeFile(path.join(root, `f${i}.txt`));
  }

  it('exhaustion case: an over-budget clock latches and STOPS the walk partway through a single directory larger than the interval', () => {
    const root = mkFixture();
    try {
      buildFlatFixture(root, FLAT_COUNT);

      let nowCalls = 0;
      const now = () => {
        nowCalls += 1;
        // Call 1 is createBudget's own startNs read; call 2 is the root
        // directory's own per-directory noteDirectory() -- both must see an
        // unexhausted clock so the walk enters the entry loop at all. Every
        // call after that sees the budget already blown, so the FIRST
        // entry-loop interval recheck (at entryScanCount === 512) is the
        // call that latches.
        return nowCalls <= 2 ? 0n : 2_000_000_000n;
      };

      const events = [];
      const result = walk([root], { now, budgetSeconds: 1 }, (e) => events.push(e));

      assert.equal(result.stopped, true);
      // Exactly ONE 'budget' skip: the recheck's own `ctx.skips.add(dirPath)`
      // immediately followed by `break`. If the `break` were missing, the
      // SAME iteration would fall through to `emitEntry`, whose `noteFile()`
      // sees the already-latched budget and adds a SECOND 'budget' skip
      // (this time keyed on the entry's absPath) before the pre-existing
      // top-of-loop `exhausted()` check catches the next entry -- this is
      // the assertion break-proof 2 depends on to distinguish "latch" from
      // "latch AND stop" (a loose `>= 1` cannot tell the two apart, because
      // noteFile()'s own latch check already prevents any EXTRA entry from
      // being emitted either way).
      assert.equal(result.skips.counts().budget, 1);
      assert.equal(events.length, WALK_ENTRY_CLOCK_INTERVAL - 1, 'entries strictly before the interval boundary must have been emitted; the boundary entry itself must not be');
      assert.ok(
        events.length < FLAT_COUNT,
        `without the entry-loop recheck this single directory would emit all ${FLAT_COUNT} files -- the only other clock read on this fixture is the ONE per-directory noteDirectory() call, which already passed by the time the walk entered the loop`
      );
    } finally {
      cleanup(root);
    }
  });

  it('PAIRED control: the identical fixture with the real clock and the default budget emits every file with zero budget skips', () => {
    const root = mkFixture();
    try {
      buildFlatFixture(root, FLAT_COUNT);

      const events = [];
      const result = walk([root], {}, (e) => events.push(e));

      // Without this control, the exhaustion case above would also pass
      // against a walk that refuses everything regardless of the clock.
      assert.equal(events.length, FLAT_COUNT);
      assert.equal(result.skips.counts().budget, 0);
      assert.equal(result.stopped, false);
    } finally {
      cleanup(root);
    }
  });

  it('noteFile() stays clock-free: total now() calls equal exactly 1 + dirsWalked + floor(entriesIterated / WALK_ENTRY_CLOCK_INTERVAL)', () => {
    // The T-17-04-04 guard: if a future change ever moves the clock read
    // into noteFile(), this count jumps from a handful to roughly the
    // entry count (612), and this assertion fails loudly.
    const root = mkFixture();
    try {
      buildFlatFixture(root, FLAT_COUNT);

      let nowCalls = 0;
      const now = () => {
        nowCalls += 1;
        return 0n; // never exhausts -- an ample budget, default budgetSeconds
      };

      const result = walk([root], { now }, () => {});

      const entriesIterated = FLAT_COUNT; // one flat directory, no subdirectories
      const expectedNowCalls = 1 + result.counts.dirsWalked + Math.floor(entriesIterated / WALK_ENTRY_CLOCK_INTERVAL);
      assert.equal(nowCalls, expectedNowCalls);
      assert.equal(result.counts.dirsWalked, 1, 'fixture sanity: exactly one directory (the root itself)');
    } finally {
      cleanup(root);
    }
  });

  it('WALK_ENTRY_CLOCK_INTERVAL stays within its stated worst-case-overrun bound (<= 512)', () => {
    // The only assertion in this file that does NOT derive from the
    // constant itself -- it pins the constant's VALUE, not just the
    // cadence SHAPE, so a future widening of the interval to silence a
    // slow test cannot pass silently. At a pessimistic 10ms/lstat, 512
    // entries is ~5.1s, ~8.5% of the default 60s budget; a larger interval
    // breaks that bound.
    assert.ok(
      WALK_ENTRY_CLOCK_INTERVAL <= 512,
      `WALK_ENTRY_CLOCK_INTERVAL (${WALK_ENTRY_CLOCK_INTERVAL}) exceeds the stated worst-case-overrun bound: at ~10ms/lstat, N entries costs ~N*10ms, and 512*10ms ~= 5.1s (~8.5% of the default 60s budget) is the largest overrun this plan justifies`
    );
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

// ---------------------------------------------------------------------------
// Break-proofs (G-1513, TRAV-16) -- performed manually during development,
// confirmed to fail, then reverted; documented here per the same convention
// as the block above.
//
// 3. BREAK-PROOF 1 -- reverted ONLY the `ctx.budget.noteDirectory()` recheck
//    inside `walkDirectory`'s entry loop (kept the `ctx.entryScanCount += 1`
//    increment; deleted the surrounding `if (... % WALK_ENTRY_CLOCK_INTERVAL
//    === 0) { if (!ctx.budget.noteDirectory()) { ...; break; } }` block
//    entirely). Re-ran `node --test tests/traverse/traverse-structural.test.js`:
//    9 pass, 2 FAILED (verbatim):
//      "exhaustion case: ...": AssertionError [ERR_ASSERTION]: Expected
//        values to be strictly equal: false !== true (on `result.stopped`)
//      "noteFile() stays clock-free: ...": AssertionError [ERR_ASSERTION]:
//        Expected values to be strictly equal: 2 !== 3 (on the total now()
//        call count -- without the recheck, only the startNs read and the
//        one per-directory noteDirectory() call touch the clock at all, so
//        the walk's own budget never re-observes the blown clock and emits
//        every one of the 612 files instead of stopping at 511). Restored.
// 4. BREAK-PROOF 2 -- reverted ONLY the `break` inside that same recheck
//    (kept the `ctx.budget.noteDirectory()` call and its `ctx.skips.add(
//    'budget', dirPath)`, so the budget DOES latch on the interval boundary
//    but the entry loop does not immediately exit). Re-ran the same command:
//    10 pass, 1 FAILED (verbatim):
//      "exhaustion case: ...": AssertionError [ERR_ASSERTION]: Expected
//        values to be strictly equal: 2 !== 1 (on `result.skips.counts()
//        .budget`).
//    Note what this failure IS and is NOT: `events.length` was UNCHANGED
//    (511 either way) -- `noteFile()`'s own latch check (it returns `false`
//    the instant `exhaustedReason !== null`, before incrementing anything)
//    already refuses to emit the boundary entry even when the inner `break`
//    is missing, and the loop's PRE-EXISTING `if (ctx.budget.exhausted())
//    break;` at the very top catches the NEXT iteration regardless. The
//    only observable difference is a SECOND 'budget' skip (the recheck's
//    own `ctx.skips.add(dirPath)` plus a follow-on one from `emitEntry`'s
//    `noteFile()` on the same entry, keyed on its absPath) -- proving the
//    inner `break` is still load-bearing (it is what keeps the skip
//    inventory accurate to "one skip per latch event"), even though on
//    this particular flat-file fixture it is not what prevents an
//    over-emission (that guarantee comes from `noteFile()` and the
//    pre-existing top-of-loop check, both untouched by this plan). This is
//    the honest scope of what break-proof 2 proves here, recorded rather
//    than overclaimed. Restored.
// ---------------------------------------------------------------------------
