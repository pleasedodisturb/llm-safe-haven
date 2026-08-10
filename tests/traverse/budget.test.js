'use strict';

// Unit tests for lib/traverse/budget.js -- the injectable-clock wall-clock
// + max-files budget core (D-17, D-19, D-20, TRAV-04). No test in this
// file sleeps or touches real time (17-VALIDATION.md's Nyquist row:
// "budget miscounts on a real huge tree cannot be sampled in CI at all" --
// only the arithmetic is provable here, via an injected clock).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { createBudget } = require('../../lib/traverse/budget.js');
const { normalizeOptions, createSkipInventory, SKIP_REASONS, DEFAULTS } = require('../../lib/traverse/index.js');

// A fake monotonic clock, in nanoseconds (BigInt), advanced ONLY by
// explicit test calls -- mirrors process.hrtime.bigint()'s contract
// (monotonic, nanosecond BigInt) without ever touching the real clock.
function makeClock(startNs = 0n) {
  let current = startNs;
  return {
    now: () => current,
    advanceMs(ms) {
      current += BigInt(ms) * 1_000_000n;
    },
    advanceSeconds(sec) {
      current += BigInt(sec) * 1_000_000_000n;
    },
  };
}

describe('budget.js -- wall-clock exhaustion', () => {
  it('is not exhausted before the deadline', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 10, maxFiles: 1000, now: clock.now });
    clock.advanceSeconds(5);
    assert.equal(budget.noteDirectory(), true);
    assert.equal(budget.exhausted(), false);
    assert.equal(budget.reason(), null);
  });

  it('is exhausted exactly at the deadline (>= budgetMs, not only >)', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 10, maxFiles: 1000, now: clock.now });
    clock.advanceSeconds(10);
    assert.equal(budget.noteDirectory(), false);
    assert.equal(budget.exhausted(), true);
    assert.equal(budget.reason(), 'budget');
  });

  it('latches -- a clock jump backwards after exhaustion cannot un-exhaust', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 10, maxFiles: 1000, now: clock.now });
    clock.advanceSeconds(20);
    assert.equal(budget.noteDirectory(), false);
    assert.equal(budget.exhausted(), true);
    // Jump the clock BACKWARDS -- exhaustion must not clear.
    clock.advanceSeconds(-15);
    assert.equal(budget.noteDirectory(), false);
    assert.equal(budget.exhausted(), true);
    assert.equal(budget.reason(), 'budget');
  });

  it('latches -- calling noteDirectory() again after exhaustion cannot un-exhaust', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 10, maxFiles: 1000, now: clock.now });
    clock.advanceSeconds(10);
    assert.equal(budget.noteDirectory(), false);
    assert.equal(budget.noteDirectory(), false);
    assert.equal(budget.reason(), 'budget');
  });
});

describe('budget.js -- max-files exhaustion is independent of the clock', () => {
  it('exhausts on max-files with the clock frozen at zero (dimensions are independent)', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 10, maxFiles: 2, now: clock.now });
    assert.equal(budget.noteFile(), true); // file 1
    assert.equal(budget.noteFile(), true); // file 2
    assert.equal(budget.noteFile(), false); // file 3 -- over maxFiles:2
    assert.equal(budget.exhausted(), true);
    assert.equal(budget.reason(), 'max-files');
  });

  it('reason() distinguishes budget vs max-files', () => {
    const clockA = makeClock();
    const budgetA = createBudget({ budgetSeconds: 0, maxFiles: 1000, now: clockA.now });
    budgetA.noteDirectory();
    assert.equal(budgetA.reason(), 'budget');

    const clockB = makeClock();
    const budgetB = createBudget({ budgetSeconds: 1000, maxFiles: 0, now: clockB.now });
    budgetB.noteFile();
    assert.equal(budgetB.reason(), 'max-files');
  });

  it('entry-granular file counting: maxFiles 3 allows exactly 3 noteFile() calls, the 4th fails, clock frozen', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 60, maxFiles: 3, now: clock.now });
    assert.equal(budget.noteFile(), true);
    assert.equal(budget.noteFile(), true);
    assert.equal(budget.noteFile(), true);
    assert.equal(budget.noteFile(), false);
    assert.equal(budget.reason(), 'max-files');
  });

  it('noteFiles(n) bulk wrapper is documented as non-enforcement but still tracks the count', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 60, maxFiles: 5, now: clock.now });
    assert.equal(budget.noteFiles(5), true);
    // Overshoots by 4 in a single call -- exactly the documented non-
    // enforcement tradeoff versus noteFile()'s per-entry guarantee.
    assert.equal(budget.noteFiles(4), false);
    assert.equal(budget.snapshot().filesWalked, 9);
    assert.equal(budget.reason(), 'max-files');
  });
});

describe('budget.js -- elapsedMs / remainingMs accuracy', () => {
  it('reports the exact integer millisecond delta across a multi-second BigInt jump', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 60, maxFiles: 1000, now: clock.now });
    clock.advanceMs(3456);
    assert.equal(budget.elapsedMs(), 3456);
    clock.advanceMs(1);
    assert.equal(budget.elapsedMs(), 3457);
  });

  it('remainingMs() is clamped at zero once past the deadline', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 5, maxFiles: 1000, now: clock.now });
    clock.advanceSeconds(9);
    assert.equal(budget.remainingMs(), 0);
  });
});

describe('budget.js -- per-tier completeness (D-20)', () => {
  it('targeted tier completes; bulk tier is cut by budget exhaustion; snapshot() reflects both', () => {
    const clock = makeClock();
    const budget = createBudget({ budgetSeconds: 10, maxFiles: 1000, now: clock.now });

    budget.enterTier('targeted');
    budget.noteDirectory();
    budget.tierComplete('targeted');

    budget.enterTier('bulk');
    clock.advanceSeconds(20);
    assert.equal(budget.noteDirectory(), false);

    const snap = budget.snapshot();
    assert.equal(snap.tiers.targeted, true);
    assert.equal(snap.tiers.bulk, false);
    assert.equal(snap.exhaustedReason, 'budget');
  });
});

describe('budget.js -- env overrides via normalizeOptions actually change exhaustion', () => {
  it('LSH_BUDGET_SECONDS=1 exhausts a budget that the default (60s) would not', () => {
    const clock = makeClock();
    const overridden = normalizeOptions({ env: { LSH_BUDGET_SECONDS: '1' }, now: clock.now });
    assert.equal(overridden.budgetSeconds, 1);
    const budget = createBudget(overridden);
    clock.advanceSeconds(2);
    assert.equal(budget.noteDirectory(), false);
    assert.equal(budget.reason(), 'budget');
  });

  it('LSH_MAX_FILES=5 exhausts a budget that the default (1,000,000) would not', () => {
    const clock = makeClock();
    const overridden = normalizeOptions({ env: { LSH_MAX_FILES: '5' }, now: clock.now });
    assert.equal(overridden.maxFiles, 5);
    const budget = createBudget(overridden);
    for (let i = 0; i < 5; i += 1) assert.equal(budget.noteFile(), true);
    assert.equal(budget.noteFile(), false);
    assert.equal(budget.reason(), 'max-files');
  });
});

// ---------------------------------------------------------------------------
// Zero-budget block (the B4 fix from 17-REVIEWS.md) -- these guards must be
// PROVABLY non-vacuous per Q-02: "0" is the most conservative expressible
// value and must be HONOURED, never silently disabled by falling back to
// the default the way the malformed-input cases below do. Paired-opposite
// tests (the fallback cases) sit right next to the "0 is honoured" cases so
// neither class can pass by accident (tests/tier3-agents.test.js:157-189
// non-vacuous-guard template).
//
// Non-vacuity mutation performed once during development, then reverted:
// changed normalizeOptions's isValidBound() check from `n >= 0` to `n > 0`
// (making "0" fall back to the default like a malformed value) and
// confirmed BOTH "0 is honoured" tests below failed -- this is the exact
// defect class the cross-AI review caught (17-REVIEWS.md).
// ---------------------------------------------------------------------------

describe('budget.js + index.js -- zero-budget is honoured, not disabled (Q-02 non-vacuous)', () => {
  it('LSH_BUDGET_SECONDS=0 normalizes to budgetSeconds:0 with NO warning', () => {
    const opts = normalizeOptions({ env: { LSH_BUDGET_SECONDS: '0' } });
    assert.equal(opts.budgetSeconds, 0);
    assert.deepEqual(opts.warnings, []);
  });

  it('a budget built from LSH_BUDGET_SECONDS=0 exhausts on the FIRST noteDirectory(), clock frozen', () => {
    const clock = makeClock();
    const opts = normalizeOptions({ env: { LSH_BUDGET_SECONDS: '0' }, now: clock.now });
    const budget = createBudget(opts);
    assert.equal(budget.noteDirectory(), false);
    assert.equal(budget.exhausted(), true);
    assert.equal(budget.reason(), 'budget');
  });

  it('LSH_MAX_FILES=0 is accepted and exhausts on the FIRST noteFile()', () => {
    const opts = normalizeOptions({ env: { LSH_MAX_FILES: '0' } });
    assert.equal(opts.maxFiles, 0);
    assert.deepEqual(opts.warnings, []);
    const budget = createBudget(opts);
    assert.equal(budget.noteFile(), false);
    assert.equal(budget.reason(), 'max-files');
  });

  for (const raw of ['-1', 'Infinity', 'abc', '']) {
    it(`LSH_BUDGET_SECONDS=${JSON.stringify(raw)} falls back to the default WITH a warning, and is NOT exhausted on the first checkpoint`, () => {
      const clock = makeClock();
      const opts = normalizeOptions({ env: { LSH_BUDGET_SECONDS: raw }, now: clock.now });
      assert.equal(opts.budgetSeconds, DEFAULTS.budgetSeconds);
      assert.equal(opts.warnings.length, 1);
      const budget = createBudget(opts);
      assert.equal(budget.noteDirectory(), true);
      assert.equal(budget.exhausted(), false);
    });
  }
});

// ---------------------------------------------------------------------------
// index.js contract-surface coverage not exercised by the env-var-driven
// cases above: explicit (non-env) budgetSeconds/maxFiles option values, the
// skipDirs Set/Array normalization branches, and createSkipInventory --
// every piece of exported code gets a unit test (CLAUDE.md).
// ---------------------------------------------------------------------------

describe('index.js -- normalizeOptions explicit option values (not via env)', () => {
  it('an explicit valid budgetSeconds option is used as-is, no warning', () => {
    const opts = normalizeOptions({ budgetSeconds: 42 });
    assert.equal(opts.budgetSeconds, 42);
    assert.deepEqual(opts.warnings, []);
  });

  it('an explicit invalid budgetSeconds option (negative) falls back to the default WITH a warning', () => {
    const opts = normalizeOptions({ budgetSeconds: -5 });
    assert.equal(opts.budgetSeconds, DEFAULTS.budgetSeconds);
    assert.equal(opts.warnings.length, 1);
    assert.match(opts.warnings[0], /invalid budgetSeconds/);
  });

  it('an explicit invalid maxFiles option (Infinity) falls back to the default WITH a warning -- it would disable the bound', () => {
    const opts = normalizeOptions({ maxFiles: Infinity });
    assert.equal(opts.maxFiles, DEFAULTS.maxFiles);
    assert.equal(opts.warnings.length, 1);
    assert.match(opts.warnings[0], /invalid maxFiles/);
  });

  it('an explicit budgetSeconds option takes precedence over the env var (precedence order)', () => {
    const opts = normalizeOptions({ budgetSeconds: 7, env: { LSH_BUDGET_SECONDS: '99' } });
    assert.equal(opts.budgetSeconds, 7);
  });
});

describe('index.js -- normalizeOptions skipDirs normalization', () => {
  it('an array skipDirs option normalizes to a Set with the same members', () => {
    const opts = normalizeOptions({ skipDirs: ['node_modules', '.git'] });
    assert.ok(opts.skipDirs instanceof Set);
    assert.deepEqual([...opts.skipDirs].sort(), ['.git', 'node_modules']);
  });

  it('a Set skipDirs option normalizes to an independent copy (not the same reference)', () => {
    const input = new Set(['dist']);
    const opts = normalizeOptions({ skipDirs: input });
    assert.ok(opts.skipDirs instanceof Set);
    assert.deepEqual([...opts.skipDirs], ['dist']);
    assert.notEqual(opts.skipDirs, input);
  });
});

describe('index.js -- createSkipInventory', () => {
  it('counts() starts zero-filled for every SKIP_REASONS key', () => {
    const inv = createSkipInventory();
    const counts = inv.counts();
    for (const reason of SKIP_REASONS) {
      assert.equal(counts[reason], 0);
    }
    assert.equal(inv.total(), 0);
  });

  it('add() increments the matching reason count and records the path; other reasons stay zero', () => {
    const inv = createSkipInventory();
    inv.add('symlink', '/a/b/link');
    inv.add('symlink', '/a/b/link2');
    inv.add('other-device', '/a/b/ignored');
    const counts = inv.counts();
    assert.equal(counts.symlink, 2);
    assert.equal(counts['other-device'], 1);
    assert.equal(counts.oversized, 0);
    assert.equal(inv.total(), 3);
    assert.deepEqual(inv.paths('symlink'), ['/a/b/link', '/a/b/link2']);
  });

  it('add() throws a TypeError on an unknown reason (a typo cannot create a ghost bucket)', () => {
    const inv = createSkipInventory();
    assert.throws(() => inv.add('not-a-real-reason', '/x'), TypeError);
  });

  it('paths() throws a TypeError on an unknown reason', () => {
    const inv = createSkipInventory();
    assert.throws(() => inv.paths('not-a-real-reason'), TypeError);
  });
});
