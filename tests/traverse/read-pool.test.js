'use strict';

// Structural property tests for lib/traverse/read-pool.js (G-1482, TRAV-01,
// D-02/D-07/D-11/D-20). Every property here is proven both directions where
// applicable so a guard cannot pass vacuously (17-VALIDATION.md Q-02).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { createReadPool } = require('../../lib/traverse/read-pool.js');
const { createBudget } = require('../../lib/traverse/budget.js');
const { normalizeOptions, createSkipInventory } = require('../../lib/traverse/index.js');

const dirs = [];
function mkFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'read-pool-'));
  dirs.push(dir);
  return dir;
}
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function writeFile(dir, name, contents = 'x') {
  const file = path.join(dir, name);
  fs.writeFileSync(file, contents);
  return file;
}

// ---------------------------------------------------------------------------
// Concurrency bound
// ---------------------------------------------------------------------------

describe('read-pool — concurrency bound', () => {
  it('with readPool: 8, maxConcurrent stays <= 8 AND > 1 (both bounds -- an accidentally-serial pool must fail too)', async () => {
    const dir = mkFixture();
    const pool = createReadPool({ readPool: 8 });
    for (let i = 0; i < 200; i += 1) {
      const file = writeFile(dir, `f${i}.js`, `content ${i}`);
      pool.submit({ absPath: file, needBulk: true });
    }
    await pool.drain();
    const { maxConcurrent } = pool.stats();
    assert.ok(maxConcurrent <= 8, `maxConcurrent ${maxConcurrent} exceeded the configured limit of 8`);
    assert.ok(maxConcurrent > 1, `maxConcurrent ${maxConcurrent} suggests the pool ran serially`);
  });
});

// ---------------------------------------------------------------------------
// Single-open contract (D-02)
// ---------------------------------------------------------------------------

describe('read-pool — single-open contract', () => {
  it('50 records, 20 of which need BOTH bulk and hash, still open exactly 50 times (one open per path)', async () => {
    const dir = mkFixture();
    let openCalls = 0;
    const realFs = require('fs');
    const countingFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: (...args) => {
          openCalls += 1;
          return realFs.promises.open(...args);
        },
      },
    };
    const pool = createReadPool({ fs: countingFs });
    for (let i = 0; i < 50; i += 1) {
      const file = writeFile(dir, `dual${i}.js`, `content ${i}`);
      const dual = i < 20;
      pool.submit({ absPath: file, needBulk: true, needHash: dual });
    }
    await pool.drain();
    assert.equal(openCalls, 50);
    assert.equal(pool.stats().opened, 50);
    assert.equal(pool.stats().submitted, 50);
  });

  it('submitting the same path twice throws synchronously (the caller cannot silently violate the one-record-per-path contract)', () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'dup.js');
    const pool = createReadPool({});
    pool.submit({ absPath: file, needBulk: true });
    assert.throws(() => pool.submit({ absPath: file, needHash: true }), /duplicate path/);
  });

  it('submitting two DIFFERENT paths does not throw (proves the guard is not vacuous)', () => {
    const dir = mkFixture();
    const pool = createReadPool({});
    pool.submit({ absPath: writeFile(dir, 'a.js') });
    assert.doesNotThrow(() => pool.submit({ absPath: writeFile(dir, 'b.js') }));
  });

  it('submitting a work record with no absPath throws a TypeError', () => {
    const pool = createReadPool({});
    assert.throws(() => pool.submit({}), TypeError);
    assert.throws(() => pool.submit(null), TypeError);
  });
});

describe('read-pool — empty files and close()-failure resilience', () => {
  it('a zero-byte file with needBulk produces an empty (not null) buffer', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'empty.js', '');
    const pool = createReadPool({});
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.equal(record.bulkSkipped, null);
    assert.equal(record.isBinary, false);
    assert.equal(record.bulkBuffer.length, 0);
  });

  it('a close() failure after a successful read is swallowed -- the record still resolves with its result', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'close-fails.js', 'content');
    const realFs = require('fs');
    const closeFailsFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: async (...args) => {
          const handle = await realFs.promises.open(...args);
          const originalClose = handle.close.bind(handle);
          return Object.assign(Object.create(Object.getPrototypeOf(handle)), handle, {
            close: async () => {
              // Actually close the real fd (avoid leaking it / triggering
              // Node's FileHandle-GC-finalizer warning) but still surface a
              // failure to the caller, simulating a close()-time error
              // AFTER a successful open/read.
              await originalClose();
              throw new Error('injected close failure');
            },
          });
        },
      },
    };
    const pool = createReadPool({ fs: closeFailsFs });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.equal(record.error, undefined);
    assert.equal(record.bulkBuffer.toString(), 'content');
  });
});

// ---------------------------------------------------------------------------
// EMFILE handling
// ---------------------------------------------------------------------------

describe('read-pool — EMFILE never crashes the pool', () => {
  it('a stubbed open() rejecting EMFILE on the 5th call yields one unreadable skip; the other 199 records still complete and the pool resolves', async () => {
    const dir = mkFixture();
    const realFs = require('fs');
    let calls = 0;
    const stubbedFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: (...args) => {
          calls += 1;
          if (calls === 5) {
            const err = new Error('EMFILE: too many open files');
            err.code = 'EMFILE';
            return Promise.reject(err);
          }
          return realFs.promises.open(...args);
        },
      },
    };
    const skipped = [];
    const skips = { add: (reason, absPath) => skipped.push({ reason, absPath }) };
    const pool = createReadPool({ fs: stubbedFs, skips, readPool: 4 });
    const files = [];
    for (let i = 0; i < 200; i += 1) {
      const file = writeFile(dir, `emfile${i}.js`, 'x');
      files.push(file);
      pool.submit({ absPath: file, needBulk: true });
    }
    const results = await pool.drain();

    assert.equal(results.length, 200);
    const unreadable = skipped.filter((s) => s.reason === 'unreadable');
    assert.equal(unreadable.length, 1);
    const errored = results.filter((r) => r.error);
    assert.equal(errored.length, 1);
    const succeeded = results.filter((r) => !r.error);
    assert.equal(succeeded.length, 199);
  });
});

// ---------------------------------------------------------------------------
// Binary bail
// ---------------------------------------------------------------------------

describe('read-pool — binary bail', () => {
  it('a file whose first chunk contains a NUL byte is not marker-matched, and bytesRead is at most sniffBytes', async () => {
    const dir = mkFixture();
    const file = path.join(dir, 'binary.bin');
    const buf = Buffer.alloc(20000, 0x61);
    buf[10] = 0x00; // NUL inside the sniff window (default sniffBytes 8000... place well within)
    buf[5] = 0x00;
    fs.writeFileSync(file, buf);

    const pool = createReadPool({ sniffBytes: 8000 });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();

    assert.equal(record.isBinary, true);
    assert.equal(record.bulkBuffer, null);
    assert.ok(pool.stats().bytesRead <= 8000, `bytesRead ${pool.stats().bytesRead} exceeded sniffBytes`);
  });

  it('the SAME size file with no NUL byte in the sniff window IS bulk-read past the sniff window (proves the guard is not vacuous)', async () => {
    const dir = mkFixture();
    const file = path.join(dir, 'text.js');
    const buf = Buffer.alloc(20000, 0x61);
    fs.writeFileSync(file, buf);

    const pool = createReadPool({ sniffBytes: 8000 });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();

    assert.equal(record.isBinary, false);
    assert.equal(record.bulkBuffer.length, 20000);
  });
});

// ---------------------------------------------------------------------------
// Budget cancellation
// ---------------------------------------------------------------------------

describe('read-pool — budget cancellation (G-1506: real createBudget(), not a one-member stub)', () => {
  // The stub this block used to use (`{ exhausted: () => noted >= 10 }`) has
  // exactly ONE of createBudget()'s ten members. It could never exercise the
  // interval-cadence recheck this file's `runWorker()` now performs (it
  // would throw `budget.noteDirectory is not a function` the instant that
  // code runs) and it advanced its own fake "clock" from a side effect
  // smuggled into the counting `fs.promises.open` stub, which is a
  // characterization of the OLD synchronous-latch behaviour, not a
  // regression guard for the live clock. Every case below drives a REAL
  // `createBudget()` instead.

  function buildFixture(dir, n, prefix) {
    const files = [];
    for (let i = 0; i < n; i += 1) files.push(writeFile(dir, `${prefix}${i}.js`, 'x'));
    return files;
  }

  function countingOpenFs() {
    let opens = 0;
    const realFs = require('fs');
    const fsImpl = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: (...args) => {
          opens += 1;
          return realFs.promises.open(...args);
        },
      },
    };
    return { fsImpl, getOpens: () => opens };
  }

  it('a real createBudget() whose clock crosses budgetSeconds mid-drain of 30 records (readPool: 1) stops opening NEW records; the rest are recorded as budget skips', async () => {
    const dir = mkFixture();
    const files = buildFixture(dir, 30, 'cross30-');
    const { fsImpl, getOpens } = countingOpenFs();

    // `now()` returns 0n for the construction-time `startNs` read (call 1),
    // then a value past `budgetSeconds * 1000` for every call after that --
    // which is the FIRST in-drain `noteDirectory()` recheck the pool
    // performs, at the 16th (READ_POOL_CLOCK_INTERVAL) completed record of
    // this readPool:1 serial drain. The crossing therefore lands mid-drain
    // deterministically, not by reading an integer off a failing run.
    const budgetSeconds = 5;
    let calls = 0;
    const now = () => {
      calls += 1;
      return calls <= 1 ? 0n : BigInt((budgetSeconds * 1000 + 1000) * 1e6);
    };
    const budget = createBudget(normalizeOptions({ budgetSeconds, now }));
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: fsImpl, budget, skips, readPool: 1 });
    for (const file of files) pool.submit({ absPath: file, needBulk: true });
    const results = await pool.drain();

    const opens = getOpens();
    assert.equal(results.length, 30);
    assert.ok(opens > 0 && opens < 30, `opens ${opens} must be strictly between 0 and 30 -- the pool must both do SOME real work and stop before the end`);
    assert.equal(skips.counts().budget, 30 - opens);
    assert.equal(results.filter((r) => r.skipped === 'budget').length, 30 - opens);
    assert.equal(budget.reason(), 'budget');
  });

  it('paired within-budget control: identical 30-record fixture, ample budget -- zero budget skips, all 30 opened', async () => {
    const dir = mkFixture();
    const files = buildFixture(dir, 30, 'cross30ctrl-');
    const { fsImpl, getOpens } = countingOpenFs();

    const budget = createBudget(normalizeOptions({ budgetSeconds: 3600, now: () => 0n }));
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: fsImpl, budget, skips, readPool: 1 });
    for (const file of files) pool.submit({ absPath: file, needBulk: true });
    const results = await pool.drain();

    assert.equal(results.length, 30);
    assert.equal(getOpens(), 30);
    assert.equal(skips.counts().budget, 0);
    assert.equal(results.filter((r) => r.skipped === 'budget').length, 0);
    assert.equal(budget.exhausted(), false);
  });

  it('15-record blind spot (documented limit, not a passing guard): a drain shorter than READ_POOL_CLOCK_INTERVAL (16) never triggers the in-drain recheck, so an over-budget clock is invisible to the pool alone', async () => {
    const dir = mkFixture();
    const files = buildFixture(dir, 15, 'short15-');
    const { fsImpl, getOpens } = countingOpenFs();

    // Over budget from the very first call AFTER construction -- but with
    // only 15 records and READ_POOL_CLOCK_INTERVAL = 16, `processed %
    // READ_POOL_CLOCK_INTERVAL === 0` is never true, so `noteDirectory()` is
    // never called inside this drain at all, and the pre-record
    // `budget.exhausted()` check only ever reads the flag `noteDirectory()`
    // would have latched -- which never ran.
    const budgetSeconds = 5;
    let calls = 0;
    const now = () => {
      calls += 1;
      return calls <= 1 ? 0n : BigInt((budgetSeconds * 1000 + 1000) * 1e6);
    };
    const budget = createBudget(normalizeOptions({ budgetSeconds, now }));
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: fsImpl, budget, skips, readPool: 1 });
    for (const file of files) pool.submit({ absPath: file, needBulk: true });
    const results = await pool.drain();

    assert.equal(results.length, 15);
    assert.equal(getOpens(), 15);
    assert.equal(
      skips.counts().budget,
      0,
      'the read pool ALONE cannot see a budget that expires during a drain shorter than READ_POOL_CLOCK_INTERVAL -- ' +
        "tests/traverse/engine.test.js's targeted-tier 15-record case (Task 2, decision D-06) is the guard that backstops this via the engine's pre-gate recheck"
    );
  });

  it('paired within-budget control for the 15-record case: identical fixture, ample budget -- same observable outcome, proving the 15-record case above is not passing because the pool is inert', async () => {
    const dir = mkFixture();
    const files = buildFixture(dir, 15, 'short15ctrl-');
    const { fsImpl, getOpens } = countingOpenFs();

    const budget = createBudget(normalizeOptions({ budgetSeconds: 3600, now: () => 0n }));
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: fsImpl, budget, skips, readPool: 1 });
    for (const file of files) pool.submit({ absPath: file, needBulk: true });
    const results = await pool.drain();

    assert.equal(results.length, 15);
    assert.equal(getOpens(), 15);
    assert.equal(skips.counts().budget, 0);
  });

  it('with NO budget supplied, all records complete without any budget skip (proves the guard is not vacuous)', async () => {
    const dir = mkFixture();
    const pool = createReadPool({ readPool: 1 });
    for (let i = 0; i < 10; i += 1) {
      pool.submit({ absPath: writeFile(dir, `nobudget${i}.js`, 'x'), needBulk: true });
    }
    const results = await pool.drain();
    assert.equal(results.filter((r) => r.skipped === 'budget').length, 0);
  });
});

// ---------------------------------------------------------------------------
// Priority ordering (D-20)
// ---------------------------------------------------------------------------

describe('read-pool — priority ordering without a second queue', () => {
  it('with readPool: 1, targeted-priority records complete before bulk-priority records submitted EARLIER', async () => {
    const dir = mkFixture();
    const order = [];
    const realFs = require('fs');
    const orderedFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: (p, ...rest) => {
          order.push(p);
          return realFs.promises.open(p, ...rest);
        },
      },
    };
    const pool = createReadPool({ fs: orderedFs, readPool: 1 });
    const bulkFile = writeFile(dir, 'bulk-first-submitted.js', 'x');
    const targetedFile = writeFile(dir, 'targeted-second-submitted.js', 'x');
    pool.submit({ absPath: bulkFile, needBulk: true, priority: 'bulk' });
    pool.submit({ absPath: targetedFile, needHash: true, priority: 'targeted' });
    await pool.drain();

    assert.deepEqual(order, [targetedFile, bulkFile]);
  });
});

// ---------------------------------------------------------------------------
// Handle close accounting
// ---------------------------------------------------------------------------

describe('read-pool — handles are always closed', () => {
  it('close() calls equal open() successes, including on a read-time error path', async () => {
    const dir = mkFixture();
    let opens = 0;
    let closes = 0;
    const realFs = require('fs');
    const flakyFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: async (...args) => {
          const handle = await realFs.promises.open(...args);
          opens += 1;
          const originalClose = handle.close.bind(handle);
          const originalStat = handle.stat.bind(handle);
          let failOnce = args[0].endsWith('fail-stat.js');
          return Object.assign(Object.create(Object.getPrototypeOf(handle)), handle, {
            stat: async (...a) => {
              if (failOnce) throw new Error('injected stat failure');
              return originalStat(...a);
            },
            close: async (...a) => {
              closes += 1;
              return originalClose(...a);
            },
          });
        },
      },
    };
    const skipped = [];
    const pool = createReadPool({ fs: flakyFs, skips: { add: (r, p) => skipped.push({ r, p }) } });
    pool.submit({ absPath: writeFile(dir, 'ok.js', 'x'), needBulk: true });
    pool.submit({ absPath: writeFile(dir, 'fail-stat.js', 'x'), needBulk: true });
    const results = await pool.drain();

    assert.equal(opens, 2);
    assert.equal(closes, 2, 'close() must be called even after a stat()-time error');
    assert.ok(results.some((r) => r.error));
    assert.ok(skipped.some((s) => s.r === 'unreadable'));
  });
});

// ---------------------------------------------------------------------------
// Unreadable / oversized accounting (G-1501/G-1512, Guard 5) -- pins the
// `recordSkip()` wrapper contract that tests/traverse/engine.test.js's
// Guards 2 and 3 depend on: `skips.add()` is called with the right reason
// AND `stats().skipped` is incremented together, for both an open()-time
// rejection and an over-cap size.
// ---------------------------------------------------------------------------

describe('read-pool — unreadable / oversized accounting (G-1501/G-1512)', () => {
  it('a rejecting open() produces exactly one "unreadable" skip entry AND increments stats().skipped', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'denied.js', 'x');
    const realFs = require('fs');
    const denyingFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: () => {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          return Promise.reject(err);
        },
      },
    };
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: denyingFs, skips });
    pool.submit({ absPath: file, needBulk: true });
    await pool.drain();

    assert.equal(skips.counts().unreadable, 1);
    assert.deepEqual(skips.paths('unreadable'), [file]);
    assert.equal(pool.stats().skipped, 1);
  });

  it('a file at/over bulkReadCapBytes produces exactly one "oversized" skip entry AND increments stats().skipped', async () => {
    const dir = mkFixture();
    const cap = normalizeOptions({}).bulkReadCapBytes;
    const file = writeFile(dir, 'huge.js', 'x'.repeat(cap));
    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();

    assert.equal(skips.counts().oversized, 1);
    assert.deepEqual(skips.paths('oversized'), [file]);
    assert.equal(pool.stats().skipped, 1);
    assert.equal(record.bulkSkipped, 'oversized-bulk');
  });
});
