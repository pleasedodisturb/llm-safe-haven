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

// ---------------------------------------------------------------------------
// A FIFO can never block or be read (G-1503, TRAV-11, D-17.1-D)
//
// A writerless FIFO planted where a regular file was classified must be
// refused in BOUNDED time (never block libuv's threadpool, T-17.1-05-01)
// and must never have a single byte reach the marker matcher or the SHA256
// digest (T-17.1-05-03). Both layers -- O_NONBLOCK (the open cannot block)
// and the post-open file-type gate (the fstat refusal) -- are exercised
// together here; break-proofs 1 and 2 below prove each is INDEPENDENTLY
// load-bearing, not merely that one covers for the other.
// ---------------------------------------------------------------------------

describe('read-pool — a FIFO can never block or be read (G-1503, TRAV-11)', () => {
  it('a writerless FIFO is refused in bounded time, zero bytes read; paired regular-file control reads normally', { timeout: 5000 }, async (t) => {
    // Copied verbatim from tests/mcp/base.test.js:57-64 -- the same guard
    // shape, not re-derived.
    const { spawnSync } = require('child_process');
    const dir = mkFixture();
    const fifoPath = path.join(dir, 'blocking.fifo');
    const mkfifo = spawnSync('mkfifo', [fifoPath]);
    if (mkfifo.error || mkfifo.status !== 0) {
      t.skip('mkfifo not available on this platform');
      return;
    }

    // Without this guard, a hypothetical platform with mkfifo but no
    // O_NONBLOCK would TIME OUT rather than skip -- in an unattended run
    // that is a five-second stall reported as a failure, not a clean skip.
    if (!require('fs').constants.O_NONBLOCK) {
      t.skip('O_NONBLOCK unavailable on this platform');
      return;
    }

    // The explicit { timeout: 5000 } above is load-bearing for two
    // reasons. (1) It is what turns the flag-reverting break-proofs
    // (recorded in 17.1-05-SUMMARY.md) into an OBSERVABLE FAILURE inside
    // the child process instead of an indefinite stall: with the flags
    // reverted, open() on a writerless FIFO blocks forever. (2) It is the
    // CI signal for research Assumption A2 -- 17.1-VALIDATION.md's
    // Manual-Only Verifications section asks a human to eyeball the
    // test-macos CI job log for THIS test the first time it lands: a
    // near-instant pass corroborates A2 (a writerless FIFO's non-blocking
    // open does not silently retry), a slow-but-green pass would mean
    // something is retrying rather than surfacing the condition promptly.

    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: fifoPath, needBulk: true, needHash: true });
    const [record] = await pool.drain();

    assert.equal(record.error, 'not-regular-file');
    assert.equal(skips.counts().unreadable, 1);
    assert.equal(skips.counts().symlink, 0);
    assert.equal(pool.stats().skipped, 1);
    assert.equal(pool.stats().bytesRead, 0, 'no byte of a FIFO may reach the marker matcher or the digest');

    // Paired control, same describe block: without this, a pool that
    // refused EVERYTHING would also pass the FIFO case above.
    const controlFile = writeFile(dir, 'fifo-control.js', 'ordinary content');
    const controlSkips = createSkipInventory();
    const controlPool = createReadPool({ skips: controlSkips });
    controlPool.submit({ absPath: controlFile, needBulk: true, needHash: true });
    const [controlRecord] = await controlPool.drain();

    assert.equal(controlSkips.total(), 0);
    assert.equal(controlPool.stats().opened, 1);
    assert.notEqual(controlRecord.digest, null);
  });

  // Break-proofs 1 and 2 (D-17.1-F, MANDATORY): run as a CHILD PROCESS
  // under a parent-enforced spawnSync timeout, never in the foreground of
  // this test runner -- see 17.1-05-SUMMARY.md for the verbatim recorded
  // output of both. Reverting the O_NONBLOCK/O_NOFOLLOW flags makes
  // open() on a writerless FIFO block in the libuv threadpool; node:test's
  // own { timeout: 5000 } marks that case FAILED but cannot cancel the
  // pending operation, so only a parent-enforced timeout on a spawned
  // child process can guarantee this session does not wedge overnight.
  //
  // Blind spot of this guard (see also 17.1-05-SUMMARY.md): it proves a
  // WRITERLESS FIFO is refused in bounded time with zero bytes read. It
  // does NOT prove anything about sockets or device nodes (no test covers
  // those; walk.js never emits them and the same file-type gate would
  // refuse them, but that is reasoning, not evidence). It does not
  // exercise a FIFO WITH a writer -- deliberately, since the file-type
  // gate returns before any read and the reviewer claim that this case
  // hangs was refuted (see the plan's REJECTED-claims list). And the
  // { timeout: 5000 } bound is a TEST-HARNESS bound, not a product bound:
  // nothing in the product cancels an in-flight read, a residual already
  // documented in plan 17.1-01's READ_POOL_CLOCK_INTERVAL comment.
});

// ---------------------------------------------------------------------------
// readBulkContent reads a CONTIGUOUS remainder and reports a short read
// (D-10 + SCAN-04, G-1541, Task 1).
//
// Review A-1 boundary: `readBulkContent` is NOT exported and `record.
// shortRead` does not exist until Task 2 -- every assertion below is on
// `record.bulkBuffer` and the skip inventory, driven through
// `createReadPool` + `submit({ needBulk: true })` + `drain()`. The `short`
// flag this task adds to `readBulkContent`'s four return paths is asserted
// in Task 2 (as `record.shortRead`), once it reaches the record.
// ---------------------------------------------------------------------------

function positionalContent(n) {
  // Position-dependent so a spliced buffer (a hole in the middle) is
  // detectable by VALUE, not merely by length -- a repeating decimal digit
  // keyed off the byte offset.
  return Buffer.from(Array.from({ length: n }, (_, i) => String(i % 10)).join(''));
}

function wrapHandleRead(realOpen, onRead) {
  return async (...args) => {
    const handle = await realOpen(...args);
    const originalRead = handle.read.bind(handle);
    let callCount = 0;
    return Object.assign(Object.create(Object.getPrototypeOf(handle)), handle, {
      read: async (buffer, offset, length, position) => {
        callCount += 1;
        return onRead({ callCount, originalRead, buffer, offset, length, position });
      },
    });
  };
}

// Half-then-zero: the FIRST read on a handle returns HALF the bytes the
// real read actually produced; every subsequent read on the SAME handle
// returns zero. Half-then-zero (rather than a fixed clamp) keeps
// hashWholeFile's `while (offset < size)` loop to exactly two iterations
// regardless of fixture size, makes `bytesRead < size` deterministic, and
// terminates the loop through the `n <= 0` guard rather than by exhausting
// the file -- the real-world shape a shrinking/truncated read takes.
function halfThenZeroFs() {
  const realFs = require('fs');
  return {
    ...realFs,
    promises: {
      ...realFs.promises,
      open: wrapHandleRead(realFs.promises.open, async ({ callCount, originalRead, buffer, offset, length, position }) => {
        if (callCount === 1) {
          const real = await originalRead(buffer, offset, length, position);
          return { bytesRead: Math.floor(real.bytesRead / 2), buffer };
        }
        return { bytesRead: 0, buffer };
      }),
    },
  };
}

// Short-sniff-then-full: the FIRST read on a handle returns half the bytes
// the real read actually produced (a short sniff); every subsequent read on
// the SAME handle delegates to the original, unmodified read. This is the
// D-10 DISCRIMINATOR: under the pre-fix splice, the second (remainder) read
// starts at the REQUESTED sniff offset rather than the ACTUAL one, so the
// bytes between the actual and requested offsets are never read and the
// returned buffer has a hole; under the fix, the remainder read starts
// exactly where the sniff actually ended, so there is no hole.
function shortSniffThenFullFs() {
  const realFs = require('fs');
  return {
    ...realFs,
    promises: {
      ...realFs.promises,
      open: wrapHandleRead(realFs.promises.open, async ({ callCount, originalRead, buffer, offset, length, position }) => {
        if (callCount === 1) {
          const real = await originalRead(buffer, offset, length, position);
          return { bytesRead: Math.floor(real.bytesRead / 2), buffer };
        }
        return originalRead(buffer, offset, length, position);
      }),
    },
  };
}

describe('read-pool — readBulkContent reads a CONTIGUOUS remainder and reports a short read (D-10 + SCAN-04, G-1541, Task 1)', () => {
  const SNIFF_BYTES = normalizeOptions({}).sniffBytes;

  it('D-10 DISCRIMINATOR: a short sniff followed by the remainder read yields a bulkBuffer BYTE-IDENTICAL to the real file — a spliced buffer would still pass a length-only check, so this asserts CONTENT equality, which the length-only version of SCAN-04 would have passed incorrectly', async () => {
    const dir = mkFixture();
    const size = SNIFF_BYTES + 2000; // larger than sniffBytes, smaller than bulkReadCapBytes
    const real = positionalContent(size);
    const file = path.join(dir, 'discriminator.txt');
    fs.writeFileSync(file, real);

    const skips = createSkipInventory();
    const pool = createReadPool({ fs: shortSniffThenFullFs(), skips });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();

    assert.ok(
      record.bulkBuffer.equals(real),
      'record.bulkBuffer must equal the real file contents byte-for-byte — a splice (bytes missing from the middle) still produces a buffer of a plausible LENGTH, so only a content comparison catches it'
    );
    assert.equal(skips.total(), 0);
  });

  it('truncation, bulk branch: a half-then-zero read yields a strict CONTIGUOUS PREFIX of the real contents, shorter than the file', async () => {
    const dir = mkFixture();
    const size = SNIFF_BYTES + 2000;
    const real = positionalContent(size);
    const file = path.join(dir, 'truncated.txt');
    fs.writeFileSync(file, real);

    const pool = createReadPool({ fs: halfThenZeroFs() });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();

    assert.ok(
      record.bulkBuffer.length < real.length,
      `bulkBuffer.length ${record.bulkBuffer.length} must be strictly shorter than the real file (${real.length})`
    );
    assert.ok(
      record.bulkBuffer.equals(real.subarray(0, record.bulkBuffer.length)),
      'the returned buffer must be a CONTIGUOUS PREFIX of the real content, not a splice'
    );
  });

  it('zero-byte file is never short: needBulk through BOTH truncating stubs AND the real fs produces zero skips and an empty buffer — treating an empty file as short would make every empty file in the tree an anomaly', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'empty-short.js', '');

    for (const fsImpl of [halfThenZeroFs(), shortSniffThenFullFs(), require('fs')]) {
      const skips = createSkipInventory();
      const pool = createReadPool({ fs: fsImpl, skips });
      pool.submit({ absPath: file, needBulk: true });
      const [record] = await pool.drain();
      assert.equal(skips.total(), 0, 'an empty file must never be treated as a short read, through any fs implementation');
      assert.equal(record.bulkBuffer.length, 0);
    }
  });

  it('PAIRED CONTROL — real fs, a file BELOW sniffBytes: bulkBuffer equals the real content exactly, zero skips', async () => {
    const dir = mkFixture();
    const real = positionalContent(200);
    const file = path.join(dir, 'below-sniff.txt');
    fs.writeFileSync(file, real);
    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.ok(record.bulkBuffer.equals(real));
    assert.equal(skips.total(), 0);
  });

  it('PAIRED CONTROL — real fs, a file ABOVE sniffBytes: bulkBuffer equals the real content exactly, zero skips', async () => {
    const dir = mkFixture();
    const size = SNIFF_BYTES + 2000;
    const real = positionalContent(size);
    const file = path.join(dir, 'above-sniff.txt');
    fs.writeFileSync(file, real);
    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.ok(record.bulkBuffer.equals(real));
    assert.equal(skips.total(), 0);
  });

  // Break-proof (MANDATORY, D-10). Revert ONLY the D-10 substitution in
  // lib/traverse/read-pool.js (put `remaining` and the remainder read's
  // `position` back on the REQUESTED `sniffLen`), re-run
  // `node --test tests/traverse/read-pool.test.js`, and record the observed
  // failure VERBATIM in the plan's SUMMARY.
  //
  // Named case that MUST fail (D-12): the D-10 DISCRIMINATOR case above, on
  // its `Buffer.equals` assertion. ONE named failure is correct and
  // sufficient here — only the short-sniff-then-full path depends on the
  // substitution. The half-then-zero case still yields a contiguous prefix
  // under the old code (its second read returns nothing, so there is no
  // splice to observe), the zero-byte case never reaches the remainder
  // read, and the real-fs paired controls never come up short. Reverting
  // the substitution therefore breaks exactly one behaviour.
  //
  // Blind spot of this break-proof (MANDATORY to state in the SUMMARY): it
  // proves the two reads are contiguous when the FIRST one comes up short.
  // It does NOT prove anything about a short REMAINDER read followed by
  // more data (there is no third read — the function reads at most twice),
  // it does NOT prove the kernel ever actually returns a short read on a
  // regular file on this platform (the stub is the only producer in this
  // suite; the real-world triggers are network filesystems, concurrent
  // truncation and signal interruption, none of which CI exercises), and it
  // says nothing about whether `sniffBytes` is the right window.
});

// ---------------------------------------------------------------------------
// A short read anywhere in the read pool records exactly one `unreadable`
// skip per RECORD, suppresses the untrustworthy digest, and keeps the
// partial content (Task 2, SCAN-04/D-03, G-1541).
//
// `record.shortRead` is the signal the four `readBulkContent` return paths
// Task 1 added `short` to now surface onto -- unobservable in Task 1
// (review A-1), asserted here for the first time.
// ---------------------------------------------------------------------------

describe('read-pool — a short read records ONE unreadable skip per record, suppresses the digest, and keeps the partial content (D-03, SCAN-04, G-1541, Task 2)', () => {
  it('the four readBulkContent return paths deferred from Task 1, now observable as record.shortRead: complete read (falsy)', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'complete.js', 'ordinary content, read in full');
    const pool = createReadPool({});
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.ok(!record.shortRead, `record.shortRead must be falsy on a complete read, got ${record.shortRead}`);
  });

  it('a truncated read (falsy -> true): record.shortRead === true', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'truncated.js', 'x'.repeat(500));
    const pool = createReadPool({ fs: halfThenZeroFs() });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.equal(record.shortRead, true);
  });

  it('a zero-byte file (falsy): record.shortRead is falsy -- an empty file is not a short read, and treating it as one would make every empty file in the tree an anomaly', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'empty.js', '');
    const pool = createReadPool({ fs: halfThenZeroFs() });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.ok(!record.shortRead, 'an empty file must never be reported as a short read');
  });

  it('a binary-sniff bail whose sniff itself came up short: record.shortRead === true', async () => {
    const dir = mkFixture();
    const buf = Buffer.alloc(200, 0x61);
    buf[5] = 0x00; // NUL well within the half-read window this stub returns
    const file = path.join(dir, 'binary-short.bin');
    fs.writeFileSync(file, buf);
    const pool = createReadPool({ fs: halfThenZeroFs() });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.equal(record.isBinary, true);
    assert.equal(record.shortRead, true);
  });

  it('bulk-only short read: one unreadable skip naming the path, record.error falsy, partial bulkBuffer retained', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'bulk-only.js', 'x'.repeat(500));
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: halfThenZeroFs(), skips });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();

    assert.equal(skips.counts().unreadable, 1);
    assert.ok(skips.paths('unreadable').includes(file));
    assert.equal(record.shortRead, true);
    assert.ok(
      !record.error,
      'Pitfall 1: a short read must NOT set record.error -- generateContentFindings skips any record with a truthy error, which would discard every finding derivable from the partial content that WAS read'
    );
    assert.ok(record.bulkBuffer !== null && record.bulkBuffer.length > 0, 'the partial bulkBuffer must be retained so marker matching still runs over it');
  });

  it('hash-only short read: one unreadable skip, digest null, record.error falsy, stats().hashed stays 0', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'hash-only.js', 'x'.repeat(1000));
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: halfThenZeroFs(), skips });
    pool.submit({ absPath: file, needHash: true });
    const [record] = await pool.drain();

    assert.equal(skips.counts().unreadable, 1);
    assert.equal(record.digest, null, 'a digest computed over fewer bytes than the file must never be emitted');
    assert.ok(!record.error);
    assert.equal(pool.stats().hashed, 0);
  });

  it('dual-tier de-dup: a record short on BOTH reads records exactly ONE unreadable entry, not two', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'dual-short.js', 'x'.repeat(500));
    const skips = createSkipInventory();
    const pool = createReadPool({ fs: halfThenZeroFs(), skips });
    pool.submit({ absPath: file, needBulk: true, needHash: true });
    const [record] = await pool.drain();

    assert.equal(record.shortRead, true);
    assert.equal(skips.counts().unreadable, 1, 'a dual-tier record short on both reads must record exactly ONE unreadable entry, not two');
    assert.equal(skips.paths('unreadable').length, 1);
  });

  it('PAIRED CONTROL — bulk-only, real fs: zero skips, shortRead falsy, error falsy', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'bulk-only-ctrl.js', 'x'.repeat(500));
    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.equal(skips.total(), 0);
    assert.ok(!record.shortRead);
    assert.ok(!record.error);
  });

  it('PAIRED CONTROL — hash-only, real fs: zero skips, non-null digest, stats().hashed === 1', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'hash-only-ctrl.js', 'x'.repeat(1000));
    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: file, needHash: true });
    const [record] = await pool.drain();
    assert.equal(skips.total(), 0);
    assert.notEqual(record.digest, null);
    assert.equal(pool.stats().hashed, 1);
  });

  it('PAIRED CONTROL — dual-tier, real fs: zero skips, shortRead falsy, non-null digest', async () => {
    const dir = mkFixture();
    const file = writeFile(dir, 'dual-ctrl.js', 'x'.repeat(500));
    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: file, needBulk: true, needHash: true });
    const [record] = await pool.drain();
    assert.equal(skips.total(), 0);
    assert.ok(!record.shortRead);
    assert.notEqual(record.digest, null);
  });

  it('PAIRED CONTROL — the existing unreadable sites still work: a rejecting open() still records unreadable and still returns a truthy record.error -- this pins the distinction the whole task rests on: a FAILED read sets error, a SHORT read does not', async () => {
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
    const [record] = await pool.drain();

    assert.equal(skips.counts().unreadable, 1);
    assert.ok(record.error, 'a FAILED read (open() rejection) must still set record.error -- unlike a SHORT read, which never does');
  });

  // Break-proof 1 (MANDATORY, the hash half). Revert ONLY the
  // `hashed.bytesRead !== size` comparison in lib/traverse/read-pool.js
  // (assign the digest unconditionally again), re-run
  // `node --test tests/traverse/read-pool.test.js tests/traverse/engine.test.js`,
  // and record the observed failure VERBATIM in the plan's SUMMARY.
  //
  // Named case that MUST fail (D-12): the hash-only short-read case above
  // (reports a non-null digest and zero skips). ONE named failure is
  // correct here -- the dual-tier de-dup case still records its single skip
  // through the BULK branch and stays green; the bulk-only case never
  // touches the hash branch; the real-fs controls never come up short; and
  // the end-to-end engine cases (tests/traverse/engine.test.js) drive bulk
  // content, not hashes. Reverting the hash comparison breaks exactly one
  // behaviour.
  //
  // Break-proof 2 (MANDATORY, the bulk half). Restore the hash comparison,
  // then revert ONLY the `noteShortRead()` call in the bulk branch, re-run,
  // and record the observed failure verbatim. The two must be proven
  // INDEPENDENTLY -- reverting them together would let one guard cover for
  // the other.
  //
  // Named cases that MUST fail (D-12): the bulk-only short-read case above
  // AND the benign end-to-end case in tests/traverse/engine.test.js (which
  // reports exitCode === 0 / incomplete === false once the bulk skip stops
  // being recorded). Two are required here: one pins the pool's recording
  // site, the other pins that the recording actually reaches the exit code
  // -- a wiring change between them would break only the second.
  //
  // Break-proof 3 (MANDATORY, Pitfall 1 -- the one that matters most).
  // Restore both, then change the short-read path to set
  // `error: 'short-read'` on the record INSTEAD of `shortRead: true`.
  // Re-run `node --test tests/traverse/engine.test.js
  // tests/traverse/read-pool.test.js` and record the observed failure
  // verbatim.
  //
  // Named cases that MUST fail (D-12): the marker-in-partial-content
  // end-to-end case in tests/traverse/engine.test.js (it loses its finding
  // and reports exitCode === 2 instead of 1) AND the bulk-only pool case's
  // `record.error` falsy assertion above. Two are required and both are
  // genuinely independent: the first proves the detection loss reaches the
  // operator's exit code, the second proves the record-level contract that
  // causes it, and an implementation that set `error` only on the hash path
  // would fail one but not the other.
  //
  // Blind spot of these break-proofs (MANDATORY to state in the SUMMARY):
  // they prove a short read reaches `incomplete` and does not suppress
  // findings. They CANNOT detect (a) a short read that is never DETECTED in
  // the first place -- if a future change stops comparing `bytesRead` to
  // `size`, the counter and the verdict go quiet together, which is why
  // this pool-level block pins the recording sites separately from the
  // engine-level end-to-end verdict; (b) whether the exit code is CORRECT
  // for an arbitrary severity mix -- tests/traverse/exit-precedence.test.js
  // owns D-18; (c) the residual documented but NOT fixed: a file
  // legitimately truncated by another process between fstat and read (log
  // rotation) is now `unreadable` -> exit 2. Semantically correct -- "I
  // tried to read N bytes and got fewer, so the digest is not trustworthy"
  // -- but no long-running high-churn tree was sampled.
});

// ---------------------------------------------------------------------------
// A symlink at the final path component is never followed (G-1503, D-06)
//
// walk.js already refuses a symlink it SEES during enumeration
// (walk.js:218-221, D-06). This is the read-side half of the same
// invariant: a symlink swapped in AFTER classification but before the
// pool's open() must be refused at the kernel level (O_NOFOLLOW), counted
// specifically in the `symlink` bucket (not `unreadable`), and its bytes
// must never be read.
// ---------------------------------------------------------------------------

describe('read-pool — a symlink at the final path component is never followed (G-1503, D-06)', () => {
  it('Case 1: the refusal -- symlink submitted directly is refused with reason discrimination (swapped, not symlink or unreadable) (D-01, G-1543/G-1544)', async (t) => {
    if (!fs.constants.O_NOFOLLOW) {
      t.skip('O_NOFOLLOW not available on this platform');
      return;
    }
    const dir = mkFixture();
    const targetPath = writeFile(dir, 'symlink-target.js', 'recognisable content for the symlink target');
    const linkPath = path.join(dir, 'symlink-link.js');
    fs.symlinkSync(targetPath, linkPath);

    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: linkPath, needBulk: true, needHash: true });
    await pool.drain();

    // This is the read-side, post-classification half of D-06: walk.js
    // already refuses a symlink it SEES during enumeration (walk.js:218-221)
    // under the `symlink` reason (unchanged, SCOPE). Submitting a symlink
    // path DIRECTLY to createReadPool -- bypassing the walk entirely -- is
    // the post-classification case, so O_NOFOLLOW's refusal here is
    // recorded as `swapped` instead (D-01, G-1543/G-1544, ANOMALY). Both
    // neighbouring reasons must be zero, or this test cannot tell a rename
    // from a split.
    assert.equal(skips.counts().swapped, 1);
    assert.equal(skips.counts().unreadable, 0);
    assert.equal(skips.counts().symlink, 0);
    assert.ok(skips.paths('swapped').includes(linkPath));
    assert.equal(pool.stats().opened, 0);
    assert.equal(pool.stats().bytesRead, 0);
  });

  it('Case 2: the paired control -- the symlink TARGET, submitted directly, IS read normally', async (t) => {
    if (!fs.constants.O_NOFOLLOW) {
      t.skip('O_NOFOLLOW not available on this platform');
      return;
    }
    const dir = mkFixture();
    const targetPath = writeFile(dir, 'symlink-target-ctrl.js', 'recognisable content for the symlink target control');
    // Note: a symlink is created in the fixture dir too (unused by this
    // case) so the fixture shape matches Case 1's; only the TARGET path is
    // ever submitted here.
    const linkPath = path.join(dir, 'symlink-link-ctrl.js');
    fs.symlinkSync(targetPath, linkPath);

    const skips = createSkipInventory();
    const pool = createReadPool({ skips });
    pool.submit({ absPath: targetPath, needBulk: true, needHash: true });
    const [record] = await pool.drain();

    assert.equal(skips.total(), 0);
    assert.equal(pool.stats().opened, 1);
    assert.notEqual(record.digest, null);
  });

  // Break-proof 1 (MANDATORY, D-06). Revert ONLY the O_NOFOLLOW bit from
  // the flags in lib/traverse/read-pool.js (leave O_NONBLOCK in place),
  // re-run node --test tests/traverse/read-pool.test.js, and record the
  // observed failure: the symlink is read successfully,
  // skips.counts().swapped === 0, stats().opened === 1 -- the literal
  // "currently read silently with the counter at 0" defect this plan
  // closes. This break-proof cannot block (no FIFO is involved), so it
  // was run in the foreground, unlike the FIFO break-proofs above. Result
  // recorded verbatim in 17.1-05-SUMMARY.md.
  //
  // Break-proof 2 (MANDATORY). Restore O_NOFOLLOW but revert the open
  // catch's error-code branch (so it records `unreadable` for every open
  // failure, including a loop-detected symlink/swap), re-run, and record
  // the failure on Case 1's reason-discrimination assertions. Also
  // recorded verbatim in 17.1-05-SUMMARY.md.
  //
  // Blind spot of these guards (MANDATORY, see also 17.1-05-SUMMARY.md):
  // they prove a symlink at the FINAL path component is refused at open
  // time. They do NOT cover a symlink in an INTERMEDIATE directory
  // component -- O_NOFOLLOW is defined to affect only the final
  // component, and intermediate components are the walk's territory
  // (walk.js:188,288 refuses them during enumeration, a different guard
  // in a different file). They also do not prove the loop-detected-errno
  // branch fires for any errno other than the one the kernel actually
  // returns on this platform.
  //
  // D-01/G-1543/G-1544 (2026-08-12, plan 18-05): the reason recorded on
  // the ELOOP branch changed from `symlink` to `swapped`, so this ELOOP
  // refusal is now the post-classification `swapped` ANOMALY, not the
  // walk-refused `symlink` SCOPE reason. Task 1's own break-proofs
  // (reverting the ANOMALY_SKIP_REASONS classification, then reverting
  // the recording site independently) are recorded verbatim in
  // 18-05-SUMMARY.md, alongside the end-to-end swap case in
  // tests/traverse/engine.test.js that pairs with Case 1 above.
});
