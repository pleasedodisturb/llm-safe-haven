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

describe('read-pool — budget cancellation', () => {
  it('a budget exhausted after the 10th record stops opening NEW records; remaining ones are recorded as budget skips', async () => {
    const dir = mkFixture();
    let noted = 0;
    const budget = {
      exhausted: () => noted >= 10,
    };
    const skipped = [];
    const skips = { add: (reason, absPath) => skipped.push({ reason, absPath }) };
    let opens = 0;
    const realFs = require('fs');
    const countingFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: (...args) => {
          opens += 1;
          noted += 1;
          return realFs.promises.open(...args);
        },
      },
    };
    const pool = createReadPool({ fs: countingFs, budget, skips, readPool: 1 });
    for (let i = 0; i < 30; i += 1) {
      const file = writeFile(dir, `budget${i}.js`, 'x');
      pool.submit({ absPath: file, needBulk: true });
    }
    const results = await pool.drain();

    assert.equal(results.length, 30);
    assert.equal(opens, 10, 'no additional open() should occur once the budget is exhausted');
    const budgetSkips = skipped.filter((s) => s.reason === 'budget');
    assert.equal(budgetSkips.length, 20);
    const skippedResults = results.filter((r) => r.skipped === 'budget');
    assert.equal(skippedResults.length, 20);
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
