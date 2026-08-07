'use strict';

/**
 * Bounded concurrent read pool (G-1482, TRAV-01, D-02/D-07/D-11/D-20).
 *
 * THIS MODULE IS D-07 -- "single process, async walk + bounded read pool
 * (~8-16 in flight), native crypto SHA256, no worker_threads". This module
 * never requires `worker_threads`; `DEFAULTS.readPool` (12, from
 * `lib/traverse/index.js`) sits inside that band. The no-worker_threads
 * half of the decision is enforced by this file's own acceptance
 * criterion (grep-asserted absence below), not just by convention.
 *
 * ---------------------------------------------------------------------
 * ONE WORK RECORD PER PATH (D-02).
 * ---------------------------------------------------------------------
 * The unit of `submit()` is an immutable per-path work record --
 * `{ absPath, classes, needBulk, needHash, needTargetedContent, priority }`
 * -- NOT a per-tier job. The caller (plan 17-11) builds exactly one record
 * per absolute path, merging every tier's requirements into the flags
 * before submitting, and the pool opens each path exactly once, performing
 * every required read from that single handle. Queueing targeted work and
 * bulk work as SEPARATE jobs would open and read a dual-tier file twice,
 * violating D-02's "true single-read, not just single-traversal" and
 * risking an inconsistent result if the file changes between reads.
 * `stats().opened` equalling the number of distinct successfully-opened
 * paths is the machine-checkable form of that contract, and submitting the
 * same path twice is a caller error `submit()` throws on synchronously.
 *
 * The work record carries NO `sizeBytes` -- the walk (`walk.js`) never
 * stats an ordinary file. Size comes from `filehandle.stat()` on the
 * ALREADY-OPEN handle (step 1 of `processOne` below), which is both the
 * only trustworthy source and the thing that closes the
 * classify-then-open TOCTOU window: a file that grew between
 * classification and open cannot slip past a bound, because the bound is
 * always evaluated against the size the open handle reports right now.
 *
 * ---------------------------------------------------------------------
 * RISK 1 -- THE 256 KiB CAP IS BULK-TIER ONLY. READ THIS BEFORE TOUCHING
 * THE HASH PATH.
 * ---------------------------------------------------------------------
 * The known-bad-hash check hashes the WHOLE candidate (bounded only by
 * `hashCandidateMaxBytes`, 1,048,576 bytes) because the real ChainDrop
 * stage-2 payload is 727,680 bytes -- well over the 262,144-byte
 * `bulkReadCapBytes` bound. Capping the hash read at the bulk-tier size
 * would silently disable the scanner's most definitive detector. The
 * sniff buffer and the bulk buffer are NEVER reused as hash input, and
 * every `filehandle.read()` in this module passes an EXPLICIT `position`
 * argument (never relies on the handle's implicit cursor) so a preceding
 * bulk read on the same handle can never shorten the digest's input.
 * `tests/traverse/hash-cap.test.js` proves this by asserting the pool's
 * digest for a 400 KiB fixture equals an independently computed
 * whole-file SHA256, including after a bulk read on the same handle.
 */

const crypto = require('crypto');
const { normalizeOptions, createSkipInventory } = require('./index.js');

const HASH_CHUNK_BYTES = 65536;

function errorDetail(err) {
  if (err && typeof err === 'object' && 'code' in err) return err.code;
  return String(err);
}

function priorityRank(priority) {
  return priority === 'targeted' ? 0 : 1;
}

/**
 * Reads every byte of `handle` from offset 0 up to `size` (already bounded
 * by the caller against `hashCandidateMaxBytes`), streaming through
 * `crypto.createHash('sha256')` in `HASH_CHUNK_BYTES` chunks. Every read
 * passes an explicit `position` -- see the RISK 1 header note.
 */
async function hashWholeFile(handle, size) {
  const hash = crypto.createHash('sha256');
  let offset = 0;
  let bytesRead = 0;
  const buf = Buffer.alloc(Math.min(HASH_CHUNK_BYTES, size) || 1);
  while (offset < size) {
    const len = Math.min(HASH_CHUNK_BYTES, size - offset);
    const chunk = len === buf.length ? buf : Buffer.alloc(len);
    const { bytesRead: n } = await handle.read(chunk, 0, len, offset);
    if (n <= 0) break; // defensive -- a shrinking file must not spin forever
    hash.update(chunk.subarray(0, n));
    offset += n;
    bytesRead += n;
  }
  return { digest: hash.digest('hex'), bytesRead };
}

/**
 * Reads the sniff window (`min(sniffBytes, size)` bytes from offset 0) on
 * the open handle. If a NUL byte is present, the file is binary (matching
 * `grep -I`) and content work stops there -- no marker matching, and the
 * bulk buffer stays `null`. Otherwise continues reading on the SAME handle
 * in one further explicit-position read up to `min(size, bulkReadCapBytes)`
 * and returns the concatenated buffer.
 */
async function readBulkContent(handle, size, sniffBytes) {
  const sniffLen = Math.min(sniffBytes, size);
  let bytesRead = 0;
  if (sniffLen === 0) {
    return { buffer: Buffer.alloc(0), isBinary: false, bytesRead: 0 };
  }
  const sniffBuf = Buffer.alloc(sniffLen);
  const sniffResult = await handle.read(sniffBuf, 0, sniffLen, 0);
  bytesRead += sniffResult.bytesRead;
  const sniffed = sniffBuf.subarray(0, sniffResult.bytesRead);

  if (sniffed.includes(0)) {
    return { buffer: null, isBinary: true, bytesRead };
  }

  const remaining = size - sniffLen;
  if (remaining <= 0) {
    return { buffer: sniffed, isBinary: false, bytesRead };
  }

  const restBuf = Buffer.alloc(remaining);
  const restResult = await handle.read(restBuf, 0, remaining, sniffLen);
  bytesRead += restResult.bytesRead;
  const buffer = Buffer.concat([sniffed, restBuf.subarray(0, restResult.bytesRead)]);
  return { buffer, isBinary: false, bytesRead };
}

/**
 * `createReadPool(options)` -- `options` is normalized via
 * `normalizeOptions()` (so `bulkReadCapBytes` / `hashCandidateMaxBytes` /
 * `sniffBytes` / `readPool` / the `fs` injectable seam all apply, matching
 * `git-ignore.js`'s established pattern). `options.budget` (a
 * `createBudget()`-shaped object) and `options.skips` (a
 * `createSkipInventory()`-shaped object) are optional; a fresh skip
 * inventory is created when one is not supplied.
 *
 * Returns `{ submit(work), drain(), stats() }`:
 *   - `submit(work)` validates and enqueues ONE work record. Synchronous;
 *     throws on a missing `absPath` or a path already submitted (the D-02
 *     one-record-per-path contract).
 *   - `drain()` starts up to `options.readPool` concurrent workers (no
 *     more than `options.readPool` `fs.promises.open()` calls in flight --
 *     RESEARCH C4's shape, no dependency, no `worker_threads`), processes
 *     every submitted record, and resolves to an array of per-record
 *     results in SUBMISSION order (not priority order -- priority only
 *     affects processing order, never the shape of the returned array).
 *   - `stats()` returns `{ opened, submitted, maxConcurrent, bytesRead,
 *     hashed, skipped }`.
 */
function createReadPool(options) {
  const normalized = normalizeOptions(options);
  const budget = (options && options.budget) || null;
  const skips = (options && options.skips) || createSkipInventory();

  const submittedPaths = new Set();
  const records = [];

  const stats = {
    opened: 0,
    submitted: 0,
    maxConcurrent: 0,
    bytesRead: 0,
    hashed: 0,
    skipped: 0,
  };

  function recordSkip(reason, absPath) {
    skips.add(reason, absPath);
    stats.skipped += 1;
  }

  function submit(work) {
    if (!work || typeof work.absPath !== 'string' || work.absPath.length === 0) {
      throw new TypeError('createReadPool.submit: work.absPath is required');
    }
    if (submittedPaths.has(work.absPath)) {
      throw new Error(
        `createReadPool.submit: duplicate path "${work.absPath}" -- one work record per path (D-02); ` +
        'merge every tier\'s requirements into a single record before submitting'
      );
    }
    submittedPaths.add(work.absPath);
    stats.submitted += 1;
    records.push({
      absPath: work.absPath,
      classes: work.classes || [],
      needBulk: !!work.needBulk,
      needHash: !!work.needHash,
      needTargetedContent: !!work.needTargetedContent,
      priority: work.priority === 'targeted' ? 'targeted' : 'bulk',
    });
  }

  /**
   * ONE `fs.promises.open` per record, then: (1) stat the open handle --
   * every size bound below reads THIS value; (2) if bulk/targeted-content
   * work is needed, the capped bulk read; (3) if a hash is needed, the
   * independent whole-candidate hash read from offset 0 (see the RISK 1
   * header note); (4) always close in a `finally`. Any error at any step
   * -- EMFILE/ENFILE/EACCES/EPERM/ENOENT/EISDIR or any other I/O error --
   * is caught and recorded as an `unreadable` skip; this function never
   * rejects (D-11).
   */
  async function processOne(work) {
    const { absPath, needBulk, needHash, needTargetedContent } = work;

    let handle;
    try {
      handle = await normalized.fs.promises.open(absPath, 'r');
    } catch (err) {
      recordSkip('unreadable', absPath);
      return { absPath, error: errorDetail(err) };
    }

    stats.opened += 1;

    try {
      const st = await handle.stat();
      const size = st.size;

      let bulkBuffer = null;
      let isBinary = false;
      let bulkSkipped = null;
      if (needBulk || needTargetedContent) {
        if (size >= normalized.bulkReadCapBytes) {
          // EXCLUSION, matching bash's `-size -256k` -- the file is not
          // truncated, it is simply not read for bulk/marker purposes.
          recordSkip('oversized', absPath);
          bulkSkipped = 'oversized-bulk';
        } else {
          const bulk = await readBulkContent(handle, size, normalized.sniffBytes);
          bulkBuffer = bulk.buffer;
          isBinary = bulk.isBinary;
          stats.bytesRead += bulk.bytesRead;
        }
      }

      let digest = null;
      let hashSkipped = null;
      if (needHash) {
        if (size >= normalized.hashCandidateMaxBytes) {
          // EXCLUSION, matching bash's `-size -1024k` prefilter intent --
          // a multi-gigabyte file is never hashed unconditionally.
          recordSkip('oversized', absPath);
          hashSkipped = 'oversized-hash';
        } else {
          const hashed = await hashWholeFile(handle, size);
          digest = hashed.digest;
          stats.bytesRead += hashed.bytesRead;
          stats.hashed += 1;
        }
      }

      return { absPath, size, bulkBuffer, isBinary, digest, bulkSkipped, hashSkipped };
    } catch (err) {
      recordSkip('unreadable', absPath);
      return { absPath, error: errorDetail(err) };
    } finally {
      try {
        await handle.close();
      } catch {
        // A close() failure after a successful open/read is not itself a
        // scan-affecting error -- swallow it rather than let it surface as
        // an unrelated rejection from an otherwise-complete record.
      }
    }
  }

  async function drain() {
    // Single per-path record storage (D-02); this sort only picks
    // PROCESSING order (targeted before bulk, D-20), it never creates a
    // second per-tier queue or duplicates a record.
    const ordered = records
      .map((record, index) => ({ record, index }))
      .sort((a, b) => priorityRank(a.record.priority) - priorityRank(b.record.priority) || a.index - b.index)
      .map((entry) => entry.record);

    const resultsByPath = new Map();
    let cursor = 0;
    let inFlight = 0;

    async function runWorker() {
      while (cursor < ordered.length) {
        const work = ordered[cursor];
        cursor += 1;

        if (budget && budget.exhausted()) {
          recordSkip('budget', work.absPath);
          resultsByPath.set(work.absPath, { absPath: work.absPath, skipped: 'budget' });
          continue; // In-flight reads (none started for this record) never
          // need to finish here -- this record never opened a handle.
        }

        inFlight += 1;
        if (inFlight > stats.maxConcurrent) stats.maxConcurrent = inFlight;
        const result = await processOne(work);
        inFlight -= 1;
        resultsByPath.set(work.absPath, result);
      }
    }

    const workerCount = ordered.length === 0 ? 0 : Math.max(1, Math.min(normalized.readPool, ordered.length));
    await Promise.all(Array.from({ length: workerCount }, runWorker));

    return records.map((record) => resultsByPath.get(record.absPath));
  }

  function statsFn() {
    return { ...stats };
  }

  return { submit, drain, stats: statsFn };
}

module.exports = { createReadPool };
