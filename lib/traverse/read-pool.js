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

/**
 * How often (in COMPLETED records, across all workers) the drain re-reads
 * the live wall clock via the budget's `noteDirectory` recheck (G-1506).
 * Justified on a
 * worst-case-overrun BOUND, not on keeping any test's call count stable --
 * tuning this to a call count is exactly the reasoning that produced defect
 * B1 (see engine.js's phase-boundary comment); Task 2 of this plan makes the
 * engine's own clock harness phase-driven rather than count-driven so no
 * test outcome depends on this number.
 *
 *   - The clock is re-read after every READ_POOL_CLOCK_INTERVAL-th COMPLETED
 *     record, across all workers (not per-worker).
 *   - Worst case after the wall-clock budget has truly expired: up to
 *     READ_POOL_CLOCK_INTERVAL - 1 (15) further completed records, plus up
 *     to `normalizeOptions().readPool` (default 12) records already
 *     in-flight when the latch fires.
 *   - Each record's I/O is bounded by the existing size caps --
 *     `bulkReadCapBytes` (256 KiB) and `hashCandidateMaxBytes` (1 MiB). At a
 *     pessimistic 10 MB/s effective throughput (spinning disk or a network
 *     mount), one worst-case record is ~125 ms.
 *   - So the bound is ~(15 + 12) x 125 ms ~ 3.4 s, ~5.6% of the default 60 s
 *     budget. Halving the interval would halve only the 15-record term, not
 *     the 12-record in-flight term, for twice the clock reads -- the bound
 *     is dominated by pool width, not by the interval.
 *   - Residual, stated explicitly: an individual in-flight read that never
 *     returns is bounded by NO interval. `budget.exhausted()` stops queued
 *     work; it cannot cancel an in-flight libuv fs operation. The only
 *     known unbounded trigger for that (a writerless FIFO's blocking
 *     `open`) is closed by plan 17.1-05's `O_NONBLOCK`. See `walk.js`'s
 *     `LSTAT_FALLBACK_CLOCK_INTERVAL = 512` for the in-repo precedent for
 *     the interval-cadence pattern itself.
 */
const READ_POOL_CLOCK_INTERVAL = 16;

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
 * in one further explicit-position read, picking up EXACTLY where the
 * sniff read actually ended (not where it was asked to end -- see D-10
 * below) up to `min(size, bulkReadCapBytes)`, and returns the concatenated
 * buffer.
 *
 * D-10 -- the splice this function used to produce. Before this fix,
 * `remaining` was computed from the REQUESTED `sniffLen` and the remainder
 * read's `position` was fixed at `sniffLen`, regardless of how many bytes
 * the sniff read actually returned. A short sniff read (fewer bytes than
 * requested -- a real, if rare, outcome of `read(2)`) therefore left a gap
 * of UNREAD bytes between `sniffResult.bytesRead` and `sniffLen`: the
 * returned buffer was a silent SPLICE with a hole in the middle, not
 * merely a truncated prefix. Marker matching then ran over silently
 * corrupted content with a plausible-looking length -- a marker string
 * spanning the hole was lost with NO signal, strictly worse than an
 * honestly-short buffer. Fixed by driving both the remainder length and
 * its read position from `sniffResult.bytesRead` (the ACTUAL sniffed
 * length), so the two reads are always contiguous -- the returned buffer
 * can be SHORT, but it can never contain a hole.
 *
 * `short` (added to every return path below) means "fewer bytes reached us
 * than the `size` argument promised". This function has no access to
 * `recordSkip` -- the CALLER (`processOne`) decides what that costs. A
 * zero-byte file is never `short`: `sniffLen === 0` returns immediately,
 * before any read, so there is nothing to have come up short of.
 */
async function readBulkContent(handle, size, sniffBytes) {
  const sniffLen = Math.min(sniffBytes, size);
  let bytesRead = 0;
  if (sniffLen === 0) {
    return { buffer: Buffer.alloc(0), isBinary: false, bytesRead: 0, short: false };
  }
  const sniffBuf = Buffer.alloc(sniffLen);
  const sniffResult = await handle.read(sniffBuf, 0, sniffLen, 0);
  const actualSniffLen = sniffResult.bytesRead;
  bytesRead += actualSniffLen;
  const sniffed = sniffBuf.subarray(0, actualSniffLen);

  if (sniffed.includes(0)) {
    // No more to read on this path -- the sniff IS the whole expectation,
    // so `short` compares against the REQUESTED sniff length.
    return { buffer: null, isBinary: true, bytesRead, short: actualSniffLen < sniffLen };
  }

  // D-10 fix: drive both the remainder's length and its read position from
  // the ACTUAL sniffed length, never the requested `sniffLen` -- this is
  // the substitution that makes the two reads contiguous.
  const remaining = size - actualSniffLen;
  if (remaining <= 0) {
    // The caller guarantees size < bulkReadCapBytes (processOne's oversized
    // gate above this call), so `size` really is the full expectation here.
    return { buffer: sniffed, isBinary: false, bytesRead, short: sniffed.length !== size };
  }

  const restBuf = Buffer.alloc(remaining);
  const restResult = await handle.read(restBuf, 0, remaining, actualSniffLen);
  bytesRead += restResult.bytesRead;
  const buffer = Buffer.concat([sniffed, restBuf.subarray(0, restResult.bytesRead)]);
  return { buffer, isBinary: false, bytesRead, short: buffer.length !== size };
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

  // Open flags (G-1503, TRAV-11) -- ported verbatim from lib/mcp/base.js:
  // `50` (the `constants` fallback, in case a test-supplied stub `fs` lacks
  // `.constants`) and `72-74` (the flag bits). `walk.js` classified this
  // path with `lstat` at time T1 and this pool opens it BY PATH at time T2
  // -- these flags are what close that window with a kernel-enforced check
  // rather than a second racing `lstat`:
  //   - O_NONBLOCK stops the open from ever blocking. It is a NO-OP on
  //     regular files -- it matters only for FIFOs and device nodes, so a
  //     future reader must not conclude that ordinary file opens became
  //     non-blocking. This is the DoS half of the fix (T-17.1-05-01); the
  //     correctness half (refusing the non-regular file outright) is the
  //     post-open file-type gate below (D-17.1-D) -- a writerless FIFO's
  //     `open(O_RDONLY|O_NONBLOCK)` SUCCEEDS (verified empirically on this
  //     machine: darwin, the fstat file-type check reports non-regular and
  //     the open itself does not block), so the flags alone do not refuse
  //     it.
  //   - O_NOFOLLOW (where the platform provides it) refuses a symlink at
  //     the final path component even if it appeared AFTER `walk.js`'s
  //     `lstat` (T-17.1-05-02/03). The kernel returns the loop-detected
  //     errno, handled in the open's catch below.
  const constants = normalized.fs.constants || require('fs').constants;
  let openFlags = constants.O_RDONLY | constants.O_NONBLOCK;
  if (constants.O_NOFOLLOW) openFlags |= constants.O_NOFOLLOW;

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
      handle = await normalized.fs.promises.open(absPath, openFlags);
    } catch (err) {
      // O_NOFOLLOW refused a symlink at the final path component -- record
      // it in the `symlink` bucket (T-17.1-05-02/03), never `unreadable`,
      // so the operator can see exactly what was refused and why (D-17.1-E,
      // ROADMAP criterion 4's reason-discrimination wording). Every other
      // open()-time failure (ENOENT/EACCES/etc.) is unchanged.
      if (err.code === 'ELOOP') {
        recordSkip('symlink', absPath);
      } else {
        recordSkip('unreadable', absPath);
      }
      return { absPath, error: errorDetail(err) };
    }

    stats.opened += 1;

    try {
      const st = await handle.stat();

      // File-type gate (D-17.1-D, layer 2 of the read-path hardening).
      // `handle.stat()` above is an `fstat` on the OPEN DESCRIPTOR -- it
      // describes the inode that was actually opened, so this can never be
      // fooled by a path swap after open (there is no TOCTOU window here;
      // see the plan's REJECTED-claims list). A FIFO/socket/device node
      // reaches this point because `O_NONBLOCK` only stops the OPEN from
      // blocking -- it does not refuse the file. The fstat result
      // deterministically reports non-regular for such a file on both BSD
      // and GNU, so this check below is the correctness gate that refuses
      // it BEFORE any byte reaches the marker matcher or the SHA256
      // digest. This costs ZERO additional syscalls -- `handle.stat()` was
      // already being called for the size bounds below. Recorded as
      // `unreadable` (D-17.1-E): `SKIP_REASONS` is frozen and this is also
      // semantically right -- a refused non-regular file IS something the
      // scan did not examine, and (with plan 17.1-01) correctly makes the
      // scan incomplete. The existing close-on-every-path `finally` below
      // covers this early return -- read and confirmed, no second close
      // added (a reviewer suggestion; redundant, see plan objective).
      if (!st.isFile()) {
        recordSkip('unreadable', absPath);
        return { absPath, error: 'not-regular-file' };
      }

      const size = st.size;

      // Once-per-RECORD short-read latch (SCAN-04, D-03, T-18-03-05). A
      // record needing BOTH bulk and hash content, short on both reads,
      // must record exactly ONE `unreadable` skip -- not two -- otherwise
      // `skips/unreadable.z` misreports how many DISTINCT paths the scan
      // failed to read. `oversized` above has the same dual-site shape
      // today (its two call sites can both fire for one record) and is NOT
      // de-duplicated -- that is a DELIBERATE divergence, not an
      // inconsistency to "harmonise" later: `oversized` is a SCOPE
      // reason with no exit-code consequence, so its accounting precision
      // does not matter the way an ANOMALY reason's does.
      let shortRead = false;
      const noteShortRead = () => {
        if (shortRead) return;
        shortRead = true;
        recordSkip('unreadable', absPath);
      };

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
          // Do NOT set `result.error` here (Pitfall 1, the most dangerous
          // way to implement this fix). `generateContentFindings` skips any
          // record with a truthy `error` (engine.js:483) -- marking a short
          // bulk read as an error would discard EVERY finding derivable
          // from the partial content that WAS read, turning a completeness
          // fix into a detection loss. `bulkBuffer` is kept regardless, so
          // marker matching over the partial content still runs -- it can
          // only ADD findings, never remove them, and under D-18 a FAIL
          // finding beats the exit-2 incompleteness this records.
          if (bulk.short) noteShortRead();
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
          // `stats.bytesRead` is a BYTE counter, not a success counter --
          // accumulate it regardless of whether the read came up short.
          stats.bytesRead += hashed.bytesRead;
          if (hashed.bytesRead !== size) {
            // A digest over fewer bytes than the file is affirmatively
            // WRONG data -- its only possible effect is a false NEGATIVE
            // against `knownBadHashes`. Null it rather than assign it; do
            // NOT increment `stats.hashed` (that counter means "a
            // trustworthy digest was produced"). No detection is actually
            // lost: the `payload-variant` FAIL branch also fires on
            // `sizeBad`, computed from `result.size` (the fstat size,
            // unaffected by a short read), so a payload-sized variant
            // still FAILs on size alone; `known-hash`/`setup-hash` degrade
            // to no-finding, but the `unreadable` skip this records makes
            // the run incomplete -> exit 2. Fail-closed.
            noteShortRead();
          } else {
            digest = hashed.digest;
            stats.hashed += 1;
          }
        }
      }

      return { absPath, size, bulkBuffer, isBinary, digest, bulkSkipped, hashSkipped, shortRead };
    } catch (err) {
      // Also covers a file deleted between `open()` and `handle.stat()`
      // (`handle.stat()` throwing ENOENT): recorded `unreadable` by this
      // GENERIC catch -- deliberately no dedicated branch or test for that
      // narrow race, per the plan's action notes.
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
    let processed = 0;

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

        // G-1506: re-evaluate the LIVE clock on an interval cadence, not
        // only at the walk's own per-directory checkpoints. Without this,
        // `budget.exhausted()` above only ever observes a flag that
        // `walk.js` last latched -- real wall-clock time spent inside this
        // drain's own I/O was never noticed (measured 3.6x overrun before
        // this fix). The call below reuses `noteDirectory` rather than a
        // bespoke API because it is budget.js's only public "recheck the
        // live clock and possibly latch" entry point; its `dirsWalked`
        // side effect is not surfaced on `TraverseResult`.
        processed += 1;
        if (budget && processed % READ_POOL_CLOCK_INTERVAL === 0) {
          budget.noteDirectory();
        }
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
