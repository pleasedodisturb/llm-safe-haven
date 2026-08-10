'use strict';

/**
 * Injectable-clock wall-clock + max-files budget core (G-1482, D-17, D-19,
 * D-20, TRAV-04).
 *
 * `createBudget(options)` -- `options` is a NORMALIZED options object, as
 * produced by `lib/traverse/index.js`'s `normalizeOptions()`:
 * `budgetSeconds`, `maxFiles`, and `now` (a `() => bigint` monotonic-
 * nanosecond clock, defaulting to `process.hrtime.bigint` -- see
 * RESEARCH.md D1/D2 for why `process.hrtime.bigint()` and not `Date.now()`
 * -- `Date.now()` is NOT monotonic and an NTP step or manual clock change
 * could make a long scan look short, and D2 for why the clock is read once
 * per directory rather than once per file -- an `O(directories)` check
 * cadence, not `O(files)`).
 *
 * This file reads the clock ONLY through `options.now()` -- `Date.now()`
 * must never appear here.
 *
 * The precedent for opts-injection is `lib/scan.js:80`
 * (`runSupplyChainScan(flags, opts = {})`).
 *
 * Two DIFFERENT enforcement cadences, deliberately:
 *   - `noteDirectory()` is the per-DIRECTORY checkpoint. It re-evaluates
 *     the wall clock -- the clock is comparatively expensive and the walk
 *     naturally yields once per `readdirSync` call, so this is the right
 *     granularity (RESEARCH.md D2).
 *   - `noteFile()` is the per-ENTRY checkpoint. It does NOT read the
 *     clock, so it stays a single integer compare -- cheap enough to call
 *     before every emitted entry. This must be entry-granular (not
 *     directory-granular like the clock) because a single directory with
 *     hundreds of thousands of entries would otherwise overshoot
 *     `maxFiles` by that entire directory before anyone noticed
 *     (T-17-04-04).
 *
 * Both checkpoints LATCH: once exhausted, a later call can never flip the
 * budget back to "may continue" -- not even a clock jump backwards. The
 * tier in progress at the moment of exhaustion is the one left incomplete;
 * a tier already marked complete via `tierComplete()` before exhaustion
 * stays complete (D-20's sticky-per-tier rule).
 */

const NS_PER_MS = 1_000_000n;

function createBudget(options) {
  const now = options.now;
  const budgetMs = options.budgetSeconds * 1000;
  const maxFiles = options.maxFiles;

  const startNs = now();

  let filesWalked = 0;
  let dirsWalked = 0;
  let exhaustedReason = null;
  let currentTier = null;
  const tierCompleteness = {};

  // Latching: the FIRST reason recorded is the one that sticks -- a later
  // call (of either kind) can never overwrite it or clear it back to null.
  function latch(reason) {
    if (exhaustedReason === null) {
      exhaustedReason = reason;
    }
  }

  function liveElapsedMs() {
    const nowNs = now();
    const deltaNs = nowNs - startNs;
    // BigInt division truncates toward zero -- exact integer millisecond
    // count, no floating-point drift across a long-running scan.
    return Number(deltaNs / NS_PER_MS);
  }

  /**
   * Per-DIRECTORY checkpoint. Re-evaluates the wall clock. Returns `true`
   * while work may continue, `false` once exhausted (this call or a prior
   * one). A `budgetSeconds: 0` budget is exhausted from the very first
   * call, with the clock frozen -- `elapsedMs (0) >= budgetMs (0)` is
   * true, which is both the deterministic test affordance
   * `normalizeOptions` accepts and the correct production behaviour for an
   * operator who deliberately sets it to zero.
   */
  function noteDirectory() {
    dirsWalked += 1;
    if (exhaustedReason === null && liveElapsedMs() >= budgetMs) {
      latch('budget');
    }
    return exhaustedReason === null;
  }

  /**
   * Per-ENTRY checkpoint, clock-free. Returns `true` while the entry may
   * be processed, `false` once `filesWalked` exceeds `maxFiles`. Uses a
   * strict `>` (not `>=`) so `maxFiles: N` allows exactly N successful
   * entries before the (N+1)th call fails -- `maxFiles: 0` therefore fails
   * on the very first call, which is the deterministic test affordance
   * `normalizeOptions` accepts for `LSH_MAX_FILES=0`.
   */
  function noteFile() {
    if (exhaustedReason !== null) return false;
    filesWalked += 1;
    if (filesWalked > maxFiles) {
      latch('max-files');
      return false;
    }
    return true;
  }

  /**
   * Bulk convenience wrapper for a caller that already knows a batch size.
   * Documented as NOT the enforcement path -- `noteFile()` above is the
   * entry-granular guarantee a huge single directory needs (T-17-04-04);
   * this wrapper can overshoot `maxFiles` within a single call by up to
   * `n - 1` entries, because it only checks the total once per call.
   */
  function noteFiles(n) {
    if (exhaustedReason !== null) return false;
    filesWalked += n;
    if (filesWalked > maxFiles) {
      latch('max-files');
      return false;
    }
    return true;
  }

  function exhausted() {
    return exhaustedReason !== null;
  }

  function reason() {
    return exhaustedReason;
  }

  /**
   * Recomputed against the live clock on every call -- a caller polling
   * `elapsedMs()` without calling `noteDirectory()` first (e.g. a TTY
   * progress line, D-09) still sees an accurate value. This re-evaluation
   * never flips `exhaustedReason` itself; only the checkpoint functions
   * above are allowed to do that.
   */
  function elapsedMs() {
    return liveElapsedMs();
  }

  function remainingMs() {
    const remaining = budgetMs - liveElapsedMs();
    return remaining > 0 ? remaining : 0;
  }

  /**
   * Records that a named tier (e.g. `'targeted'` / `'bulk'`, D-20) has
   * begun. Idempotent -- entering the same tier twice does not reset its
   * completeness.
   */
  function enterTier(name) {
    currentTier = name;
    if (!(name in tierCompleteness)) tierCompleteness[name] = false;
  }

  /**
   * Records that a named tier finished on its own (not by exhaustion).
   * If exhaustion happens later while a DIFFERENT tier is current, this
   * tier's completeness is untouched (D-20 sticky-per-tier rule).
   */
  function tierComplete(name) {
    tierCompleteness[name] = true;
    if (currentTier === name) currentTier = null;
  }

  function snapshot() {
    return {
      elapsedMs: liveElapsedMs(),
      filesWalked,
      dirsWalked,
      budgetMs,
      maxFiles,
      exhaustedReason,
      tiers: { ...tierCompleteness },
    };
  }

  return {
    noteDirectory,
    noteFile,
    noteFiles,
    exhausted,
    reason,
    elapsedMs,
    remainingMs,
    snapshot,
    enterTier,
    tierComplete,
  };
}

module.exports = { createBudget };
