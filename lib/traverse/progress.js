'use strict';

/**
 * TTY-only, self-overwriting stderr progress line (G-1482, D-09, T-17-04b).
 *
 * `grep -rn "isTTY" .` returned zero hits before this file -- there is no
 * in-repo precedent for this pattern, so the rules are spelled out here:
 *
 *   - Writes to `options.stderr` ONLY when `options.stderr.isTTY === true`.
 *     Every method is a no-op otherwise, so a piped run or a CI log stays
 *     completely clean -- no progress output, no ANSI escapes, no residue.
 *   - NEVER writes to stdout. stdout belongs to the bash scanner's report.
 *   - `finish()` clears the line with `\r` + the ANSI erase-to-end-of-line
 *     sequence (`\x1b[K`), NOT a fixed run of spaces -- a terminal resized
 *     mid-scan makes a space-padded clear leave visible residue, while the
 *     erase sequence is width-independent.
 */

const DEFAULT_INTERVAL_MS = 1500;

function createProgress(options = {}) {
  const stderr = options.stderr;
  const intervalMs = typeof options.progressIntervalMs === 'number' ? options.progressIntervalMs : DEFAULT_INTERVAL_MS;
  const active = Boolean(stderr && stderr.isTTY === true);

  let lastWriteAt = 0;

  /**
   * Renders one self-overwriting line, throttled to `intervalMs`. `stats`
   * is a loose bag of whatever counters the caller has on hand at the call
   * site (filesWalked, candidatesRead, elapsedMs, remainingMs) -- every
   * field defaults to 0 so a partial `stats` object never throws.
   */
  function update(stats = {}) {
    if (!active) return;
    const now = Date.now();
    if (now - lastWriteAt < intervalMs) return;
    lastWriteAt = now;

    const filesWalked = stats.filesWalked || 0;
    const candidatesRead = stats.candidatesRead || 0;
    const elapsedSeconds = Math.floor((stats.elapsedMs || 0) / 1000);
    const remainingSeconds = Math.floor((stats.remainingMs || 0) / 1000);

    const line =
      `\rScanning... ${filesWalked} files walked, ${candidatesRead} candidates read, ` +
      `${elapsedSeconds}s elapsed, ${remainingSeconds}s budget remaining`;
    stderr.write(line);
  }

  /** Clears the line, width-independently. No-op when not a TTY. */
  function finish() {
    if (!active) return;
    stderr.write('\r\x1b[K');
  }

  return { update, finish };
}

module.exports = { createProgress };
