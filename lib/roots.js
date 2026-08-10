'use strict';

// Single source of truth for the default code-root list and LSH_ROOTS
// parsing (D-08). This module REPLACES the hand-synced pair that used to
// drift independently:
//   - scripts/scan-chaindrop-aug2026.sh SEARCH_ROOTS (formerly lines ~107-115)
//   - lib/scan.js SCAN_DIRS (formerly lines 7-14, no LSH_ROOTS support at all)
// The traversal engine (plan 17-07+), lib/scan.js (plan 17-13), and the bash
// scanner (plan 17-14) all adopt getRoots()/DEFAULT_ROOT_NAMES from here.
//
// The `:` delimiter is bash-compatible (`IFS=':' read -r -a`) and must not
// be changed to `,` or any other separator. Roots are the ONLY
// user-controlled input to the traversal engine's scope, so an entry that
// is not an existing directory is dropped rather than silently walked —
// this mirrors bash's `[ -d "$d" ]` existence guard exactly.

const fs = require('fs');
const path = require('path');
const os = require('os');

// Order matters — matches the bash loop at (formerly) line 112 and
// lib/scan.js SCAN_DIRS 1:1. Do not reorder without updating both
// SEARCH_ROOTS-equivalent callers.
const DEFAULT_ROOT_NAMES = Object.freeze(['Projects', 'Developer', 'Code', 'src', 'repos', 'workspace']);

/**
 * Splits a colon-separated LSH_ROOTS value into candidate path strings.
 * Matches bash's `IFS=':' read -r -a _lsh_roots <<< "$LSH_ROOTS"` splitting
 * exactly: no trimming of whitespace (bash does not trim either), and
 * empty segments produced by a leading/trailing/doubled `:` are dropped.
 * Returns [] for undefined, null, or the empty string.
 */
function parseRootsEnv(value) {
  if (value === undefined || value === null || value === '') return [];
  return String(value).split(':').filter((segment) => segment !== '');
}

/**
 * Returns the absolute, deduplicated, existence-filtered list of scan
 * roots. When opts.env.LSH_ROOTS (or process.env.LSH_ROOTS) is a non-empty
 * string, its parsed entries are the ONLY source of candidates — an
 * override, not a merge, matching bash's if/else exactly. Otherwise the
 * candidates are DEFAULT_ROOT_NAMES joined onto homedir(), in order.
 *
 * Each candidate is filtered with fs.statSync(...).isDirectory() inside a
 * try/catch: a nonexistent path, a broken symlink, or a permission error
 * all drop the entry silently, matching bash's `[ -d "$d" ]` test. A
 * symlink that resolves to a real directory is accepted (statSync follows
 * symlinks, matching bash's `-d`).
 *
 * opts (for testing): { env = process.env, fs = require('fs'), homedir =
 * os.homedir, onMissingRoot }.
 *
 * G-1504 / D-17.1-A / D-17.1-B (17.1-CONTEXT.md): `onMissingRoot(candidate)`
 * is an ADDITIVE callback seam, defaulting to a no-op — getRoots() keeps
 * returning a bare string[], never a { roots, missing } shape, so
 * lib/scan.js and its existing tests are untouched by this seam (verified —
 * git diff on both is empty). It fires ONLY for candidates that came from an
 * explicitly-configured LSH_ROOTS entry, never for the six DEFAULT_ROOT_NAMES
 * probe: the default list is a probe, not a configuration — most machines
 * legitimately have only one or two of the six, and warning about the other
 * four on every run is noise that trains operators to ignore warnings. An
 * LSH_ROOTS entry that does not exist, however, is a typo or an unmounted
 * volume the operator explicitly asked for, and must not vanish silently.
 * It fires ONCE PER OCCURRENCE, not once per unique path — the `seen` dedup
 * below applies only to entries that SURVIVE the isDir filter (`continue`
 * on a miss runs before the dedup ever sees the candidate), so a missing
 * root listed twice in LSH_ROOTS calls `onMissingRoot` twice. A caller that
 * wants one line per path (e.g. lib/traverse/run.js) dedupes on its own side.
 */
function getRoots(opts = {}) {
  const env = opts.env || process.env;
  const fsImpl = opts.fs || fs;
  const homedir = opts.homedir || os.homedir;
  const onMissingRoot = opts.onMissingRoot || (() => {});

  let candidates;
  let explicit;
  if (typeof env.LSH_ROOTS === 'string' && env.LSH_ROOTS !== '') {
    candidates = parseRootsEnv(env.LSH_ROOTS);
    explicit = true;
  } else {
    const home = homedir();
    candidates = DEFAULT_ROOT_NAMES.map((name) => path.join(home, name));
    explicit = false;
  }

  const seen = new Set();
  const result = [];
  for (const candidate of candidates) {
    let isDir = false;
    try {
      isDir = fsImpl.statSync(candidate).isDirectory();
    } catch {
      isDir = false; // nonexistent, broken symlink, or unreadable — drop it
    }
    if (!isDir) {
      if (explicit) onMissingRoot(candidate);
      continue;
    }

    const resolved = path.resolve(candidate);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    result.push(resolved);
  }
  return result;
}

module.exports = { DEFAULT_ROOT_NAMES, parseRootsEnv, getRoots };
