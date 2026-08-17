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

// D-20-14 / D-20-01(2) (EXIT-04, G-1621): the two frozen contract strings
// the zero-default-root fallback and its cause clause render verbatim.
// Exported so every consumer (today: lib/scan.js; a future phase's
// lib/audit.js, lib/install.js, lib/traverse/run.js) quotes the SAME text
// instead of retyping it -- mirrors the DEFAULT_ROOT_NAMES single-source
// pattern above.
//
// CWD_FALLBACK_NOTICE is the stderr notice BODY only -- each caller
// prefixes it with its own `llm-safe-haven: ` diagnostic prefix (matching
// every other stderr line this codebase prints), so this string alone is
// never a complete line.
const CWD_FALLBACK_NOTICE = 'scanning current directory (no default scan root found)';
// NO_SCAN_ROOT_CAUSE is the cause-clause text rendered through the
// EXISTING could-not-verify block (lib/scan.js buildCauseClauses() /
// printEnvScanResult()) -- quoted verbatim in the ticket and the roadmap.
const NO_SCAN_ROOT_CAUSE = 'no scan root could be resolved';

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
 * all fail the isDirectory() check the same way, matching bash's
 * `[ -d "$d" ]` test. A symlink that resolves to a real directory is
 * accepted (statSync follows symlinks, matching bash's `-d`).
 *
 * A failing candidate is NOT always dropped silently, though (G-1504 /
 * D-03, revised 2026-08-10): an explicitly-configured (LSH_ROOTS) miss
 * fires `onMissingRoot` before being dropped -- see that callback's own doc
 * comment just below. Only the DEFAULT root probe (no LSH_ROOTS set) still
 * drops a miss with no callback at all (D-17.1-B).
 *
 * opts (for testing): { env = process.env, fs = require('fs'), homedir =
 * os.homedir, onMissingRoot, onUnreadableRoot }.
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
 *
 * EXIT-02 / D-07b (G-1542, plan 18-04 Task 3): `onUnreadableRoot(candidate,
 * code)` is a SEPARATE additive callback, also defaulting to a no-op, from
 * the SAME `statSync` try/catch this function always had. The errno decides
 * which of the two callbacks (if either) fires:
 *   - `ENOENT` / `ENOTDIR` mean the candidate is genuinely ABSENT (includes
 *     the broken-symlink case above: a broken symlink resolves to ENOENT).
 *     Unchanged: only `onMissingRoot`, only when `explicit`.
 *   - A SUCCESSFUL `statSync` whose `isDirectory()` is `false` also falls
 *     through to the ABSENT branch (no failure code was ever recorded) — a
 *     regular file named `~/Projects` is a scope fact, not an anomaly.
 *   - Everything else (`EACCES`, `EPERM`, `ELOOP`, `EIO`, `ENOTCONN`,
 *     `EOVERFLOW`, or any code `statSync` can throw that isn't one of the
 *     two above) means the path MAY exist and this process could not find
 *     out. `onUnreadableRoot` fires for these on BOTH the explicit AND the
 *     DEFAULT probe — D-17.1-B governs ABSENCE, which is routine on an
 *     ordinary machine missing some of the six default names; unreadability
 *     never is.
 *
 * A SEPARATE callback, not a widened `onMissingRoot(candidate, kind)`, for
 * three reasons: (1) the two callbacks have different firing conditions —
 * `onMissingRoot` is explicit-only, `onUnreadableRoot` fires on the default
 * probe too, and one callback cannot carry two gating rules without a `kind`
 * argument; (2) both existing callers (lib/scan.js, lib/traverse/run.js)
 * are arity-1 and would silently ignore a second parameter while still
 * printing "does not exist or is not a directory" — factually wrong for a
 * root that exists but cannot be read, and a SILENT wrong message is the
 * failure mode this whole phase exists to eliminate; (3) an additive
 * callback preserves the bare-`string[]` return contract `:60-66` locks.
 *
 * D-20-05 / EXIT-04 (G-1621): `onNoDefaultRoots()` is a FOURTH reason a
 * separate callback beats widening an existing one, extending the three
 * above: it is arity-0 and fires POST-LOOP, once, over the AGGREGATE
 * result -- a firing condition (`!explicit && result.length === 0`) that
 * shares nothing with the two per-candidate callbacks above, which fire
 * (or don't) once PER CANDIDATE as the loop runs. Fired immediately before
 * `return result`. It reports a FACT -- zero default roots resolved -- not
 * a decision: it fires even when every one of the six candidates failed as
 * UNREADABLE (via onUnreadableRoot above), because the result IS still
 * empty either way; partitioning "genuinely absent" from "unreadable" is
 * the CALLER's job (see lib/scan.js's own onNoDefaultRoots wiring), not
 * this seam's. It never fires in explicit LSH_ROOTS mode -- an operator
 * who configured LSH_ROOTS explicitly keeps the existing onMissingRoot/
 * onUnreadableRoot per-entry signal instead, exactly as before this phase.
 */
function getRoots(opts = {}) {
  const env = opts.env || process.env;
  const fsImpl = opts.fs || fs;
  const homedir = opts.homedir || os.homedir;
  const onMissingRoot = opts.onMissingRoot || (() => {});
  const onUnreadableRoot = opts.onUnreadableRoot || (() => {});
  const onNoDefaultRoots = opts.onNoDefaultRoots || (() => {});

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
    let failureCode = null;
    try {
      isDir = fsImpl.statSync(candidate).isDirectory();
    } catch (err) {
      isDir = false;
      // EXIT-02 / D-07b: capture the errno rather than collapsing every
      // throw into one bare `isDir = false` — the partition below is what
      // separates "genuinely absent" from "could not find out".
      failureCode = (err && err.code) || 'UNKNOWN';
    }
    if (!isDir) {
      if (failureCode !== null && failureCode !== 'ENOENT' && failureCode !== 'ENOTDIR') {
        // Unreachable-but-maybe-exists: fires on BOTH the explicit and the
        // default probe (D-17.1-B governs absence, not unreachability).
        onUnreadableRoot(candidate, failureCode);
      } else if (explicit) {
        // ENOENT/ENOTDIR (genuinely absent), or a successful statSync
        // whose isDirectory() was false (failureCode stays null) —
        // unchanged D-17.1-B behaviour: explicit-only, silent on the
        // default probe.
        onMissingRoot(candidate);
      }
      continue;
    }

    const resolved = path.resolve(candidate);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    result.push(resolved);
  }

  if (!explicit && result.length === 0) onNoDefaultRoots();

  return result;
}

/**
 * D-20-01 / EXIT-04 (G-1621): "does this directory look like a project" --
 * the ONE heuristic both the cwd-fallback decision below and its callers
 * share. `.git` is checked with a plain `existsSync`, deliberately NOT an
 * `isDirectory()` check, because a git WORKTREE or SUBMODULE points `.git`
 * at a real gitdir elsewhere via a one-line `gitdir: ...` FILE -- both
 * shapes count (20-CONTEXT.md "Looks like a project": ".git (dir or file
 * -- worktrees) OR package.json. Nothing fancier."). `fsImpl` defaults to
 * the real `fs` module, matching the DI convention `getRoots()` itself
 * uses above.
 */
function looksLikeProject(dir, fsImpl) {
  const fsi = fsImpl || fs;
  return fsi.existsSync(path.join(dir, '.git')) || fsi.existsSync(path.join(dir, 'package.json'));
}

/**
 * D-20-01(1) (G-1621): the ONE place the zero-default-root cwd fallback is
 * DECIDED. Deliberately NOT inside `getRoots()` -- `getRoots()` stays the
 * pure, existence-filtered CONFIGURED/DEFAULT root list `:38-43` documents;
 * inventing a root from `process.cwd()` is product policy, which belongs
 * to the CALLER (see the "three reasons" doc comment above `getRoots()`
 * for the same separation-of-concerns argument applied to
 * `onUnreadableRoot`).
 *
 * opts (for testing): { cwd = process.cwd(), fs = require('fs') }. Returns
 * the resolved absolute root when `cwd` looks like a project
 * (`looksLikeProject()` above), else `null` -- the caller decides what
 * `null` means (today, lib/scan.js: `incomplete = true`, exit 2 via the
 * existing `computeExit()`).
 */
function resolveZeroRootFallback(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const fsi = opts.fs || fs;
  if (looksLikeProject(cwd, fsi)) return path.resolve(cwd);
  return null;
}

module.exports = {
  DEFAULT_ROOT_NAMES, parseRootsEnv, getRoots,
  CWD_FALLBACK_NOTICE, NO_SCAN_ROOT_CAUSE,
  looksLikeProject, resolveZeroRootFallback,
};
