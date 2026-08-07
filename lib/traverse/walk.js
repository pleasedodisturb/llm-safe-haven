'use strict';

/**
 * Single-pass enumeration core (G-1482, TRAV-01/TRAV-04, D-06/D-12/D-23/D-26).
 *
 * `walkRoot(root, options, visit)` / `walk(roots, options, visit)` perform one
 * synchronous `readdirSync(dir, { withFileTypes: true })` per directory,
 * lstat-only symlink handling, per-root device-boundary containment, honest
 * read-error accounting, and order-independent innermost-repo attribution.
 * This is the enumeration every targeted IOC check and the bulk content tier
 * ride -- content reads and hashing are async and live in a different module
 * (`read-pool.js`, plan 17-10). This module never opens a file and never
 * stats an ordinary file (no `sizeBytes` on `WalkEvent` -- see the typedef
 * note in `lib/traverse/index.js`).
 *
 * Synchronous by design: `lib/scan.js`'s `scanForEnvFiles()` is synchronous
 * and its return value is pinned by existing tests, so this module must be
 * callable from it without changing that function's signature (D-23,
 * landing in plan 17-13).
 *
 * ---------------------------------------------------------------------
 * THE NO-POLICY-PRUNE RULE (B1).
 * ---------------------------------------------------------------------
 * This module applies exactly THREE physical exclusions and no others:
 *   (1) it never descends INTO a `.git` directory (structural -- it is
 *       git's object store, not user content);
 *   (2) it never follows or descends into a symlink (D-06);
 *   (3) it never crosses a device boundary (D-12).
 * It applies NO IOC-policy prune -- no PRUNE_COMMON, no node_modules
 * exclusion, no .cache exclusion, no media-extension list, no size cap, no
 * gitignore. Those all live in `lib/traverse/classify.js` and are applied
 * PER CLASS, because one physical walk serves classes with mutually
 * incompatible scopes. The concrete proof this matters, verified against
 * `scripts/scan-chaindrop-aug2026.sh`: its PRUNE_COMMON (line 180) does not
 * contain node_modules, and section 2's preinstall check (line 277) uses
 * `grep -r` with no prune whatsoever, so it reaches node_modules, dist,
 * build, .next, .nuxt and target today. A physical prune here would narrow
 * that pass and silently lose detection -- including the D-25
 * preinstall-inside-node_modules case. Do NOT add a directory-name-prune
 * parameter to this module. If a future change appears to need one, that is
 * the signal to add a class in `classify.js` instead.
 *
 * The one exception is the per-consumer enumeration SHAPE (`maxDepth`,
 * `skipDirs`, `skipDotDirs`), which exists solely so `lib/scan.js` keeps its
 * shipped `findEnvFiles` semantics (D-23). All three default to "no limit"
 * (`Infinity`, empty `Set`, `false` -- see `normalizeOptions` in
 * `lib/traverse/index.js`), so the wave-spec driver (plan 17-11's
 * `Traversal` class) gets the maximally inclusive walk described above by
 * simply not setting them. Plan 17-11 THROWS if the wave-spec driver ever
 * sets these three options -- a physical prune during a walk serving
 * conflicting per-class scopes (D-13's targeted vs bulk tiers) is exactly
 * the B1 silent-detection-loss defect this file exists to prevent.
 *
 * ---------------------------------------------------------------------
 * Repo-boundary attribution (D-26 / B6).
 * ---------------------------------------------------------------------
 * Before emitting, classifying or recursing into ANY entry of a directory,
 * the COMPLETE Dirent array returned by that directory's single readdir is
 * scanned for an entry named `.git` -- `isDirectory()` OR `isFile()` (a
 * linked git worktree stores `.git` as a text file containing `gitdir:`).
 * If present, the directory becomes the innermost repo root for its whole
 * subtree. `readdirSync` gives NO ordering guarantee, so recording the
 * boundary lazily "when the `.git` entry is reached" would attribute every
 * earlier sibling to the OUTER repo on some filesystems and the inner repo
 * on others -- a non-deterministic D-26 violation. This pre-scan is a
 * separate loop over the same in-memory array; it costs one extra pass over
 * a small array and adds no syscall. This is UNRELATED to the hardcoded
 * `.claude/worktrees` prune, which is a class policy in `classify.js`, not
 * a walk concern -- same word ("worktree"), unrelated concepts: that prune
 * is about this project's own dev-tooling directory name, while this
 * section is about git's own linked-worktree `.git`-as-a-file mechanism.
 */

const path = require('path');
const { normalizeOptions, createSkipInventory } = require('./index.js');
const { createBudget } = require('./budget.js');

// How often (in lstat fallbacks) the DT_UNKNOWN path re-checks the wall
// clock via the existing `noteDirectory()` API -- see the long comment on
// `resolveEntryType` below for why this is needed at all.
const LSTAT_FALLBACK_CLOCK_INTERVAL = 512;

/**
 * Resolves whether a Dirent is a directory/file/symlink, falling back to an
 * explicit `lstatSync` only when all three Dirent type predicates are false
 * (the DT_UNKNOWN case -- common on FUSE and some network mounts, where
 * EVERY entry can be DT_UNKNOWN, degrading this to one lstat per file, and
 * each such lstat may itself be slow, e.g. a network round-trip).
 *
 * Wall-clock containment on this path (do not overclaim it). The ordinary
 * budget clock is read once per directory via `noteDirectory()` --
 * deliberately, because a clock read per entry costs real time across
 * hundreds of thousands of entries for no correctness gain on the common
 * Dirent-type-known path. That per-directory cadence is NOT sufficient
 * here: one enormous directory of slow DT_UNKNOWN entries would not
 * re-check the wall clock until the walk returned from it, so a wall-clock
 * budget could be exceeded by an unbounded margin while `maxFiles` is still
 * far away. Therefore, on this fallback path ONLY, `noteDirectory()` (the
 * existing clock check -- no new API) is called once every
 * `LSTAT_FALLBACK_CLOCK_INTERVAL` lstat fallbacks, tracked by a counter
 * local to the walk, and the walk stops when it returns false. This is
 * scoped strictly to the DT_UNKNOWN branch so the common path keeps its
 * clock-free per-entry cost. The device-boundary check (D-12) is the
 * primary defence here -- it keeps network mounts out of scope unless the
 * user opted them in via `LSH_ROOTS` -- and this periodic check is the
 * secondary bound for the opted-in case.
 *
 * Returns `{ isDir, isFile, stat }` on success, or `null` when the entry
 * should be skipped (symlink, unreadable, or budget exhaustion mid-scan --
 * `ctx.skips` has already been updated in every case).
 */
function resolveEntryType(entry, absPath, dirPath, ctx) {
  let isDir = entry.isDirectory();
  let isFile = entry.isFile();

  if (isDir || isFile) {
    return { isDir, isFile, stat: null };
  }

  // DT_UNKNOWN -- all three Dirent predicates are false. Fall back to an
  // explicit lstat.
  ctx.lstatFallbackCount += 1;
  if (ctx.lstatFallbackCount % LSTAT_FALLBACK_CLOCK_INTERVAL === 0) {
    if (!ctx.budget.noteDirectory()) {
      ctx.skips.add('budget', dirPath);
      return null;
    }
  }

  let stat;
  try {
    stat = ctx.options.fs.lstatSync(absPath);
  } catch {
    ctx.skips.add('unreadable', absPath);
    return null;
  }

  if (stat.isSymbolicLink()) {
    ctx.skips.add('symlink', absPath);
    return null;
  }

  return { isDir: stat.isDirectory(), isFile: stat.isFile(), stat };
}

/**
 * Emits (if the budget allows) and, for a directory that survives the
 * device-boundary check, recurses. Returns nothing -- all bookkeeping lives
 * on `ctx`.
 */
function emitEntry(entry, absPath, depth, isDirectory, repoRoot, ctx) {
  if (!ctx.budget.noteFile()) {
    ctx.skips.add('budget', absPath);
    return;
  }
  ctx.filesWalked += 1;
  ctx.visit({ absPath, dirent: entry, depth, repoRoot, isDirectory });

  if (isDirectory) {
    walkDirectory(absPath, depth, ctx);
  }
}

/**
 * Processes one directory: single readdir, `.git` pre-scan for repo
 * attribution, then one pass over the Dirent array applying the safety
 * guards in order (symlink skip, DT_UNKNOWN fallback, skipDirs/skipDotDirs,
 * device containment, budget) before emitting and recursing.
 *
 * `depth` is the nesting level of `dirPath` itself (root is 0); children --
 * files and directories alike -- are emitted/recursed at `depth + 1`.
 */
function walkDirectory(dirPath, depth, ctx) {
  if (depth > ctx.options.maxDepth) return;

  ctx.options.onReaddir(dirPath);

  let entries;
  try {
    entries = ctx.options.fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    ctx.skips.add('unreadable', dirPath);
    return;
  }

  ctx.dirsWalked += 1;

  if (!ctx.budget.noteDirectory()) {
    ctx.skips.add('budget', dirPath);
    return;
  }

  // Repo-boundary pre-scan (D-26 / B6) -- see the header comment. A second
  // pass over the SAME in-memory array; no extra syscall.
  let pushedRepo = false;
  for (const e of entries) {
    if (e.name === '.git' && (e.isDirectory() || e.isFile())) {
      ctx.repoStack.push(dirPath);
      pushedRepo = true;
      break;
    }
  }

  try {
    const repoRoot = ctx.repoStack.length > 0 ? ctx.repoStack[ctx.repoStack.length - 1] : null;

    for (const entry of entries) {
      if (ctx.budget.exhausted()) break;

      // Structural exclusion: never descend into or emit `.git`, whether it
      // is a directory (git's object store) or a file (a linked worktree's
      // `gitdir:` pointer). Its presence was already consumed by the
      // pre-scan above.
      if (entry.name === '.git' && (entry.isDirectory() || entry.isFile())) continue;

      const absPath = path.join(dirPath, entry.name);

      if (entry.isSymbolicLink()) {
        ctx.skips.add('symlink', absPath);
        continue;
      }

      const resolved = resolveEntryType(entry, absPath, dirPath, ctx);
      if (resolved === null) {
        if (ctx.budget.exhausted()) break;
        continue;
      }
      const { isDir, isFile, stat } = resolved;

      if (isDir) {
        if (ctx.options.skipDirs.has(entry.name) || (ctx.options.skipDotDirs && entry.name.startsWith('.'))) {
          continue;
        }

        // Device containment (D-12). Reuse the lstat already performed for
        // a DT_UNKNOWN fallback when available -- otherwise this is the
        // one lstat-per-directory the device check costs on filesystems
        // where the Dirent type is already known. Always compared against
        // the dev captured once for the current ROOT (never the immediate
        // parent), per the D-12 contract.
        let dirStat = stat;
        if (!dirStat) {
          try {
            dirStat = ctx.options.fs.lstatSync(absPath);
          } catch {
            ctx.skips.add('unreadable', absPath);
            continue;
          }
        }
        if (dirStat.dev !== ctx.rootDev) {
          ctx.skips.add('other-device', absPath);
          continue;
        }

        emitEntry(entry, absPath, depth + 1, true, repoRoot, ctx);
      } else if (isFile) {
        emitEntry(entry, absPath, depth + 1, false, repoRoot, ctx);
      }
      // Neither directory, file, nor symlink after resolution (a device
      // node, FIFO, socket, or similarly exotic entry) -- not a class this
      // walk classifies; quietly skipped, not counted (no SKIP_REASONS
      // bucket fits and it is not a safety-relevant omission).
    }
  } finally {
    if (pushedRepo) ctx.repoStack.pop();
  }
}

/**
 * Walks one root: captures its device id once (D-12 -- "an explicit root
 * always enters regardless of its dev", so this call never itself performs
 * a device-boundary check against anything), resets the per-root repo
 * stack, then delegates to `walkDirectory`. An inaccessible root is
 * recorded `unreadable` and produces zero entries, never a throw.
 */
function walkOneRoot(root, ctx) {
  let rootStat;
  try {
    rootStat = ctx.options.fs.lstatSync(root);
  } catch {
    ctx.skips.add('unreadable', root);
    return;
  }

  ctx.rootDev = rootStat.dev;
  ctx.repoStack = [];
  walkDirectory(root, 0, ctx);
}

/**
 * Walks every root in order, sharing one budget and one skip inventory
 * across all of them, capturing each root's own device id as it starts.
 * Returns `{ counts: { filesWalked, dirsWalked, rootsWalked }, skips,
 * stopped }`. `stopped` is true iff the shared budget was exhausted at any
 * point -- callers use it to mark the tier in progress incomplete (D-20).
 *
 * `options.budget` is an injectable seam -- a pre-built budget object (the
 * `createBudget()` interface) that, when supplied, is used verbatim instead
 * of constructing one from the normalized options. This is read from the
 * RAW `options` argument (before `normalizeOptions` strips unrecognized
 * keys), matching the `fs` / `spawnSync` / `now` injectable-seam pattern
 * `normalizeOptions` already establishes. No production caller needs to set
 * it -- its only purpose is letting tests wrap `noteDirectory()` /
 * `noteFile()` with counting doubles to prove the structural call-cadence
 * properties (`tests/traverse/traverse-structural.test.js`) without
 * duplicating `budget.js`'s own arithmetic.
 */
function walk(roots, options, visit) {
  const normalized = normalizeOptions(options);
  const budget = (options && options.budget) || createBudget(normalized);
  const skips = createSkipInventory();

  const ctx = {
    options: normalized,
    budget,
    skips,
    visit,
    filesWalked: 0,
    dirsWalked: 0,
    lstatFallbackCount: 0,
    rootDev: null,
    repoStack: [],
  };

  let rootsWalked = 0;
  for (const root of roots) {
    if (budget.exhausted()) break;
    walkOneRoot(root, ctx);
    rootsWalked += 1;
  }

  return {
    counts: {
      filesWalked: ctx.filesWalked,
      dirsWalked: ctx.dirsWalked,
      rootsWalked,
    },
    skips,
    stopped: budget.exhausted(),
  };
}

/**
 * Convenience wrapper for the single-root case -- identical semantics to
 * `walk([root], options, visit)`.
 */
function walkRoot(root, options, visit) {
  return walk([root], options, visit);
}

module.exports = { walk, walkRoot };
