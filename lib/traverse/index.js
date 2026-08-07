'use strict';

/**
 * Traversal engine contract surface (G-1482, TRAV-01/TRAV-04, D-17/D-18/D-19).
 *
 * `lib/traverse/` is split per concern -- one file per responsibility --
 * following the `lib/mcp/` precedent (`lib/mcp/base.js` plus
 * `lib/mcp/parsers/*.js` / `lib/mcp/detectors/*.js`) rather than one large
 * file. This file is the shared contract every other engine module
 * (17-07 walk, 17-08 git-ignore, 17-10 read pool/classification, 17-11
 * orchestrator) implements against: option shape, skip-reason vocabulary,
 * file classes, result shape, and the exit-code rule. Without a contract
 * landing first, each of those modules would invent its own option shape
 * and skip-reason vocabulary independently.
 *
 * This phase also introduces the first class in `lib/` (`Traversal`,
 * landing in plan 17-11, not this file) -- every other module in `lib/`
 * (agents, mcp parsers/detectors, scan.js, cli.js -- confirmed via
 * `grep -rn "^class " lib/`, zero hits before this phase) exports plain
 * named functions, and the class exists solely because D-03 requires an
 * enumeration API that serves BOTH the wave-spec driver and non-wave
 * consumers such as `lib/scan.js`. A future reader must not conclude
 * classes are this codebase's house style from that one exception -- this
 * file itself, and everything it exports, is plain functions and frozen
 * data, matching the rest of `lib/`.
 *
 * Exit-code semantics are this project's EXISTING 0/1/2 contract
 * (`lib/mcp/base.js:326-335`, mirrored at `lib/scan.js:76-79,111-118`),
 * refined by D-18's precedence rule below -- not a replacement. Only
 * FAIL-severity findings ever count toward "findings" for the purpose of
 * the exit code; WARN and INFO never do (see `computeExit` for the full
 * table and its citation).
 *
 * D-20 -- why `TraverseResult` carries a `tiers` object: targeted checks
 * (the D-13 gitignore-tiering-exempt classes) ride the SAME physical walk
 * as the bulk-content scan and finish first, so `incomplete` usually means
 * only the bulk tier ran out of budget. But the walk is shared -- an
 * enumeration-phase exhaustion (the budget or max-files bound tripping
 * during directory enumeration itself, before either tier has finished
 * classifying) cuts BOTH tiers, and `tiers.targeted.complete` can
 * legitimately be `false` too. The report must say which tier was cut, not
 * just that the scan as a whole was incomplete.
 *
 * Degradation-vs-incompleteness rule (every downstream module implements
 * this): a git degradation (`no-git`, `not-a-repo`, `bare-repo`,
 * `git-refused`, `git-timeout`) fails OPEN for the bulk tier -- MORE files
 * get scanned, not fewer, because the D-13 gitignore-based prune simply
 * does not apply when git could not be consulted. It is recorded in
 * `degradations` and printed in the report but does NOT set `incomplete`.
 * Marking it incomplete would emit exit 2 on every machine without git
 * installed and train operators to ignore exit 2 -- the one code that must
 * never be ignored, because it is the only signal that a scan reporting
 * "clean" might not have actually finished. Only budget/max-files
 * exhaustion sets `incomplete`.
 */

// ---------------------------------------------------------------------
// EXIT -- mirrors lib/mcp/base.js:326-335's frozen enum rather than
// re-inventing the magic numbers. A scan that did not finish is NEVER
// reported as 0 ("clean") -- a security gate must distinguish "no
// findings" from "the scan did not finish".
// ---------------------------------------------------------------------
const EXIT = Object.freeze({
  CLEAN: 0,
  FINDINGS: 1,
  INCOMPLETE: 2,
});

// ---------------------------------------------------------------------
// FILE_CLASSES -- the class taxonomy formalizing the bash scanner's
// per-section prune scopes (RESEARCH.md A1 -- the bash scanner has NO
// unified prune list; each section applies a DIFFERENT scope, and that
// variance IS the de-facto class taxonomy this array formalizes).
//
//   class              | A1 row(s)      | prune scope (bash today)
//   -------------------|----------------|----------------------------------
//   all-files           | 1a/1a2/1b/5    | PRUNE_COMMON only -- node_modules
//                       |                | INCLUDED (walks everywhere else
//                       |                | PRUNE_COMMON excludes: .git,
//                       |                | target, dist, build, .next,
//                       |                | .nuxt, .claude/worktrees)
//   no-prune            | 2              | NONE -- grep -r has zero
//                       |                | directory-prune; the current
//                       |                | scanner's WIDEST scan, even .git
//   lockfiles           | 3a             | PRUNE_COMMON + node_modules
//                       |                | EXCLUDED
//   family-packages     | 3b             | ONLY .claude/worktrees excluded
//                       |                | -- deliberately walks INTO
//                       |                | node_modules to find installed
//                       |                | compromised-family packages
//   agent-config        | 4a/4b          | PRUNE_COMMON + node_modules
//                       |                | EXCLUDED
//   marker-config       | (new -- see    | .env / .env.* / .npmrc marker-
//                       |  note below)   | string scanning, TARGETED tier
//   bulk-content         | 6b            | PRUNE_COMMON + node_modules +
//                       |                | .cache excluded, size <256k,
//                       |                | extension allowlist
//   env-secrets          | (lib/scan.js) | .env / .env.* discovery -- the
//                       |                | class lib/scan.js consumes
//                       |                | (D-23); blanket dot-dir skip,
//                       |                | broader than PRUNE_COMMON
//
// `env-secrets` is the class `lib/scan.js` consumes (D-23) -- its existing
// `findEnvFiles` semantics must stay byte-identical after adoption.
//
// `marker-config` is a TARGETED class, not folded into `bulk-content`,
// because it exists to carry `.env` / `.env.*` / `.npmrc` marker-string
// scanning (the credential-file half of A1 row 6b's marker check): those
// files are near-universally gitignored, and moving their marker scan into
// the prunable bulk tier (D-13) would be a silent coverage regression
// against the old, ungated section 6b -- a gitignored `.env` carrying a
// ChainDrop marker string would stop being detected. See the tiering note
// in plan 17-10 Task 1 for the full rationale.
// ---------------------------------------------------------------------
const FILE_CLASSES = Object.freeze([
  'all-files',
  'no-prune',
  'lockfiles',
  'family-packages',
  'agent-config',
  'marker-config',
  'bulk-content',
  'env-secrets',
]);

// ---------------------------------------------------------------------
// SKIP_REASONS -- the last five are the D-14 git-delegated-ignore
// degradation reasons from RESEARCH.md section B2: `no-git` (binary
// missing), `not-a-repo` (outside any work tree), `bare-repo`
// (`--is-inside-work-tree` reports "false" with exit 0), `git-refused`
// (the safe.directory dubious-ownership refusal, exit 128, since git
// 2.35.2 / CVE-2022-24765), and `git-timeout` (the subprocess was killed
// or timed out -- mirrors lib/scan.js:111-118's killed-by-signal handling).
// ---------------------------------------------------------------------
const SKIP_REASONS = Object.freeze([
  'gitignored',
  'media',
  'oversized',
  'symlink',
  'other-device',
  'unreadable',
  'budget',
  'no-git',
  'not-a-repo',
  'bare-repo',
  'git-refused',
  'git-timeout',
]);

// ---------------------------------------------------------------------
// DEFAULTS -- budgetSeconds:60 / maxFiles:1000000 are LOCKED by human
// ruling (17-BENCH-BASELINE.md, approved 2026-08-07): measured against the
// real 418,728-entry / 374,642-file monorepo that motivated G-1482, bare
// enumeration took 986.7ms (well under the 15s "keep as-is" threshold) and
// total entries stayed under 500k -- the decision table's first branch
// applies, so the pre-bench placeholder numbers are CONFIRMED, not
// replaced. Do not substitute different numbers.
// ---------------------------------------------------------------------
const DEFAULTS = Object.freeze({
  budgetSeconds: 60,
  maxFiles: 1000000,
  readPool: 12,
  bulkReadCapBytes: 262144,
  hashCandidateMaxBytes: 1048576,
  sniffBytes: 8000,
  progressIntervalMs: 1500,
  gitMaxBufferBytes: 268435456,
  gitTimeoutMs: 10000,
});

/**
 * A value is a legal budget bound iff it is a finite number >= 0. Zero is
 * legal (the most conservative expressible value -- it can only force an
 * incomplete verdict, never widen a scan, so it can never be used to
 * disable the bound). `Infinity` is the one value that WOULD disable the
 * bound, so it is explicitly rejected alongside NaN and negatives.
 */
function isValidBound(n) {
  return typeof n === 'number' && Number.isFinite(n) && n >= 0;
}

/**
 * Coerces a raw env-var string to a Number, treating an empty/whitespace-
 * only string as invalid rather than letting `Number('')` silently
 * coerce to 0 -- that would conflate "the variable was unset/blank" with
 * the legal, deliberate, explicit zero.
 */
function coerceEnvNumber(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') return NaN;
  return Number(raw);
}

/**
 * Resolves one bound (budgetSeconds or maxFiles) per the precedence order:
 * explicit option argument, then the named env var, then the default.
 * Never throws. An invalid explicit value OR an invalid/malformed env
 * value falls back to `defaultValue` and appends a `warnings` entry naming
 * the offending source -- it never disables the bound.
 */
function resolveBound({ explicit, envRaw, envVarName, optionName, defaultValue, warnings }) {
  if (explicit !== undefined) {
    if (isValidBound(explicit)) return explicit;
    warnings.push(`invalid ${optionName}: ${explicit}`);
    return defaultValue;
  }
  if (envRaw !== undefined) {
    const parsed = coerceEnvNumber(envRaw);
    if (isValidBound(parsed)) return parsed;
    warnings.push(`invalid ${envVarName}: ${envRaw}`);
    return defaultValue;
  }
  return defaultValue;
}

/**
 * Normalizes a raw options object into the frozen shape every engine
 * module reads. Resolves `budgetSeconds` / `maxFiles` per the precedence
 * documented on `resolveBound`, plus a small set of enumeration-shape and
 * injectable-seam options. Never throws.
 *
 * IMPORTANT -- `maxDepth` / `skipDirs` / `skipDotDirs` exist ONLY so
 * `lib/scan.js` can preserve its shipped `findEnvFiles` semantics (D-23:
 * `maxDepth` default 4 there, `SKIP_DIRS` set, blanket dot-directory
 * skip). These three are a PER-CONSUMER ENUMERATION SHAPE, NOT a
 * detection policy, and the wave-spec driver (plan 17-11's `Traversal`
 * class) MUST NEVER SET THEM -- 17-11 enforces that with a throw, because
 * a physical prune during a walk serving conflicting per-class scopes
 * (D-13's targeted vs bulk tiers) is the B1 silent-detection-loss defect:
 * pruning `node_modules` for one class would also hide it from every other
 * class sharing the same walk.
 */
function normalizeOptions(opts = {}) {
  const env = opts.env || process.env;
  const warnings = [];

  const budgetSeconds = resolveBound({
    explicit: opts.budgetSeconds,
    envRaw: env.LSH_BUDGET_SECONDS,
    envVarName: 'LSH_BUDGET_SECONDS',
    optionName: 'budgetSeconds',
    defaultValue: DEFAULTS.budgetSeconds,
    warnings,
  });

  const maxFiles = resolveBound({
    explicit: opts.maxFiles,
    envRaw: env.LSH_MAX_FILES,
    envVarName: 'LSH_MAX_FILES',
    optionName: 'maxFiles',
    defaultValue: DEFAULTS.maxFiles,
    warnings,
  });

  // Enumeration-shape options (D-23) -- see the IMPORTANT note above.
  const maxDepth = typeof opts.maxDepth === 'number' ? opts.maxDepth : Infinity;
  let skipDirs;
  if (opts.skipDirs instanceof Set) {
    skipDirs = new Set(opts.skipDirs);
  } else if (Array.isArray(opts.skipDirs)) {
    skipDirs = new Set(opts.skipDirs);
  } else {
    skipDirs = new Set();
  }
  const skipDotDirs = opts.skipDotDirs === true;

  const normalized = {
    budgetSeconds,
    maxFiles,
    readPool: typeof opts.readPool === 'number' ? opts.readPool : DEFAULTS.readPool,
    bulkReadCapBytes: typeof opts.bulkReadCapBytes === 'number' ? opts.bulkReadCapBytes : DEFAULTS.bulkReadCapBytes,
    hashCandidateMaxBytes: typeof opts.hashCandidateMaxBytes === 'number' ? opts.hashCandidateMaxBytes : DEFAULTS.hashCandidateMaxBytes,
    sniffBytes: typeof opts.sniffBytes === 'number' ? opts.sniffBytes : DEFAULTS.sniffBytes,
    progressIntervalMs: typeof opts.progressIntervalMs === 'number' ? opts.progressIntervalMs : DEFAULTS.progressIntervalMs,
    gitMaxBufferBytes: typeof opts.gitMaxBufferBytes === 'number' ? opts.gitMaxBufferBytes : DEFAULTS.gitMaxBufferBytes,
    gitTimeoutMs: typeof opts.gitTimeoutMs === 'number' ? opts.gitTimeoutMs : DEFAULTS.gitTimeoutMs,

    // Enumeration shape (D-23) -- see IMPORTANT note above normalizeOptions.
    maxDepth,
    skipDirs,
    skipDotDirs,

    // Injectable seams, defaulting to the real implementations.
    fs: opts.fs || require('fs'),
    spawnSync: opts.spawnSync || require('child_process').spawnSync,
    now: opts.now || process.hrtime.bigint,
    env,
    onReaddir: typeof opts.onReaddir === 'function' ? opts.onReaddir : () => {},
    stderr: opts.stderr || process.stderr,

    warnings,
  };

  return Object.freeze(normalized);
}

/**
 * Creates a fresh skip inventory -- a counted, path-attributed ledger of
 * every entry the walk declined to fully process, keyed by SKIP_REASONS.
 * `add()` throws a TypeError on an unknown reason so a typo cannot
 * silently create a ghost bucket that never shows up in the report.
 */
function createSkipInventory() {
  const counts = {};
  const pathsByReason = {};
  for (const reason of SKIP_REASONS) {
    counts[reason] = 0;
    pathsByReason[reason] = [];
  }

  return {
    add(reason, absPath) {
      if (!SKIP_REASONS.includes(reason)) {
        throw new TypeError(`createSkipInventory.add: unknown skip reason "${reason}"`);
      }
      counts[reason] += 1;
      pathsByReason[reason].push(absPath);
    },
    counts() {
      return { ...counts };
    },
    paths(reason) {
      if (!SKIP_REASONS.includes(reason)) {
        throw new TypeError(`createSkipInventory.paths: unknown skip reason "${reason}"`);
      }
      return pathsByReason[reason].slice();
    },
    total() {
      return Object.values(counts).reduce((sum, n) => sum + n, 0);
    },
  };
}

/**
 * Implements D-18's exit-precedence rule exactly, reproducing the ground
 * truth in `scripts/scan-chaindrop-aug2026.sh:72-78`: `fail()` increments
 * `FINDINGS`, `warn()`/`info()`/`pass()` do NOT, and the script exits 1 iff
 * `FINDINGS > 0`. Only FAIL-severity findings ever count -- `warn` and
 * `info` counts never affect the exit code. This is the rule that pins
 * `variant-small`, `setup-bare`, `bun-staging`, and `vscode-task-info` --
 * the four corpus cases that are warn-only today and must keep exiting 0.
 *
 *   severityCounts.fail > 0                => EXIT.FINDINGS (regardless of
 *                                              `incomplete` -- a real
 *                                              compromise is never masked
 *                                              by an unfinished scan)
 *   severityCounts.fail === 0 && incomplete => EXIT.INCOMPLETE (the
 *                                              dangerous "looked clean but
 *                                              did not finish" case)
 *   otherwise                               => EXIT.CLEAN
 *
 * Throws a TypeError when called with a `findingCount` property (the old,
 * severity-blind shape) or without a `severityCounts` object, so a
 * downstream module cannot silently regress to counting all findings
 * equally regardless of severity.
 */
function computeExit(input) {
  if (!input || typeof input !== 'object' || Object.prototype.hasOwnProperty.call(input, 'findingCount')) {
    throw new TypeError(
      'computeExit: expected { severityCounts, incomplete } -- the legacy ' +
      '{ findingCount } shape is severity-blind (T-17-04-03) and is not supported'
    );
  }
  const { severityCounts, incomplete } = input;
  if (!severityCounts || typeof severityCounts !== 'object') {
    throw new TypeError('computeExit: severityCounts is required -- { fail, warn, info }');
  }

  const fail = severityCounts.fail || 0;
  // warn/info are read but deliberately never influence the branches below
  // -- see the doc comment above for the scan-chaindrop-aug2026.sh:72-78
  // citation this reproduces.
  if (fail > 0) return EXIT.FINDINGS;
  if (incomplete) return EXIT.INCOMPLETE;
  return EXIT.CLEAN;
}

// ---------------------------------------------------------------------
// JSDoc typedefs -- the shapes every sibling engine module (17-07..17-11)
// implements against. Not executable; documentation-only.
// ---------------------------------------------------------------------

/**
 * @typedef {object} TraverseOptions
 * @property {number} budgetSeconds
 * @property {number} maxFiles
 * @property {number} readPool
 * @property {number} bulkReadCapBytes
 * @property {number} hashCandidateMaxBytes
 * @property {number} sniffBytes
 * @property {number} progressIntervalMs
 * @property {number} gitMaxBufferBytes
 * @property {number} gitTimeoutMs
 * @property {number} maxDepth - lib/scan.js enumeration shape only (D-23); never set by the wave-spec driver
 * @property {Set<string>} skipDirs - lib/scan.js enumeration shape only (D-23); never set by the wave-spec driver
 * @property {boolean} skipDotDirs - lib/scan.js enumeration shape only (D-23); never set by the wave-spec driver
 * @property {object} fs
 * @property {Function} spawnSync
 * @property {Function} now - () => bigint, monotonic nanoseconds
 * @property {object} env
 * @property {Function} onReaddir
 * @property {object} stderr
 * @property {string[]} warnings
 */

/**
 * @typedef {object} SkipInventory
 * @property {(reason: string, absPath: string) => void} add - throws TypeError on an unknown reason
 * @property {() => object} counts - every SKIP_REASONS key present, zero-filled
 * @property {(reason: string) => string[]} paths
 * @property {() => number} total
 */

/**
 * @typedef {object} IgnoreIndex
 * @property {(absPath: string) => boolean} isIgnored
 * @property {string} repoRoot
 * @property {string|null} degraded - one of the D-14 degradation SKIP_REASONS, or null
 */

/**
 * @typedef {object} WalkEvent
 * @property {string} absPath
 * @property {object} dirent
 * @property {number} depth
 * @property {string} repoRoot
 * @property {boolean} isDirectory
 *
 * NOTE: deliberately NO `sizeBytes` field. The walk never stats an
 * ordinary file -- every size-based decision is made in `read-pool.js`
 * from `FileHandle.stat()` AFTER the file is already open, which also
 * closes the classify-then-open TOCTOU window a separate pre-open stat
 * would leave.
 */

/**
 * @typedef {object} Finding
 * @property {string} id
 * @property {string} class - one of FILE_CLASSES
 * @property {string} absPath
 * @property {string} detail
 * @property {'fail'|'warn'|'info'} severity
 */

/**
 * @typedef {object} TraverseResult
 * @property {Finding[]} findings
 * @property {SkipInventory} skips
 * @property {object} counts
 * @property {string[]} degradations
 * @property {{targeted: {complete: boolean}, bulk: {complete: boolean}}} tiers
 * @property {boolean} incomplete
 * @property {number} exitCode
 */

module.exports = {
  EXIT,
  FILE_CLASSES,
  SKIP_REASONS,
  DEFAULTS,
  normalizeOptions,
  createSkipInventory,
  computeExit,
};
