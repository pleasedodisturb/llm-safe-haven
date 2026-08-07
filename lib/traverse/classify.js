'use strict';

/**
 * Per-class file classification (G-1482, TRAV-01/TRAV-03/TRAV-05, D-13/D-25).
 *
 * `walk.js` (plan 17-07) applies NO IOC-policy prune -- see its
 * NO-POLICY-PRUNE header -- so it emits a `WalkEvent` for every entry under
 * every directory, node_modules included. This module is therefore the
 * ONLY place any of the bash scanner's per-section directory-prune scopes
 * exist. Every prune decision below is data-driven, cites the
 * `17-RESEARCH.md` A1 row and `scripts/scan-chaindrop-aug2026.sh` line it
 * preserves, and is proven both directions (present vs pruned) in
 * `tests/traverse/classify.test.js`. A MISSING prune here is a performance
 * bug (the read pool opens more files than it needs to); a WRONG prune here
 * is a detection loss (D-13's whole point) -- so every prune scope is kept
 * as narrow, and only as narrow, as its A1 row.
 *
 * `classify()` makes NO size decision -- the walk emits no size (see the
 * `WalkEvent` typedef note in `lib/traverse/index.js`) and nothing here
 * stats a file; every size bound is applied in `read-pool.js` (plan 17-10
 * Task 2) after the handle is already open, which is also what closes the
 * classify-then-open TOCTOU window.
 *
 * IOC literals (filenames, lockfile names, compromised family names, the
 * preinstall-marker filename, the bulk-content extension allowlist) are
 * read from the `spec` argument (`manifests/waves/chaindrop-aug2026.json`,
 * plan 17-04) rather than re-hardcoded here -- this module owns tiering
 * POLICY (which check tier a class belongs to, which directories prune it),
 * the spec owns the IOC DATA.
 */

const path = require('path');

// ---------------------------------------------------------------------
// PRUNE_COMMON_NAMES -- verbatim reproduction of the bash `PRUNE_COMMON`
// array (scripts/scan-chaindrop-aug2026.sh:180): `.git`, `target`, `dist`,
// `build`, `.next`, `.nuxt`, plus the path-suffix rule `*/.claude/worktrees`
// (a two-segment suffix, checked separately in `crossesPrunedDir` below --
// a flat Set of exact names cannot express it).
//
// `node_modules` is DELIBERATELY ABSENT from this Set -- it is absent from
// the bash array at line 180, and several passes (all-files, no-prune,
// family-packages) therefore descend into it TODAY. Any class that must
// additionally exclude node_modules layers that exclusion on top of this
// Set explicitly (`includeNodeModules: true` in the per-class prune scopes
// below), rather than this Set growing a second, contradictory member.
//
// This constant lives HERE, not in `walk.js`, because a single physical
// walk serves classes with mutually incompatible scopes -- pruning
// physically in `walk.js` would narrow section 2 (the `no-prune` class
// below), which uses `grep -r` with NO directory-prune at all and must
// still reach `dist/`, `build/`, `.next/`, `target/` and `node_modules/`.
// ---------------------------------------------------------------------
const PRUNE_COMMON_NAMES = Object.freeze(new Set(['.git', 'target', 'dist', 'build', '.next', '.nuxt']));

const EMPTY_NAMES = Object.freeze(new Set());

// ---------------------------------------------------------------------
// MEDIA_EXTENSIONS -- D-15's FIRST layer ("known media/binary extensions
// skipped at enumeration -- never opened"). The SECOND layer -- the
// null-byte sniff plus the 256 KiB bulk cap -- lives in `read-pool.js`
// (plan 17-10 Task 2), not here.
//
// This list only ever affects the BULK tier. A targeted filename or hash
// check still sees these files -- a payload renamed to `.png` must still
// be caught by name and hash, so this Set is consulted from the
// `bulk-content` branch of `classify()` ONLY.
// ---------------------------------------------------------------------
const MEDIA_EXTENSIONS = Object.freeze(new Set([
  // images
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.tiff', '.heic',
  // video
  '.mp4', '.mov', '.avi', '.mkv', '.webm',
  // audio
  '.mp3', '.wav', '.flac', '.aac', '.ogg',
  // archives
  '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar',
  // binaries / objects
  '.pdf', '.so', '.dylib', '.dll', '.exe', '.o', '.a', '.class', '.jar', '.wasm', '.node', '.bin', '.dmg', '.iso',
  // fonts
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  // databases
  '.sqlite', '.db', '.mdb',
  // lockfile-adjacent binaries
  '.pack', '.idx',
]));

// ---------------------------------------------------------------------
// Per-class prune scopes -- each cites its A1 row / script line.
// ---------------------------------------------------------------------

// A1 rows 1a/1a2/1b/5, script lines 204/227/250/468: PRUNE_COMMON only,
// node_modules IS walked.
const ALL_FILES_PRUNE = { names: PRUNE_COMMON_NAMES, includeNodeModules: false, includeCache: false, worktrees: true };

// A1 row 3a, script line 348: PRUNE_COMMON plus node_modules excluded.
const LOCKFILES_PRUNE = { names: PRUNE_COMMON_NAMES, includeNodeModules: true, includeCache: false, worktrees: true };

// A1 row 3b, script line 380: ONLY `*/.claude/worktrees` excluded --
// deliberately walks INTO node_modules to find installed compromised-family
// packages.
const FAMILY_PACKAGES_PRUNE = { names: EMPTY_NAMES, includeNodeModules: false, includeCache: false, worktrees: true };

// A1 rows 4a/4b, script lines 405/442: PRUNE_COMMON plus node_modules
// excluded.
const AGENT_CONFIG_PRUNE = { names: PRUNE_COMMON_NAMES, includeNodeModules: true, includeCache: false, worktrees: true };

// The bulk-tier coverage fix (see the `marker-config` note in
// `lib/traverse/index.js`'s FILE_CLASSES table) and A1 row 6b, script lines
// 490-494: PRUNE_COMMON plus node_modules plus `.cache` excluded.
const MARKER_CONFIG_PRUNE = { names: PRUNE_COMMON_NAMES, includeNodeModules: true, includeCache: true, worktrees: true };
const BULK_CONTENT_PRUNE = MARKER_CONFIG_PRUNE;

/**
 * Simulates, for a SINGLE already-enumerated `WalkEvent`, whether a
 * directory-pruned `find` invocation covering `opts`'s scope would ever
 * have reached this path -- i.e. whether any ancestor directory segment of
 * `absPath` is a name this class prunes. Checks directory segments only
 * (never the file's own basename), and the `.claude` + `worktrees` suffix
 * rule is a two-segment adjacency check since `PRUNE_COMMON_NAMES` cannot
 * express a path suffix.
 *
 * KNOWN LIMITATION (documented, not a defect this plan resolves): this
 * checks every ancestor segment from the filesystem root downward, not
 * only segments below the scan root actually passed to `walk()` -- the
 * physical walk never tells `classify()` which root produced a given
 * event. In practice this is safe: this project's own default roots
 * (`~/Projects`, `~/Developer`, ...) and any operator-supplied `LSH_ROOTS`
 * are not expected to sit under a directory literally named `dist`,
 * `build`, `target`, `.next`, `.nuxt` or `node_modules` -- if that ever
 * changes, tightening this to a root-relative check is a `classify.js`-only
 * change, not a `walk.js` one.
 */
function crossesPrunedDir(absPath, opts) {
  const segments = path.dirname(absPath).split(path.sep);
  for (let i = 0; i < segments.length; i += 1) {
    const seg = segments[i];
    if (!seg) continue;
    if (opts.names.has(seg)) return true;
    if (opts.includeNodeModules && seg === 'node_modules') return true;
    if (opts.includeCache && seg === '.cache') return true;
    if (opts.worktrees && seg === '.claude' && segments[i + 1] === 'worktrees') return true;
  }
  return false;
}

/**
 * True for every class except `bulk-content`. Targeted classes are D-13's
 * always-run tier -- they are never consulted against the ignore resolver,
 * because `.gitignore` is attacker-controlled and must never be able to
 * hide a payload.
 */
function isTargetedClass(className) {
  return className !== 'bulk-content';
}

// ---------------------------------------------------------------------
// Membership predicates -- data comes from `spec`, matching comes from
// here.
// ---------------------------------------------------------------------

// `Math_*.js` / `math_*.js` are the only two globs this spec ever expresses
// -- a single `<prefix>*<suffix>` shape, no general glob engine needed.
function matchSimpleGlob(name, glob) {
  const starIdx = glob.indexOf('*');
  if (starIdx === -1) return name === glob;
  const prefix = glob.slice(0, starIdx);
  const suffix = glob.slice(starIdx + 1);
  return name.length >= prefix.length + suffix.length && name.startsWith(prefix) && name.endsWith(suffix);
}

function isVariantName(name, spec) {
  const variant = spec.fileMarkers.variantPattern;
  if (variant.excludeExactNames.includes(name)) return false;
  return variant.globs.some((g) => matchSimpleGlob(name, g));
}

// A1 rows 1a/1a2/1b: exact FAIL filenames, the Math_*.js / math_*.js
// variant globs, and `setup.mjs`. Section 5's hash-candidate name
// restriction (script:468, `setup.mjs|Math_Symbol.js|math_init.js|
// router_runtime.js`) is a SUBSET of this same membership -- the read pool
// (plan 17-10 Task 2 / plan 17-11) hashes files in this class matching
// those particular names; no separate list is needed here.
function isAllFilesMember(name, spec) {
  return spec.fileMarkers.fail.includes(name) || isVariantName(name, spec) || spec.fileMarkers.warnOnly.includes(name);
}

function familyPackageName(absPath, spec) {
  if (path.basename(absPath) !== 'package.json') return null;
  const segments = path.dirname(absPath).split(path.sep);
  const idx = segments.lastIndexOf('node_modules');
  if (idx === -1 || idx >= segments.length - 1) return null;
  const next = segments[idx + 1];
  if (next.startsWith('@')) {
    if (idx + 2 !== segments.length - 1) return null; // package.json must be the direct child
    const scoped = `${next}/${segments[idx + 2]}`;
    return spec.compromisedFamily.includes(scoped) ? scoped : null;
  }
  if (idx + 1 !== segments.length - 1) return null; // package.json must be the direct child
  return spec.compromisedFamily.includes(next) ? next : null;
}

function agentConfigMatch(absPath) {
  const base = path.basename(absPath);
  const parent = path.basename(path.dirname(absPath));
  if (parent === '.claude' && (base === 'settings.json' || base === 'settings.local.json')) return true;
  if (parent === '.vscode' && base === 'tasks.json') return true;
  return false;
}

// Byte-identical to `lib/scan.js:40` (D-23) -- exact name `.env`, or a name
// starting with `.env.` that does NOT end in `.example`, `.template` or
// `.sample`.
function isEnvSecretsMember(name) {
  return name === '.env' || (name.startsWith('.env.') && !name.endsWith('.example') && !name.endsWith('.template') && !name.endsWith('.sample'));
}

// `.env`, any `.env.*` (no exemption suffixes -- deliberately broader than
// `env-secrets` above, since a `.env.example` carrying a live IOC marker
// string is still worth flagging even though it is not itself a live
// credential file), and `.npmrc`.
function isMarkerConfigMember(name) {
  return name === '.env' || name.startsWith('.env.') || name === '.npmrc';
}

const bulkAllowlistCache = new WeakMap();

// A1 row 6b's extension/name allowlist, MINUS `.npmrc` and `.env` -- those
// are handled by `marker-config` above (the targeted tier) so no file is
// marker-scanned twice. See the `marker-config` note in
// `lib/traverse/index.js` for the full D-13 tiering rationale.
function bulkAllowlist(spec) {
  const cached = bulkAllowlistCache.get(spec);
  if (cached) return cached;
  const globs = spec.classes['bulk-content'].fileGlobs;
  const set = new Set();
  for (const g of globs) {
    if (g === '.npmrc' || g === '.env') continue;
    set.add(g.startsWith('*.') ? g.slice(1) : g);
  }
  bulkAllowlistCache.set(spec, set);
  return set;
}

/**
 * `classify(event, spec, ctx)` -- `event` is a `WalkEvent` (see
 * `lib/traverse/index.js`), `spec` is the parsed wave spec (plan 17-04),
 * and `ctx` carries `{ ignore, selfRoot, skips }`: the ignore resolver
 * (`createIgnoreResolver()`, plan 17-08), this project's own repo root (so
 * a scan of `~/Projects` never flags this tool's own manifests/tests --
 * every bash section applies this same self-exclusion per-root), and the
 * skip inventory (accepted for future callers; this module itself records
 * nothing there -- `read-pool.js` and the plan-17-11 orchestrator own
 * skip-inventory writes for size/gitignore/media outcomes).
 *
 * Returns `{ classes: string[], bulkEligible: boolean, skipReason:
 * string|null }`. `bulkEligible` and `skipReason` describe the
 * `bulk-content` decision specifically (the only class with a tri-state
 * outcome: matched-and-eligible, matched-but-skipped, or not-a-candidate at
 * all) -- every other class is a simple present/absent membership test.
 */
function classify(event, spec, ctx) {
  const { absPath, repoRoot } = event;
  const name = path.basename(absPath);

  // Self-root exclusion first -- scripts/scan-chaindrop-aug2026.sh applies
  // this filter in sections 1, 2, 3, 4, 5 and 6 (once per root); the engine
  // applies it once, centrally, here.
  if (ctx.selfRoot && (absPath === ctx.selfRoot || absPath.startsWith(ctx.selfRoot + path.sep))) {
    return { classes: [], bulkEligible: false, skipReason: null };
  }

  const classes = [];
  let bulkEligible = false;
  let skipReason = null;

  // all-files (A1 rows 1a/1a2/1b/5, script lines 204/227/250/468).
  if (isAllFilesMember(name, spec) && !crossesPrunedDir(absPath, ALL_FILES_PRUNE)) {
    classes.push('all-files');
  }

  // no-prune (A1 row 2, script line 277): NO directory prune whatsoever,
  // matching `grep -r`. D-25: a `preinstall` marker inside
  // `node_modules/<family>/package.json` MUST reach this class -- section 2
  // also reaches `dist/`, `build/`, `.next/` and `target/` because it
  // prunes nothing at all. Adding any prune to this class would be a
  // silent detection loss.
  if (name === spec.installMarker.filename) {
    classes.push('no-prune');
  }

  // lockfiles (A1 row 3a, script line 348).
  if (spec.lockfiles.includes(name) && !crossesPrunedDir(absPath, LOCKFILES_PRUNE)) {
    classes.push('lockfiles');
  }

  // family-packages (A1 row 3b, script line 380).
  if (familyPackageName(absPath, spec) && !crossesPrunedDir(absPath, FAMILY_PACKAGES_PRUNE)) {
    classes.push('family-packages');
  }

  // agent-config (A1 rows 4a/4b, script lines 405/442).
  if (agentConfigMatch(absPath) && !crossesPrunedDir(absPath, AGENT_CONFIG_PRUNE)) {
    classes.push('agent-config');
  }

  // env-secrets (D-23) -- membership only, byte-identical to
  // `lib/scan.js:40`. No directory-name prune applied HERE: the
  // scan.js-specific dot-dir / SKIP_DIRS behavior is a per-consumer
  // enumeration SHAPE applied at the WALK level via `skipDirs`/
  // `skipDotDirs` (see the IMPORTANT note on `normalizeOptions` in
  // `lib/traverse/index.js`) when plan 17-13 wires `lib/scan.js` to this
  // engine -- duplicating it here would risk the two copies drifting.
  // Targeted tier: NEVER gitignore-pruned, because `.env` files are
  // deliberately gitignored, which is the whole point.
  if (isEnvSecretsMember(name)) {
    classes.push('env-secrets');
  }

  // marker-config: `.env` / `.env.*` / `.npmrc` marker-string scanning in
  // the TARGETED tier -- the ignore resolver is never consulted for these
  // names. Old section 6b had no gitignore awareness at all, and `.env` /
  // `.npmrc` are the files in its extension allowlist that are
  // near-universally gitignored -- leaving them in the prunable bulk tier
  // would lose exactly the credential-bearing files a marker string is
  // most likely to appear in. A residual coverage difference remains for
  // OTHER gitignored text files outside the six commonly-pruned
  // directories -- that is D-13's deliberate trade-off, pinned explicitly
  // by plan 17-05's `KNOWN_TIERING_TRADEOFFS` case rather than left
  // undiscovered.
  const isMarkerCandidate = isMarkerConfigMember(name);
  if (isMarkerCandidate && !crossesPrunedDir(absPath, MARKER_CONFIG_PRUNE)) {
    classes.push('marker-config');
  }

  // bulk-content (A1 row 6b, script lines 490-494). `.npmrc` and `.env` are
  // handled by marker-config above and must NOT also appear here, so no
  // file is marker-scanned twice. This is the ONLY class where the ignore
  // resolver's bulk-eligibility check is consulted.
  if (!isMarkerCandidate) {
    const ext = path.extname(name);
    if (MEDIA_EXTENSIONS.has(ext)) {
      skipReason = 'media';
    } else if (bulkAllowlist(spec).has(ext) && !crossesPrunedDir(absPath, BULK_CONTENT_PRUNE)) {
      // A file with no known repo (repoRoot === null) has no `.gitignore`
      // to consult -- it is eligible by construction, and the resolver is
      // not invoked for it (no repository to probe).
      const decision = repoRoot ? ctx.ignore.isBulkEligible(absPath, repoRoot) : { eligible: true, reason: null };
      if (decision.eligible) {
        classes.push('bulk-content');
        bulkEligible = true;
      } else {
        skipReason = 'gitignored';
      }
    }
  }

  return { classes, bulkEligible, skipReason };
}

module.exports = {
  MEDIA_EXTENSIONS,
  PRUNE_COMMON_NAMES,
  classify,
  isTargetedClass,
};
