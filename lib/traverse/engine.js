'use strict';

/**
 * Traversal engine orchestrator (G-1482, TRAV-01/TRAV-04/TRAV-05, D-02/D-03/
 * D-13/D-20/D-25).
 *
 * `Traversal` is the first class in `lib/` -- every other module under
 * `lib/` (agents, mcp parsers/detectors, scan.js, cli.js, and every sibling
 * file in `lib/traverse/`) exports plain named functions, and this one
 * exception exists solely because D-03 requires a single enumeration API
 * that serves BOTH the wave-spec-driven scanner (`run()`) AND a non-wave
 * consumer such as `lib/scan.js` (`enumerateSync()`). The object holds walk
 * state, the skip inventory and the shared budget across two phases of
 * asynchronous work -- state a plain function would otherwise have to
 * thread through every call by hand. Everything else exported here
 * (`traverse`, `DETECTOR_OWNERSHIP`) is a plain function or frozen data,
 * matching the rest of this codebase.
 *
 * This module composes `walk.js` (one physical pass per root), `classify.js`
 * (per-class membership), `read-pool.js` (the bounded, single-open-per-path
 * content/hash reader) and `budget.js` (the shared wall-clock + max-files
 * bound) -- it re-implements none of them. The only IOC-matching logic that
 * lives here is the per-detector escalation rule (fail vs warn, which
 * finding id fires), because that decision genuinely needs the walk +
 * classify + read-pool outputs together; every literal IOC value (hashes,
 * marker strings, poisoned versions, filenames, patterns) is read from the
 * `spec` argument at call time -- none is hardcoded in this file.
 *
 * 2026-08-07: this engine no longer consults git at all. `lib/traverse/
 * git-ignore.js` (the module that consulted `.gitignore` to decide which
 * files the retired `bulk-content` class could skip) and its two call
 * sites here have been deleted entirely -- see `classify.js`'s module
 * header for the full tiering-trade-off-reversal history. `tests/traverse/
 * zero-git-subprocess.test.js` proves, through a real `run()` call, that
 * no `child_process.spawnSync` invocation happens anywhere in a scan.
 *
 * ---------------------------------------------------------------------
 * TWO-PHASE run() (D-20).
 * ---------------------------------------------------------------------
 * `run()` walks each root exactly ONCE, building one immutable work record
 * per absolute path (merging every class's read requirements into
 * `needHash` / `needTargetedContent` / `needBulk` -- D-02's true single
 * read). Records whose classes include any TARGETED class (everything
 * except `bulk-content`, per `classify.js`'s `isTargetedClass`) are
 * submitted to the read pool FIRST and drained; only once that phase
 * finishes without exhausting the shared budget are the remaining
 * bulk-content-only records submitted and drained. If the budget latches
 * during the walk itself, BOTH tiers are marked incomplete, because the
 * walk is the shared enumeration both tiers ride -- an enumeration cut
 * means neither tier's classification work finished, regardless of which
 * tier's READS would have run first. See the `tiers` field on the returned
 * `TraverseResult` and `lib/traverse/index.js`'s D-20 header for the full
 * rule this reproduces.
 *
 * 2026-08-10 (G-1502 / TRAV-10, D-08): `run()`'s single walk now ALSO
 * builds `byClass`, the same per-`FILE_CLASSES` enumeration `enumerateSync()`
 * produces, unconditionally, for every classified path -- not just the ones
 * that reach `workMap`. `lib/traverse/run.js` no longer constructs a SECOND
 * `Traversal`/`enumerateSync()` pass to populate `lists/<class>.z`; it reads
 * `byClass` straight off this method's result. This restores D-20's
 * walk-once guarantee at the `run.js` entry-point level (the old second pass
 * was a real, independently-budgeted walk of its own, observing a different
 * filesystem snapshot under a different budget -- the reproduction on
 * record is a poisoned `keyv@6.0.0` vanishing from `lists/lockfiles.z`, 6/6
 * attempts). Consequence: class lists now truncate WITH the scan, because
 * one budget governs both findings and lists -- see `run()`'s own doc
 * comment below for the full account and the load-bearing subset proof.
 *
 * NOTE (2026-08-07): `classify()` can no longer assign the `bulk-content`
 * class to anything (see above), so the "bulk" half of this two-phase
 * split -- `bulkComplete`, `pool2`, the phase-boundary budget recheck --
 * is presently always a zero-record no-op: every real work record is
 * `priority: 'targeted'` now. This structure is left in place rather than
 * collapsed to a single phase, because it is the general-purpose
 * priority-ordering mechanism D-20 defines (targeted reads before bulk
 * reads), not itself gitignore-consultation plumbing, and a future
 * wave-spec class could reintroduce a genuinely lower-priority tier. This
 * was flagged explicitly, not silently decided, when discovered during the
 * 2026-08-07 tiering-trade-off reversal -- see the 17-14 plan summary.
 *
 * Every distinct verdict below has its own stable, kebab-case finding id
 * (including non-fail WARN/INFO verdicts) so the id-to-report-string
 * mapping is a pure lookup table on the bash side, with no severity
 * branching of its own -- see `severityCounts` on the returned result,
 * fed through `computeExit` for the D-18 exit-precedence rule. The engine
 * never prints to stdout; any diagnostics it emits go to stderr only.
 *
 * ---------------------------------------------------------------------
 * DETECTOR_OWNERSHIP (T-17-15).
 * ---------------------------------------------------------------------
 * Every ChainDrop detector in `scripts/scan-chaindrop-aug2026.sh` is owned
 * by exactly ONE side -- this engine XOR the bash script -- never both,
 * never neither. `DETECTOR_OWNERSHIP` is the single exportable authority
 * both sides implement against; plan 17-14 implements exactly the `bash`
 * rows and removes exactly the `engine` rows from the shell script. The
 * table below is reproduced from the plan that authored it; only the
 * detector-name prose for the two persistence-watcher / static-path rows
 * has been reworded from the plan's own phrasing to avoid embedding the
 * literal watcher-script/service filenames as string literals in this
 * file -- see the "no IOC literal hardcoded" acceptance rule below. The
 * SEMANTICS of every row are unchanged.
 *
 *   section | detector                                   | owner  | engine finding ids
 *   --------|---------------------------------------------|--------|----------------------------------------------
 *   1a      | exact FAIL filenames                         | engine | file-marker
 *   1a2     | Math_* / math_* variant escalation           | engine | payload-variant, payload-variant-warn
 *   1b      | setup.mjs triage                             | engine | setup-hash, setup-preinstall-pair, setup-bare
 *   1c      | revocation-watcher static persistence paths  | bash   | (none)
 *   2       | preinstall marker in package.json            | engine | install-marker
 *   3a      | poisoned versions in lockfiles               | bash   | (none)
 *   3b      | installed poisoned family versions           | engine | poisoned-installed
 *   4a      | .claude/settings*.json hook commands         | engine | claude-hook
 *   4b      | .vscode/tasks.json folderOpen                | engine | vscode-task, vscode-task-info
 *   5       | known-bad payload hashes                     | engine | known-hash
 *   6a      | marker strings in shell history              | bash   | (none)
 *   6b      | marker strings in code roots                 | engine | marker-string
 *   6c      | staging directories in TMPDIR                | bash   | (none)
 *   7       | GitHub dead-drop repo audit                  | bash   | (none)
 *
 * Row 1c is FOUR absolute `[ -e ]` presence checks with no matching logic
 * at all, one of which (a systemd unit) lies outside every scan root and
 * outside the engine's own device/root containment -- the engine supplies
 * the checked absolute locations from the spec's `staticPaths` section so
 * bash never re-hardcodes them, but performs none of the checking itself.
 *
 * Row 3a's `poisoned_hit_in_file()` awk window matcher (script line 298,
 * called at line 340) carries a yarn-Berry false-negative lesson from its
 * own development history and is DELIBERATELY NOT reimplemented here --
 * see plan 17-14. A claim investigated and found WRONG during this plan's
 * review, recorded so no future agent re-derives it: `poisoned_hit_in_file()`
 * is lockfile-only, but section 2's preinstall check (script line 277) is a
 * SEPARATE `grep -rlE ... --include=package.json` that never calls it. A
 * preinstall marker inside a compromised-family package's own
 * `node_modules/<family>/package.json` is therefore ALREADY detected by
 * today's bash scanner via section 2 alone -- D-25 (the `no-prune` class's
 * unrestricted scope, implemented below) closes a TEST gap, not a
 * detection gap, and `poisoned_hit_in_file()` must never be extended to
 * also match `package.json`.
 *
 * Rows 1c/3a/6a/6c/7 supply their bash-owned detector's INPUT DATA (spec
 * lists, classified file sets) but emit no finding of their own -- this
 * plan's `run()` therefore never produces a finding for any of those five
 * rows; the code below implements ONLY the nine `engine`-owned rows.
 */

const path = require('path');

const { FILE_CLASSES, SKIP_REASONS, normalizeOptions, createSkipInventory, computeExit } = require('./index.js');
const { walk } = require('./walk.js');
const { classify, isTargetedClass } = require('./classify.js');
const { createReadPool } = require('./read-pool.js');
const { createBudget } = require('./budget.js');

// ---------------------------------------------------------------------
// DETECTOR_OWNERSHIP -- see the header comment above for the full table
// and its citations. Frozen so a caller cannot mutate the authority both
// sides implement against.
// ---------------------------------------------------------------------
const DETECTOR_OWNERSHIP = Object.freeze(
  [
    {
      section: '1a',
      detector: 'exact FAIL filenames',
      owner: 'engine',
      findingIds: ['file-marker'],
      rationale: 'Pure name-based presence check across every scan root -- traversal-driven, no read needed.',
    },
    {
      section: '1a2',
      detector: 'Math_*/math_* variant escalation',
      owner: 'engine',
      findingIds: ['payload-variant', 'payload-variant-warn'],
      rationale: 'Traversal + hash + size: FAIL on a known-bad hash or a payload-sized file, otherwise WARN so a renamed variant still surfaces.',
    },
    {
      section: '1b',
      detector: 'setup.mjs triage',
      owner: 'engine',
      findingIds: ['setup-hash', 'setup-preinstall-pair', 'setup-bare'],
      rationale: 'Traversal + hash + a sibling-directory content read (same package.json the no-prune class already reads).',
    },
    {
      section: '1c',
      detector: 'revocation-watcher static persistence paths',
      owner: 'bash',
      findingIds: [],
      rationale:
        'Four ABSOLUTE presence-only checks, no matching logic, and one of the four locations lies outside every scan root and outside the ' +
        "engine's device/root containment entirely. The engine supplies the checked absolute locations from the spec's staticPaths section " +
        'so bash never re-hardcodes them, but performs none of the presence checking itself.',
    },
    {
      section: '2',
      detector: 'preinstall marker in package.json',
      owner: 'engine',
      findingIds: ['install-marker'],
      rationale: 'Traversal-driven; the no-prune class (D-25) applies NO directory prune, so this reaches every package.json under every scan root, node_modules included.',
    },
    {
      section: '3a',
      detector: 'poisoned versions in lockfiles',
      owner: 'bash',
      findingIds: [],
      rationale:
        "The awk package-section-window matcher (script's poisoned_hit_in_file()) carries a yarn-Berry false-negative lesson from its own " +
        'development history and is deliberately NOT reimplemented here -- see plan 17-14. The engine classifies matching files into the ' +
        "lockfiles class for bash to consume; it performs none of the version matching itself.",
    },
    {
      section: '3b',
      detector: 'installed poisoned family versions',
      owner: 'engine',
      findingIds: ['poisoned-installed'],
      rationale: 'Traversal-driven: reads the exact on-disk name/version from each compromised-family package.json and compares against the spec.',
    },
    {
      section: '4a',
      detector: '.claude/settings*.json hook commands',
      owner: 'engine',
      findingIds: ['claude-hook'],
      rationale: 'The engine already owns the per-root discovered agent-config files; the static $HOME settings paths are the same file NAME pattern, matched by the same content check, so one detector has one owner.',
    },
    {
      section: '4b',
      detector: '.vscode/tasks.json folderOpen',
      owner: 'engine',
      findingIds: ['vscode-task', 'vscode-task-info'],
      rationale: 'Traversal-driven content check: FAIL on the ChainDrop-specific persistence pattern, INFO on any other folderOpen auto-run task.',
    },
    {
      section: '5',
      detector: 'known-bad payload hashes',
      owner: 'engine',
      findingIds: ['known-hash'],
      rationale: 'Traversal + hash over the small, spec-derived set of payload-shaped candidate filenames.',
    },
    {
      section: '6a',
      detector: 'marker strings in shell history',
      owner: 'bash',
      findingIds: [],
      rationale: "Two ABSOLUTE $HOME history files, checked one marker string at a time, each with its own report line. The engine supplies the marker-string list from the spec; it never reads a shell-history file itself.",
    },
    {
      section: '6b',
      detector: 'marker strings in code roots',
      owner: 'engine',
      findingIds: ['marker-string'],
      rationale: 'Traversal-driven, entirely within the targeted marker-config class -- there is no longer a separate gitignore-prunable bulk tier (2026-08-07 tiering-trade-off reversal; see lib/traverse/classify.js\'s module header).',
    },
    {
      section: '6c',
      detector: 'staging directories in TMPDIR',
      owner: 'bash',
      findingIds: [],
      rationale: 'A directory-glob check under TMPDIR, entirely outside every scan root -- out of the traversal engine\'s scope by construction.',
    },
    {
      section: '7',
      detector: 'GitHub dead-drop repo audit',
      owner: 'bash',
      findingIds: [],
      rationale: 'Requires network access and the gh CLI -- out of the engine\'s offline, filesystem-only scope entirely.',
    },
  ].map((row) => Object.freeze(row))
);

// ---------------------------------------------------------------------
// Internal helpers -- IOC MATCHING logic only; every literal value below
// is read from `spec`, never hardcoded (grep-asserted by this file's own
// acceptance criteria).
// ---------------------------------------------------------------------

// Classes whose finding logic needs the file's CONTENT (as opposed to
// `all-files`, which needs a HASH, and `bulk-content`, tracked separately
// as `needBulk`).
const TARGETED_CONTENT_CLASSES = new Set(['no-prune', 'family-packages', 'agent-config', 'marker-config']);

/**
 * Section 5's hash-candidate set is a SUBSET of `all-files` -- every
 * `all-files` member whose name is NOT also one of the static persistence
 * paths the spec's `staticPaths` section lists (those are presence-only
 * checks, bash-owned, row 1c -- never hashed) is a hash candidate, plus
 * every `warnOnly` name (setup.mjs). Derived from the spec at call time so
 * no filename is hardcoded here.
 */
function computeHashCandidateNames(spec) {
  const staticBasenames = new Set(spec.staticPaths.map((p) => path.basename(p)));
  const candidates = new Set(spec.fileMarkers.warnOnly);
  for (const name of spec.fileMarkers.fail) {
    if (!staticBasenames.has(name)) candidates.add(name);
  }
  return candidates;
}

// `<prefix>*<suffix>` is the only glob shape the spec's variant pattern
// ever expresses -- mirrors classify.js's own `matchSimpleGlob`, which is
// not exported; duplicated here (short, single-purpose) because engine.js
// needs the same predicate AFTER the read-pool phase to decide which
// FINDING id applies, a different question from classify.js's CLASS
// membership decision.
function matchesVariantGlob(name, glob) {
  const starIdx = glob.indexOf('*');
  if (starIdx === -1) return name === glob;
  const prefix = glob.slice(0, starIdx);
  const suffix = glob.slice(starIdx + 1);
  return name.length >= prefix.length + suffix.length && name.startsWith(prefix) && name.endsWith(suffix);
}

function isVariantCandidate(name, spec) {
  const variant = spec.fileMarkers.variantPattern;
  if (variant.excludeExactNames.includes(name)) return false;
  return variant.globs.some((g) => matchesVariantGlob(name, g));
}

function buildMarkerRegex(markerStrings) {
  const escaped = markerStrings.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(escaped.join('|'));
}

function mkFinding(id, cls, absPath, detail, severity) {
  return { id, class: cls, absPath, detail, severity };
}

/**
 * Merges every SKIP_REASONS bucket of `source` into `target` -- used to
 * fold `walk()`'s own returned skip inventory (structural skips: symlink /
 * other-device / unreadable / budget) into the one shared inventory this
 * module also writes read-pool-driven (`oversized` / further `unreadable` /
 * `budget`) skips into, so the caller sees ONE combined ledger. `classify()`
 * itself never adds a skip reason any more (2026-08-07 tiering-trade-off
 * reversal removed the only two it ever produced, `gitignored` and
 * `media`, along with the `bulk-content` class they were specific to).
 */
function mergeSkips(target, source) {
  for (const reason of SKIP_REASONS) {
    for (const p of source.paths(reason)) target.add(reason, p);
  }
}

// A minimal spec stand-in for `enumerateSync()` callers that never pass a
// `spec` (D-23's `lib/scan.js` use case). Every array is empty and the
// install-marker filename is an unmatchable sentinel, so classes that
// genuinely need spec DATA (all-files, no-prune, lockfiles, family-packages)
// simply never match anything -- classes that need no spec data at all
// (env-secrets, agent-config) are unaffected. `classes['bulk-content']
// .fileGlobs` stays present (empty) because `classify.js`'s
// `isMarkerConfigMember` unconditionally reads it as the data source for
// `marker-config` membership (2026-08-07 tiering-trade-off reversal --
// `bulk-content` itself can no longer be assigned; this is its allowlist
// living on as marker-config's data source, not a bulk-content revival).
const EMPTY_SPEC = Object.freeze({
  fileMarkers: Object.freeze({ fail: [], warnOnly: [], variantPattern: Object.freeze({ globs: [], excludeExactNames: [] }) }),
  installMarker: Object.freeze({ filename: '__unmatchable__' }),
  lockfiles: Object.freeze([]),
  compromisedFamily: Object.freeze([]),
  classes: Object.freeze({ 'bulk-content': Object.freeze({ fileGlobs: Object.freeze([]) }) }),
});

/**
 * Decides whether a classified file needs any read-pool work at all, and
 * if so, what kind and at what priority (D-20: targeted before bulk).
 * Returns `null` when the file's classes require no read (e.g. a bare
 * `lockfiles` or `env-secrets` membership with nothing else -- both are
 * presence/name-only for every finding this plan implements).
 */
function buildWorkFlags(classes, name, spec, hashCandidateNames) {
  const needHash = classes.includes('all-files') && (hashCandidateNames.has(name) || isVariantCandidate(name, spec));
  const needTargetedContent = classes.some((c) => TARGETED_CONTENT_CLASSES.has(c));
  const needBulk = classes.includes('bulk-content');
  if (!needHash && !needTargetedContent && !needBulk) return null;
  const priority = classes.some(isTargetedClass) ? 'targeted' : 'bulk';
  return { needHash, needTargetedContent, needBulk, priority };
}

/**
 * Generates every content/hash-dependent finding (everything except
 * `file-marker`, which needs no read and is emitted inline during the
 * walk -- see `run()` below) by joining each work record against its
 * read-pool result. One pass over `workMap`; every finding id here is one
 * of the nine `engine`-owned ids in `DETECTOR_OWNERSHIP`.
 */
function generateContentFindings({ spec, workMap, resultsByPath, hashCandidateNames, findings }) {
  const knownBad = new Map(spec.knownBadHashes.map((e) => [e.sha256.toLowerCase(), e]));
  const installMarkerRe = new RegExp(spec.installMarker.jsPattern);
  const commandSusRe = new RegExp(spec.persistence.claudeSettings.commandPattern);
  const vscodeTriggerRe = new RegExp(spec.persistence.vscodeTasks.triggerPattern);
  const vscodeFailRe = new RegExp(spec.persistence.vscodeTasks.failPattern, 'i');
  const markerRe = buildMarkerRegex(spec.markerStrings);

  function textOf(absPath) {
    const r = resultsByPath.get(absPath);
    if (!r || !r.bulkBuffer || r.isBinary) return null;
    return r.bulkBuffer.toString('utf8');
  }

  for (const [absPath, rec] of workMap) {
    const result = resultsByPath.get(absPath);
    if (!result || result.error) continue;
    const name = path.basename(absPath);
    const text = textOf(absPath);

    // --- section 1a2/1b/5: all-files hash-based checks -------------------
    if (rec.classes.includes('all-files')) {
      if (hashCandidateNames.has(name) && result.digest && knownBad.has(result.digest.toLowerCase())) {
        findings.push(mkFinding('known-hash', 'all-files', absPath, 'File matches a known ChainDrop payload hash', 'fail'));
      }

      if (isVariantCandidate(name, spec)) {
        const hashBad = Boolean(result.digest && knownBad.has(result.digest.toLowerCase()));
        const sizeBad = typeof result.size === 'number' && result.size >= spec.fileMarkers.variantPattern.sizeThresholdBytes;
        if (hashBad || sizeBad) {
          const why = hashBad ? 'known hash' : `${result.size}B`;
          findings.push(mkFinding('payload-variant', 'all-files', absPath, `Stage-2 payload variant (${why})`, 'fail'));
        } else {
          findings.push(mkFinding('payload-variant-warn', 'all-files', absPath, 'File matches the ChainDrop stage-2 naming pattern', 'warn'));
        }
      }

      if (spec.fileMarkers.warnOnly.includes(name)) {
        const hashBad = Boolean(result.digest && knownBad.has(result.digest.toLowerCase()));
        if (hashBad) {
          findings.push(mkFinding('setup-hash', 'all-files', absPath, 'setup.mjs matches a known ChainDrop loader hash', 'fail'));
        } else {
          const siblingPkg = path.join(path.dirname(absPath), 'package.json');
          const siblingText = textOf(siblingPkg);
          if (siblingText && installMarkerRe.test(siblingText)) {
            findings.push(
              mkFinding('setup-preinstall-pair', 'all-files', absPath, "setup.mjs paired with a 'preinstall: node setup.mjs' package.json (ChainDrop)", 'fail')
            );
          } else {
            findings.push(mkFinding('setup-bare', 'all-files', absPath, 'setup.mjs present with no worm markers (likely benign)', 'warn'));
          }
        }
      }
    }

    // --- section 2: preinstall marker (D-25, no directory prune) --------
    if (rec.classes.includes('no-prune') && text && installMarkerRe.test(text)) {
      findings.push(mkFinding('install-marker', 'no-prune', absPath, "package.json has 'preinstall: node setup.mjs' (ChainDrop install trigger)", 'fail'));
    }

    // --- section 3b: installed poisoned family versions ------------------
    if (rec.classes.includes('family-packages') && text) {
      const nameMatch = /"name"\s*:\s*"([^"]+)"/.exec(text);
      const verMatch = /"version"\s*:\s*"([^"]+)"/.exec(text);
      if (nameMatch && verMatch) {
        const pkgName = nameMatch[1];
        const pkgVer = verMatch[1];
        const poisoned = spec.poisonedVersions[pkgName];
        if (Array.isArray(poisoned) && poisoned.includes(pkgVer)) {
          findings.push(mkFinding('poisoned-installed', 'family-packages', absPath, `Installed poisoned version on disk: ${pkgName}@${pkgVer}`, 'fail'));
        }
      }
    }

    // --- sections 4a/4b: agent-config persistence -------------------------
    if (rec.classes.includes('agent-config') && text) {
      const parent = path.basename(path.dirname(absPath));
      if (parent === '.claude' && (name === 'settings.json' || name === 'settings.local.json')) {
        if (text.includes('"hooks"')) {
          const susLines = text.split('\n').filter((line) => /"command"\s*:/.test(line) && commandSusRe.test(line));
          if (susLines.length > 0) {
            findings.push(mkFinding('claude-hook', 'agent-config', absPath, susLines.slice(0, 5).join('\n'), 'fail'));
          }
        }
      } else if (parent === '.vscode' && name === 'tasks.json') {
        if (vscodeTriggerRe.test(text)) {
          const cmdMatches = text.match(/"(command|label)"\s*:\s*"[^"]*"/g) || [];
          if (vscodeFailRe.test(cmdMatches.join('\n'))) {
            findings.push(mkFinding('vscode-task', 'agent-config', absPath, 'folderOpen task matches ChainDrop persistence', 'fail'));
          } else {
            findings.push(mkFinding('vscode-task-info', 'agent-config', absPath, 'folderOpen auto-run task present (review if unexpected)', 'info'));
          }
        }
      }
    }

    // --- section 6b: marker strings (marker-config; see classify.js's
    // 2026-08-07 module header -- `bulk-content` can no longer be a
    // member of `rec.classes` at all, so this no longer branches on it) --
    if (rec.classes.includes('marker-config') && text && markerRe.test(text)) {
      findings.push(mkFinding('marker-string', 'marker-config', absPath, 'ChainDrop marker string found', 'fail'));
    }
  }
}

// ---------------------------------------------------------------------
// Traversal -- see the module header for why this is the one class in
// `lib/`.
// ---------------------------------------------------------------------
class Traversal {
  constructor(opts = {}) {
    const { roots, classes, spec = null, ...options } = opts;

    // Wave-driver guard -- see the module header's D-23/B1 citation. A
    // physical prune during a walk serving mutually incompatible per-class
    // scopes is a silent-detection-loss defect and must be impossible to
    // introduce by accident, so this throws rather than warns.
    if (spec !== null && spec !== undefined) {
      const skipDirsSize = options.skipDirs instanceof Set ? options.skipDirs.size : Array.isArray(options.skipDirs) ? options.skipDirs.length : 0;
      if (options.maxDepth !== undefined || skipDirsSize > 0 || options.skipDotDirs === true) {
        throw new TypeError(
          'Traversal: maxDepth/skipDirs/skipDotDirs are a per-consumer enumeration shape (D-23, ' +
            'lib/scan.js only) and MUST NEVER be set on a wave-spec-driven Traversal -- a physical ' +
            'prune here would narrow every class sharing this walk, including the no-prune class ' +
            '(D-25), which must reach node_modules/dist/build/.next/target. See the NO-POLICY-PRUNE ' +
            'header in lib/traverse/walk.js.'
        );
      }
    }

    this.roots = Array.isArray(roots) ? roots.slice() : [];
    this.classes = Array.isArray(classes) ? classes.slice() : FILE_CLASSES.slice();
    this.spec = spec;
    this.selfRoot = options.selfRoot || null;
    this.rawOptions = options;
    this._lastResult = null;
  }

  /**
   * The synchronous, read-free enumeration path (D-03/D-20's non-wave
   * consumer API). No file is opened, no hash computed, and NO subprocess
   * is EVER spawned any more, regardless of which classes are requested --
   * `classify()` never consults git (2026-08-07 tiering-trade-off reversal;
   * see `lib/traverse/classify.js`'s module header). `spec` may be omitted
   * entirely when every requested class needs no spec DATA (e.g.
   * `env-secrets`, the class `lib/scan.js` consumes).
   *
   * G-1511 / TRAV-14: the returned object also carries `stopped` --
   * `walkResult.stopped` (`walk.js`'s `stopped: budget.exhausted()`),
   * `true` when the shared budget latched at ANY point during this walk.
   * This path passes NO budget of its own, so `walk()` builds the DEFAULT
   * 60s / `DEFAULTS.maxFiles` budget (`lib/traverse/index.js`'s
   * `normalizeOptions`) -- truncation is reachable on a large tree, not
   * hypothetical. Before G-1511 this field was computed by `walk()` and
   * silently discarded here, so `lib/scan.js`'s `.env` secret scan
   * (`findEnvFilesDetailed`, the sole caller of this enumeration for a
   * real budget-bearing tree) could time out mid-tree and still report
   * clean. The addition is purely ADDITIVE: every existing consumer that
   * destructures `{ byClass, skips, counts }` is unaffected by an extra
   * key on the returned object.
   */
  enumerateSync() {
    const spec = this.spec || EMPTY_SPEC;
    const requestedSet = new Set(this.classes);
    const skips = createSkipInventory();
    const byClass = new Map(this.classes.map((c) => [c, []]));

    const walkResult = walk(this.roots, this.rawOptions, (event) => {
      if (event.isDirectory) return;
      const c = classify(event, spec, { selfRoot: this.selfRoot, skips });
      if (c.skipReason) skips.add(c.skipReason, event.absPath);
      for (const cls of c.classes) {
        if (requestedSet.has(cls)) byClass.get(cls).push(event.absPath);
      }
    });

    mergeSkips(skips, walkResult.skips);

    return { byClass, skips, counts: walkResult.counts, stopped: walkResult.stopped };
  }

  /**
   * The full two-tier pass (D-20). Requires `spec`. See the module header
   * for the phase ordering and the enumeration-vs-read-phase exhaustion
   * rule.
   *
   * G-1502 / TRAV-10 (D-08/D-20): `run()` now also returns `byClass`, a
   * per-`FILE_CLASSES` enumeration built from this SAME single walk --
   * unconditionally, for every classified path, regardless of whether that
   * path needs any read-pool work (the work-flags helper below returning
   * `null` used to mean a bare `lockfiles`-class file such as
   * `package-lock.json` never reached `workMap`; `run()` itself simply had
   * no per-class enumeration output at all before this change).
   * `lib/traverse/run.js` no longer needs a second `Traversal`/
   * `enumerateSync()` pass to populate `lists/<class>.z` for the bash
   * scanner -- one walk, one budget, one snapshot of the filesystem now
   * feeds both findings and lists. This restores D-20's walk-once guarantee
   * at the `run.js` entry-point level (it already held inside this method).
   *
   * BEHAVIOUR CHANGE (Guard 5, decision D-08): because `byClass` is now
   * populated from the SAME budgeted walk as everything else, a class list
   * truncates exactly when the scan truncates. Previously, `run.js`'s
   * second, independently-budgeted `enumerateSync()` walk could enumerate
   * further than a budget-limited `run()` did, so `lists/<class>.z` could
   * list files the findings pass never examined -- and, worse, a poisoned
   * `package-lock.json` needing zero read-pool work could vanish from
   * `lists/lockfiles.z` entirely if the second walk were simply deleted
   * without this collector (the naive-fix regression this plan exists to
   * avoid; see `tests/traverse/run-cli.test.js` break-proof 1). The new,
   * single-budget behaviour is more honest -- one budget now governs
   * everything an operator sees -- but it IS observable: `lists/*.z` may be
   * shorter on an incomplete scan than it would have been under the old
   * two-budget arrangement. See `tests/traverse/results-protocol.test.js`
   * Guard 5 for the load-bearing proof (a budget-latched fixture asserting
   * `run().byClass` is a strict SUBSET of `enumerateSync().byClass`, not
   * merely plumbing agreement on a fixture too small to latch).
   */
  async run() {
    if (!this.spec) {
      throw new Error('Traversal.run: a validated wave spec is required -- construct with { spec }');
    }
    const spec = this.spec;
    const normalized = normalizeOptions(this.rawOptions);
    const budget = this.rawOptions.budget || createBudget(normalized);
    const skips = createSkipInventory();
    const findings = [];
    const workMap = new Map();
    // G-1502: mirrors `enumerateSync()`'s own `byClass`/`requestedSet`
    // construction (lines 518-520 above) exactly -- same data shape, so
    // `lib/traverse/results.js`'s `classListEntries` (which already accepts
    // either a Map or a plain object) needs no change.
    const byClass = new Map(this.classes.map((c) => [c, []]));
    const requestedSet = new Set(this.classes);
    const hashCandidateNames = computeHashCandidateNames(spec);

    const walkOptions = { ...this.rawOptions, budget };
    const walkResult = walk(this.roots, walkOptions, (event) => {
      if (event.isDirectory) return;
      const c = classify(event, spec, { selfRoot: this.selfRoot, skips });
      if (c.skipReason) skips.add(c.skipReason, event.absPath);

      // G-1502 collector -- UNCONDITIONAL and placed BEFORE the
      // `c.classes.length === 0` early return below, so no later ordering
      // change can silently drop it. Deliberately does NOT consult the
      // work-flags helper below, `priority`, or `hashCandidateNames`: a
      // file that classifies but needs zero read-pool work (the reproduction
      // on record: a bare `package-lock.json`, since `lockfiles` is in
      // neither `TARGETED_CONTENT_CLASSES` nor `bulk-content`, and
      // `package-lock.json` is not a hash-candidate name) still MUST appear
      // in its class list. A device/budget/symlink-pruned entry never
      // reaches this callback at all (`walk.js`'s `emitEntry()` returns on
      // `noteFile()` failure BEFORE `ctx.visit`, and the symlink/device-
      // boundary guards run earlier still inside `walkDirectory`'s entry
      // loop) -- so no separate guard against pruned-entries-reaching-the-
      // collector is needed or added here.
      for (const cls of c.classes) {
        if (requestedSet.has(cls)) byClass.get(cls).push(event.absPath);
      }

      if (c.classes.length === 0) return;

      const name = path.basename(event.absPath);

      // Section 1a: exact-filename markers need no read at all -- emitted
      // inline as the walk visits them, so a later budget cut still leaves
      // every marker discovered before the cut in `findings` (D-20's
      // enumeration-exhaustion case).
      if (c.classes.includes('all-files') && spec.fileMarkers.fail.includes(name)) {
        findings.push(mkFinding('file-marker', 'all-files', event.absPath, `ChainDrop file marker '${name}' present`, 'fail'));
      }

      const flags = buildWorkFlags(c.classes, name, spec, hashCandidateNames);
      if (flags) workMap.set(event.absPath, { absPath: event.absPath, classes: c.classes, ...flags });
    });

    mergeSkips(skips, walkResult.skips);

    const resultsByPath = new Map();

    // D-20 tier tracking (G-1506, decision D-06). `budget.snapshot().tiers`
    // (read below, after both phases) is the SINGLE source of tier
    // completeness -- no local boolean is derived from `walkResult.stopped`
    // any more. A tier that is never entered (the `walkResult.stopped`
    // enumeration-exhaustion case) is simply absent from `tiers`, which is
    // the correct "not complete" verdict.
    budget.enterTier('targeted');
    if (!walkResult.stopped) {
      const targetedRecords = [...workMap.values()].filter((r) => r.priority === 'targeted');
      const pool1 = createReadPool({ ...this.rawOptions, budget, skips });
      for (const r of targetedRecords) pool1.submit(r);
      for (const res of await pool1.drain()) resultsByPath.set(res.absPath, res);

      // D-20 phase-boundary recheck (G-1506, decision D-06 / defect B1).
      // Three facts, all load-bearing:
      // (a) `read-pool.js`'s drain() (Task 1 of this plan) now ALSO advances
      //     the clock on an interval cadence (READ_POOL_CLOCK_INTERVAL, 16
      //     completed records), so this call is the phase-BOUNDARY check,
      //     not the only clock advance that happens during the read phase.
      // (b) This call MUST precede the `tierComplete('targeted')` gate
      //     immediately below it. A drain shorter than
      //     READ_POOL_CLOCK_INTERVAL advances the clock ZERO times inside
      //     the drain itself, so without this recheck running first, the
      //     gate would read a STALE `exhausted()` flag and report a tier
      //     that blew the budget as `complete: true` -- this was defect B1,
      //     reintroduced by an earlier version of this very plan, and
      //     reordering this one call is the single most important line in
      //     this plan.
      // (c) `noteDirectory()` is reused rather than a bespoke API because it
      //     is `budget.js`'s only public "recheck the live clock and
      //     possibly latch" entry point; its `dirsWalked` side effect is not
      //     exposed on `TraverseResult`.
      budget.noteDirectory();
      if (!budget.exhausted()) budget.tierComplete('targeted');

      budget.enterTier('bulk');
      if (!budget.exhausted()) {
        const bulkRecords = [...workMap.values()].filter((r) => r.priority === 'bulk');
        const pool2 = createReadPool({ ...this.rawOptions, budget, skips });
        for (const r of bulkRecords) pool2.submit(r);
        for (const res of await pool2.drain()) resultsByPath.set(res.absPath, res);
        budget.noteDirectory(); // symmetric post-phase recheck, same ordering rule as (b) above
        if (!budget.exhausted()) budget.tierComplete('bulk');
      }
    }

    generateContentFindings({ spec, workMap, resultsByPath, hashCandidateNames, findings });

    const severityCounts = { fail: 0, warn: 0, info: 0 };
    for (const f of findings) severityCounts[f.severity] += 1;

    const tiers = budget.snapshot().tiers;
    const targetedComplete = tiers.targeted === true;
    const bulkComplete = tiers.bulk === true;

    // G-1501 / G-1512 (TRAV-15, decisions D-01/D-02). Five explicit points:
    // (a) this restores the project's standing locked rule from
    //     .planning/STATE.md -- "Incomplete scan -> exit 2, never 0".
    // (b) the blanket `unreadable > 0` form -- every unreadable path,
    //     directory OR file -- is what ROADMAP criterion 1's wording
    //     requires; decision D-01 rejected narrowing it to directories-only
    //     or adding a `--lenient` opt-out in this phase.
    // (c) `oversized > 0` joins it per decision D-02 (G-1512): a file too
    //     large to examine is not examined. It is the only one of the five
    //     SKIP_REASONS that is neither intentional scope nor otherwise
    //     propagated -- `budget` already propagates via the tiers above;
    //     `symlink` and `other-device` are DELIBERATELY excluded here (D-06
    //     never-follow-symlinks and the D-12 device anchor are intentional
    //     scope boundaries, not omissions) -- named explicitly so a future
    //     reader does not "complete the set" by folding them in too.
    // (d) the D-24 hash cap and the bulk read cap themselves are UNCHANGED
    //     by this -- this is about reporting, not about raising a cap.
    // (e) operator-facing consequence: a scan root containing a
    //     pre-existing permission-restricted path, or one very large file,
    //     now exits 2. The offending paths are already enumerated in the
    //     retained results dir at skips/unreadable.z and skips/oversized.z
    //     (lib/traverse/results.js:267), with counts at
    //     scalars/skip-unreadable and scalars/skip-oversized.
    const incomplete = !targetedComplete || !bulkComplete || skips.counts().unreadable > 0 || skips.counts().oversized > 0;
    const exitCode = computeExit({ severityCounts, incomplete });
    // Always empty: `degradations` existed exclusively to report git
    // health (D-14), surfaced only through the now-deleted
    // `lib/traverse/git-ignore.js`'s `isBulkEligible`/`indexFor`, which was
    // itself only ever called from the now-deleted `bulk-content`
    // classification branch. Nothing in this engine consults git any more,
    // so there is nothing left to degrade. The field is kept on
    // `TraverseResult` (and in `lib/traverse/results.js`'s written
    // protocol / `scripts/scan-chaindrop-aug2026.sh`'s summary block) for
    // shape stability rather than as a schema change -- see the
    // 2026-08-07 tiering-trade-off-reversal note in
    // `lib/traverse/classify.js`'s module header for the full history.
    const degradations = [];

    const result = {
      findings,
      skips,
      counts: walkResult.counts,
      byClass,
      degradations,
      tiers: { targeted: { complete: targetedComplete }, bulk: { complete: bulkComplete } },
      incomplete,
      exitCode,
    };
    this._lastResult = result;
    return result;
  }

  /** Findings of one class from the most recent `run()` (results-writer accessor). */
  findingsOfClass(className) {
    return this._lastResult ? this._lastResult.findings.filter((f) => f.class === className) : [];
  }

  /** The severity histogram `computeExit` was fed on the most recent `run()`. */
  severityCounts() {
    const counts = { fail: 0, warn: 0, info: 0 };
    if (!this._lastResult) return counts;
    for (const f of this._lastResult.findings) counts[f.severity] += 1;
    return counts;
  }

  /** The combined skip inventory from the most recent `run()`. */
  skipInventory() {
    return this._lastResult ? this._lastResult.skips : createSkipInventory();
  }
}

/** Convenience wrapper: `new Traversal(opts).run()`. */
async function traverse(opts) {
  const t = new Traversal(opts);
  return t.run();
}

module.exports = { Traversal, traverse, DETECTOR_OWNERSHIP };
