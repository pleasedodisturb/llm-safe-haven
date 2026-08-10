#!/usr/bin/env node
'use strict';

/**
 * Argv entry point for the traversal engine (G-1482, D-04/D-05/D-09/D-19).
 *
 * Invoked exactly ONCE by the bash scanner (plan 17-14):
 *
 *   node lib/traverse/run.js --spec <path> --results-dir <path> \
 *     [--roots a:b:c] [--self-root <path>]
 *
 * Fail-closed throughout: an unknown flag, an invalid spec, or a bad
 * `--results-dir` all exit 2 -- never 0, never 1 -- and a crash (a thrown
 * exception or an unhandled rejection) also exits 2, never 1, because the
 * consumer treats exit 1 as "findings were written to the results dir";
 * a crash writes nothing there.
 *
 * Prints NOTHING to stdout -- stdout belongs to the bash scanner's report.
 * All diagnostics (usage, warnings, errors) go to stderr.
 */

const fs = require('fs');

const { loadWaveSpec } = require('./wave-spec.js');
const { getRoots } = require('../roots.js');
const { normalizeOptions, computeExit } = require('./index.js');
const { Traversal } = require('./engine.js');
const { writeResults } = require('./results.js');
const { createProgress } = require('./progress.js');

const KNOWN_FLAGS = new Set(['--spec', '--results-dir', '--roots', '--self-root']);

const USAGE = 'Usage: node lib/traverse/run.js --spec <path> --results-dir <path> [--roots a:b:c] [--self-root <path>]\n';

/**
 * Strict argv parser. Never throws. Returns `{ error }` on the first
 * unrecognized flag or missing value, otherwise `{ result }` -- mirroring
 * lib/cli.js's refusal to run on an unknown option rather than ignoring it.
 */
function parseArgv(argv) {
  const result = { spec: null, resultsDir: null, roots: null, selfRoot: null };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!KNOWN_FLAGS.has(flag)) {
      return { error: `unknown flag: ${flag}` };
    }
    const value = argv[i + 1];
    if (value === undefined) {
      return { error: `flag ${flag} requires a value` };
    }
    i += 1;
    if (flag === '--spec') result.spec = value;
    else if (flag === '--results-dir') result.resultsDir = value;
    else if (flag === '--roots') result.roots = value;
    else if (flag === '--self-root') result.selfRoot = value;
  }
  return { result };
}

/** T-17-09 -- lstat (never stat), so a symlinked --results-dir is refused, not followed. */
function checkResultsDir(resultsDir) {
  let st;
  try {
    st = fs.lstatSync(resultsDir);
  } catch {
    return `--results-dir does not exist: ${resultsDir}`;
  }
  if (st.isSymbolicLink()) return `--results-dir must not be a symlink: ${resultsDir}`;
  if (!st.isDirectory()) return `--results-dir is not a directory: ${resultsDir}`;
  return null;
}

async function main() {
  const argv = process.argv.slice(2);
  const parsed = parseArgv(argv);
  if (parsed.error) {
    process.stderr.write(`run.js: ${parsed.error}\n${USAGE}`);
    process.exitCode = 2;
    return;
  }

  const { spec: specPath, resultsDir, roots: rootsArg, selfRoot } = parsed.result;
  if (!specPath || !resultsDir) {
    process.stderr.write(`run.js: --spec and --results-dir are both required\n${USAGE}`);
    process.exitCode = 2;
    return;
  }

  // D-05 fail-closed gate -- never continue with a fallback/default IOC set.
  const loaded = loadWaveSpec(specPath);
  if (!loaded.valid) {
    process.stderr.write(`run.js: invalid wave spec: ${loaded.reason}\n`);
    process.exitCode = 2;
    return;
  }
  const spec = loaded.spec;

  const resultsDirError = checkResultsDir(resultsDir);
  if (resultsDirError) {
    process.stderr.write(`run.js: ${resultsDirError}\n`);
    process.exitCode = 2;
    return;
  }

  const env = process.env;
  // G-1504 / D-03 (17.1-CONTEXT.md) -- collect every explicitly-configured
  // root getRoots() had to drop (missing, or not a directory). Populated
  // whether the roots came from --roots or from LSH_ROOTS in the
  // environment -- both paths fold into the SAME getRoots() call below, so
  // one missing-root callback wiring covers both (see the module header:
  // "--roots" is folded into the env before getRoots ever sees it).
  const missingRoots = [];
  const roots = getRoots({
    env: rootsArg ? { ...env, LSH_ROOTS: rootsArg } : env,
    onMissingRoot: (candidate) => missingRoots.push(candidate),
  });

  // Surface normalizeOptions' own warnings (invalid env overrides falling
  // back to defaults) before the run -- normalizeOptions never throws.
  const normalized = normalizeOptions({ env });
  for (const warning of normalized.warnings) {
    process.stderr.write(`run.js: warning: ${warning}\n`);
  }
  // getRoots() reports missingRoots once per OCCURRENCE (lib/roots.js's own
  // documented contract -- a missing candidate reaches the drop path on
  // every occurrence, not just the first), so dedupe here to print one
  // stderr line per unique path. These are operator-supplied paths echoed
  // back to the operator's own terminal, not scanned-tree content (contrast
  // scripts/bench-traverse.js's bucketed git error reasons, which exist
  // because git embeds SCANNED paths in its own error text) -- so the raw
  // path is printed verbatim, no sanitisation.
  for (const missingRoot of new Set(missingRoots)) {
    process.stderr.write(`run.js: warning: configured scan root does not exist or is not a directory: ${missingRoot}\n`);
  }

  const progress = createProgress({ stderr: process.stderr, progressIntervalMs: normalized.progressIntervalMs });
  const budgetMs = normalized.budgetSeconds * 1000;
  const startedAt = Date.now();
  let dirsSeen = 0;
  // onReaddir only reports directory paths, not per-file counts -- used
  // here as a progress-line proxy only; findings.json/scalars carry the
  // exact walked counts once the run finishes.
  const onReaddir = () => {
    dirsSeen += 1;
    const elapsedMs = Date.now() - startedAt;
    progress.update({
      filesWalked: dirsSeen,
      candidatesRead: 0,
      elapsedMs,
      remainingMs: Math.max(budgetMs - elapsedMs, 0),
    });
  };

  const startNs = process.hrtime.bigint();
  const traversal = new Traversal({ roots, spec, selfRoot: selfRoot || null, env, onReaddir });
  const engineResult = await traversal.run();
  const elapsedMs = Number((process.hrtime.bigint() - startNs) / 1_000_000n);

  progress.finish();

  // G-1504 / decision D-03 (17.1-CONTEXT.md) -- THIS SUPERSEDES the earlier
  // D-17.1-C ("stderr only; the exit code is deliberately unchanged"),
  // overruled by the operator after cross-AI review reached the opposite
  // conclusion independently: with every configured root missing, the
  // scanner examines NOTHING and, without this block, would exit 0 --
  // directly contradicting the phase goal that ALL CLEAR + exit 0 means the
  // whole requested tree was examined. A requested root that was never
  // examined makes the run incomplete, exactly like an unreadable path or
  // an oversized file already do (G-1501/G-1512, plan 17.1-01) -- this
  // applies to ANY missing configured root, not only the all-missing case.
  // The DEFAULT root probe never reaches this point at all (D-17.1-B stops
  // it upstream in getRoots()), so an ordinary machine missing four of the
  // six default names still exits 0 here. `computeExit` (not a hardcoded
  // 2) is reused so D-18 precedence stays in ONE place: a real FAIL finding
  // still beats incompleteness and still exits 1, never 2. NO
  // results-directory schema change is made -- the existing `incomplete`
  // and `exitCode` scalars carry the new verdict, so lib/traverse/
  // results.js and the bash scanner's protocol both stay frozen (the object
  // below is a spread COPY with two fields overridden, never a mutation of
  // the engine's own result).
  const missingRootIncomplete = missingRoots.length > 0;
  const result = missingRootIncomplete
    ? {
      ...engineResult,
      incomplete: true,
      exitCode: computeExit({ severityCounts: traversal.severityCounts(), incomplete: true }),
    }
    : engineResult;

  // G-1502 / TRAV-10 (D-20, D-08): `lists/<class>.z` is now sourced
  // straight from `result.byClass` -- the SAME single walk `traversal.run()`
  // already performed above, not a second, independently-budgeted
  // `Traversal` read-free pass. This REVERSES the Phase 17 decision
  // (recorded in .planning/STATE.md) that justified populating the results
  // dir's class lists via a second, read-free enumeration pass rather
  // than modifying engine.js's `TraverseResult` -- do not "restore" that
  // second walk. Two independently-budgeted walks meant a file could exist
  // for the findings pass and not for the list pass: the reproduction on
  // record is a poisoned `keyv@6.0.0` vanishing from `lists/lockfiles.z`,
  // 6/6 attempts, because the two walks observed two different filesystem
  // snapshots under two different budgets. One walk, one budget, one
  // snapshot now feeds both findings AND lists (D-20's walk-once guarantee,
  // restored at this entry-point level). Consequence, intended and
  // documented: class lists now truncate WITH the scan -- when
  // `result.incomplete` is true because the single budget latched,
  // `byClass` truncates at exactly the same point the findings pass did,
  // which is more honest than the old two-budget arrangement (where the
  // second, unbudgeted walk could list files the findings pass never saw).
  writeResults(resultsDir, result, spec, {
    roots,
    elapsedMs,
    byClass: result.byClass,
  });

  process.exitCode = result.exitCode;
}

main().catch((err) => {
  process.stderr.write(`run.js: unexpected error: ${(err && err.stack) || err}\n`);
  process.exitCode = 2;
});

// Never 0, never 1 on a crash -- a crash writes nothing to the results dir,
// which the consumer must never confuse with exit 1's "findings written".
process.on('unhandledRejection', (err) => {
  process.stderr.write(`run.js: unhandled rejection: ${(err && err.stack) || err}\n`);
  process.exitCode = 2;
});
