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
const { normalizeOptions, FILE_CLASSES } = require('./index.js');
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
  const roots = getRoots({ env: rootsArg ? { ...env, LSH_ROOTS: rootsArg } : env });

  // Surface normalizeOptions' own warnings (invalid env overrides falling
  // back to defaults) before the run -- normalizeOptions never throws.
  const normalized = normalizeOptions({ env });
  for (const warning of normalized.warnings) {
    process.stderr.write(`run.js: warning: ${warning}\n`);
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
  const result = await traversal.run();
  const elapsedMs = Number((process.hrtime.bigint() - startNs) / 1_000_000n);

  progress.finish();

  // A second, read-free pass (D-03's non-wave-consumer API, reused here)
  // over every FILE_CLASSES bucket -- this is what populates
  // `lists/<class>.z` for the bash scanner's remaining checks (e.g. section
  // 3a's poisoned-lockfile matcher needs the full `lockfiles` class list,
  // not just the ones the engine itself flagged). No file is opened and no
  // hash computed by this pass; it walks again rather than threading a
  // second collector through `run()`'s single pass, per D-20's own
  // documented "exactly once" guarantee applying to `run()` itself, not to
  // this entry point's orchestration of it.
  const enumTraversal = new Traversal({ roots, classes: FILE_CLASSES, spec, selfRoot: selfRoot || null, env });
  const enumResult = enumTraversal.enumerateSync();

  writeResults(resultsDir, result, spec, {
    roots,
    elapsedMs,
    byClass: enumResult.byClass,
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
