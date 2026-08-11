#!/usr/bin/env node
// ============================================================================
// bench-traverse — local, read-only traversal benchmark (G-1482 / plan 17-02)
// ============================================================================
//
// MANUAL, LOCAL-ONLY TOOL. No CI runner has access to the private 373k-file
// monorepo this script exists to measure — it is never wired into `npm test`
// or any CI job. Run it by hand against a real tree when you need numbers.
//
// Exact invocation:
//   node scripts/bench-traverse.js --root <abs path> [--mode baseline|engine]
//     [--baseline <path-to-baseline-json>] [--json]
//
// Examples:
//   node scripts/bench-traverse.js --root ~/Projects --mode baseline
//   node scripts/bench-traverse.js --root ~/Projects --mode baseline --json | tee /tmp/bench.json
//   node scripts/bench-traverse.js --root ~/Projects --mode engine --baseline /tmp/bench.json --json
//
// What it measures (--mode baseline):
//   1. enumerate            — bare recursive fs.readdirSync walk, lstat-free
//   2. enumerate+lstat-dirs — the same walk plus one fs.lstatSync per directory
//   3. git-repos            — one `git ls-files` per discovered repo boundary
//   4. old-scanner          — scripts/scan-chaindrop-aug2026.sh end to end, but that
//                             script was itself retrofitted onto the traversal engine on
//                             2026-08-07 (zero `find` passes), so this phase measures the
//                             CURRENT engine-backed scanner, not a pre-engine one.
//                             A baseline recorded today is therefore NOT a pre-engine
//                             measurement: it records `meta.scannerEngineBacked: true`, and
//                             `--mode engine --baseline <that file>` REFUSES to report a
//                             speedup rather than divide the same program by itself.
//
// What it measures (--mode engine, plan 17-15):
//   1. engineRun            — a single direct `node lib/traverse/run.js` invocation
//                             against the wave spec, timed end to end, with the
//                             counts/skip totals read back from the results dir's
//                             findings.json (the results dir is created and removed
//                             by this script -- nothing is left behind)
//   2. engineScanner        — scripts/scan-chaindrop-aug2026.sh end to end, same as
//                             baseline's old-scanner phase, but the script itself has
//                             been retrofitted onto the traversal engine (zero `find`
//                             passes as of 2026-08-07) -- this number is what
//                             directly compares against a recorded baseline's
//                             oldScanner figure
//   3. comparison           — only present with --baseline <path>: old vs new
//                             scanner wall-clock, the speedup ratio, and whether the
//                             60s budget fired on this run (engineRun.incomplete or
//                             tiers.targeted.complete === false)
//
// Stdout discipline. With --json, stdout carries EXACTLY ONE JSON object and
// nothing else — every human-readable line, every warning, and every byte of
// any child process's output goes to stderr instead. The whole point of
// --json is to be pipeable into `tee`/`jq`; a single stray line on stdout
// (e.g. the old scanner's own multi-page report) would silently break that
// for the caller, so the old scanner's stdio is always piped and forwarded
// to OUR stderr in --json mode, and 'inherit' only in human mode.
//
// Information disclosure discipline. Output reports counts and timings only.
// No file path from the scanned tree is ever printed beyond the root the
// operator supplied on the command line (T-17-02-03) — this applies to error
// messages too: fs/git error text is deliberately NOT included verbatim,
// because it can embed the offending path (e.g. git's "dubious ownership in
// repository at '<path>'" message).
//
// Zero dependencies — Node.js built-ins only (fs, path, os, child_process).
// Read-only: the script never writes into the scanned tree, only to its own
// stdout/stderr.

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const GIT_LS_FILES_ARGS = ['ls-files', '--cached', '--others', '--exclude-standard', '--full-name', '-z'];
const GIT_ENV_OVERRIDES = { GIT_OPTIONAL_LOCKS: '0', GIT_PAGER: '', GIT_TERMINAL_PROMPT: '0' };
// The date scripts/scan-chaindrop-aug2026.sh was retrofitted onto the traversal
// engine (zero `find` passes). SOURCE: this file's own `--mode engine` header
// block above (the `engineScanner` entry, lines 38-43), which has carried the
// retrofit date on line 41 since the retrofit landed — this constant is read
// off that admission, not guessed and not inferred from git history. A baseline
// recorded before this instant measured a genuinely different program; one
// recorded after it did not.
const SCANNER_RETROFIT_ISO = '2026-08-07T00:00:00Z';

const MAX_BUFFER = 256 * 1024 * 1024; // 256 MiB — a large repo's NUL-delimited ls-files output, or a long scanner report, can run to tens of MB; Node's ~1 MiB default would silently truncate and make the measurement wrong.

function msFrom(startNs, endNs) {
  return Number(endNs - startNs) / 1e6;
}

function logErr(msg) {
  process.stderr.write(`bench-traverse: ${msg}\n`);
}

function printUsage() {
  logErr(
    'Usage: node scripts/bench-traverse.js --root <abs path> [--mode baseline|engine] ' +
      '[--baseline <path-to-baseline-json>] [--json]'
  );
}

function parseArgs(argv) {
  const out = { root: undefined, mode: 'baseline', baseline: undefined, json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--root') {
      out.root = argv[++i];
    } else if (arg === '--mode') {
      out.mode = argv[++i];
    } else if (arg === '--baseline') {
      out.baseline = argv[++i];
    } else if (arg === '--json') {
      out.json = true;
    }
  }
  return out;
}

// ----------------------------------------------------------------------------
// Shared recursive walk. Never follows symlinks (T-17-02-01: an entry whose
// Dirent.isSymbolicLink() is true is counted and never recursed into, which
// is what makes a symlink cycle in the scanned tree structurally unable to
// hang this script). Directories named `.git` are treated as repo boundaries
// when findGitRepos is set (both the normal isDirectory() shape and the
// linked-worktree isFile() shape count, per RESEARCH.md B2) and are not
// descended into — VCS internals are not code the engine this bench feeds
// into would walk either.
// ----------------------------------------------------------------------------
function walkTree(root, options) {
  const state = {
    files: 0,
    dirs: 0,
    symlinks: 0,
    unknown: 0,
    maxDepth: 0,
    maxDirEntries: 0,
    readErrorCount: 0,
    lstatErrorCount: 0,
    devices: new Set(),
    gitRepoDirs: [], // absolute paths — in-memory only, NEVER included in output (T-17-02-03)
  };

  visit(root, 0);
  return state;

  function visit(dir, depth) {
    if (depth > state.maxDepth) state.maxDepth = depth;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      state.readErrorCount++;
      return;
    }

    if (entries.length > state.maxDirEntries) state.maxDirEntries = entries.length;

    if (options.findGitRepos) {
      const hasGit = entries.some((e) => e.name === '.git' && (e.isDirectory() || e.isFile()));
      if (hasGit) state.gitRepoDirs.push(dir);
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        state.symlinks++;
        continue; // never follow (T-17-02-01)
      }

      if (entry.isDirectory()) {
        state.dirs++;
        const full = path.join(dir, entry.name);

        if (options.lstatDirs) {
          try {
            const st = fs.lstatSync(full);
            state.devices.add(st.dev);
          } catch {
            state.lstatErrorCount++;
          }
        }

        if (options.findGitRepos && entry.name === '.git') {
          continue; // repo boundary already recorded above; don't descend into VCS internals
        }

        visit(full, depth + 1);
        continue;
      }

      if (entry.isFile()) {
        state.files++;
        continue;
      }

      // Dirent type unknown on this filesystem (DT_UNKNOWN) — the bare
      // baseline walk is lstat-free by design, so an unknown entry is
      // counted, not classified further, and never recursed into.
      state.unknown++;
    }
  }
}

function measureEnumerate(root) {
  const start = process.hrtime.bigint();
  const state = walkTree(root, { lstatDirs: false, findGitRepos: false });
  const end = process.hrtime.bigint();
  return {
    wallClockMs: msFrom(start, end),
    totalEntries: state.files + state.dirs + state.symlinks + state.unknown,
    files: state.files,
    dirs: state.dirs,
    symlinks: state.symlinks,
    unknown: state.unknown,
    maxDepth: state.maxDepth,
    maxDirEntries: state.maxDirEntries,
    readErrorCount: state.readErrorCount,
  };
}

function measureEnumerateLstatDirs(root) {
  const start = process.hrtime.bigint();
  const state = walkTree(root, { lstatDirs: true, findGitRepos: false });
  try {
    const st = fs.lstatSync(root);
    state.devices.add(st.dev);
  } catch {
    state.lstatErrorCount++;
  }
  const end = process.hrtime.bigint();
  return {
    wallClockMs: msFrom(start, end),
    totalEntries: state.files + state.dirs + state.symlinks + state.unknown,
    files: state.files,
    dirs: state.dirs,
    symlinks: state.symlinks,
    unknown: state.unknown,
    maxDepth: state.maxDepth,
    maxDirEntries: state.maxDirEntries,
    distinctDeviceCount: state.devices.size,
    lstatErrorCount: state.lstatErrorCount,
  };
}

// Buckets a failed `git ls-files` invocation into a named reason WITHOUT ever
// including raw stderr text — git's own error messages can embed the
// offending path (e.g. "dubious ownership in repository at '<path>'"), which
// would violate the no-path-disclosure rule (T-17-02-03).
function classifyGitFailure(status, stderrBuf) {
  const text = stderrBuf ? stderrBuf.toString('utf8') : '';
  if (/dubious ownership/i.test(text)) return 'dubious-ownership (safe.directory)';
  if (/not a git repository/i.test(text)) return 'not-a-git-repository';
  if (/must be run in a work tree/i.test(text)) return 'bare-repo';
  return `exit ${status}`;
}

function measureGitRepos(root) {
  const start = process.hrtime.bigint();
  const state = walkTree(root, { lstatDirs: false, findGitRepos: true });

  let gitLsFilesWallClockMs = 0;
  let slowestRepoMs = 0;
  let erroredRepoCount = 0;
  const erroredRepos = [];

  for (const repoDir of state.gitRepoDirs) {
    const repoStart = process.hrtime.bigint();
    const result = spawnSync('git', ['-C', repoDir, ...GIT_LS_FILES_ARGS], {
      maxBuffer: MAX_BUFFER,
      env: { ...process.env, ...GIT_ENV_OVERRIDES },
    });
    const repoEnd = process.hrtime.bigint();
    const repoMs = msFrom(repoStart, repoEnd);
    gitLsFilesWallClockMs += repoMs;
    if (repoMs > slowestRepoMs) slowestRepoMs = repoMs;

    if (result.error) {
      erroredRepoCount++;
      erroredRepos.push({ reason: `spawn-error:${result.error.code || 'UNKNOWN'}` });
    } else if (result.status !== 0) {
      erroredRepoCount++;
      erroredRepos.push({ reason: classifyGitFailure(result.status, result.stderr) });
    }
  }

  const end = process.hrtime.bigint();
  return {
    wallClockMs: msFrom(start, end),
    reposFound: state.gitRepoDirs.length,
    gitLsFilesWallClockMs,
    slowestRepoMs,
    erroredRepoCount,
    erroredRepos,
  };
}

function runOldScanner(root, jsonMode) {
  const scriptPath = path.join(__dirname, 'scan-chaindrop-aug2026.sh');

  if (!fs.existsSync(scriptPath)) {
    logErr(`old scanner not found at ${scriptPath} — skipping old-scanner phase`);
    return { wallClockMs: 0, exitCode: null, skipped: true, skipReason: 'script-not-found' };
  }

  const env = { ...process.env, LSH_ROOTS: root, LSH_NO_NETWORK: '1' };
  const start = process.hrtime.bigint();

  let result;
  if (jsonMode) {
    // --json mode: never inherit — the old scanner's multi-page report must
    // not reach OUR stdout. Pipe it and forward to stderr instead.
    result = spawnSync('bash', [scriptPath], { env, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: MAX_BUFFER });
  } else {
    // Human mode: inheriting stdio is the more useful behaviour — the
    // operator watches the old scanner's report live.
    result = spawnSync('bash', [scriptPath], { env, stdio: 'inherit', maxBuffer: MAX_BUFFER });
  }

  const end = process.hrtime.bigint();
  const wallClockMs = msFrom(start, end);

  if (result.error) {
    if (result.error.code === 'ENOENT') {
      logErr('bash not found on PATH — skipping old-scanner phase');
      return { wallClockMs, exitCode: null, skipped: true, skipReason: 'bash-unavailable' };
    }
    logErr(`old scanner spawn failed (${result.error.code || 'UNKNOWN'}) — skipping old-scanner phase`);
    return { wallClockMs, exitCode: null, skipped: true, skipReason: `spawn-error:${result.error.code || 'UNKNOWN'}` };
  }

  if (jsonMode) {
    if (result.stdout && result.stdout.length) process.stderr.write(result.stdout);
    if (result.stderr && result.stderr.length) process.stderr.write(result.stderr);
  }

  return { wallClockMs, exitCode: result.status, skipped: false, skipReason: null };
}

// ----------------------------------------------------------------------------
// --mode engine (plan 17-15). Measures the actual traversal engine's own
// instrumentation rather than this script's independent walkTree() -- the
// two are deliberately different code paths (baseline mode exists to
// measure the FILESYSTEM, engine mode exists to measure THE PRODUCT).
// ----------------------------------------------------------------------------

/**
 * A single direct `node lib/traverse/run.js` invocation against the real
 * wave spec, timed end to end. Creates its own temp results dir and removes
 * it before returning -- this script leaves nothing behind regardless of
 * outcome. No file path from the scanned tree is ever surfaced here beyond
 * aggregate counts and skip totals (T-17-02-03), matching baseline mode's
 * own information-disclosure discipline.
 */
function runEngineRunPhase(root, jsonMode) {
  const specPath = path.join(__dirname, '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
  const runJsPath = path.join(__dirname, '..', 'lib', 'traverse', 'run.js');
  const resultsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-traverse-engine-run-'));

  try {
    const start = process.hrtime.bigint();
    const result = spawnSync('node', [runJsPath, '--spec', specPath, '--results-dir', resultsDir, '--roots', root], {
      maxBuffer: MAX_BUFFER,
      env: process.env,
      stdio: jsonMode ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    });
    const end = process.hrtime.bigint();
    const wallClockMs = msFrom(start, end);

    if (jsonMode) {
      if (result.stdout && result.stdout.length) process.stderr.write(result.stdout);
      if (result.stderr && result.stderr.length) process.stderr.write(result.stderr);
    }

    if (result.error) {
      return {
        wallClockMs,
        exitCode: null,
        spawnError: result.error.code || 'UNKNOWN',
        findingsRead: false,
      };
    }

    let findings = null;
    let readError = null;
    try {
      findings = JSON.parse(fs.readFileSync(path.join(resultsDir, 'findings.json'), 'utf8'));
    } catch (err) {
      readError = (err && err.code) || 'PARSE_ERROR';
    }

    return {
      wallClockMs,
      exitCode: result.status,
      findingsRead: Boolean(findings),
      readError: findings ? null : readError,
      counts: findings ? findings.counts : null,
      severityCounts: findings ? findings.severityCounts : null,
      skips: findings ? findings.skips : null,
      incomplete: findings ? findings.incomplete : null,
      tiers: findings ? findings.tiers : null,
    };
  } finally {
    // Own the temp dir end to end -- created above, removed here, no matter
    // which return path was taken.
    fs.rmSync(resultsDir, { recursive: true, force: true });
  }
}

/**
 * Loads a previously-recorded baseline JSON (this script's own --mode
 * baseline --json output) and reports the engine-backed scanner's speedup
 * against its `oldScanner.wallClockMs` figure, plus whether the 60s budget
 * fired on THIS run (`engineRun.incomplete`, or an explicit
 * `tiers.targeted.complete === false` -- the enumeration-phase-exhaustion
 * case documented in lib/traverse/engine.js's module header, which sets
 * `incomplete` too, but is named explicitly here for readability of the
 * comparison object). Never throws -- an unreadable/malformed baseline
 * degrades to an `{ error }` field rather than crashing the whole run.
 *
 * A baseline that cannot be shown to predate SCANNER_RETROFIT_ISO degrades the
 * same way, to an `{ error }` naming its post-retrofit provenance (TOOL-02 /
 * G-1546) -- see the provenance gate below for why a ratio against such a file
 * is meaningless. There is exactly ONE return site for that error string.
 */
function buildComparison(baselinePath, engineScanner, engineRun) {
  let baseline;
  try {
    baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
  } catch (err) {
    logErr(`--baseline "${baselinePath}" could not be read/parsed (${(err && err.code) || (err && err.message) || 'UNKNOWN'}) — comparison omitted`);
    return { error: `baseline-unreadable:${(err && err.code) || 'UNKNOWN'}` };
  }

  const oldScannerWallClockMs = baseline && baseline.oldScanner ? baseline.oldScanner.wallClockMs : undefined;
  if (typeof oldScannerWallClockMs !== 'number') {
    logErr(`--baseline "${baselinePath}" is missing oldScanner.wallClockMs — comparison omitted`);
    return { error: 'baseline-missing-oldScanner-wallClockMs' };
  }

  // ---- provenance gate (TOOL-02 / G-1546) ---------------------------------
  // Deliberately placed AFTER the two guards above: an unreadable or
  // shape-invalid baseline must report THAT, not a verdict about provenance.
  //
  // Both `--mode baseline` phase 4 (`oldScanner`) and `--mode engine` phase 2
  // (`engineScanner`) call the SAME runOldScanner(), which spawns the SAME
  // scripts/scan-chaindrop-aug2026.sh. Since the 2026-08-07 retrofit that
  // script IS the traversal engine, so a baseline recorded after that date
  // measures the very program this run measures, and their ratio is a program
  // divided by itself dressed up as a speedup. Refuse rather than fabricate.
  //
  // Precedence, most explicit evidence first:
  //   1. meta.scannerEngineBacked === false -> accept (declared pre-retrofit)
  //   2. meta.scannerEngineBacked === true  -> refuse
  //   3. a parseable meta.timestamp strictly before the retrofit -> accept
  //   4. anything else (absent, unparseable, or on/after) -> refuse, fail closed
  const meta = baseline && baseline.meta;
  let provenance;
  if (meta && meta.scannerEngineBacked === false) {
    provenance = 'declared-pre-retrofit';
  } else if (meta && meta.scannerEngineBacked === true) {
    provenance = null;
  } else {
    const recordedMs = Date.parse((meta && meta.timestamp) || '');
    provenance = Number.isFinite(recordedMs) && recordedMs < Date.parse(SCANNER_RETROFIT_ISO) ? 'pre-retrofit-timestamp' : null;
  }

  if (provenance === null) {
    logErr(
      `--baseline "${baselinePath}" cannot be shown to predate the ${SCANNER_RETROFIT_ISO} retrofit, ` +
        'so its old-scanner phase measures the same engine-backed scanner this run measures — a ratio ' +
        'against it would compare a program with itself; comparison omitted'
    );
    // No speedupRatio / oldScannerWallClockMs / newScannerWallClockMs /
    // budgetFired key at all, so nothing downstream can render half a
    // comparison. printEngineReport's existing `comparison.error` branch
    // already handles this shape — no printer change is needed.
    return { error: 'baseline-post-retrofit' };
  }

  const newScannerWallClockMs = engineScanner.wallClockMs;
  const speedupRatio = newScannerWallClockMs > 0 ? oldScannerWallClockMs / newScannerWallClockMs : null;
  const budgetFired = Boolean(engineRun.incomplete) || Boolean(engineRun.tiers && engineRun.tiers.targeted && engineRun.tiers.targeted.complete === false);

  return { oldScannerWallClockMs, newScannerWallClockMs, speedupRatio, budgetFired, provenance };
}

function runEngine(root, jsonMode, baselinePath) {
  logErr(`engine mode starting for root ${root}`);

  logErr('phase 1/2 — engineRun (direct lib/traverse/run.js invocation)');
  const engineRun = runEngineRunPhase(root, jsonMode);
  logErr(`engineRun done in ${engineRun.wallClockMs.toFixed(1)}ms (exit ${engineRun.exitCode})`);

  logErr('phase 2/2 — engineScanner (scripts/scan-chaindrop-aug2026.sh, engine-backed)');
  const engineScanner = runOldScanner(root, jsonMode);
  logErr(`engineScanner done in ${engineScanner.wallClockMs.toFixed(1)}ms (exit ${engineScanner.exitCode})`);

  const result = {
    meta: {
      root,
      mode: 'engine',
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpus: os.cpus().length,
      timestamp: new Date().toISOString(),
    },
    engineRun,
    engineScanner,
  };

  if (baselinePath) {
    result.comparison = buildComparison(baselinePath, engineScanner, engineRun);
  }

  return result;
}

function printEngineReport(result) {
  const { meta, engineRun, engineScanner, comparison } = result;
  console.log(`\nbench-traverse engine report`);
  console.log(`  root:     ${meta.root}`);
  console.log(`  node:     ${meta.node}  platform: ${meta.platform}/${meta.arch}  cpus: ${meta.cpus}`);
  console.log(`  time:     ${meta.timestamp}`);
  console.log(`\n  engineRun (direct lib/traverse/run.js invocation)`);
  console.log(`    wall clock: ${engineRun.wallClockMs.toFixed(1)}ms`);
  console.log(`    exit code:  ${engineRun.exitCode}`);
  console.log(`    incomplete: ${engineRun.incomplete}`);
  if (engineRun.counts) {
    console.log(`    files walked: ${engineRun.counts.filesWalked}`);
    console.log(`    dirs walked:  ${engineRun.counts.dirsWalked}`);
  }
  if (engineRun.skips) {
    console.log(`    skip totals:  ${JSON.stringify(engineRun.skips)}`);
  }
  console.log(`\n  engineScanner (scripts/scan-chaindrop-aug2026.sh, retrofitted -- engine-backed)`);
  console.log(`    wall clock: ${engineScanner.wallClockMs.toFixed(1)}ms`);
  console.log(`    exit code:  ${engineScanner.exitCode}`);
  console.log(`    skipped:    ${engineScanner.skipped}${engineScanner.skipReason ? ` (${engineScanner.skipReason})` : ''}`);
  if (comparison) {
    console.log(`\n  comparison vs --baseline`);
    if (comparison.error) {
      console.log(`    error: ${comparison.error}`);
    } else {
      console.log(`    old scanner wall clock: ${comparison.oldScannerWallClockMs.toFixed(1)}ms`);
      console.log(`    new scanner wall clock: ${comparison.newScannerWallClockMs.toFixed(1)}ms`);
      console.log(`    speedup ratio:          ${comparison.speedupRatio !== null ? comparison.speedupRatio.toFixed(2) : 'n/a'}x`);
      console.log(`    60s budget fired:       ${comparison.budgetFired}`);
    }
  }
  console.log('');
}

function runBaseline(root, jsonMode) {
  logErr(`baseline mode starting for root ${root}`);

  logErr('phase 1/4 — enumerate');
  const enumerate = measureEnumerate(root);
  logErr(`enumerate done in ${enumerate.wallClockMs.toFixed(1)}ms (${enumerate.totalEntries} entries)`);

  logErr('phase 2/4 — enumerate+lstat-dirs');
  const enumerateLstatDirs = measureEnumerateLstatDirs(root);
  logErr(`enumerate+lstat-dirs done in ${enumerateLstatDirs.wallClockMs.toFixed(1)}ms (${enumerateLstatDirs.distinctDeviceCount} device(s))`);

  logErr('phase 3/4 — git-repos');
  const gitRepos = measureGitRepos(root);
  logErr(`git-repos done in ${gitRepos.wallClockMs.toFixed(1)}ms (${gitRepos.reposFound} repo(s), ${gitRepos.erroredRepoCount} errored)`);

  logErr('phase 4/4 — old-scanner');
  const oldScanner = runOldScanner(root, jsonMode);
  logErr(`old-scanner done in ${oldScanner.wallClockMs.toFixed(1)}ms (exit ${oldScanner.exitCode})`);

  return {
    meta: {
      root,
      mode: 'baseline',
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpus: os.cpus().length,
      timestamp: new Date().toISOString(),
      // TOOL-02 / G-1546. The phase-4 measurement this file labels `oldScanner`
      // is, since the 2026-08-07 retrofit, the CURRENT engine-backed scanner --
      // runBaseline and runEngine call the same runOldScanner(). Recording that
      // fact IN the artifact means a future reader never has to date the file by
      // hand, and a baseline recorded by THIS code refuses itself for the right
      // reason (explicit declaration) rather than sneaking past a date check.
      scannerEngineBacked: true,
    },
    enumerate,
    enumerateLstatDirs,
    gitRepos,
    oldScanner,
  };
}

function printHumanReport(result) {
  const { meta, enumerate, enumerateLstatDirs, gitRepos, oldScanner } = result;
  console.log(`\nbench-traverse baseline report`);
  console.log(`  root:     ${meta.root}`);
  console.log(`  node:     ${meta.node}  platform: ${meta.platform}/${meta.arch}  cpus: ${meta.cpus}`);
  console.log(`  time:     ${meta.timestamp}`);
  console.log(`\n  enumerate (bare readdirSync walk)`);
  console.log(`    wall clock:        ${enumerate.wallClockMs.toFixed(1)}ms`);
  console.log(`    total entries:     ${enumerate.totalEntries}`);
  console.log(`    files/dirs/links:  ${enumerate.files}/${enumerate.dirs}/${enumerate.symlinks}`);
  console.log(`    unknown-type:      ${enumerate.unknown}`);
  console.log(`    max depth:         ${enumerate.maxDepth}`);
  console.log(`    largest dir:       ${enumerate.maxDirEntries} entries`);
  console.log(`    read errors:       ${enumerate.readErrorCount}`);
  console.log(`\n  enumerate+lstat-dirs`);
  console.log(`    wall clock:        ${enumerateLstatDirs.wallClockMs.toFixed(1)}ms`);
  console.log(`    distinct devices:  ${enumerateLstatDirs.distinctDeviceCount}`);
  console.log(`    lstat errors:      ${enumerateLstatDirs.lstatErrorCount}`);
  console.log(`\n  git-repos`);
  console.log(`    wall clock:              ${gitRepos.wallClockMs.toFixed(1)}ms`);
  console.log(`    repos found:              ${gitRepos.reposFound}`);
  console.log(`    total ls-files wall time: ${gitRepos.gitLsFilesWallClockMs.toFixed(1)}ms`);
  console.log(`    slowest single repo:      ${gitRepos.slowestRepoMs.toFixed(1)}ms`);
  console.log(`    errored repos:            ${gitRepos.erroredRepoCount}`);
  console.log(`\n  old-scanner`);
  console.log(`    wall clock: ${oldScanner.wallClockMs.toFixed(1)}ms`);
  console.log(`    exit code:  ${oldScanner.exitCode}`);
  console.log(`    skipped:    ${oldScanner.skipped}${oldScanner.skipReason ? ` (${oldScanner.skipReason})` : ''}`);
  console.log('');
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.root) {
    printUsage();
    process.exit(2);
  }

  // Single documented dispatch point for --mode. Both `baseline` and
  // `engine` are implemented; any other value is refused with exit 2.
  if (args.mode !== 'baseline' && args.mode !== 'engine') {
    logErr(`unknown --mode "${args.mode}". Valid modes: baseline, engine.`);
    process.exit(2);
  }

  let rootStat;
  try {
    rootStat = fs.statSync(args.root);
  } catch (err) {
    logErr(`--root "${args.root}" does not exist or is not readable (${err.code || 'UNKNOWN'})`);
    process.exit(2);
  }
  if (!rootStat.isDirectory()) {
    logErr(`--root "${args.root}" is not a directory`);
    process.exit(2);
  }

  const resolvedRoot = path.resolve(args.root);

  let baselinePath = null;
  if (args.baseline) {
    baselinePath = path.resolve(args.baseline);
  }

  const result = args.mode === 'engine' ? runEngine(resolvedRoot, args.json, baselinePath) : runBaseline(resolvedRoot, args.json);

  if (args.json) {
    process.stdout.write(JSON.stringify(result) + '\n');
  } else if (result.meta.mode === 'engine') {
    printEngineReport(result);
  } else {
    printHumanReport(result);
  }

  process.exit(0);
}

// Direct CLI execution is byte-identical to before this guard existed; what
// changes is that `require()`ing this file no longer runs a benchmark and no
// longer calls process.exit() on the requiring process.
if (require.main === module) {
  main();
}

// `scripts/**` is excluded from the coverage denominator (package.json:42) and
// absent from the test glob (package.json:41), so nothing in this file has ever
// had a path to a unit test. This export exists for exactly one reason: to give
// the one piece of real logic here -- buildComparison and the retrofit boundary
// it gates on -- the unit tests the repo's standing rule requires of every piece
// of code. Nothing in production imports this module.
module.exports = { buildComparison, SCANNER_RETROFIT_ISO };
