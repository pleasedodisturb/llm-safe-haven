'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const { Traversal, ANOMALY_SKIP_REASONS } = require('./traverse/engine.js');
// EXIT-01 / D-04 (G-1545): computeExit is the ONE place D-18 exit
// precedence lives -- scan() must never re-derive it locally. No require
// cycle: lib/traverse/index.js requires nothing from lib/ (only lazy
// require('fs') internally), and lib/scan.js already depends on
// ./traverse/engine.js, which itself depends on index.js.
const { computeExit, EXIT } = require('./traverse/index.js');

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', '__pycache__', '.venv', 'venv']);

/**
 * D-23/D-03: `.env` discovery is now a thin wrapper over the shared
 * traversal engine's `env-secrets` class instead of a hand-rolled
 * recursive fs.readdirSync walk. `maxDepth`/`skipDirs`/`skipDotDirs` are
 * the per-consumer enumeration SHAPE the engine reserves exactly for this
 * caller (lib/traverse/index.js's normalizeOptions IMPORTANT note) --
 * `maxDepth || 4` reproduces the OLD walk's exact falsy-zero-coerces-to-4
 * quirk byte-for-byte, since `maxDepth` was never validated as a positive
 * integer before this change either.
 *
 * `classes: ['env-secrets']` alone means no `spec` is needed (env-secrets
 * membership needs no spec DATA -- see EMPTY_SPEC in engine.js) and
 * `bulk-content` is never requested, so `enumerateSync()` never
 * constructs a real ignore resolver and spawns zero subprocesses -- `.env`
 * files are deliberately gitignored, and the whole point of this class
 * being TARGETED tier is that gitignore is never consulted for it.
 *
 * Returns `{ files, skips, incomplete }` -- `files` is the SAME plain path
 * array `findEnvFiles()` always returned (see below); `skips` is the
 * engine's counted-skip inventory (symlinks, permission-denied
 * directories, etc.) that the old hand-rolled walk silently swallowed.
 *
 * `incomplete` (G-1511 / TRAV-14) is the engine's `stopped` flag: this
 * enumeration passes NO budget of its own, so `walk()` builds the DEFAULT
 * 60s / 1,000,000-entry budget, and a large enough tree really can
 * truncate the walk before every path is examined. Before this change the
 * flag was computed by the engine and discarded here, so a truncated
 * `.env` secret scan reported clean (see `scan()` below for the exit-code
 * consequence).
 */
function findEnvFilesDetailed(startDir, maxDepth) {
  const result = new Traversal({
    roots: [startDir],
    classes: ['env-secrets'],
    maxDepth: maxDepth || 4,
    skipDirs: SKIP_DIRS,
    skipDotDirs: true,
  }).enumerateSync();

  const skipCounts = result.skips.counts();

  // anomalyCount/anomalyReasons (review C-4, G-1545 D-07a): named for what
  // they count -- deliberately NOT a name that implies only 'unreadable'
  // entries were counted. Summed over EVERY
  // ANOMALY_SKIP_REASONS member ({unreadable, budget, swapped} -- `swapped`
  // landed in this same phase, plan 18-05), not just 'unreadable' -- a budget-truncated or
  // swap-affected enumeration is just as much "could not verify" as an
  // unreadable path is, and naming the counter after one member would
  // misreport the other two. `countAnomalySkips()` (engine.js) deliberately
  // EXCLUDES 'budget' because `run()`'s tier completeness already carries
  // that signal separately; `enumerateSync()` (this call) has NO tiers --
  // `stopped` carries budget instead -- so summing every
  // ANOMALY_SKIP_REASONS member here is a correct SUPERSET whose only extra
  // term is one `stopped` already flags. `swapped` (plan 18-05, now landed)
  // is picked up automatically by the same generic loop -- though a read
  // pool is never constructed on this enumerateSync() path, so it can never
  // actually fire here.
  const anomalyReasons = {};
  let anomalyCount = 0;
  for (const reason of ANOMALY_SKIP_REASONS) {
    // Defensive coercion: counts() zero-fills from SKIP_REASONS only, so an
    // ANOMALY_SKIP_REASONS member absent from SKIP_REASONS would read as
    // undefined here -- Number(undefined) is NaN, and `NaN > 0` is false,
    // which would silently make `scan` report clean again through the very
    // fix meant to stop that. Unreachable today (SKIP_REASONS partition is
    // pinned by tests/traverse/engine.test.js), but the hardening is one
    // token and removes a whole class of future regression.
    const raw = Number(skipCounts[reason]);
    const n = Number.isFinite(raw) ? raw : 0;
    anomalyReasons[reason] = n;
    anomalyCount += n;
  }

  return {
    files: result.byClass.get('env-secrets') || [],
    skips: result.skips,
    incomplete: result.stopped === true || anomalyCount > 0,
    anomalyCount,
    anomalyReasons,
  };
}

function findEnvFiles(startDir, maxDepth) {
  return findEnvFilesDetailed(startDir, maxDepth).files;
}

/**
 * D-08's `getRoots` point-of-use call (see the doc comment this replaces
 * on the old `scanForEnvFiles`, now moved here): required and called HERE
 * rather than cached in a module-level const, so a caller that re-requires
 * this module against a stubbed `os.homedir()` always sees roots computed
 * against the CURRENT homedir. `homedir: os.homedir` is passed explicitly,
 * using THIS module's own `os` binding (fresh on every re-require),
 * because `lib/roots.js` captures its own `os` reference at ITS OWN
 * module top level -- a stub installed after roots.js was first required
 * elsewhere in the process would otherwise never reach it.
 *
 * G-1511 / TRAV-14: the additive detailed accessor. Same
 * `getRoots({ homedir: os.homedir })` call, same per-root loop, same
 * dedup-and-sort as `scanForEnvFiles()` always did -- but calls
 * `findEnvFilesDetailed(dir)` per root and ORs each root's `incomplete`
 * flag, so `incomplete` is true when ANY root's enumeration truncated.
 * `scanForEnvFiles()` below is reduced to a thin wrapper over this
 * function's `.files`, so there is exactly one implementation and the two
 * can never drift apart.
 *
 * G-1504 / D-03 (17.1-CONTEXT.md): a configured-but-missing root (LSH_ROOTS)
 * must also make this run incomplete -- `lib/traverse/run.js` already wires
 * `getRoots()`'s `onMissingRoot` seam this way (see its own module header);
 * this was the one caller left silently dropping the miss (found by
 * cross-model review, G-1504). Same seam, same OR-into-incomplete shape,
 * same once-per-unique-path stderr dedup as run.js's own wiring -- so a
 * missing root behaves identically whether it was reached via `scan` or
 * `run.js`. The DEFAULT root probe (no LSH_ROOTS set) never fires
 * `onMissingRoot` at all (D-17.1-B, enforced inside getRoots() itself), so
 * an ordinary machine missing some of the six default names is unaffected.
 */
function scanForEnvFilesDetailed() {
  const { getRoots } = require('./roots.js');
  const allFiles = [];
  let incomplete = false;
  const missingRoots = [];
  const unreadableRoots = [];
  let anomalyCount = 0;
  const anomalyReasons = {};
  for (const reason of ANOMALY_SKIP_REASONS) anomalyReasons[reason] = 0;

  const roots = getRoots({
    homedir: os.homedir,
    onMissingRoot: (candidate) => missingRoots.push(candidate),
    // EXIT-02 / D-07b (G-1542): a configured root that EXISTS but could
    // not be READ (EACCES on a parent lacking +x, EIO, a dead network
    // mount, ...) is a different operator action than one that is absent
    // -- getRoots()'s errno partition routes it here instead of
    // onMissingRoot, on BOTH the explicit and the DEFAULT probe.
    onUnreadableRoot: (candidate, code) => unreadableRoots.push({ candidate, code }),
  });

  for (const dir of roots) {
    const found = findEnvFilesDetailed(dir);
    allFiles.push(...found.files);
    if (found.incomplete) incomplete = true;
    anomalyCount += found.anomalyCount;
    for (const reason of ANOMALY_SKIP_REASONS) {
      anomalyReasons[reason] += found.anomalyReasons[reason] || 0;
    }
  }

  if (missingRoots.length > 0) {
    incomplete = true;
    for (const missingRoot of new Set(missingRoots)) {
      console.error(`llm-safe-haven: warning: configured scan root does not exist or is not a directory: ${missingRoot}`);
    }
  }

  if (unreadableRoots.length > 0) {
    incomplete = true;
    // Deduped by candidate path, exactly like the missingRoots block above
    // -- but the wording MUST differ: "does not exist" is factually wrong
    // for a root that exists but could not be read, and a silent wrong
    // message is the failure mode this whole phase exists to eliminate.
    const seenCandidates = new Set();
    for (const { candidate, code } of unreadableRoots) {
      if (seenCandidates.has(candidate)) continue;
      seenCandidates.add(candidate);
      console.error(`llm-safe-haven: warning: configured scan root could not be read (${code}) — it may or may not exist: ${candidate}`);
    }
  }

  // rootFailures: { missing, unreadable } -- both count every OCCURRENCE
  // the underlying getRoots() callbacks fired (mirroring onMissingRoot's
  // own once-per-occurrence contract), not the deduped stderr-line count.
  return {
    files: [...new Set(allFiles)].sort(),
    incomplete,
    anomalyCount,
    anomalyReasons,
    rootFailures: { missing: missingRoots.length, unreadable: unreadableRoots.length },
  };
}

// WARNING (D-11): this thin wrapper DISCARDS `incomplete`/`anomalyCount`/
// `rootFailures` -- it must NEVER be used by any command that reports a
// verdict (a "clean"/"not clean" claim to the operator). scan(), audit()
// and install() all use scanForEnvFilesDetailed() + printEnvScanResult()
// instead. Kept exported/public because it predates this plan and may have
// other consumers.
function scanForEnvFiles() {
  return scanForEnvFilesDetailed().files;
}

// ---------------------------------------------------------------------
// Cause taxonomy (review C-4) -- shared by the stdout could-not-verify
// line, the stderr diagnostic, and scan()'s next-steps override, so
// budget exhaustion, traversal unreadability, a swapped path, and a
// root-resolution failure can never render as the same sentence.
// ---------------------------------------------------------------------

/**
 * Builds the ORDERED list of cause clauses that actually fired for
 * `detail` (a scanForEnvFilesDetailed()-shaped object). Order is fixed:
 * budget, unreadable, swapped, root -- callers that need "the" cause (the
 * next-steps remedy) take clauses[0].
 *
 * Budget detection reads `anomalyReasons.budget` only (no separate
 * `stopped` field is threaded through the five-field return contract):
 * every call site in lib/traverse/walk.js that latches the shared budget
 * (via budget.js's noteDirectory()/noteFile() returning false) records a
 * 'budget' skip in the SAME call before returning -- so on this
 * single-root-per-call enumerateSync() path, `stopped === true` and
 * `anomalyReasons.budget > 0` are always true together. Verified by
 * reading lib/traverse/walk.js:174/202/238/274 and budget.js's latch().
 */
function buildCauseClauses(detail) {
  const reasons = detail.anomalyReasons || {};
  const rootFailures = detail.rootFailures || { missing: 0, unreadable: 0 };
  const rootFailureCount = (rootFailures.missing || 0) + (rootFailures.unreadable || 0);

  const clauses = [];
  if (reasons.budget > 0) {
    clauses.push({
      id: 'budget',
      text: 'the scan stopped early before every path was examined, because a limit was reached',
    });
  }
  if (reasons.unreadable > 0) {
    clauses.push({ id: 'unreadable', text: `${reasons.unreadable} path(s) could not be read` });
  }
  if (reasons.swapped > 0) {
    // Unreachable on this path today -- the env-secrets enumeration never
    // constructs a read pool, so a TOCTOU swap (plan 18-05) can never fire
    // here. Kept so a future swap-affected cause is never silently
    // rendered as one of the other three; do not delete as dead code.
    clauses.push({ id: 'swapped', text: `${reasons.swapped} path(s) changed underneath the scan` });
  }
  if (rootFailureCount > 0) {
    clauses.push({ id: 'root', text: `${rootFailureCount} configured scan root(s) could not be resolved` });
  }

  // G-1617 (CodeRabbit PR #97 + Kimi-K3 cross-AI review, 2026-08-13).
  //
  // Every clause above is hand-written, but `incomplete` is derived
  // GENERICALLY by iterating the frozen ANOMALY_SKIP_REASONS set (see
  // scanForEnvFilesDetailed's anomaly loop). Those are two sources of truth
  // kept in sync by convention. A SEVENTH anomaly reason would set
  // `incomplete` without producing a clause, and the caller's
  // `clauses[0].id` would throw -- in the operator-facing next-steps block
  // of a security scanner, on a scan that already could not finish.
  //
  // Not reachable on today's six-reason vocabulary (verified: the `stopped`
  // latch also records a `budget` skip, so this list is never empty). The
  // partition test in tests/traverse/engine.test.js forces a new reason to
  // be CLASSIFIED; nothing forced it to be EXPLAINED. This is the
  // mechanism for the second half -- paired with the drift test in
  // tests/scan.test.js that fails if any ANOMALY_SKIP_REASONS member has no
  // clause, so the fallback below stays unreachable rather than becoming a
  // silent catch-all that hides the omission.
  if (clauses.length === 0) {
    clauses.push({
      id: 'unknown',
      text: 'the scan could not confirm it examined every path, for a reason it could not name',
    });
  }
  return clauses;
}

/** The per-cause remedy sentence (review C-1) -- `command` names the
 * INVOKING command ('scan' | 'audit' | 'install'), never hardcoded to
 * 'scan', so audit's and install's own next-steps blocks (Task 4) point
 * at themselves. */
function remedyForCause(clauseId, command, C) {
  const cmdText = `${C.cyan}npx llm-safe-haven ${command}${C.reset}`;
  switch (clauseId) {
    case 'budget':
      return `Narrow the scan roots or raise the enumeration limit, then re-run ${cmdText}`;
    case 'unreadable':
      return `Restore read access to the paths the scan could not read, then re-run ${cmdText}`;
    case 'swapped':
      return `Re-run ${cmdText} on a tree with no concurrent writers`;
    case 'root':
      return `Fix or remove the configured scan root, then re-run ${cmdText}`;
    default:
      return `Re-run ${cmdText} once the underlying issue is resolved`;
  }
}

/**
 * THE SHARED RENDERER (D-11) -- the one place that decides whether to
 * print a green "No .env files found" check. Written ONCE here and
 * consumed by scan() (Task 1/2), audit() and install() (Task 4), so the
 * three commands can never drift apart on this decision.
 *
 * `detail` is scanForEnvFilesDetailed()'s return value. `opts.command`
 * ('scan' | 'audit' | 'install') is used only by scan()'s own next-steps
 * override, never by this function directly.
 *
 * Exactly three branches:
 *   - detail.incomplete === false                          -> printEnvScan(detail.files). Byte-identical to before this plan.
 *   - detail.incomplete === true && detail.files.length > 0 -> printEnvScan(detail.files), THEN the could-not-verify line (findings AND incompleteness are both true; report both).
 *   - detail.incomplete === true && detail.files.length===0 -> do NOT call printEnvScan (the green check would be a false all-clear). Render the "Project scan:" heading (same text/indentation printEnvScan uses) followed by the could-not-verify line.
 *
 * Prints the COUNT, never the paths: scanned-tree paths are
 * attacker-influenceable and lib/scorecard.js's sanitizeForTerminal is not
 * applied on this render path -- adding a new hostile-content render site
 * to fix a reporting defect would be a net loss (CWE-150). The full
 * per-path list remains available through the engine's skip inventory.
 */
function printEnvScanResult(detail, opts = {}) {
  const { printEnvScan, C } = require('./scorecard.js');

  if (!detail.incomplete) {
    printEnvScan(detail.files);
    return;
  }

  if (detail.files.length > 0) {
    printEnvScan(detail.files);
  } else {
    console.log('');
    console.log(`  ${C.bold}Project scan:${C.reset}`);
  }

  const clauseText = buildCauseClauses(detail).map((c) => c.text).join('; ');
  console.log(`    ${C.yellow}◆${C.reset} ${C.yellow}could not verify: ${clauseText} — this is not a clean result${C.reset}`);
}

// Bundled IOC scanners (shipped in the package via package.json "files").
// The newest one covers the most vectors; it is the default for --supply-chain.
// scan-chaindrop-aug2026.sh is a superset of the June Miasma scanner's general
// agent-persistence/workflow/tasks vectors plus the Aug 2026 ChainDrop IOCs.
const SUPPLY_CHAIN_SCANNER = 'scan-chaindrop-aug2026.sh';

/**
 * Runs the bundled supply-chain IOC scanner (a POSIX shell script) and streams
 * its output. Network-free: sets LSH_NO_NETWORK so the scanner skips its only
 * optional network call (the `gh repo list` dead-drop audit).
 *
 * opts (for testing): { platform, spawnSync, scriptsDir }.
 * Returns { ran, code, script?, reason? } — never throws.
 * Exit-code convention: 0 = clean, 1 = findings, 2 = error/could-not-complete.
 * A could-not-run or interrupted scan is NEVER reported as 0 ("clean") — a
 * security gate must distinguish "no IOCs found" from "the scan did not finish".
 */
function runSupplyChainScan(flags, opts = {}) {
  const { printHeader, C } = require('./scorecard.js');
  const platform = opts.platform || process.platform;
  const spawnSync = opts.spawnSync || require('child_process').spawnSync;
  const scriptsDir = opts.scriptsDir || path.join(__dirname, '..', 'scripts');
  const script = path.join(scriptsDir, SUPPLY_CHAIN_SCANNER);

  printHeader();
  console.log(`  ${C.bold}Supply-chain IOC scan (ChainDrop / Mini Shai-Hulud)...${C.reset}`);
  console.log('');

  if (platform === 'win32') {
    console.log(`  ${C.yellow}◆${C.reset} The supply-chain scanner is a POSIX shell script (macOS/Linux).`);
    console.log(`     On Windows, run it under WSL or Git Bash:`);
    console.log(`       bash "${script}"`);
    return { ran: false, reason: 'win32', code: 2 };
  }

  if (!fs.existsSync(script)) {
    console.log(`  ${C.yellow}◆${C.reset} Scanner not found at ${script}`);
    return { ran: false, reason: 'missing', code: 2 };
  }

  // Honor the no-network posture: skip the scanner's optional gh dead-drop audit.
  const env = Object.assign({}, process.env, { LSH_NO_NETWORK: '1' });
  const result = spawnSync('bash', [script], { stdio: 'inherit', env });

  if (result.error) {
    console.log(`  ${C.yellow}◆${C.reset} Could not run the scanner (is bash installed?): ${result.error.message}`);
    return { ran: false, reason: 'spawn-error', code: 2 };
  }
  // result.status is null when the child was killed by a signal (e.g. SIGKILL
  // from the OOM killer, or SIGINT). Treat that as code 2 (incomplete) — never
  // 0, or an interrupted scan would falsely read as "clean".
  if (result.status === null) {
    console.log(`  ${C.yellow}◆${C.reset} Scan did not complete (killed by ${result.signal || 'a signal'}) — treating as incomplete, not clean.`);
    return { ran: false, reason: 'killed', code: 2 };
  }
  return { ran: true, code: result.status, script };
}

function scan(flags, opts) {
  if (flags && flags.mcp) {
    return require('./scan-mcp.js').scanMcp(flags, opts);
  }

  if (flags && flags.supplyChain) {
    return runSupplyChainScan(flags, opts);
  }

  const { printHeader, printNextSteps, C } = require('./scorecard.js');

  printHeader();
  console.log(`  ${C.bold}Scanning for exposed secrets...${C.reset}`);
  console.log('');

  const detail = scanForEnvFilesDetailed();
  const { files: envFiles, incomplete } = detail;
  printEnvScanResult(detail, { command: 'scan' });

  // Check for common dangerous files in home dir
  const dangerousFiles = [
    '.aws/credentials',
    '.config/gcloud/application_default_credentials.json',
    '.kube/config',
    '.npmrc',
  ].map(f => path.join(os.homedir(), f)).filter(f => fs.existsSync(f));

  if (dangerousFiles.length > 0) {
    console.log('');
    console.log(`  ${C.bold}Credential files accessible to agents:${C.reset}`);
    for (const f of dangerousFiles) {
      console.log(`    ${C.yellow}\u25c6${C.reset} ${C.dim}${f}${C.reset}`);
    }
  }

  // THE NEXT-STEPS FIX (review C-1). printNextSteps(1)'s "remove .env
  // files" instruction is correct only when files were actually observed.
  // On an INCOMPLETE scan that found NONE, that sentence tells the
  // operator to remediate something never observed, on the strength of a
  // scan that could not see -- so this state gets its own remedy block,
  // built from the SAME ordered cause list buildCauseClauses() and
  // printEnvScanResult() both use, rather than calling printNextSteps at
  // all. In every OTHER state (complete, or incomplete-with-findings) the
  // clean/findings next-steps text is BYTE-IDENTICAL to before this plan.
  if (incomplete && envFiles.length === 0) {
    const clauses = buildCauseClauses(detail);
    console.log('');
    console.log(`  ${C.bold}Next steps:${C.reset}`);
    console.log(`    ${remedyForCause(clauses[0].id, 'scan', C)}`);
    console.log(`    Docs: ${C.dim}https://github.com/pleasedodisturb/llm-safe-haven${C.reset}`);
    console.log('');
  } else {
    printNextSteps(envFiles.length === 0 ? 2 : 1);
  }

  // G-1511 / TRAV-14, extended by G-1545/D-07a and EXIT-01/D-04: the
  // exit-code contract (0 = clean, 1 = findings, 2 = error-or-incomplete)
  // requires this path to never exit 0 when the scan did not finish, AND
  // (new, EXIT-01) to exit 1 -- not implicit 0 -- when a `.env` is found.
  // `settleCommand` (lib/cli.js) already propagates a numeric
  // `result.code` SYNCHRONOUSLY for a plain-object return -- read
  // directly, this needs no lib/cli.js change, and the env path stays
  // fully synchronous (no `await` was introduced above).
  //
  // D-07a (2026-08-12, this plan): unreadable directories encountered
  // during this enumeration fold into `incomplete` via
  // scanForEnvFilesDetailed()'s anomalyCount (findEnvFilesDetailed, Part
  // A). This REVERSES the prior deferral recorded here (`git log` this
  // line's history): a `.env` behind a mode-000 directory used to print a
  // GREEN CHECK and exit 0 -- reproduced three times on b25b8b5. The "far
  // wider blast radius" concern that justified the deferral was MEASURED,
  // not assumed: `unreadable: 0` across the real default root set on the
  // reference machine, because this enumeration's own maxDepth:4 +
  // SKIP_DIRS + skipDotDirs walk is narrow by construction.
  //
  // EXIT-01/D-04 (this plan): `lib/scan.js` never imported `computeExit`
  // before this plan -- it hand-rolled its exit logic, and that was the
  // root cause, not a symptom. This phase IS the separate product
  // decision the old deferral comment described: the same `.env` already
  // made `audit` exit 1, `scan --mcp` exit 1, and `scan --supply-chain`
  // exit 1, while this path alone exited (implicit) 0. Precedence now
  // lives in ONE place (computeExit, D-18: fail beats incomplete beats
  // clean) -- no hand-rolled fallback ladder sits beside it.
  //
  // `--mcp` and `--supply-chain` are unconditional early returns above
  // (:179-185), so the env scan and a supply-chain scan can never both run
  // in one invocation -- there is no exit-code combination problem here.
  // If a future requirement wants both in one run, that is a new product
  // decision (flag precedence, combined reporting), out of EXIT-01's scope.
  //
  // The stderr diagnostic's cause clause is built from the SAME ordered
  // list the stdout render and the next-steps block use (review C-4) --
  // stdout and stderr can never name different causes for one run. It no
  // longer claims "exiting 2" -- under D-18, a `.env` found alongside an
  // incomplete enumeration now exits 1, not 2 (findings beat
  // incompleteness), so the diagnostic states only what is certain: the
  // scan did not finish and its results are incomplete.
  if (incomplete) {
    const clauseText = buildCauseClauses(detail).map((c) => c.text).join('; ');
    console.error(`llm-safe-haven: the secret scan did not finish (${clauseText}) \u2014 results are incomplete`);
  }

  // Severity histogram (Pitfall 3): `dangerousFiles` maps to `info`, which
  // computeExit deliberately never branches on. Mapping them to `fail`
  // would make `scan` exit 1 on essentially every developer machine that
  // has ever run `npm login` -- a D-02b-class crying-wolf regression. They
  // are informational by construction: the "Credential files accessible
  // to agents" header wording, the yellow diamond glyph, and the fact
  // that their presence is normal on a real developer machine all say so.
  const severityCounts = { fail: envFiles.length, warn: 0, info: dangerousFiles.length };
  const code = computeExit({ severityCounts, incomplete });

  // Return-shape decision, not an accident: `undefined` on CLEAN (rather
  // than an unconditional `{ code }`) keeps D-04's "test blast radius is
  // nil" literally true -- tests/scan.test.js:573 and :654 both pin the
  // clean case to `undefined` -- and keeps settleCommand's behaviour
  // byte-identical: it no-ops on `undefined` rather than assigning
  // `process.exitCode = 0`, which would otherwise mask an earlier
  // non-zero assignment. The alternative (unconditional `{ code }`) costs
  // exactly two assertion edits and is also safe today -- this was chosen,
  // not stumbled into.
  return code === EXIT.CLEAN ? undefined : { code };
}

module.exports = {
  scan, scanForEnvFiles, scanForEnvFilesDetailed, findEnvFiles, findEnvFilesDetailed,
  printEnvScanResult, runSupplyChainScan, SUPPLY_CHAIN_SCANNER,
  // G-1617: exported so the ANOMALY_SKIP_REASONS -> clause coverage can be
  // asserted by a MECHANISM instead of maintained by convention.
  buildCauseClauses, remedyForCause,
};
