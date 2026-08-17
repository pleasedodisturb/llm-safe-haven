'use strict';

const { detectAll } = require('./agents/index.js');
// D-11 (G-1545, plan 18-04 Task 4): scanForEnvFilesDetailed() +
// printEnvScanResult() replace the OLDER, incomplete-discarding wrapper
// pair (see lib/scan.js's own warning comment at its definition) -- that
// discarded flag is exactly the defect this task closes. Both are Task 1's
// shared, exported one-implementation path, also consumed by
// lib/install.js and lib/scan.js, so all three commands render the same
// could-not-verify state identically.
const { scanForEnvFilesDetailed, printEnvScanResult, buildCauseClauses } = require('./scan.js');
const {
  printHeader, printAgentSection,
  printLevel, printNextSteps, printMcpAuditSection, computeSecurityLevel,
  C,
} = require('./scorecard.js');
const { buildEnvelope } = require('./scan-mcp.js');
const { EXIT, splitFindingsByConfidence } = require('./mcp/base.js');
// G-1615: the ONE place exit precedence is derived (D-04). audit must not
// re-derive it -- see the precedence note on auditExitCode() below.
const { computeExit } = require('./traverse/index.js');

/**
 * Runs the MCP scan offline, in-process, exactly once per audit call
 * (D-01/D-02 — audit NEVER dispatches through the scan-command orchestrator,
 * it always calls buildEnvelope directly, always with online:false
 * regardless of what the caller passed).
 *
 * D-03 containment: the ENTIRE envelope consumption — the buildEnvelope
 * await AND the count derivation over envelope.findings — sits inside the
 * try (Phase 8 review F4: the counts previously ran outside it, so a
 * malformed envelope with a non-array `findings` would have thrown past
 * the containment this docblock promises). Any throw, and equally a
 * truthy envelope WITHOUT a findings array, degrades to the same
 * incomplete result: envelope null, mcp.ran false, and
 * computeSecurityLevel's incomplete-scan ceiling fires. audit() must
 * never crash and must never silently report a false-clean level because
 * the scan didn't finish.
 */
async function getMcpInputs(flags) {
  try {
    const envelope = await buildEnvelope({ ...flags, online: false }, {});
    if (envelope && Array.isArray(envelope.findings)) {
      const { verifiedCount, unverifiedCount } = splitFindingsByConfidence(envelope.findings);
      return {
        envelope,
        mcp: { ran: true, exitCode: envelope.exitCode, verifiedCount, unverifiedCount },
      };
    }
  } catch {
    // fall through to the degraded incomplete result below
  }

  return {
    envelope: null,
    mcp: { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 },
  };
}

/**
 * WR-03 boundary normalization: agent modules are plugins, and "a broken
 * module never crashes the CLI" (CLAUDE.md). The try/catch around
 * agent.audit() only contains a THROWING module — a non-throwing but
 * malformed return (null, or a non-numeric level, or a non-array checks)
 * previously escaped it:
 *   - human path: `auditResult.level` on null -> TypeError -> audit()
 *     rejects -> CLI .catch exits 2, whole scorecard aborted.
 *   - --json path: same TypeError AFTER the JSON branch was selected but
 *     BEFORE anything printed -> empty stdout + exit 2, so a consumer
 *     faces JSON.parse('').
 *   - level: undefined -> Math.max(...) -> NaN poisons the level math.
 * Normalizing here guarantees both paths always complete and --json
 * always emits a JSON envelope.
 */
function normalizeAuditResult(auditResult) {
  if (!auditResult || typeof auditResult.level !== 'number' || Number.isNaN(auditResult.level)) {
    return { checks: [], level: 0 };
  }
  if (!Array.isArray(auditResult.checks)) {
    return { ...auditResult, checks: [] };
  }
  return auditResult;
}

/**
 * The single plugin-boundary wrapper around agent.audit() (Phase 8 review
 * F7 — audit(), auditJson(), and install() previously hand-rolled the
 * same try/catch + normalizeAuditResult pair three times): a throwing OR
 * malformed module degrades to { checks: [], level: 0 } — a broken
 * module never crashes the CLI (CLAUDE.md).
 */
function auditAgentSafe(agent) {
  let auditResult = null;
  try {
    auditResult = agent.audit();
  } catch {
    auditResult = null;
  }
  return normalizeAuditResult(auditResult);
}

/**
 * The single scorecard pipeline tail (F7): run the offline in-process
 * MCP scan (getMcpInputs — D-03/F4 contained, never network) and fold
 * agent levels + env-file count + MCP state + env-scan state through
 * computeSecurityLevel, the single source of truth (SCOR-03). All three
 * scorecard producers — audit(), auditJson(), and lib/install.js —
 * MUST call this instead of repeating the getMcpInputs +
 * computeSecurityLevel block, so their level math can never diverge.
 *
 * EXIT-05 (G-1623, D-20-06): `env` is the fourth parameter, forwarded
 * VERBATIM into computeSecurityLevel's own `env` input — never coerced,
 * never defaulted to a "complete" object here. A caller that omits it
 * lands in computeSecurityLevel's own fail-closed branch, which is the
 * entire reason the signal is an object rather than a boolean: this
 * function must not paper over a forgotten call site by inventing a
 * clean default (research Pitfall 4 — two of three call sites updated is
 * the exact failure mode this parameter, verified at all three, closes).
 */
async function computeScorecardLevel(flags, agentLevels, envFileCount, env) {
  const { envelope, mcp } = await getMcpInputs(flags);
  const { level, caps } = computeSecurityLevel({ agentLevels, envFileCount, mcp, env });
  return { envelope, mcp, level, caps };
}

async function audit(flags) {
  if (flags.json) {
    return auditJson(flags);
  }

  printHeader();
  console.log(`  ${C.bold}Auditing security posture...${C.reset}`);
  console.log('');

  const agents = detectAll();
  const found = agents.filter(a => a.detected.found);

  // IN-03: an intentional human/--json asymmetry on zero agents. The
  // human path is a quick posture summary — with nothing detected there
  // is nothing to report, so it short-circuits HERE, before the env/MCP
  // scan ever runs (getMcpInputs/buildEnvelope are never called below).
  // auditJson(), by contrast, always computes the full machine record
  // (agents: [], envFiles, mcp, levelCaps) regardless of agent count,
  // because --json is a stable machine-readable contract a consumer may
  // script against unconditionally. Exit codes on zero agents therefore
  // diverge: the human path ALWAYS exits 1 (it never scans), while --json
  // exits 1 only when its MCP scan completes — an incomplete scan yields
  // auditExitCode(...) === 2, because the fail-closed exit contract
  // (locked security-gate-exit-codes rule) wins over path parity. Both
  // cases are pinned in tests/audit.test.js.
  if (found.length === 0) {
    console.log(`  No AI coding agents detected.`);
    console.log('');
    return { code: 1 };
  }

  const agentLevels = [];

  for (const agent of found) {
    const auditResult = auditAgentSafe(agent);
    agentLevels.push(auditResult.level);

    printAgentSection(agent, agent.detected, null, auditResult);
    console.log('');
  }

  // .env scan (D-11): the shared anomaly-aware detail path -- audit() must
  // never again print a green check over an unread secret via the
  // `incomplete`-discarding thin wrapper (scanForEnvFiles, defined in
  // lib/scan.js).
  const envDetail = scanForEnvFilesDetailed();
  printEnvScanResult(envDetail, { command: 'audit' });
  const envFiles = envDetail.files;

  // SCOR-01: MCP scan runs offline in-process, feeding computeSecurityLevel
  // the same way the .env scan does — a verified finding (or an incomplete
  // scan) demotes the level exactly like tracked .env files do.
  //
  // NOTE (scope boundary, CLOSED — G-1623, EXIT-05): computeSecurityLevel
  // now takes the env scan's own completeness as a fourth input, threaded
  // through computeScorecardLevel below exactly like the MCP half always
  // was. An incomplete env scan now caps the printed Security Level (via
  // the env-incomplete cap, ceiling 2), in addition to the exit code
  // (below) and the rendered could-not-verify block (above) — all three
  // signals agree. A Level "2: Guarded" beside a could-not-verify block was
  // the standing inconsistency this closes.
  const { envelope, mcp, level, caps } = await computeScorecardLevel(flags, agentLevels, envFiles.length, { ran: true, incomplete: envDetail.incomplete === true });

  printMcpAuditSection(envelope, mcp);
  printLevel(level, caps);
  printNextSteps(level, caps);

  return { code: auditExitCode(level, mcp, envDetail.incomplete, envFiles.length) };
}

/**
 * The audit exit-code contract (0 = clean, 1 = findings/low level,
 * 2 = error-or-incomplete — the locked security-gate-exit-codes rule):
 *
 *   - 2 when the MCP scan audit itself initiated did not complete
 *     (mcp.ran === false OR mcp.exitCode === EXIT.INCOMPLETE) — audit
 *     runs the MCP scan in-process, so an unfinished scan means audit's
 *     own verdict is incomplete and must never exit 0/1 as if it were
 *     trustworthy. (Previously the mcp-incomplete level ceiling (2)
 *     equaled the pass threshold, so an incomplete scan could never
 *     move audit's exit code — contradicting the fail-closed contract.)
 *   - 2 also when the ENV scan audit itself ran did not complete
 *     (`envIncomplete`, D-11, G-1545, plan 18-04 Task 4) — audit runs the
 *     env scan in-process too, so an unfinished env scan makes audit's own
 *     verdict incomplete for exactly the same reason an unfinished MCP
 *     scan does (the locked security-gate-exit-codes rule, applied to the
 *     second of audit's two in-process scans).
 *   - 0 when both scans completed and the Security Level is 2+.
 *   - 1 whenever the Security Level is below 2 — INCLUDING when a scan did
 *     not complete. See the precedence note below.
 *
 * Verified MCP findings are intentionally LEVEL-ONLY: they demote the
 * Security Level (blocking Level 3+) but never fail audit's exit code
 * by themselves — `scan --mcp` (exit 1 on verified findings) is the CI
 * gate for MCP findings.
 *
 * PRECEDENCE (G-1615, 2026-08-13). This function used to read
 * `if (mcpIncomplete || envIncomplete) return 2;` BEFORE the level check,
 * which inverted the canonical ladder in `computeExit()`
 * (lib/traverse/index.js): findings (1) beat incompleteness (2), not the
 * other way round. `scan` routed through `computeExit()` and `audit` did
 * not, so the same machine state produced exit 1 from one command and
 * exit 2 from the other.
 *
 * The prior behaviour was deliberate and argued, not accidental: the old
 * comment reasoned that an unfinished scan makes audit's verdict
 * untrustworthy, so it "must never exit 0/1 as if it were trustworthy".
 * That argument holds for exit 0 and is preserved — an incomplete scan can
 * still never report clean. It does NOT hold for exit 1: a tracked `.env`
 * that WAS observed is ground truth regardless of what else went unread,
 * and reporting it as "the scan did not finish" demotes a certain,
 * actionable finding into an infrastructure warning. It also let an
 * operator mask a real finding's exit signal by introducing an unreadable
 * sibling directory or a dead network mount.
 *
 * D-04 (18-CONTEXT.md) is the governing decision: exit precedence is
 * derived in ONE place. This function no longer re-derives it.
 *
 * THE FINDING TERM IS `envFileCount`, NOT `level < 2`. This distinction is
 * the whole correctness of the fix and the first attempt got it wrong.
 * `level` is a POSTURE score: it is below 2 when a secret was found, but
 * ALSO when there are simply no agents installed to audit, and ALSO when an
 * incomplete MCP scan caps it. Mapping `level < 2` onto computeExit's
 * `fail` therefore turned "nothing to audit + broken scan" into exit 1 and
 * broke the named IN-03 contract ("zero-agents --json path with an
 * INCOMPLETE MCP scan exits 2, not 1 — fail-closed wins over zero-agents
 * parity"), which is a deliberate decision, not a stale test.
 *
 * Only an OBSERVED tracked `.env` is ground truth that survives an
 * incomplete scan — you do not need to have finished looking to know that
 * what you already saw is real. A merely-low posture does not survive it,
 * because a posture computed from an unfinished scan is exactly the
 * untrustworthy verdict the fail-closed rule exists to suppress.
 *
 * Exported for tests — the inversion survived precisely because this was a
 * module-private function with no isolated unit coverage.
 *
 * @param {number} level         Security Level 0-4 (posture, NOT a finding count)
 * @param {object} mcp           MCP scan result ({ ran, exitCode })
 * @param {boolean} envIncomplete  the env scan could not read everything
 * @param {number} envFileCount  tracked `.env` files ACTUALLY OBSERVED
 */
function auditExitCode(level, mcp, envIncomplete, envFileCount = 0) {
  const mcpIncomplete = !mcp || mcp.ran === false || mcp.exitCode === EXIT.INCOMPLETE;
  const incomplete = mcpIncomplete || !!envIncomplete;
  // An observed .env beats incompleteness (computeExit: fail -> 1 before
  // incomplete -> 2). A low level with NO observed finding does not, so a
  // broken scan still fails closed to 2 rather than claiming a verdict.
  const exit = computeExit({
    severityCounts: { fail: envFileCount > 0 ? 1 : 0 },
    incomplete,
  });
  // Scans complete and posture below the pass threshold -> 1, unchanged.
  if (exit === 0 && level < 2) return 1;
  return exit;
}

async function auditJson(flags = {}) {
  const agents = detectAll();
  const envDetail = scanForEnvFilesDetailed();
  const envFiles = envDetail.files;

  const agentResults = agents.map(a => {
    // Not-found agents never have audit() called (normalized null ->
    // { checks: [], level: 0 }), exactly as before the F7 dedupe.
    const auditResult = a.detected.found ? auditAgentSafe(a) : normalizeAuditResult(null);

    return {
      id: a.id,
      name: a.name,
      tier: a.tier,
      found: a.detected.found,
      version: a.detected.version || null,
      level: auditResult.level,
      checks: auditResult.checks,
    };
  });

  // Computed as a local BEFORE the result object below — never read a
  // still-being-built object's own property (the self-reference/TDZ
  // anti-pattern the original inline math had).
  const agentLevels = agentResults.filter(a => a.found).map(a => a.level);

  // EXIT-05 (G-1623, D-20-06): the same env-completeness input `audit()`
  // passes, forwarded verbatim -- the level math and the `envIncomplete`
  // key below now describe the SAME fact.
  const { envelope, mcp, level, caps } = await computeScorecardLevel(flags, agentLevels, envFiles.length, { ran: true, incomplete: envDetail.incomplete === true });

  // D-11: additive-only. Existing keys (agents, envFiles, envFileCount,
  // overallLevel) keep their names and order; mcp + levelCaps are new.
  //
  // G-1619 (cross-AI review round 2, codex). This block used to omit
  // `envIncomplete` as a "deliberate deferral", justified by: "the exit
  // code already carries the signal". THAT JUSTIFICATION WAS TRUE UNTIL
  // G-1615 (029396f) AND THAT COMMIT INVALIDATED IT. Before it, an observed
  // `.env` on an incomplete scan exited 2, so a consumer could see the
  // incompleteness in the exit code. After it, that state exits 1 —
  // identical to a COMPLETE scan with the same finding — and with no
  // envIncomplete key the two states were byte-identical in both channels.
  // Verified: two fixtures differing only by an unreadable directory
  // produced byte-identical `audit --json` output and the same exit code.
  //
  // A fix that relocates a signal must carry the signal to its new home.
  // This is that carry: the exit code keeps precedence (finding beats
  // incompleteness), and the envelope keeps fidelity (both facts remain
  // legible to a machine consumer). Still additive — no existing key
  // changes name, type or position, so the frozen shape is intact.
  const envCauses = envDetail.incomplete
    ? buildCauseClauses(envDetail).map((c) => c.id)
    : [];
  const result = {
    agents: agentResults,
    envFiles,
    envFileCount: envFiles.length,
    overallLevel: level,
    mcp: {
      ran: mcp.ran,
      exitCode: mcp.exitCode,
      findingsCount: envelope ? envelope.findings.length : 0,
      verifiedCount: mcp.verifiedCount,
      unverifiedCount: mcp.unverifiedCount,
    },
    levelCaps: caps,
    // The env half of the completeness contract, in the machine channel.
    // `envCauses` uses the SAME ordered clause list the human renderer
    // prints, so the two channels can never describe the run differently.
    envIncomplete: envDetail.incomplete === true,
    envCauses,
  };

  // Stdout purity: the full JSON envelope is ALWAYS printed before the
  // exit code is decided — an exit-2 (incomplete MCP OR env scan) run
  // still emits valid JSON, and the consumer can read mcp.exitCode +
  // levelCaps to see the MCP half; the env half is now also folded into
  // the exit code itself (D-11).
  console.log(JSON.stringify(result, null, 2));
  return { code: auditExitCode(level, mcp, envDetail.incomplete, envFiles.length) };
}

// auditAgentSafe/computeScorecardLevel are exported for lib/install.js
// (CR-01/F7): the default `install` scorecard MUST feed
// computeSecurityLevel through the exact same offline, D-03-contained
// MCP path audit uses — never re-derive the level inline (SCOR-03).
// getMcpInputs/normalizeAuditResult stay exported for direct unit tests.
module.exports = {
  audit,
  getMcpInputs,
  normalizeAuditResult,
  auditAgentSafe,
  computeScorecardLevel,
  // G-1615: exported so the exit ladder can be unit-tested in isolation.
  // It was module-private, and that is exactly why the inversion survived
  // every gate this phase ran.
  auditExitCode,
};
