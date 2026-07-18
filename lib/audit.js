'use strict';

const { detectAll } = require('./agents/index.js');
const { scanForEnvFiles } = require('./scan.js');
const {
  printHeader, printAgentSection, printEnvScan,
  printLevel, printNextSteps, printMcpAuditSection, computeSecurityLevel,
  C,
} = require('./scorecard.js');
const { buildEnvelope } = require('./scan-mcp.js');
const { EXIT, splitFindingsByConfidence } = require('./mcp/base.js');

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
 * agent levels + env-file count + MCP state through
 * computeSecurityLevel, the single source of truth (SCOR-03). All three
 * scorecard producers — audit(), auditJson(), and lib/install.js —
 * MUST call this instead of repeating the getMcpInputs +
 * computeSecurityLevel block, so their level math can never diverge.
 */
async function computeScorecardLevel(flags, agentLevels, envFileCount) {
  const { envelope, mcp } = await getMcpInputs(flags);
  const { level, caps } = computeSecurityLevel({ agentLevels, envFileCount, mcp });
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
  // script against unconditionally. Both paths still return { code: 1 }
  // for zero agents — pinned in tests/audit.test.js.
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

  // .env scan
  const envFiles = scanForEnvFiles();
  printEnvScan(envFiles);

  // SCOR-01: MCP scan runs offline in-process, feeding computeSecurityLevel
  // the same way the .env scan does — a verified finding (or an incomplete
  // scan) demotes the level exactly like tracked .env files do.
  const { envelope, mcp, level, caps } = await computeScorecardLevel(flags, agentLevels, envFiles.length);

  printMcpAuditSection(envelope, mcp);
  printLevel(level, caps);
  printNextSteps(level, caps);

  return { code: auditExitCode(level, mcp) };
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
 *   - 0 when the scan completed and the Security Level is 2+.
 *   - 1 when the scan completed and the Security Level is below 2.
 *
 * Verified MCP findings are intentionally LEVEL-ONLY: they demote the
 * Security Level (blocking Level 3+) but never fail audit's exit code
 * by themselves — `scan --mcp` (exit 1 on verified findings) is the CI
 * gate for MCP findings.
 */
function auditExitCode(level, mcp) {
  const mcpIncomplete = !mcp || mcp.ran === false || mcp.exitCode === EXIT.INCOMPLETE;
  if (mcpIncomplete) return 2;
  return level >= 2 ? 0 : 1;
}

async function auditJson(flags = {}) {
  const agents = detectAll();
  const envFiles = scanForEnvFiles();

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

  const { envelope, mcp, level, caps } = await computeScorecardLevel(flags, agentLevels, envFiles.length);

  // D-11: additive-only. Existing keys (agents, envFiles, envFileCount,
  // overallLevel) keep their names and order; mcp + levelCaps are new.
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
  };

  // Stdout purity: the full JSON envelope is ALWAYS printed before the
  // exit code is decided — an exit-2 (incomplete MCP scan) run still
  // emits valid JSON, and the consumer can read mcp.exitCode + levelCaps
  // to see exactly why the code is 2.
  console.log(JSON.stringify(result, null, 2));
  return { code: auditExitCode(level, mcp) };
}

// auditAgentSafe/computeScorecardLevel are exported for lib/install.js
// (CR-01/F7): the default `install` scorecard MUST feed
// computeSecurityLevel through the exact same offline, D-03-contained
// MCP path audit uses — never re-derive the level inline (SCOR-03).
// getMcpInputs/normalizeAuditResult stay exported for direct unit tests.
module.exports = { audit, getMcpInputs, normalizeAuditResult, auditAgentSafe, computeScorecardLevel };
