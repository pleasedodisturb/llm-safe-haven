'use strict';

const { detectAll } = require('./agents/index.js');
const { scanForEnvFiles } = require('./scan.js');
const {
  printHeader, printAgentSection, printEnvScan,
  printLevel, printNextSteps, printMcpAuditSection, computeSecurityLevel,
  C,
} = require('./scorecard.js');
const { buildEnvelope } = require('./scan-mcp.js');
const { CONFIDENCE, EXIT } = require('./mcp/base.js');

/**
 * Runs the MCP scan offline, in-process, exactly once per audit call
 * (D-01/D-02 — audit NEVER dispatches through the scan-command orchestrator,
 * it always calls buildEnvelope directly, always with online:false
 * regardless of what the caller passed).
 *
 * D-03 containment: a throw from buildEnvelope (a hostile config engineered
 * to crash discovery/parsing/detection) is caught here and treated as an
 * incomplete scan — envelope stays null, mcp.ran stays false, and
 * computeSecurityLevel's incomplete-scan ceiling fires. audit() must never
 * crash and must never silently report a false-clean level because the
 * scan didn't finish.
 */
async function getMcpInputs(flags) {
  let envelope = null;
  try {
    envelope = await buildEnvelope({ ...flags, online: false }, {});
  } catch {
    envelope = null;
  }

  if (envelope) {
    const verifiedCount = envelope.findings.filter(f => f.confidence === CONFIDENCE.VERIFIED).length;
    const unverifiedCount = envelope.findings.length - verifiedCount;
    return {
      envelope,
      mcp: { ran: true, exitCode: envelope.exitCode, verifiedCount, unverifiedCount },
    };
  }

  return {
    envelope: null,
    mcp: { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 },
  };
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

  if (found.length === 0) {
    console.log(`  No AI coding agents detected.`);
    console.log('');
    return { code: 1 };
  }

  const agentLevels = [];

  for (const agent of found) {
    let auditResult = null;
    try {
      auditResult = agent.audit();
    } catch {
      auditResult = { checks: [], level: 0 };
    }
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
  const { envelope, mcp } = await getMcpInputs(flags);

  const { level, caps } = computeSecurityLevel({
    agentLevels,
    envFileCount: envFiles.length,
    mcp,
  });

  printMcpAuditSection(envelope);
  printLevel(level, caps);
  printNextSteps(level, caps);

  // Exit code: 0 if Level 2+, 1 if below (for CI)
  return { code: level >= 2 ? 0 : 1 };
}

async function auditJson(flags = {}) {
  const agents = detectAll();
  const envFiles = scanForEnvFiles();

  const agentResults = agents.map(a => {
    let auditResult = { checks: [], level: 0 };
    try {
      if (a.detected.found) auditResult = a.audit();
    } catch { /* ignore */ }

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

  const { envelope, mcp } = await getMcpInputs(flags);

  const { level, caps } = computeSecurityLevel({
    agentLevels,
    envFileCount: envFiles.length,
    mcp,
  });

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

  console.log(JSON.stringify(result, null, 2));
  return { code: level >= 2 ? 0 : 1 };
}

module.exports = { audit };
