'use strict';

const { detectAll, getByIds } = require('./agents/index.js');
const { scanForEnvFiles } = require('./scan.js');
const {
  printHeader, printAgentSection, printEnvScan,
  printLevel, printNextSteps, printMcpAuditSection,
  C, PASS, DOT,
} = require('./scorecard.js');
const { auditAgentSafe, computeScorecardLevel } = require('./audit.js');

// async as of Phase 8 review fix CR-01: the default `install` scorecard
// runs the same offline in-process MCP scan audit does (getMcpInputs —
// D-03 contained, never network) and computes its printed level through
// computeSecurityLevel, the single source of truth (SCOR-03). The
// previous inline maxLevel math + hand-rolled .env demotion could show
// an uncapped "Level 3: Hardened" to a user whose MCP configs carry
// verified findings — a false security assurance on the primary user
// path, contradicting docs/mcp-security.md §6 and the README Level table.
async function install(flags) {
  printHeader();

  // 1. Detect agents
  let agents;
  if (flags.agent) {
    const ids = flags.agent.split(',').map(s => s.trim());
    agents = getByIds(ids).map(a => {
      try {
        return { ...a, detected: a.detect() };
      } catch {
        return { ...a, detected: { found: false } };
      }
    });

    const notFound = ids.filter(id => !agents.find(a => a.id === id));
    if (notFound.length) {
      console.log(`  ${C.yellow}Unknown agent(s): ${notFound.join(', ')}${C.reset}`);
      console.log(`  ${C.dim}Available: claude-code, cursor, windsurf, cline, continue-dev, aider, codex-cli${C.reset}`);
      console.log('');
    }
  } else {
    agents = detectAll();
  }

  const found = agents.filter(a => a.detected.found);
  const notFound = agents.filter(a => !a.detected.found);

  if (found.length === 0) {
    console.log(`  No AI coding agents detected.`);
    console.log('');
    console.log(`  ${C.dim}Supported: Claude Code, Cursor, Windsurf, Cline, Continue.dev, Aider, Codex CLI${C.reset}`);
    console.log(`  ${C.dim}Use --agent <id> to target a specific agent${C.reset}`);
    console.log('');
    // Plain return (same effective exit 0): install() resolves, run()'s
    // settleCommand sees no { code } and leaves process.exitCode alone —
    // implicit 0, exactly as the previous process.exit(0) produced, but
    // without hard-terminating an async function mid-flight (consistent
    // with install()'s no-process.exit style everywhere else). install is
    // informational, never a CI gate — see docs/mcp-security.md §6.
    return;
  }

  // 2. Show detected agents
  console.log(`  ${C.bold}Detected agents:${C.reset}`);
  for (const agent of found) {
    const version = agent.detected.version ? ` ${C.dim}${agent.detected.version}${C.reset}` : '';
    console.log(`    ${PASS} ${agent.name}${version}`);
  }
  for (const agent of notFound) {
    console.log(`    ${DOT} ${C.dim}${agent.name} — not installed${C.reset}`);
  }
  console.log('');

  // 3. Harden each detected agent
  const projectDir = process.cwd();
  const agentLevels = [];

  console.log(`  ${C.bold}Hardening:${C.reset}`);
  console.log('');

  for (const agent of found) {
    let hardenResult = null;

    try {
      hardenResult = agent.harden(projectDir, flags);
    } catch (err) {
      hardenResult = { actions: [], warnings: [`Hardening failed: ${err.message}`] };
    }

    // WR-03 plugin boundary, shared with lib/audit.js (F7): a throwing
    // or malformed audit() return must never poison the level math or
    // crash the renderer — a broken module never crashes the CLI.
    const auditResult = auditAgentSafe(agent);
    agentLevels.push(auditResult.level);

    printAgentSection(agent, agent.detected, hardenResult, auditResult);
    console.log('');
  }

  // 4. Scan for .env files + offline MCP scan (CR-01/F7: the exact same
  // pipeline tail as `audit` — a verified MCP finding or an incomplete
  // scan demotes the printed level exactly like tracked .env files do;
  // getMcpInputs fails closed to mcp-incomplete on any throw).
  const envFiles = scanForEnvFiles();
  printEnvScan(envFiles);

  const { envelope, level, caps } = await computeScorecardLevel(flags, agentLevels, envFiles.length);

  // 5. Print scorecard
  printMcpAuditSection(envelope);
  printLevel(level, caps);
  printNextSteps(level, caps);
}

module.exports = { install };
