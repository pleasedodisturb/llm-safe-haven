'use strict';

const { detectAll, getByIds } = require('./agents/index.js');
const { scanForEnvFiles } = require('./scan.js');
const {
  printHeader, printAgentSection, printEnvScan,
  printLevel, printNextSteps, C, PASS, DOT,
} = require('./scorecard.js');

function install(flags) {
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
    process.exit(0);
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
  let maxLevel = 0;

  console.log(`  ${C.bold}Hardening:${C.reset}`);
  console.log('');

  for (const agent of found) {
    let hardenResult = null;
    let auditResult = null;

    try {
      hardenResult = agent.harden(projectDir, flags);
    } catch (err) {
      hardenResult = { actions: [], warnings: [`Hardening failed: ${err.message}`] };
    }

    try {
      auditResult = agent.audit();
      if (auditResult.level > maxLevel) maxLevel = auditResult.level;
    } catch {
      auditResult = { checks: [], level: 0 };
    }

    printAgentSection(agent, agent.detected, hardenResult, auditResult);
    console.log('');
  }

  // 4. Scan for .env files
  const envFiles = scanForEnvFiles();
  printEnvScan(envFiles);

  if (envFiles.length > 0 && maxLevel >= 2) {
    maxLevel = 1; // Demote if .env files exist
  }

  // 5. Print scorecard
  printLevel(maxLevel);
  printNextSteps(maxLevel);
}

module.exports = { install };
