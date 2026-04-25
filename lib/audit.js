'use strict';

const { detectAll } = require('./agents/index.js');
const { scanForEnvFiles } = require('./scan.js');
const {
  printHeader, printAgentSection, printEnvScan,
  printLevel, printNextSteps, C, PASS, FAIL, DOT,
} = require('./scorecard.js');

function audit(flags) {
  if (flags.json) {
    return auditJson();
  }

  printHeader();
  console.log(`  ${C.bold}Auditing security posture...${C.reset}`);
  console.log('');

  const agents = detectAll();
  const found = agents.filter(a => a.detected.found);

  if (found.length === 0) {
    console.log(`  No AI coding agents detected.`);
    console.log('');
    process.exit(1);
  }

  let maxLevel = 0;

  for (const agent of found) {
    let auditResult = null;
    try {
      auditResult = agent.audit();
      if (auditResult.level > maxLevel) maxLevel = auditResult.level;
    } catch {
      auditResult = { checks: [], level: 0 };
    }

    printAgentSection(agent, agent.detected, null, auditResult);
    console.log('');
  }

  // .env scan
  const envFiles = scanForEnvFiles();
  printEnvScan(envFiles);

  if (envFiles.length > 0 && maxLevel >= 2) {
    maxLevel = 1;
  }

  printLevel(maxLevel);
  printNextSteps(maxLevel);

  // Exit code: 0 if Level 2+, 1 if below (for CI)
  process.exit(maxLevel >= 2 ? 0 : 1);
}

function auditJson() {
  const agents = detectAll();
  const envFiles = scanForEnvFiles();

  const result = {
    agents: agents.map(a => {
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
    }),
    envFiles,
    envFileCount: envFiles.length,
    overallLevel: Math.max(0, ...agents.filter(a => a.detected.found).map(a => {
      try { return a.audit().level; } catch { return 0; }
    })),
  };

  if (envFiles.length > 0 && result.overallLevel >= 2) {
    result.overallLevel = 1;
  }

  console.log(JSON.stringify(result, null, 2));
  process.exit(result.overallLevel >= 2 ? 0 : 1);
}

module.exports = { audit };
