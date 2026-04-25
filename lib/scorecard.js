'use strict';

// ANSI color codes — zero dependencies
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
};

const PASS = `${C.green}\u2713${C.reset}`;
const FAIL = `${C.red}\u2717${C.reset}`;
const WARN = `${C.yellow}\u25c6${C.reset}`;
const DOT = `${C.dim}\u00b7${C.reset}`;

const LEVEL_LABELS = [
  'Exposed',
  'Basic',
  'Guarded',
  'Hardened',
  'Fortified',
];

const LEVEL_BAR_CHARS = [0, 5, 10, 15, 20];

function printHeader() {
  console.log('');
  console.log(`${C.bold}${C.cyan}  \u{1F512} LLM Safe Haven \u2014 Security Scorecard${C.reset}`);
  console.log('');
}

function printAgentSection(agent, detected, hardenResult, auditResult) {
  const icon = detected.found ? PASS : DOT;
  const version = detected.version ? ` ${C.dim}${detected.version}${C.reset}` : '';
  const tierLabel = agent.tier === 1 ? 'Full support' : agent.tier === 2 ? 'Solid support' : 'Advise only';

  console.log(`  ${icon} ${C.bold}${agent.name}${C.reset}${version} ${C.dim}(${tierLabel})${C.reset}`);

  if (!detected.found) return;

  // Show hardening actions
  if (hardenResult) {
    for (const action of hardenResult.actions) {
      console.log(`    ${PASS} ${action}`);
    }
    for (const warning of hardenResult.warnings) {
      console.log(`    ${WARN} ${C.yellow}${warning}${C.reset}`);
    }
  }

  // Show audit checks
  if (auditResult) {
    for (const check of auditResult.checks) {
      const icon = check.pass ? PASS : FAIL;
      console.log(`    ${icon} ${check.name} \u2014 ${C.dim}${check.detail}${C.reset}`);
    }
  }
}

function printEnvScan(envFiles) {
  console.log('');
  console.log(`  ${C.bold}Project scan:${C.reset}`);

  if (envFiles.length === 0) {
    console.log(`    ${PASS} No .env files found`);
  } else {
    console.log(`    ${FAIL} ${C.red}${envFiles.length} .env file(s) found:${C.reset}`);
    for (const f of envFiles.slice(0, 10)) {
      console.log(`      ${C.dim}${f}${C.reset}`);
    }
    if (envFiles.length > 10) {
      console.log(`      ${C.dim}...and ${envFiles.length - 10} more${C.reset}`);
    }
  }
}

function printLevel(level) {
  const label = LEVEL_LABELS[level] || 'Unknown';
  const filled = LEVEL_BAR_CHARS[level] || 0;
  const empty = 20 - filled;
  const bar = '\u2588'.repeat(filled) + '\u2591'.repeat(empty);

  console.log('');
  console.log(`  ${C.bold}Security Level: ${level} of 4${C.reset}`);
  console.log(`  \u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510`);
  console.log(`  \u2502 ${bar}  Level ${level}: ${label} \u2502`);
  console.log(`  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`);
}

function printNextSteps(level) {
  console.log('');
  console.log(`  ${C.bold}Next steps:${C.reset}`);

  if (level < 1) {
    console.log(`    Run ${C.cyan}npx llm-safe-haven${C.reset} to install basic hooks`);
  } else if (level < 2) {
    console.log(`    Set up audit logging and remove .env files`);
  } else if (level < 3) {
    console.log(`    Set up a credential proxy (see docs/credential-management.md)`);
  } else if (level < 4) {
    console.log(`    Run agents in containers for full isolation`);
  } else {
    console.log(`    ${C.green}Maximum hardening achieved${C.reset}`);
  }

  console.log(`    Docs: ${C.dim}https://github.com/pleasedodisturb/llm-safe-haven${C.reset}`);
  console.log('');
}

module.exports = {
  printHeader,
  printAgentSection,
  printEnvScan,
  printLevel,
  printNextSteps,
  C, PASS, FAIL, WARN, DOT,
};
