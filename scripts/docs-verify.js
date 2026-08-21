#!/usr/bin/env node
// Deterministic, zero-dependency documentation drift guard (G-1570,
// GUARD-01).
//
// This is the command README.md and CI tell a contributor to run before
// opening a PR that touches markdown or the code it documents. It must
// stay copy-pasteable and dependency-free -- built-ins only, no npm
// packages.
//
// Usage:
//   node scripts/docs-verify.js [--root <dir>]
//
// Exit codes (this project's existing 0/1/2 contract, lib/traverse/
// index.js EXIT / docs/mcp-security.md Section 6): 0 when the sweep
// completed with zero findings; 1 when the sweep completed and found at
// least one drift finding; 2 when the sweep itself could not finish
// (unreadable input, a check module that threw or failed to load, zero
// markdown discovered, zero checks loaded, an unrecognized CLI flag) --
// regardless of finding count. An incomplete sweep is never treated as
// clean.

'use strict';

const path = require('path');

const { buildContext } = require('../lib/docs-verify/helpers/context.js');
const { loadChecks, runAll, tallySeverities, computeExit, formatReport, EXIT } = require('../lib/docs-verify/index.js');

const DEFAULT_ROOT = path.join(__dirname, '..');

/**
 * Accepts only `--root <dir>`. An unrecognized flag fails closed -- exit
 * 2, matching the WR-01 precedent in lib/cli.js: a security-relevant tool
 * must never silently ignore a typo'd flag and run a different sweep than
 * the one requested.
 */
function parseArgs(argv) {
  const result = { root: DEFAULT_ROOT };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--root') {
      const value = argv[i + 1];
      if (typeof value !== 'string' || value === '') {
        return { error: '--root requires a value' };
      }
      result.root = path.resolve(value);
      i += 1;
      continue;
    }
    return { error: `unrecognized option "${arg}"` };
  }
  return result;
}

function main(argv) {
  const parsed = parseArgs(argv);
  if (parsed.error) {
    process.stdout.write(`FAIL  ${parsed.error}\n`);
    return EXIT.INCOMPLETE;
  }

  const context = buildContext(parsed.root);
  const { checks, errors: checkErrors } = loadChecks();
  const { findings, incomplete } = runAll(context, checks, checkErrors);
  const severityCounts = tallySeverities(findings);
  const exitCode = computeExit({ severityCounts, incomplete });

  process.stdout.write(formatReport({ findings, incomplete }));
  process.stdout.write('\n');

  return exitCode;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { main, parseArgs };
