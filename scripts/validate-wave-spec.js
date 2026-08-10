#!/usr/bin/env node
// Validate one or more wave-spec JSON files (G-1482, TRAV-08).
//
// This is the command docs/wave-spec.md tells a wave author to run before
// opening a PR. It must stay copy-pasteable and dependency-free — built-ins
// only, no npm packages.
//
// Usage:
//   node scripts/validate-wave-spec.js <path-to-spec.json>
//   node scripts/validate-wave-spec.js                # validates every
//                                                       # manifests/waves/*.json
//
// Exit codes (matches this project's existing 0/1/2 contract,
// lib/traverse/index.js EXIT): 0 when every file validates; 2 when any file
// is invalid or unreadable. Never 1 — an invalid spec is an incomplete/
// could-not-run condition here, not a "findings" condition.

'use strict';

const fs = require('fs');
const path = require('path');
const { loadWaveSpec } = require('../lib/traverse/wave-spec');

const WAVES_DIR = path.join(__dirname, '..', 'manifests', 'waves');

function discoverBundledSpecs() {
  let entries;
  try {
    entries = fs.readdirSync(WAVES_DIR);
  } catch (err) {
    return { error: `could not read ${WAVES_DIR}: ${(err && err.code) || (err && err.message) || 'unknown error'}` };
  }
  const files = entries
    .filter((name) => name.endsWith('.json'))
    .map((name) => path.join(WAVES_DIR, name))
    .sort();
  return { files };
}

function validateOne(specPath) {
  const result = loadWaveSpec(specPath);
  if (result.valid) {
    const sectionCount = Object.keys(result.spec).length;
    return {
      ok: true,
      line: `OK  ${specPath}  (specVersion ${result.spec.specVersion}, ${sectionCount} sections)`,
    };
  }
  return { ok: false, line: `FAIL ${specPath}  ${result.reason}` };
}

function main(argv) {
  let targets;

  if (argv.length > 0) {
    targets = argv;
  } else {
    const discovered = discoverBundledSpecs();
    if (discovered.error) {
      process.stdout.write(`FAIL (no argument given)  ${discovered.error}\n`);
      return 2;
    }
    if (discovered.files.length === 0) {
      process.stdout.write(`FAIL (no argument given)  no *.json files found under ${WAVES_DIR}\n`);
      return 2;
    }
    targets = discovered.files;
  }

  let anyFailed = false;
  for (const specPath of targets) {
    const { ok, line } = validateOne(specPath);
    process.stdout.write(`${line}\n`);
    if (!ok) anyFailed = true;
  }

  return anyFailed ? 2 : 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { main, validateOne, discoverBundledSpecs };
