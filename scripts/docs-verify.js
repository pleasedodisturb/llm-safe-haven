#!/usr/bin/env node
// STUB (RED phase, G-1570) -- see lib/docs-verify/helpers/discover-md.js
// stub header. Real implementation lands in the GREEN commit.

'use strict';

function parseArgs() {
  return { root: process.cwd() };
}

function main() {
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { main, parseArgs };
