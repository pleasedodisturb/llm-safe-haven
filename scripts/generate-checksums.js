#!/usr/bin/env node
// Generate SHA256 checksums for hook files.
// Writes hooks/checksums.json with { "filename": "hex-hash", ... }
//
// Run: node scripts/generate-checksums.js
// Zero dependencies — Node.js built-ins only.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const HOOKS_DIR = path.join(__dirname, '..', 'hooks');
const CHECKSUMS_PATH = path.join(HOOKS_DIR, 'checksums.json');

function sha256(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function generateChecksums() {
  const hookFiles = fs.readdirSync(HOOKS_DIR)
    .filter(f => f.endsWith('.js'))
    .sort();

  if (hookFiles.length === 0) {
    console.error('No .js files found in hooks/');
    process.exit(1);
  }

  const checksums = {};
  for (const file of hookFiles) {
    const filePath = path.join(HOOKS_DIR, file);
    checksums[file] = sha256(filePath);
  }

  fs.writeFileSync(CHECKSUMS_PATH, JSON.stringify(checksums, null, 2) + '\n');

  console.log(`Generated checksums for ${hookFiles.length} hook(s):`);
  for (const [file, hash] of Object.entries(checksums)) {
    console.log(`  ${file}: ${hash.slice(0, 16)}...`);
  }
  console.log(`\nWritten to ${CHECKSUMS_PATH}`);
}

generateChecksums();
