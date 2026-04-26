'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const SCAN_DIRS = [
  path.join(os.homedir(), 'Projects'),
  path.join(os.homedir(), 'Developer'),
  path.join(os.homedir(), 'Code'),
  path.join(os.homedir(), 'src'),
  path.join(os.homedir(), 'repos'),
  path.join(os.homedir(), 'workspace'),
];

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', '__pycache__', '.venv', 'venv']);

function findEnvFiles(startDir, maxDepth) {
  const results = [];
  if (!fs.existsSync(startDir)) return results;

  function walk(dir, depth) {
    if (depth > (maxDepth || 4)) return;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // Permission denied or other error
    }

    for (const entry of entries) {
      // M-6: Skip symlinks to prevent symlink-following attacks
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        walk(path.join(dir, entry.name), depth + 1);
      } else if (entry.isFile()) {
        if (entry.name === '.env' || (entry.name.startsWith('.env.') && !entry.name.endsWith('.example') && !entry.name.endsWith('.template') && !entry.name.endsWith('.sample'))) {
          results.push(path.join(dir, entry.name));
        }
      }
    }
  }

  walk(startDir, 0);
  return results;
}

function scanForEnvFiles() {
  const allFiles = [];

  for (const dir of SCAN_DIRS) {
    const found = findEnvFiles(dir);
    allFiles.push(...found);
  }

  // Deduplicate
  return [...new Set(allFiles)].sort();
}

function scan(flags) {
  const { printHeader, printEnvScan, printNextSteps, C } = require('./scorecard.js');

  printHeader();
  console.log(`  ${C.bold}Scanning for exposed secrets...${C.reset}`);
  console.log('');

  const envFiles = scanForEnvFiles();
  printEnvScan(envFiles);

  // Check for common dangerous files in home dir
  const dangerousFiles = [
    '.aws/credentials',
    '.config/gcloud/application_default_credentials.json',
    '.kube/config',
    '.npmrc',
  ].map(f => path.join(os.homedir(), f)).filter(f => fs.existsSync(f));

  if (dangerousFiles.length > 0) {
    console.log('');
    console.log(`  ${C.bold}Credential files accessible to agents:${C.reset}`);
    for (const f of dangerousFiles) {
      console.log(`    ${C.yellow}\u25c6${C.reset} ${C.dim}${f}${C.reset}`);
    }
  }

  printNextSteps(envFiles.length === 0 ? 2 : 1);
}

module.exports = { scan, scanForEnvFiles, findEnvFiles };
