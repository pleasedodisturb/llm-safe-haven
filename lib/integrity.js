'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CHECKSUMS_PATH = path.join(__dirname, '..', 'hooks', 'checksums.json');

/**
 * Computes SHA256 hex digest of a file's contents.
 */
function sha256(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Loads the known-good checksums shipped with the package.
 * Returns null if checksums.json is missing or unparseable.
 */
function loadChecksums() {
  try {
    const raw = fs.readFileSync(CHECKSUMS_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Verifies installed hooks against known-good SHA256 checksums.
 *
 * @param {string} hooksDir - Path to the directory where hooks are installed
 *   (e.g. ~/.claude/hooks)
 * @returns {{ results: Array<{name: string, status: 'ok'|'tampered'|'missing', expected?: string, actual?: string}> }}
 */
function verifyHooks(hooksDir) {
  const checksums = loadChecksums();
  const results = [];

  if (!checksums) {
    // No checksums.json shipped — can't verify anything
    return {
      results: [{
        name: 'checksums.json',
        status: 'missing',
        detail: 'No checksums.json found in package — run generate-checksums first',
      }],
    };
  }

  for (const [filename, expectedHash] of Object.entries(checksums)) {
    const installedPath = path.join(hooksDir, filename);

    if (!fs.existsSync(installedPath)) {
      results.push({
        name: filename,
        status: 'missing',
        expected: expectedHash,
      });
      continue;
    }

    const actualHash = sha256(installedPath);

    if (actualHash === expectedHash) {
      results.push({
        name: filename,
        status: 'ok',
      });
    } else {
      results.push({
        name: filename,
        status: 'tampered',
        expected: expectedHash,
        actual: actualHash,
      });
    }
  }

  return { results };
}

module.exports = { verifyHooks, loadChecksums, sha256 };
