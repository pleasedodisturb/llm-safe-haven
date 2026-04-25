'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const assert = require('assert');
const { execSync } = require('child_process');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SCRIPT_PATH = path.join(__dirname, '..', 'scripts', 'generate-checksums.js');
const CHECKSUMS_PATH = path.join(__dirname, '..', 'hooks', 'checksums.json');
const HOOKS_DIR = path.join(__dirname, '..', 'hooks');

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
    passed++;
  } catch (err) {
    console.log(`  FAIL  ${name}`);
    console.log(`        ${err.message}`);
    failed++;
  }
}

console.log('generate-checksums.test.js');
console.log('');

// -- Script runs successfully -----------------------------------------------

test('generate-checksums.js runs without errors', () => {
  const output = execSync(`node ${SCRIPT_PATH}`, { encoding: 'utf8' });
  assert.ok(output.includes('Generated checksums'), 'Should print success message');
  assert.ok(output.includes('checksums.json'), 'Should mention output file');
});

// -- Produces valid checksums.json ------------------------------------------

test('generates valid JSON with correct structure', () => {
  execSync(`node ${SCRIPT_PATH}`, { encoding: 'utf8' });

  assert.ok(fs.existsSync(CHECKSUMS_PATH), 'checksums.json should exist');

  const raw = fs.readFileSync(CHECKSUMS_PATH, 'utf8');
  const checksums = JSON.parse(raw);

  assert.ok(typeof checksums === 'object' && checksums !== null);
  assert.ok(!Array.isArray(checksums), 'Should be an object, not array');

  const keys = Object.keys(checksums);
  assert.ok(keys.length > 0, 'Should have at least one entry');
});

// -- Every hook file is included --------------------------------------------

test('includes all .js files from hooks/', () => {
  execSync(`node ${SCRIPT_PATH}`, { encoding: 'utf8' });

  const checksums = JSON.parse(fs.readFileSync(CHECKSUMS_PATH, 'utf8'));
  const hookFiles = fs.readdirSync(HOOKS_DIR)
    .filter(f => f.endsWith('.js'))
    .sort();

  for (const file of hookFiles) {
    assert.ok(checksums[file], `checksums.json should include ${file}`);
  }
});

// -- Hashes are correct SHA256 values ---------------------------------------

test('hashes match manual SHA256 computation', () => {
  execSync(`node ${SCRIPT_PATH}`, { encoding: 'utf8' });

  const checksums = JSON.parse(fs.readFileSync(CHECKSUMS_PATH, 'utf8'));

  for (const [file, hash] of Object.entries(checksums)) {
    const filePath = path.join(HOOKS_DIR, file);
    const content = fs.readFileSync(filePath);
    const expected = crypto.createHash('sha256').update(content).digest('hex');

    assert.strictEqual(hash, expected, `Hash mismatch for ${file}`);
  }
});

// -- Idempotent: running twice produces same output -------------------------

test('running twice produces identical checksums', () => {
  execSync(`node ${SCRIPT_PATH}`, { encoding: 'utf8' });
  const first = fs.readFileSync(CHECKSUMS_PATH, 'utf8');

  execSync(`node ${SCRIPT_PATH}`, { encoding: 'utf8' });
  const second = fs.readFileSync(CHECKSUMS_PATH, 'utf8');

  assert.strictEqual(first, second, 'Checksums should be deterministic');
});

// -- Hash format is 64 lowercase hex chars ----------------------------------

test('all hashes are 64-char lowercase hex strings', () => {
  execSync(`node ${SCRIPT_PATH}`, { encoding: 'utf8' });

  const checksums = JSON.parse(fs.readFileSync(CHECKSUMS_PATH, 'utf8'));

  for (const [file, hash] of Object.entries(checksums)) {
    assert.strictEqual(hash.length, 64, `${file} hash length should be 64`);
    assert.ok(/^[0-9a-f]{64}$/.test(hash), `${file} hash should be lowercase hex`);
  }
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('');
console.log(`${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
