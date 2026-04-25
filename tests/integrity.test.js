'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const assert = require('assert');
const { verifyHooks, loadChecksums, sha256 } = require('../lib/integrity.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'integrity-test-'));
}

function writeFile(dir, name, content) {
  fs.writeFileSync(path.join(dir, name), content);
}

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

console.log('integrity.test.js');
console.log('');

// -- sha256 -----------------------------------------------------------------

test('sha256 returns correct hex digest', () => {
  const dir = tmpDir();
  const filePath = path.join(dir, 'test.txt');
  fs.writeFileSync(filePath, 'hello world');

  const expected = crypto.createHash('sha256').update('hello world').digest('hex');
  const actual = sha256(filePath);

  assert.strictEqual(actual, expected);
  fs.rmSync(dir, { recursive: true });
});

test('sha256 hashes exact bytes (no normalization)', () => {
  const dir = tmpDir();
  const f1 = path.join(dir, 'a.txt');
  const f2 = path.join(dir, 'b.txt');
  fs.writeFileSync(f1, 'line1\nline2\n');
  fs.writeFileSync(f2, 'line1\r\nline2\r\n');

  assert.notStrictEqual(sha256(f1), sha256(f2), 'Different line endings should produce different hashes');
  fs.rmSync(dir, { recursive: true });
});

// -- loadChecksums ----------------------------------------------------------

test('loadChecksums returns object from hooks/checksums.json', () => {
  const checksums = loadChecksums();
  assert.ok(checksums !== null, 'checksums.json should be loadable');
  assert.ok(typeof checksums === 'object');
  assert.ok(Object.keys(checksums).length > 0, 'Should have at least one entry');

  // Every value should look like a hex SHA256 (64 chars)
  for (const [file, hash] of Object.entries(checksums)) {
    assert.ok(file.endsWith('.js'), `Key should be a .js filename: ${file}`);
    assert.strictEqual(hash.length, 64, `Hash for ${file} should be 64 hex chars`);
    assert.ok(/^[0-9a-f]{64}$/.test(hash), `Hash for ${file} should be lowercase hex`);
  }
});

// -- verifyHooks: all ok ----------------------------------------------------

test('verifyHooks returns ok for matching files', () => {
  const dir = tmpDir();
  const checksums = loadChecksums();

  // Copy actual hook files to temp dir
  const hooksDir = path.join(__dirname, '..', 'hooks');
  for (const file of Object.keys(checksums)) {
    fs.copyFileSync(path.join(hooksDir, file), path.join(dir, file));
  }

  const result = verifyHooks(dir);
  assert.ok(result.results.length > 0, 'Should have results');

  for (const r of result.results) {
    assert.strictEqual(r.status, 'ok', `${r.name} should be ok, got ${r.status}`);
  }

  fs.rmSync(dir, { recursive: true });
});

// -- verifyHooks: tampered --------------------------------------------------

test('verifyHooks detects tampered hook', () => {
  const dir = tmpDir();
  const checksums = loadChecksums();

  // Copy actual hook files
  const hooksDir = path.join(__dirname, '..', 'hooks');
  for (const file of Object.keys(checksums)) {
    fs.copyFileSync(path.join(hooksDir, file), path.join(dir, file));
  }

  // Tamper with one file
  const firstFile = Object.keys(checksums)[0];
  const tamperedPath = path.join(dir, firstFile);
  fs.appendFileSync(tamperedPath, '\n// tampered\n');

  const result = verifyHooks(dir);
  const tampered = result.results.find(r => r.name === firstFile);

  assert.ok(tampered, `Should find result for ${firstFile}`);
  assert.strictEqual(tampered.status, 'tampered', 'Tampered file should be detected');
  assert.ok(tampered.expected, 'Should include expected hash');
  assert.ok(tampered.actual, 'Should include actual hash');
  assert.notStrictEqual(tampered.expected, tampered.actual, 'Hashes should differ');

  fs.rmSync(dir, { recursive: true });
});

// -- verifyHooks: missing ---------------------------------------------------

test('verifyHooks detects missing hook', () => {
  const dir = tmpDir();
  // Empty directory — all hooks are "missing"

  const result = verifyHooks(dir);
  assert.ok(result.results.length > 0, 'Should have results');

  for (const r of result.results) {
    assert.strictEqual(r.status, 'missing', `${r.name} should be missing, got ${r.status}`);
    assert.ok(r.expected, 'Missing result should include expected hash');
  }

  fs.rmSync(dir, { recursive: true });
});

// -- verifyHooks: partial install -------------------------------------------

test('verifyHooks handles mix of ok, tampered, and missing', () => {
  const dir = tmpDir();
  const checksums = loadChecksums();
  const files = Object.keys(checksums);

  assert.ok(files.length >= 3, 'Need at least 3 hooks for this test');

  const hooksDir = path.join(__dirname, '..', 'hooks');

  // First file: copy correctly (ok)
  fs.copyFileSync(path.join(hooksDir, files[0]), path.join(dir, files[0]));

  // Second file: tamper
  fs.copyFileSync(path.join(hooksDir, files[1]), path.join(dir, files[1]));
  fs.appendFileSync(path.join(dir, files[1]), '// injected');

  // Third file: don't copy (missing)

  const result = verifyHooks(dir);

  const statuses = {};
  for (const r of result.results) {
    statuses[r.name] = r.status;
  }

  assert.strictEqual(statuses[files[0]], 'ok');
  assert.strictEqual(statuses[files[1]], 'tampered');
  assert.strictEqual(statuses[files[2]], 'missing');

  fs.rmSync(dir, { recursive: true });
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('');
console.log(`${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
