'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { writeIgnoreFile, SENSITIVE_PATTERNS } = require('../../lib/agents/base.js');

describe('writeIgnoreFile', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-base-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates file when it does not exist', () => {
    const result = writeIgnoreFile(tmpDir, '.testignore', ['.env', '*.pem'], false);
    assert.strictEqual(result.written, true);
    assert.ok(fs.existsSync(result.path), 'file should exist on disk');

    const content = fs.readFileSync(result.path, 'utf8');
    assert.ok(content.includes('.env'), 'file should contain .env pattern');
    assert.ok(content.includes('*.pem'), 'file should contain *.pem pattern');
  });

  it('skips when file already exists (returns reason: already exists)', () => {
    const filePath = path.join(tmpDir, '.testignore');
    fs.writeFileSync(filePath, '# existing content\n');

    const result = writeIgnoreFile(tmpDir, '.testignore', ['.env'], false);
    assert.strictEqual(result.written, false);
    assert.strictEqual(result.reason, 'already exists');

    // Original content should be preserved
    const content = fs.readFileSync(filePath, 'utf8');
    assert.strictEqual(content, '# existing content\n');
  });

  it('respects dryRun flag (returns reason: dry-run, does not write)', () => {
    const result = writeIgnoreFile(tmpDir, '.testignore', ['.env'], true);
    assert.strictEqual(result.written, false);
    assert.strictEqual(result.reason, 'dry-run');
    assert.ok(!fs.existsSync(result.path), 'file should NOT exist on disk in dry-run mode');
  });
});

describe('SENSITIVE_PATTERNS', () => {
  it('is a non-empty array', () => {
    assert.ok(Array.isArray(SENSITIVE_PATTERNS), 'SENSITIVE_PATTERNS should be an array');
    assert.ok(SENSITIVE_PATTERNS.length > 0, 'SENSITIVE_PATTERNS should not be empty');
  });
});
