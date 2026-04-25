'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { _backupFile: backupFile } = require('../lib/agents/claude-code.js');

describe('backupFile', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-backup-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns null when the source file does not exist', () => {
    const result = backupFile(path.join(tmpDir, 'nonexistent.json'));
    assert.equal(result, null);
  });

  it('creates a backup with .bak. and ISO timestamp in the filename', () => {
    const filePath = path.join(tmpDir, 'settings.json');
    fs.writeFileSync(filePath, '{"hello":"world"}');

    const result = backupFile(filePath);

    assert.notEqual(result, null);
    assert.ok(fs.existsSync(result), 'backup file should exist on disk');
    assert.match(path.basename(result), /^settings\.json\.bak\.\d{4}-\d{2}-\d{2}T\d{6}/);
    // Verify no colons in the backup filename (filesystem-safe)
    assert.ok(!path.basename(result).includes(':'), 'backup filename must not contain colons');
  });

  it('preserves the original file content in the backup', () => {
    const filePath = path.join(tmpDir, 'settings.json');
    const content = '{"hooks":{"PreToolUse":[]}}';
    fs.writeFileSync(filePath, content);

    const result = backupFile(filePath);

    assert.equal(fs.readFileSync(result, 'utf8'), content);
  });

  it('keeps only the 3 most recent backups', () => {
    const filePath = path.join(tmpDir, 'settings.json');
    fs.writeFileSync(filePath, 'v1');

    // Create 5 pre-existing backups with known timestamps
    const timestamps = [
      '2026-04-20T100000.000Z',
      '2026-04-21T100000.000Z',
      '2026-04-22T100000.000Z',
      '2026-04-23T100000.000Z',
      '2026-04-24T100000.000Z',
    ];
    for (const ts of timestamps) {
      fs.writeFileSync(path.join(tmpDir, `settings.json.bak.${ts}`), 'old');
    }

    // Call backupFile which adds one more (total 6) then trims to 3
    const result = backupFile(filePath);
    assert.notEqual(result, null);

    const backups = fs.readdirSync(tmpDir)
      .filter(f => f.startsWith('settings.json.bak.'))
      .sort();

    assert.equal(backups.length, 3, `expected 3 backups, got ${backups.length}: ${backups.join(', ')}`);

    // The kept backups should be the 3 newest (the two latest pre-existing + the new one)
    // The oldest 3 should have been deleted
    for (const ts of timestamps.slice(0, 3)) {
      const oldFile = path.join(tmpDir, `settings.json.bak.${ts}`);
      assert.ok(!fs.existsSync(oldFile), `old backup ${ts} should have been deleted`);
    }
  });

  it('does not fail when backup directory is read-only (graceful error handling)', () => {
    // Use a path inside a non-existent directory to simulate write failure
    const badPath = path.join(tmpDir, 'no-such-dir', 'settings.json');

    // Should return null, not throw
    const result = backupFile(badPath);
    assert.equal(result, null);
  });

  it('backup is placed in the same directory as the source file', () => {
    const subDir = path.join(tmpDir, 'sub');
    fs.mkdirSync(subDir);
    const filePath = path.join(subDir, 'settings.json');
    fs.writeFileSync(filePath, '{}');

    const result = backupFile(filePath);

    assert.equal(path.dirname(result), subDir);
  });
});
