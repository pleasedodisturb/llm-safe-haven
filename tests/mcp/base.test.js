'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {
  readConfigSafe,
  stripProtoPollution,
  MAX_CONFIG_SIZE,
} = require('../../lib/mcp/base.js');

describe('readConfigSafe', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-mcp-base-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns { ok:false, reason:"symlink", code:2 } for a symlinked config (checked via lstatSync, never following the link)', () => {
    const targetPath = path.join(tmpDir, 'target.json');
    fs.writeFileSync(targetPath, '{"mcpServers":{}}');
    const linkPath = path.join(tmpDir, 'link.json');
    fs.symlinkSync(targetPath, linkPath);

    const result = readConfigSafe(linkPath);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'symlink');
    assert.strictEqual(result.code, 2);
  });

  it('returns { ok:false, reason:"oversized", code:2 } for a file over MAX_CONFIG_SIZE', () => {
    const bigPath = path.join(tmpDir, 'big.json');
    const oversized = Buffer.alloc(MAX_CONFIG_SIZE + 1, 'a');
    fs.writeFileSync(bigPath, oversized);

    const result = readConfigSafe(bigPath);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'oversized');
    assert.strictEqual(result.code, 2);
  });

  it('returns { ok:false, reason:"unreadable", code:2 } for a nonexistent path, and never throws', () => {
    const missingPath = path.join(tmpDir, 'does-not-exist.json');

    let result;
    assert.doesNotThrow(() => {
      result = readConfigSafe(missingPath);
    });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unreadable');
    assert.strictEqual(result.code, 2);
  });

  it('returns { ok:true, raw } for a well-formed small regular file', () => {
    const goodPath = path.join(tmpDir, 'good.json');
    fs.writeFileSync(goodPath, '{"mcpServers":{}}');

    const result = readConfigSafe(goodPath);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.raw, '{"mcpServers":{}}');
  });

  it('never throws for any hostile input class (symlink, oversized, unreadable)', () => {
    const linkPath = path.join(tmpDir, 'link2.json');
    const targetPath = path.join(tmpDir, 'target2.json');
    fs.writeFileSync(targetPath, '{}');
    fs.symlinkSync(targetPath, linkPath);

    assert.doesNotThrow(() => readConfigSafe(linkPath));
    assert.doesNotThrow(() => readConfigSafe(path.join(tmpDir, 'nope.json')));
  });
});

describe('stripProtoPollution', () => {
  it('deletes __proto__, constructor, and prototype own-keys and returns the object', () => {
    const obj = JSON.parse('{"__proto__":{"polluted":true},"constructor":"bad","prototype":"bad","safe":"value"}');
    const result = stripProtoPollution(obj);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, '__proto__'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, 'constructor'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, 'prototype'), false);
    assert.strictEqual(result.safe, 'value');
  });

  it('returns {} for a non-plain-object input (array)', () => {
    const result = stripProtoPollution([1, 2, 3]);
    assert.deepStrictEqual(result, {});
  });

  it('returns {} for a non-plain-object input (null)', () => {
    const result = stripProtoPollution(null);
    assert.deepStrictEqual(result, {});
  });

  it('returns {} for a non-plain-object input (primitive string)', () => {
    const result = stripProtoPollution('not an object');
    assert.deepStrictEqual(result, {});
  });
});
