'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {
  readConfigSafe,
  stripProtoPollution,
  stripJsonc,
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

describe('stripJsonc', () => {
  // Combines a // line comment, a /* block */ comment, a trailing comma
  // before }, and a URL value containing // in one blob — the single
  // fixture required by RESEARCH.md Pattern 6 / Pitfall 5.
  const blob = `{
  // this is a line comment
  "name": "test-server", /* inline block comment */
  "url": "https://mcp.example.com/mcp",
  "args": ["a", "b",],
}`;

  it('removes // line comments and /* block */ comments and trailing commas', () => {
    const stripped = stripJsonc(blob);
    const parsed = JSON.parse(stripped);
    assert.strictEqual(parsed.name, 'test-server');
    assert.deepStrictEqual(parsed.args, ['a', 'b']);
  });

  it('does NOT truncate a URL value containing //', () => {
    const stripped = stripJsonc(blob);
    const parsed = JSON.parse(stripped);
    assert.strictEqual(parsed.url, 'https://mcp.example.com/mcp');
  });

  it('does not strip a // that appears inside a string literal', () => {
    const input = '{"comment_lookalike": "http://example.com//path"}';
    const parsed = JSON.parse(stripJsonc(input));
    assert.strictEqual(parsed.comment_lookalike, 'http://example.com//path');
  });

  it('preserves escaped quotes inside strings so string boundaries are tracked correctly', () => {
    const input = '{"quoted": "a \\"quoted\\" value // not a comment"}';
    const parsed = JSON.parse(stripJsonc(input));
    assert.strictEqual(parsed.quoted, 'a "quoted" value // not a comment');
  });

  it('produces output parseable by JSON.parse for a full valid JSONC sample', () => {
    assert.doesNotThrow(() => JSON.parse(stripJsonc(blob)));
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
