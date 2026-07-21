'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parse, agentId } = require('../../../lib/mcp/parsers/antigravity.js');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'antigravity');

function source(fixtureName, scope = 'global') {
  return { agentId: 'antigravity', scope, path: path.join(FIXTURES, fixtureName), format: 'json' };
}

describe('parsers/antigravity', () => {
  it('exports agentId "antigravity"', () => {
    assert.strictEqual(agentId, 'antigravity');
  });

  it('parses a well-formed config into normalized servers', () => {
    const result = parse(source('valid.json'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 2);

    const local = result.servers.find(s => s.name === 'local-server');
    assert.ok(local);
    assert.strictEqual(local.agentId, 'antigravity');
    assert.strictEqual(local.command, 'node');
    assert.deepStrictEqual(local.args, ['server.js', '--flag']);
    assert.strictEqual(local.env.API_KEY, '${env:API_KEY}');
    assert.deepStrictEqual(Object.keys(local).sort(), [
      'agentId', 'args', 'command', 'configPath', 'env', 'headers', 'name', 'scope', 'url',
    ]);
    // authProviderType/oauth are read-and-ignored — never leak into the
    // normalized shape.
    assert.strictEqual(Object.prototype.hasOwnProperty.call(local, 'authProviderType'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(local, 'oauth'), false);
  });

  it('maps serverUrl into the normalized url field (non-vacuous — a parser ignoring serverUrl would fail this)', () => {
    const result = parse(source('valid.json'));
    const remote = result.servers.find(s => s.name === 'remote-server');
    assert.ok(remote);
    assert.strictEqual(remote.url, 'https://mcp.example.com/mcp');
  });

  it('malformed JSON returns { ok:false, reason:"malformed", code:2 }', () => {
    const result = parse(source('malformed.json'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'malformed');
    assert.strictEqual(result.code, 2);
  });

  it('a config containing only prototype-pollution keys returns reason "polluted"', () => {
    const result = parse(source('proto-poisoned.json'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'polluted');
    assert.strictEqual(result.code, 2);
  });

  it('propagates readConfigSafe failures (symlink/oversized/unreadable) unchanged', () => {
    const result = parse(source('does-not-exist.json'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unreadable');
    assert.strictEqual(result.code, 2);
  });

  it('resolved path never leaks the sibling IDE-adjacent agent\'s directory ancestry (Pitfall 1 regression)', () => {
    // Regression guard: the parser module source must never reference the
    // other agent's codeium/windsurf path convention for Antigravity
    // (D-06 hard gate) — the resolved path is ~/.gemini/config/, unrelated.
    const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'parsers', 'antigravity.js'), 'utf8');
    assert.strictEqual(/codeium|windsurf/i.test(src), false);
  });
});
