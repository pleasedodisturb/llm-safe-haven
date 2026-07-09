'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { parse, agentId } = require('../../../lib/mcp/parsers/cline.js');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'cline');

function source(fixtureName) {
  return { agentId: 'cline', scope: 'global', path: path.join(FIXTURES, fixtureName) };
}

describe('parsers/cline', () => {
  it('exports agentId "cline"', () => {
    assert.strictEqual(agentId, 'cline');
  });

  it('parses a well-formed JSONC config into normalized servers', () => {
    const result = parse(source('good.jsonc'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 2);
    const local = result.servers.find(s => s.name === 'local-server');
    assert.ok(local);
    assert.strictEqual(local.agentId, 'cline');
    assert.strictEqual(local.command, 'node');
    assert.deepStrictEqual(local.args, ['server.js']);
    assert.strictEqual(local.env.API_KEY, '${env:API_KEY}');
    assert.deepStrictEqual(Object.keys(local).sort(), [
      'agentId', 'args', 'command', 'configPath', 'env', 'headers', 'name', 'scope', 'url',
    ]);
  });

  it('a URL value survives JSONC stripping (no truncation on the // in https://)', () => {
    const result = parse(source('good.jsonc'));
    const remote = result.servers.find(s => s.name === 'remote-server');
    assert.ok(remote);
    assert.strictEqual(remote.url, 'https://mcp.example.com/mcp');
  });

  it('malformed JSONC returns { ok:false, reason:"malformed", code:2 }', () => {
    const result = parse(source('malformed.jsonc'));
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
    const result = parse(source('does-not-exist.jsonc'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unreadable');
    assert.strictEqual(result.code, 2);
  });
});
