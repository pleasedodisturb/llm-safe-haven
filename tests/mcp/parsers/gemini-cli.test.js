'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { parse, agentId } = require('../../../lib/mcp/parsers/gemini-cli.js');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'gemini-cli');

function source(fixtureName, scope = 'user') {
  return { agentId: 'gemini-cli', scope, path: path.join(FIXTURES, fixtureName), format: 'json' };
}

describe('parsers/gemini-cli', () => {
  it('exports agentId "gemini-cli"', () => {
    assert.strictEqual(agentId, 'gemini-cli');
  });

  it('parses a well-formed config into normalized servers', () => {
    const result = parse(source('valid.json'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 2);

    const local = result.servers.find(s => s.name === 'local-server');
    assert.ok(local);
    assert.strictEqual(local.agentId, 'gemini-cli');
    assert.strictEqual(local.command, 'node');
    assert.deepStrictEqual(local.args, ['server.js', '--flag']);
    assert.strictEqual(local.env.API_KEY, '${env:API_KEY}');
    assert.deepStrictEqual(Object.keys(local).sort(), [
      'agentId', 'args', 'command', 'configPath', 'env', 'headers', 'name', 'scope', 'url',
    ]);
    // cwd/trust/includeTools/excludeTools are read-and-ignored — they must
    // never leak into the normalized shape.
    assert.strictEqual(Object.prototype.hasOwnProperty.call(local, 'cwd'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(local, 'trust'), false);
  });

  it('maps httpUrl into the normalized url field (non-vacuous — a parser ignoring httpUrl would fail this)', () => {
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

  it('CR-01: a server named __proto__ ALONGSIDE a legit server fails closed (polluted, code 2) — never silently dropped with exit 0', () => {
    const result = parse(source('proto-mixed.json'));
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

  it('tags returned servers with the caller-provided scope', () => {
    const result = parse(source('valid.json', 'project'));
    assert.strictEqual(result.ok, true);
    for (const server of result.servers) {
      assert.strictEqual(server.scope, 'project');
    }
  });
});
