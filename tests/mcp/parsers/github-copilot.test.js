'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { parse, agentId } = require('../../../lib/mcp/parsers/github-copilot.js');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'github-copilot');

function source(fixtureName, scope = 'project') {
  return { agentId: 'github-copilot', scope, path: path.join(FIXTURES, fixtureName), format: 'jsonc' };
}

describe('parsers/github-copilot', () => {
  it('exports agentId "github-copilot"', () => {
    assert.strictEqual(agentId, 'github-copilot');
  });

  it('parses a well-formed JSONC config keyed on `servers` into normalized servers', () => {
    const result = parse(source('valid.jsonc'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 2);

    const local = result.servers.find(s => s.name === 'local-server');
    assert.ok(local);
    assert.strictEqual(local.agentId, 'github-copilot');
    assert.strictEqual(local.command, 'node');
    assert.deepStrictEqual(local.args, ['server.js', '--flag']);
    assert.strictEqual(local.env.API_KEY, '${input:api-key}');
    assert.deepStrictEqual(Object.keys(local).sort(), [
      'agentId', 'args', 'command', 'configPath', 'env', 'headers', 'name', 'scope', 'url',
    ]);
    // type/envFile are read-and-ignored — never leak into the normalized
    // shape.
    assert.strictEqual(Object.prototype.hasOwnProperty.call(local, 'type'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(local, 'envFile'), false);
  });

  it('a URL value survives JSONC stripping (no truncation on the // in https://)', () => {
    const result = parse(source('valid.jsonc'));
    const remote = result.servers.find(s => s.name === 'remote-server');
    assert.ok(remote);
    assert.strictEqual(remote.url, 'https://mcp.example.com/mcp');
  });

  it('ignores top-level `inputs` and `sandbox` — only `servers` entries surface', () => {
    const result = parse(source('inputs-ignored.jsonc'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 1);
    assert.strictEqual(result.servers[0].name, 'local-server');
    assert.ok(!result.servers.some(s => s.name === 'inputs' || s.name === 'sandbox'));
  });

  it('malformed JSONC returns { ok:false, reason:"malformed", code:2 }', () => {
    const result = parse(source('malformed.jsonc'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'malformed');
    assert.strictEqual(result.code, 2);
  });

  it('a config containing only prototype-pollution keys under `servers` returns reason "polluted"', () => {
    const result = parse(source('proto-poisoned.jsonc'));
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

  describe('key discipline (D-07 non-vacuity)', () => {
    let tmpDir;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-mcp-copilot-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('a fixture keyed on `mcpServers` instead of `servers` yields zero servers (proves the parser keys on `servers` only)', () => {
      const configPath = path.join(tmpDir, 'mcp.json');
      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: { should_be_ignored: { command: 'node', args: ['x.js'] } },
      }));
      const result = parse({ agentId: 'github-copilot', scope: 'project', path: configPath, format: 'jsonc' });
      assert.strictEqual(result.ok, true);
      assert.deepStrictEqual(result.servers, []);
    });
  });
});
