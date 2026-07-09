'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { parse, agentId, _extractServers } = require('../../../lib/mcp/parsers/cursor.js');
const { MAX_CONFIG_SIZE } = require('../../../lib/mcp/base.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'cursor');
const EXPECTED_SERVER_KEYS = ['agentId', 'args', 'command', 'configPath', 'env', 'headers', 'name', 'scope', 'url'];

function makeSource(scope, fixtureName) {
  return { agentId: 'cursor', scope, path: path.join(FIXTURES_DIR, fixtureName), format: 'jsonc' };
}

describe('cursor parser', () => {
  it('exports agentId "cursor"', () => {
    assert.strictEqual(agentId, 'cursor');
  });

  describe('JSONC with URL-survival (Pitfall 5 regression)', () => {
    it('parses a JSONC config with // comment, /* block */ comment, and trailing commas', () => {
      const result = parse(makeSource('global', 'with-comments-and-url.jsonc'));
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers.length, 1);
      assert.strictEqual(result.servers[0].name, 'example-server');
      assert.strictEqual(result.servers[0].command, 'node');
      assert.deepStrictEqual(result.servers[0].args, ['server.js']);
    });

    it('the URL value survives intact — NOT truncated at the // inside https://', () => {
      const result = parse(makeSource('global', 'with-comments-and-url.jsonc'));
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers[0].url, 'https://mcp.example.com/mcp');
    });

    it('tags returned servers with the caller-provided scope', () => {
      const result = parse(makeSource('project', 'with-comments-and-url.jsonc'));
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers[0].scope, 'project');
    });
  });

  describe('hostile input handling', () => {
    it('returns { ok:false, reason:"malformed", code:2 } for JSONC that is still broken after comment/comma stripping', () => {
      const result = parse(makeSource('global', 'malformed.jsonc'));
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'malformed');
      assert.strictEqual(result.code, 2);
    });

    it('returns { ok:false, reason:"polluted", code:2 } when mcpServers\' only content is a __proto__ key', () => {
      const result = parse(makeSource('global', 'proto-poisoned.jsonc'));
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'polluted');
      assert.strictEqual(result.code, 2);
    });

    it('CR-01: a server named __proto__ ALONGSIDE a legit server fails closed (polluted, code 2) — never silently dropped with exit 0', () => {
      const result = parse(makeSource('global', 'proto-mixed.jsonc'));
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'polluted');
      assert.strictEqual(result.code, 2);
    });

    it('CR-01: a server named constructor or prototype alongside legit servers also fails closed', () => {
      for (const hostileName of ['constructor', 'prototype']) {
        const result = _extractServers(
          JSON.parse(`{"legit":{"command":"node"},"${hostileName}":{"command":"curl"}}`),
          'cursor', 'global', '/fake/.cursor/mcp.json'
        );
        assert.strictEqual(result.ok, false, `${hostileName} must fail closed`);
        assert.strictEqual(result.reason, 'polluted');
        assert.strictEqual(result.code, 2);
      }
    });

    describe('symlink / oversized delegation to readConfigSafe (identical to Claude Code)', () => {
      let tmpDir;

      beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-mcp-cursor-test-'));
      });

      afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      });

      it('returns reason "symlink" code 2 for a symlinked config, never following the link', () => {
        const targetPath = path.join(tmpDir, 'target.jsonc');
        fs.writeFileSync(targetPath, '{"mcpServers":{}}');
        const linkPath = path.join(tmpDir, 'link.jsonc');
        fs.symlinkSync(targetPath, linkPath);

        const result = parse({ agentId: 'cursor', scope: 'global', path: linkPath, format: 'jsonc' });
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.reason, 'symlink');
        assert.strictEqual(result.code, 2);
      });

      it('returns reason "oversized" code 2 for a file over MAX_CONFIG_SIZE', () => {
        const bigPath = path.join(tmpDir, 'big.jsonc');
        fs.writeFileSync(bigPath, Buffer.alloc(MAX_CONFIG_SIZE + 1, 'a'));

        const result = parse({ agentId: 'cursor', scope: 'global', path: bigPath, format: 'jsonc' });
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.reason, 'oversized');
        assert.strictEqual(result.code, 2);
      });
    });
  });

  describe('normalized server shape', () => {
    it('every returned server matches the normalizeServer 9-key shape with agentId "cursor"', () => {
      const result = parse(makeSource('global', 'with-comments-and-url.jsonc'));
      assert.strictEqual(result.ok, true);
      for (const server of result.servers) {
        assert.deepStrictEqual(Object.keys(server).sort(), EXPECTED_SERVER_KEYS);
        assert.strictEqual(server.agentId, 'cursor');
      }
    });
  });

  describe('_extractServers internal helper', () => {
    it('treats an absent mcpServers value as zero servers, not pollution', () => {
      const result = _extractServers(undefined, 'cursor', 'global', '/fake/.cursor/mcp.json');
      assert.strictEqual(result.ok, true);
      assert.deepStrictEqual(result.servers, []);
    });
  });
});
