'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { parse, agentId, _extractServers } = require('../../../lib/mcp/parsers/claude-code.js');
const { MAX_CONFIG_SIZE } = require('../../../lib/mcp/base.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'claude-code');
const EXPECTED_SERVER_KEYS = ['agentId', 'args', 'command', 'configPath', 'env', 'headers', 'name', 'scope', 'url'];

function makeSource(scope, fixtureName) {
  return { agentId: 'claude-code', scope, path: path.join(FIXTURES_DIR, fixtureName), format: 'json' };
}

describe('claude-code parser', () => {
  it('exports agentId "claude-code"', () => {
    assert.strictEqual(agentId, 'claude-code');
  });

  describe('dual-scope extraction (Pitfall 3)', () => {
    it('user scope extracts the top-level mcpServers entry', () => {
      const result = parse(makeSource('user', 'dual-scope.json'));
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers.length, 1);
      assert.strictEqual(result.servers[0].scope, 'user');
      assert.strictEqual(result.servers[0].name, 'user-server');
    });

    it('local scope extracts projects[<cwd>].mcpServers when opts.cwd matches the fixture key', () => {
      const result = parse(makeSource('local', 'dual-scope.json'), { cwd: '/repo' });
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers.length, 1);
      assert.strictEqual(result.servers[0].scope, 'local');
      assert.strictEqual(result.servers[0].name, 'local-server');
    });

    it('BOTH user and local servers are present when parsing the SAME dual-scope fixture — neither is silently dropped', () => {
      const userResult = parse(makeSource('user', 'dual-scope.json'));
      const localResult = parse(makeSource('local', 'dual-scope.json'), { cwd: '/repo' });
      assert.strictEqual(userResult.ok, true);
      assert.strictEqual(localResult.ok, true);
      const combined = [...userResult.servers, ...localResult.servers];
      assert.strictEqual(combined.length, 2);
      assert.deepStrictEqual(combined.map(s => s.scope).sort(), ['local', 'user']);
      assert.deepStrictEqual(combined.map(s => s.name).sort(), ['local-server', 'user-server']);
    });

    it('local scope yields no servers when opts.cwd does not match any projects[] key', () => {
      const result = parse(makeSource('local', 'dual-scope.json'), { cwd: '/no-such-project' });
      assert.strictEqual(result.ok, true);
      assert.deepStrictEqual(result.servers, []);
    });

    it('defaults opts.cwd to process.cwd() when not injected', () => {
      const result = parse(makeSource('local', 'dual-scope.json'));
      assert.strictEqual(result.ok, true);
      // process.cwd() during test run is never "/repo", so no match expected.
      assert.deepStrictEqual(result.servers, []);
    });
  });

  describe('project scope (.mcp.json)', () => {
    it('parseMcpJson-equivalent extraction returns servers tagged scope project', () => {
      const result = parse(makeSource('project', 'mcp-json-project.json'));
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers.length, 1);
      assert.strictEqual(result.servers[0].scope, 'project');
      assert.strictEqual(result.servers[0].name, 'project-server');
    });
  });

  describe('hostile input handling', () => {
    it('returns { ok:false, reason:"malformed", code:2 } for invalid JSON — never ok:true with an empty list', () => {
      const result = parse(makeSource('project', 'malformed.json'));
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'malformed');
      assert.strictEqual(result.code, 2);
    });

    it('returns { ok:false, reason:"polluted", code:2 } when mcpServers\' only content is a __proto__ key', () => {
      const result = parse(makeSource('project', 'proto-poisoned.json'));
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'polluted');
      assert.strictEqual(result.code, 2);
    });

    it('CR-01: a server named __proto__ ALONGSIDE a legit server fails closed (polluted, code 2) — never silently dropped with exit 0', () => {
      const result = parse(makeSource('project', 'proto-mixed.json'));
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'polluted');
      assert.strictEqual(result.code, 2);
    });

    describe('symlink / oversized delegation to readConfigSafe', () => {
      let tmpDir;

      beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-mcp-claude-code-test-'));
      });

      afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      });

      it('returns reason "symlink" code 2 for a symlinked config, never following the link', () => {
        const targetPath = path.join(tmpDir, 'target.json');
        fs.writeFileSync(targetPath, '{"mcpServers":{}}');
        const linkPath = path.join(tmpDir, 'link.json');
        fs.symlinkSync(targetPath, linkPath);

        const result = parse({ agentId: 'claude-code', scope: 'project', path: linkPath, format: 'json' });
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.reason, 'symlink');
        assert.strictEqual(result.code, 2);
      });

      it('returns reason "oversized" code 2 for a file over MAX_CONFIG_SIZE', () => {
        const bigPath = path.join(tmpDir, 'big.json');
        fs.writeFileSync(bigPath, Buffer.alloc(MAX_CONFIG_SIZE + 1, 'a'));

        const result = parse({ agentId: 'claude-code', scope: 'project', path: bigPath, format: 'json' });
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.reason, 'oversized');
        assert.strictEqual(result.code, 2);
      });
    });
  });

  describe('normalized server shape', () => {
    it('every returned server matches the normalizeServer 9-key shape with agentId "claude-code"', () => {
      const result = parse(makeSource('user', 'dual-scope.json'));
      assert.strictEqual(result.ok, true);
      for (const server of result.servers) {
        assert.deepStrictEqual(Object.keys(server).sort(), EXPECTED_SERVER_KEYS);
        assert.strictEqual(server.agentId, 'claude-code');
        assert.strictEqual(server.command, 'node');
        assert.deepStrictEqual(server.args, server.name === 'user-server' ? ['user-server.js'] : server.args);
      }
    });
  });

  describe('_extractServers internal helper', () => {
    it('treats an absent mcpServers value as zero servers, not pollution', () => {
      const result = _extractServers(undefined, 'claude-code', 'user', '/fake/.claude.json');
      assert.strictEqual(result.ok, true);
      assert.deepStrictEqual(result.servers, []);
    });

    // WR-01: this previously asserted ok:true with [] — silently treating
    // a structurally wrong mcpServers as "nothing configured", diverging
    // from windsurf/cline (which returned malformed code 2). The review
    // proved that divergence hostile-unsafe: a payload's detectability
    // must never depend on which agent's file it lands in, and malformed
    // input must surface as exit 2, never pass as clean.
    it('treats a non-object mcpServers value as malformed (code 2), matching the shared container policy', () => {
      const result = _extractServers('not-an-object', 'claude-code', 'user', '/fake/.claude.json');
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'malformed');
      assert.strictEqual(result.code, 2);
    });

    it('treats an array mcpServers value as malformed (code 2), matching the shared container policy', () => {
      const result = _extractServers(['x'], 'claude-code', 'user', '/fake/.claude.json');
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'malformed');
      assert.strictEqual(result.code, 2);
    });
  });
});
