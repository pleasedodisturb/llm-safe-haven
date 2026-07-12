'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { id, requirement, run } = require('../../../lib/mcp/detectors/typosquat.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'typosquat');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, `${name}.json`), 'utf8'));
}

function makeServer(overrides = {}) {
  return {
    agentId: 'claude-code',
    scope: 'user',
    configPath: '/fake/.claude.json',
    name: 'test-server',
    command: null,
    args: [],
    env: {},
    url: null,
    headers: {},
    ...overrides,
  };
}

describe('typosquat detector (MCPD-03)', () => {
  it('exports id "typosquat" and requirement "MCPD-03"', () => {
    assert.strictEqual(id, 'typosquat');
    assert.strictEqual(requirement, 'MCPD-03');
  });

  describe('bad fixture (real bundled allowlist)', () => {
    it('flags @modelcontextprotocol/server-filesytem (dist 1 from server-filesystem)', () => {
      const findings = run(loadFixture('bad'), {});
      assert.ok(findings.some(f =>
        f.id === 'typosquat/near-known-name' && f.serverName === 'npx-typo-filesystem'));
    });

    it('flags a uvx server installing mcp-server-fetc (dist 1 from mcp-server-fetch)', () => {
      const findings = run(loadFixture('bad'), {});
      assert.ok(findings.some(f =>
        f.id === 'typosquat/near-known-name' && f.serverName === 'uvx-typo-fetch'));
    });

    it('flags @upstash/kontext7-mcp as a SEPARATE finding against the full-spec-stored @upstash/context7-mcp (comparison class 3)', () => {
      const findings = run(loadFixture('bad'), {});
      const hit = findings.find(f =>
        f.id === 'typosquat/near-known-name' && f.serverName === 'npx-typo-kontext7');
      assert.ok(hit, 'expected a near-known-name finding for the kontext7 server');
      assert.ok(hit.message.includes('@upstash/context7-mcp'), `message should name the matched full-spec entry: ${hit.message}`);
    });

    it('flags a scope-squat (@modelcontextprotocoI, capital I) via scope-segment comparison (D-02)', () => {
      const findings = run(loadFixture('bad'), {});
      assert.ok(findings.some(f =>
        f.id === 'typosquat/near-known-name' && f.serverName === 'npx-scope-squat-memory'));
    });

    it('flags the typosquat when the server NAME is benign but the args carry it (Pitfall 2 — compares derived pkgName, not server.name)', () => {
      const findings = run(loadFixture('bad'), {});
      assert.ok(findings.some(f =>
        f.id === 'typosquat/near-known-name' && f.serverName === 'totally-safe-server'));
    });

    it('every emitted finding is severity high, confidence verified, id typosquat/near-known-name (D-05)', () => {
      const findings = run(loadFixture('bad'), {});
      assert.ok(findings.length > 0);
      for (const f of findings) {
        assert.strictEqual(f.severity, 'high');
        assert.strictEqual(f.confidence, 'verified');
        assert.strictEqual(f.id, 'typosquat/near-known-name');
        assert.strictEqual(f.detector, 'typosquat');
      }
    });

    it('produces exactly 5 findings (one per typosquat server in the fixture)', () => {
      const findings = run(loadFixture('bad'), {});
      assert.strictEqual(findings.length, 5);
    });
  });

  describe('clean fixture — exact matches never flag, even near other entries (D-02)', () => {
    it('produces zero findings on the clean, exact-match fixture', () => {
      assert.deepStrictEqual(run(loadFixture('clean'), {}), []);
    });

    it('a url-only server yields zero findings (D-01 — never compares server.url)', () => {
      const servers = [makeServer({ command: null, args: [], url: 'https://mcp.example.com/x' })];
      assert.deepStrictEqual(run(servers, {}), []);
    });
  });

  describe('combosquat fixture — honest limitation, zero findings (D-04)', () => {
    it('produces ZERO findings for an MCP-flavored combosquat (edit distance far outside threshold)', () => {
      assert.deepStrictEqual(run(loadFixture('combosquat'), {}), []);
    });
  });

  describe('D-02/D-03 algorithm edge cases (isolated synthetic allowlist)', () => {
    let tmpDir;
    let manifestPath;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-typosquat-test-'));
      manifestPath = path.join(tmpDir, 'mini-manifest.json');
      fs.writeFileSync(manifestPath, JSON.stringify({
        manifestVersion: 1,
        updated: '2026-07-12',
        knownScopes: ['@acme'],
        servers: ['server-git', 'server-got', 'abc'],
      }));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('D-02: an exact match short-circuits to zero findings even when within threshold of a DIFFERENT entry (server-git never flagged for proximity to server-got)', () => {
      const servers = [makeServer({ command: 'npx', args: ['server-git'] })];
      assert.deepStrictEqual(run(servers, { manifestPath }), []);
    });

    it('sanity: a genuine near-miss against this mini allowlist IS flagged', () => {
      const servers = [makeServer({ command: 'npx', args: ['server-gyt'] })];
      const findings = run(servers, { manifestPath });
      assert.ok(findings.some(f => f.id === 'typosquat/near-known-name'));
    });

    it('D-03 FP guard: segments under 4 characters are never matched, even at distance 1', () => {
      const servers = [makeServer({ command: 'npx', args: ['abd'] })];
      assert.deepStrictEqual(run(servers, { manifestPath }), []);
    });
  });

  describe('D-07: manifest load failure', () => {
    it('a missing manifest file yields exactly ONE typosquat/allowlist-unavailable finding (info, unverified), never [] and never a throw', () => {
      const servers = loadFixture('bad');
      let findings;
      assert.doesNotThrow(() => {
        findings = run(servers, { manifestPath: '/does/not/exist/mcp-known-servers.json' });
      });
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].id, 'typosquat/allowlist-unavailable');
      assert.strictEqual(findings[0].severity, 'info');
      assert.strictEqual(findings[0].confidence, 'unverified');
    });

    it('a corrupt (non-JSON) manifest file also yields exactly one allowlist-unavailable finding', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-typosquat-corrupt-'));
      const manifestPath = path.join(tmpDir, 'corrupt.json');
      fs.writeFileSync(manifestPath, '{ not valid json');
      try {
        const findings = run(loadFixture('bad'), { manifestPath });
        assert.strictEqual(findings.length, 1);
        assert.strictEqual(findings[0].id, 'typosquat/allowlist-unavailable');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('a manifest missing the servers[] array yields exactly one allowlist-unavailable finding', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-typosquat-noservers-'));
      const manifestPath = path.join(tmpDir, 'no-servers.json');
      fs.writeFileSync(manifestPath, JSON.stringify({ manifestVersion: 1, knownScopes: [] }));
      try {
        const findings = run(loadFixture('bad'), { manifestPath });
        assert.strictEqual(findings.length, 1);
        assert.strictEqual(findings[0].id, 'typosquat/allowlist-unavailable');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('hostile / edge-case handling', () => {
    it('empty servers array returns [] and does not throw', () => {
      assert.deepStrictEqual(run([], {}), []);
    });

    it('a server with command null and args empty produces no findings and does not throw', () => {
      const servers = [makeServer({ command: null, args: [] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('an npx server with only flag args (no package spec) produces no finding', () => {
      const servers = [makeServer({ command: 'npx', args: ['--yes'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'typosquat.js'), 'utf8');
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });
  });
});
