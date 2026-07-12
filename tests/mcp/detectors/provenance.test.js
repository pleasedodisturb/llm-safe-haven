'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { id, requirement, run } = require('../../../lib/mcp/detectors/provenance.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'provenance');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, `${name}.json`), 'utf8'));
}

// MCPO-04 zero-fetch assertion: a spy fetchImpl that THROWS if ever
// invoked. Used on every offline-path test — if the detector ever
// referenced fetchImpl offline, these tests would fail loudly instead
// of silently passing.
function throwingFetch() {
  throw new Error('fetchImpl must never be called when offline (MCPO-04/D-11)');
}

// Injected fetchImpl factory matching the registry version-doc response
// shape (06-RESEARCH.md Pattern 2): { ok, status, text() }.
function fetchReturning({ ok = true, status = 200, body = null } = {}) {
  return async () => ({
    ok,
    status,
    text: async () => JSON.stringify(body),
  });
}

describe('provenance detector (MCPD-02)', () => {
  it('exports id "provenance" and requirement "MCPD-02"', () => {
    assert.strictEqual(id, 'provenance');
    assert.strictEqual(requirement, 'MCPD-02');
  });

  describe('offline (MCPO-04 zero-fetch guarantee)', () => {
    it('every npx server yields provenance/unverified-offline and NEVER calls fetchImpl', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      assert.ok(findings.length > 0);
      for (const f of findings) {
        assert.strictEqual(f.id, 'provenance/unverified-offline');
        assert.strictEqual(f.severity, 'info');
        assert.strictEqual(f.confidence, 'unverified');
      }
    });

    it('defaults to offline when context.online is omitted entirely', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { fetchImpl: throwingFetch });
      assert.ok(findings.length > 0);
      assert.ok(findings.every((f) => f.id === 'provenance/unverified-offline'));
    });

    it('never produces a clean result or a higher-severity finding offline', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      const npxCount = servers.filter((s) => s.command === 'npx').length;
      assert.strictEqual(findings.length, npxCount);
      for (const f of findings) {
        assert.notStrictEqual(f.severity, 'high');
        assert.notStrictEqual(f.severity, 'critical');
        assert.notStrictEqual(f.severity, 'medium');
      }
    });

    it('the offline message reads as neutral status, not alarming', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      for (const f of findings) {
        assert.ok(f.message.includes('--online'), `expected --online guidance in: ${f.message}`);
      }
    });
  });

  describe('online + attestations present', () => {
    it('produces zero findings (clean)', async () => {
      const servers = loadFixture('clean');
      const fetchImpl = fetchReturning({ body: { dist: { attestations: { url: 'https://example.com' } } } });
      const findings = await run(servers, { online: true, fetchImpl });
      assert.deepStrictEqual(findings, []);
    });
  });

  describe('online + attestations absent', () => {
    it('produces provenance/no-attestation (low, verified)', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f, 'expected a provenance/no-attestation finding');
      assert.strictEqual(f.severity, 'low');
      assert.strictEqual(f.confidence, 'verified');
    });

    it('the message says "lacks a provenance attestation", never "verified authentic"', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f.message.toLowerCase().includes('lacks a provenance attestation'));
      assert.ok(!f.message.toLowerCase().includes('verified authentic'));
    });
  });

  describe('online + fetch failure', () => {
    it('a throwing fetchImpl produces provenance/fetch-failed (info, unverified) and run() never rejects', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = async () => {
        throw new Error('network down');
      };
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      const f = findings.find((x) => x.id === 'provenance/fetch-failed');
      assert.ok(f, 'expected a provenance/fetch-failed finding');
      assert.strictEqual(f.severity, 'info');
      assert.strictEqual(f.confidence, 'unverified');
    });

    it('a 404-shaped response produces provenance/fetch-failed, NOT no-attestation (Pitfall 5)', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ ok: false, status: 404, body: 'Not Found' });
      const findings = await run(servers, { online: true, fetchImpl });
      const provenanceFindings = findings.filter((f) => f.id.startsWith('provenance/'));
      assert.ok(provenanceFindings.some((f) => f.id === 'provenance/fetch-failed'));
      assert.ok(!provenanceFindings.some((f) => f.id === 'provenance/no-attestation'));
    });

    it('an oversized response degrades to fetch-failed, never throws', async () => {
      const servers = loadFixture('bad');
      const hugeBody = { dist: { attestations: null }, padding: 'x'.repeat(6 * 1024 * 1024) };
      const fetchImpl = fetchReturning({ body: hugeBody });
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      assert.ok(findings.some((f) => f.id === 'provenance/fetch-failed'));
    });
  });

  describe('D-08: npm-only gating', () => {
    it('uvx and url-only servers yield nothing, even online', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      const npxCount = servers.filter((s) => s.command === 'npx').length;
      assert.strictEqual(findings.length, npxCount);
    });

    it('uvx and url-only servers yield nothing offline either', async () => {
      const servers = loadFixture('bad');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      const npxCount = servers.filter((s) => s.command === 'npx').length;
      assert.strictEqual(findings.length, npxCount);
    });
  });

  describe('D-10: version selection', () => {
    it('a pinned spec fetches that exact version', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'pinned',
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.2.3'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      let requestedUrl = null;
      const fetchImpl = async (url) => {
        requestedUrl = url;
        return { ok: true, status: 200, text: async () => JSON.stringify({ dist: {} }) };
      };
      await run(servers, { online: true, fetchImpl });
      assert.ok(requestedUrl, 'expected fetchImpl to be called');
      assert.ok(requestedUrl.endsWith('/1.2.3'), `expected pinned version in URL: ${requestedUrl}`);
    });

    it('an unpinned spec fetches "latest" and the message notes the caveat', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'unpinned',
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      let requestedUrl = null;
      const fetchImpl = async (url) => {
        requestedUrl = url;
        return { ok: true, status: 200, text: async () => JSON.stringify({ dist: {} }) };
      };
      const findings = await run(servers, { online: true, fetchImpl });
      assert.ok(requestedUrl, 'expected fetchImpl to be called');
      assert.ok(requestedUrl.endsWith('/latest'), `expected "latest" in URL: ${requestedUrl}`);
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f);
      assert.ok(f.message.toLowerCase().includes('latest'), `expected latest caveat in: ${f.message}`);
    });

    it('never re-reports unpinnedness itself (that is MCPD-01 territory)', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'unpinned',
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      assert.ok(!findings.some((f) => f.id.includes('unpinned')));
    });
  });

  describe('hostile / edge-case handling', () => {
    it('empty servers array resolves to [] and does not throw', async () => {
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run([], { online: false, fetchImpl: throwingFetch });
      });
      assert.deepStrictEqual(findings, []);
    });

    it('a server with command null produces no findings and does not throw, offline or online', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'no-command',
          command: null,
          args: [],
          env: {},
          url: null,
          headers: {},
        },
      ];
      await assert.doesNotReject(async () => {
        assert.deepStrictEqual(await run(servers, { online: false, fetchImpl: throwingFetch }), []);
        assert.deepStrictEqual(await run(servers, { online: true, fetchImpl: throwingFetch }), []);
      });
    });

    it('an npx server with only flag args (no package spec) produces no finding', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'flags-only',
          command: 'npx',
          args: ['--yes'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      assert.deepStrictEqual(findings, []);
    });

    it('every emitted finding carries detector "provenance"', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      assert.ok(findings.length > 0);
      for (const f of findings) assert.strictEqual(f.detector, 'provenance');
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(
        path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'provenance.js'),
        'utf8'
      );
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });

    it('the registry host is a hardcoded literal, never built from server.url', () => {
      const src = fs.readFileSync(
        path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'provenance.js'),
        'utf8'
      );
      assert.ok(src.includes("'registry.npmjs.org'"));
      assert.ok(!/server\.url.*registry\.npmjs\.org/.test(src));
    });
  });
});
