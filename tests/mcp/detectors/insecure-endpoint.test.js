'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { id, requirement, run } = require('../../../lib/mcp/detectors/insecure-endpoint.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'insecure-endpoint');

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

describe('insecure-endpoint detector (MCPD-06)', () => {
  it('exports id "insecure-endpoint" and requirement "MCPD-06"', () => {
    assert.strictEqual(id, 'insecure-endpoint');
    assert.strictEqual(requirement, 'MCPD-06');
  });

  it('flags a plain-http server (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'insecure-endpoint/plain-http'));
  });

  it('flags a 0.0.0.0 wildcard bind (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'insecure-endpoint/wildcard-bind'));
  });

  it('flags unauthenticated transport (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'insecure-endpoint/unauthenticated-transport'));
  });

  it('produces zero findings on a clean https + Authorization-header fixture', () => {
    const servers = loadFixture('clean');
    assert.deepStrictEqual(run(servers, {}), []);
  });

  it('every emitted finding carries confidence "verified"', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.confidence, 'verified');
  });

  it('every emitted finding carries detector "insecure-endpoint" (D-16)', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.detector, 'insecure-endpoint');
  });

  describe('D-07 boundary: no version-binding findings from this detector', () => {
    it('an unversioned https URL never yields an unpinned-execution rule id', () => {
      const servers = [makeServer({
        url: 'https://mcp.example.com/server',
        headers: { Authorization: 'Bearer redacted' },
      })];
      const findings = run(servers, {});
      assert.ok(findings.every(f => !f.id.includes('unpinned-execution')));
    });
  });

  describe('hostile / edge-case handling', () => {
    it('empty servers array returns [] and does not throw', () => {
      assert.deepStrictEqual(run([], {}), []);
    });

    it('server.url === null produces no finding for that server', () => {
      const servers = [makeServer({ url: null })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a malformed/unparseable server.url is skipped, no throw, no finding', () => {
      const servers = [makeServer({ url: 'not a valid url ::::' })];
      assert.doesNotThrow(() => run(servers, {}));
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'insecure-endpoint.js'), 'utf8');
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });
  });
});
