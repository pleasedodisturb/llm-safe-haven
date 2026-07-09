'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { id, requirement, run } = require('../../../lib/mcp/detectors/scope-breadth.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'scope-breadth');

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

describe('scope-breadth detector (MCPD-07)', () => {
  it('exports id "scope-breadth" and requirement "MCPD-07"', () => {
    assert.strictEqual(id, 'scope-breadth');
    assert.strictEqual(requirement, 'MCPD-07');
  });

  it('flags unscoped broad-capability servers at info severity (known-unscoped fixture)', () => {
    const servers = loadFixture('unscoped');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'scope-breadth/unscoped-broad-capability'));
    for (const f of findings) assert.strictEqual(f.severity, 'info');
    // Both the server-filesystem AND the shell server should be flagged.
    assert.strictEqual(findings.length, 2);
  });

  it('produces zero findings when the same broad-capability server declares an explicit path (scoped fixture)', () => {
    const servers = loadFixture('scoped');
    assert.deepStrictEqual(run(servers, {}), []);
  });

  it('a non-broad-capability server never fires, even alongside a scoped broad server', () => {
    const servers = loadFixture('scoped');
    const findings = run(servers, {});
    assert.ok(findings.every(f => f.serverName !== 'fetch'));
  });

  it('every emitted finding carries confidence "verified"', () => {
    const findings = run(loadFixture('unscoped'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.confidence, 'verified');
  });

  it('every emitted finding carries detector "scope-breadth" (D-16)', () => {
    const findings = run(loadFixture('unscoped'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.detector, 'scope-breadth');
  });

  describe('hostile / edge-case handling', () => {
    it('empty servers array returns [] and does not throw', () => {
      assert.deepStrictEqual(run([], {}), []);
    });

    it('a server with empty args and no command/name never fires', () => {
      const servers = [makeServer({ args: [] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a non-broad server (e.g. a fetch server) produces zero findings', () => {
      const servers = [makeServer({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-fetch'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'scope-breadth.js'), 'utf8');
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });
  });
});
