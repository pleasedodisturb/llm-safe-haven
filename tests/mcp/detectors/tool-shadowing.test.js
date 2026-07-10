'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { id, requirement, run } = require('../../../lib/mcp/detectors/tool-shadowing.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'tool-shadowing');

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

describe('tool-shadowing detector (MCPD-08)', () => {
  it('exports id "tool-shadowing" and requirement "MCPD-08"', () => {
    assert.strictEqual(id, 'tool-shadowing');
    assert.strictEqual(requirement, 'MCPD-08');
  });

  it('flags a same-name/different-signature collision (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some((f) => f.id === 'tool-shadowing/name-collision'));
  });

  it('the colliding finding is severity medium', () => {
    const findings = run(loadFixture('bad'), {});
    const finding = findings.find((f) => f.id === 'tool-shadowing/name-collision');
    assert.strictEqual(finding.severity, 'medium');
  });

  it('produces zero findings on a same-name/identical-signature scope-override fixture (clean)', () => {
    const servers = loadFixture('clean');
    assert.deepStrictEqual(run(servers, {}), []);
  });

  it('every finding message contains the honesty disclaimer (static server-name collision, not verified tool-level shadowing)', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) {
      assert.ok(f.message.includes('static server-name collision check, not verified tool-level shadowing'));
    }
  });

  it('every emitted finding carries confidence "verified"', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.confidence, 'verified');
  });

  it('every emitted finding carries detector "tool-shadowing" (D-16)', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.detector, 'tool-shadowing');
  });

  describe('hostile / edge-case handling', () => {
    it('empty servers array returns [] and does not throw', () => {
      assert.deepStrictEqual(run([], {}), []);
    });

    it('servers with null names are ignored', () => {
      const servers = [
        makeServer({ name: null, command: 'a' }),
        makeServer({ name: null, command: 'b' }),
      ];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a single-occurrence name produces zero findings', () => {
      const servers = [makeServer({ name: 'solo', command: 'npx' })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'tool-shadowing.js'), 'utf8');
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });
  });
});
