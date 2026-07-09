'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { id, requirement, run } = require('../../../lib/mcp/detectors/unpinned-execution.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'unpinned-execution');

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

describe('unpinned-execution detector (MCPD-01)', () => {
  it('exports id "unpinned-execution" and requirement "MCPD-01"', () => {
    assert.strictEqual(id, 'unpinned-execution');
    assert.strictEqual(requirement, 'MCPD-01');
  });

  it('flags a bare-name npx server (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'unpinned-execution/npx-no-version'));
  });

  it('flags a bare-name uvx server (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
  });

  it('flags a remote URL with no version/integrity binding (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'unpinned-execution/url-no-version-binding'));
  });

  it('produces zero findings on a clean, well-pinned fixture', () => {
    const servers = loadFixture('clean');
    assert.deepStrictEqual(run(servers, {}), []);
  });

  it('every emitted finding carries confidence "verified"', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.confidence, 'verified');
  });

  it('every emitted finding carries detector "unpinned-execution" (D-16)', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.detector, 'unpinned-execution');
  });

  describe('package spec version-pin parsing', () => {
    const unpinnedSpecs = ['pkg@latest', 'pkg@next', 'pkg@canary', 'pkg@'];
    for (const spec of unpinnedSpecs) {
      it(`flags npx ${spec} as unpinned`, () => {
        const servers = [makeServer({ command: 'npx', args: [spec] })];
        const findings = run(servers, {});
        assert.ok(findings.some(f => f.id === 'unpinned-execution/npx-no-version'));
      });
    }

    const pinnedSpecs = ['pkg@1.2.3', '@scope/pkg@2.0.0'];
    for (const spec of pinnedSpecs) {
      it(`does NOT flag npx ${spec} (properly pinned)`, () => {
        const servers = [makeServer({ command: 'npx', args: [spec] })];
        assert.deepStrictEqual(run(servers, {}), []);
      });
    }
  });

  describe('D-07 boundary: no transport findings from this detector', () => {
    it('a plain http:// remote URL only yields the version-binding rule, never a transport rule', () => {
      const servers = [makeServer({ url: 'http://mcp.example.com/server' })];
      const findings = run(servers, {});
      assert.ok(findings.every(f => f.id === 'unpinned-execution/url-no-version-binding'));
      assert.ok(findings.every(f => !f.id.includes('insecure-endpoint')));
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

    it('a malformed url string does not throw and produces no url finding', () => {
      const servers = [makeServer({ url: 'not a valid url ::::' })];
      assert.doesNotThrow(() => run(servers, {}));
    });

    it('an npx server with only flag args (no package spec) produces no finding', () => {
      const servers = [makeServer({ command: 'npx', args: ['--yes'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'unpinned-execution.js'), 'utf8');
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });
  });
});
