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

    it('F2: flags a PINNED uvx typosquat (mcp-server-fetc==1.0.0) — the == suffix is split off before comparison', () => {
      const servers = [makeServer({ command: 'uvx', args: ['mcp-server-fetc==1.0.0'] })];
      const findings = run(servers, {});
      const f = findings.find(x => x.id === 'typosquat/near-known-name');
      assert.ok(f, 'expected a near-known-name finding for the ==-pinned typosquat');
      assert.ok(f.message.includes('mcp-server-fetch'), `expected the known name in: ${f.message}`);
    });

    it('F1: flags a uvx typosquat behind --python 3.12 (the flag value is never mistaken for the spec)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--python', '3.12', 'mcp-server-fetc'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'typosquat/near-known-name'),
        'expected the positional after --python <value> to be compared');
    });

    it('G-1368 pin: a git direct-reference spec refuses to derive a name — no typosquat finding, no throw', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', 'git+https://github.com/oraios/serena@d2f6f8b0c3a94ef7f4b8c19aa2f0e3d4c5b6a798', 'serena'] })];
      assert.doesNotThrow(() => run(servers, {}));
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('F1: flags a uvx typosquat selected via --from (the --from value is the installed package)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', 'mcp-server-fetc==1.0.0', 'mcp-server-fetch'] })];
      const findings = run(servers, {});
      const f = findings.find(x => x.id === 'typosquat/near-known-name');
      assert.ok(f, 'expected the --from spec, not the benign command token, to be compared');
    });

    it('F3: flags an UNSCOPED typo of a full-spec entry\'s name half (kontext7-mcp), naming the full spec', () => {
      const servers = [makeServer({ command: 'npx', args: ['kontext7-mcp'] })];
      const findings = run(servers, {});
      const f = findings.find(x => x.id === 'typosquat/near-known-name');
      assert.ok(f, 'expected a near-known-name finding for the unscoped name-half typo');
      assert.ok(f.message.includes('@upstash/context7-mcp'), `message should name the full spec: ${f.message}`);
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

    it('IN-03: a scope-class hit is phrased as "known scope", never "known package"', () => {
      const findings = run(loadFixture('bad'), {});
      const f = findings.find(x => x.serverName === 'npx-scope-squat-memory');
      assert.ok(f);
      assert.ok(f.message.includes('known scope "@modelcontextprotocol"'), `expected scope phrasing: ${f.message}`);
      assert.ok(f.message.includes('scope "@modelcontextprotocoI"'), `expected the compared scope segment named: ${f.message}`);
      assert.ok(!f.message.includes('known package "@modelcontextprotocol"'), `a scope must not be called a package: ${f.message}`);
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

  describe('WR-04: scope-confusion — exact known scoped name under a missing/foreign scope', () => {
    it('flags an unscoped publication of a known scoped name half (npx server-filesystem)', () => {
      const findings = run(loadFixture('scope-confusion'), {});
      const f = findings.find(x => x.serverName === 'npx-scope-removal');
      assert.ok(f, 'expected a finding for the scope-removal squat');
      assert.strictEqual(f.id, 'typosquat/scope-confusion');
      assert.strictEqual(f.severity, 'high');
      assert.strictEqual(f.confidence, 'verified');
      assert.ok(f.message.includes('WITHOUT its scope'), `expected scope-removal wording: ${f.message}`);
    });

    it('flags a known scoped name half under a foreign scope (npx @evil/server-filesystem)', () => {
      const findings = run(loadFixture('scope-confusion'), {});
      const f = findings.find(x => x.serverName === 'npx-foreign-scope');
      assert.ok(f, 'expected a finding for the foreign-scope squat');
      assert.strictEqual(f.id, 'typosquat/scope-confusion');
      assert.ok(f.message.includes('@evil'), `expected the foreign scope named: ${f.message}`);
    });

    it('flags a full-spec entry\'s name half under a foreign scope (npx @evil/context7-mcp)', () => {
      const findings = run(loadFixture('scope-confusion'), {});
      const f = findings.find(x => x.serverName === 'npx-foreign-scope-fullspec-half');
      assert.ok(f, 'expected a finding for the full-spec name-half squat');
      assert.strictEqual(f.id, 'typosquat/scope-confusion');
    });

    it('produces exactly 3 findings on the scope-confusion fixture, all typosquat/scope-confusion', () => {
      const findings = run(loadFixture('scope-confusion'), {});
      assert.strictEqual(findings.length, 3);
      assert.ok(findings.every(f => f.id === 'typosquat/scope-confusion'));
    });

    it('legitimate exact full-spec and knownScope+bare matches still short-circuit clean', () => {
      const servers = [
        makeServer({ command: 'npx', args: ['@modelcontextprotocol/server-filesystem'] }),
        makeServer({ command: 'npx', args: ['@upstash/context7-mcp'] }),
      ];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a genuinely-unscoped known name (firecrawl-mcp) is still exact-known when unscoped — no finding', () => {
      const servers = [makeServer({ command: 'npx', args: ['firecrawl-mcp'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('FP guard: a name half under 4 chars never fires scope-confusion (@evil/mcp vs the "mcp" half of @playwright/mcp)', () => {
      const servers = [makeServer({ command: 'npx', args: ['@evil/mcp'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a knownScopes scope carrying another entry\'s name half stays clean (publishing under it requires owning the scope)', () => {
      const servers = [makeServer({ command: 'npx', args: ['@stripe/server-filesystem'] })];
      assert.deepStrictEqual(run(servers, {}), []);
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

    it('F3 lockstep check: a scopedOnly[] entry missing from servers[] fails closed as allowlist-unavailable', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-typosquat-drift-'));
      const manifestPath = path.join(tmpDir, 'drifted.json');
      fs.writeFileSync(manifestPath, JSON.stringify({
        manifestVersion: 1,
        knownScopes: ['@acme'],
        scopedOnly: ['server-ghost'], // NOT present in servers[] — drifted
        servers: ['server-real'],
      }));
      try {
        const findings = run(loadFixture('bad'), { manifestPath });
        assert.strictEqual(findings.length, 1);
        assert.strictEqual(findings[0].id, 'typosquat/allowlist-unavailable');
        assert.strictEqual(findings[0].severity, 'info');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('F3 sanity: the BUNDLED manifest passes the lockstep check (no context override)', () => {
      // If manifests/mcp-known-servers.json ever drifts, this fails loudly.
      const servers = [makeServer({ command: 'npx', args: ['firecrawl-mcp'] })];
      assert.deepStrictEqual(run(servers, {}), []);
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

    describe('F4: edit-distance DoS guards', () => {
      it('a 500k-char package arg completes run() in under 50ms (never reaches the DP matrix)', () => {
        const servers = [makeServer({ command: 'npx', args: ['a'.repeat(500 * 1024) ] })];
        const started = process.hrtime.bigint();
        const findings = run(servers, {});
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
        assert.deepStrictEqual(findings, []);
        assert.ok(elapsedMs < 50, `expected <50ms, took ${elapsedMs.toFixed(1)}ms`);
      });

      it('a name just over npm\'s 214-char maximum is skipped without comparison (no finding, fast)', () => {
        const servers = [makeServer({ command: 'npx', args: ['b'.repeat(215)] })];
        const started = process.hrtime.bigint();
        const findings = run(servers, {});
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
        assert.deepStrictEqual(findings, []);
        assert.ok(elapsedMs < 50, `expected <50ms, took ${elapsedMs.toFixed(1)}ms`);
      });

      it('the length-difference prune never skips a genuine within-threshold match (distance still computed correctly)', () => {
        // dist 1 pairs with length diff 0 and 1, and a transposition —
        // the guards must not change any distance result.
        const servers = [
          makeServer({ name: 'sub', command: 'npx', args: ['@modelcontextprotocol/server-filesytem'] }),
          makeServer({ name: 'del', command: 'npx', args: ['mcp-server-fetc'] }),
          makeServer({ name: 'swap', command: 'npx', args: ['mcp-server-fecth'] }),
        ];
        const findings = run(servers, {});
        for (const name of ['sub', 'del', 'swap']) {
          assert.ok(findings.some(f => f.serverName === name && f.id === 'typosquat/near-known-name'),
            `expected near-known-name for ${name}`);
        }
      });
    });
  });

  describe('G-1376: scope-confusion genericness bar', () => {
    describe('real bundled allowlist — the 5 known FP vendor packages (D-06)', () => {
      const vendorPackages = [
        '@ui5/mcp-server',
        '@cap-js/mcp-server',
        '@launchdarkly/mcp-server',
        '@hubspot/mcp-server',
        '@browserstack/mcp-server',
      ];
      for (const pkg of vendorPackages) {
        it(`produces zero scope-confusion findings for ${pkg}@1.0.0`, () => {
          const servers = [makeServer({ command: 'npx', args: ['-y', `${pkg}@1.0.0`] })];
          const findings = run(servers, {});
          assert.ok(!findings.some(f => f.id === 'typosquat/scope-confusion'),
            `expected no scope-confusion finding for legitimate vendor package ${pkg}, got: ${JSON.stringify(findings)}`);
        });
      }
    });

    describe('true-positive retention (D-07)', () => {
      it('foreign-scope distinctive half (@evil/context7-mcp) still fires scope-confusion', () => {
        const findings = run(loadFixture('scope-confusion'), {});
        const f = findings.find(x => x.serverName === 'npx-foreign-scope-fullspec-half');
        assert.ok(f, 'expected a finding for the full-spec distinctive name-half squat');
        assert.strictEqual(f.id, 'typosquat/scope-confusion');
      });

      it('bare unscoped scopedOnly half (server-filesystem) still fires scope-confusion', () => {
        const servers = [makeServer({ command: 'npx', args: ['server-filesystem'] })];
        const findings = run(servers, {});
        assert.ok(findings.some(f => f.id === 'typosquat/scope-confusion'),
          'expected the bare scopedOnly half to still fire scope-confusion');
      });

      it('existing scope-confusion fixture still produces exactly 3 findings', () => {
        const findings = run(loadFixture('scope-confusion'), {});
        assert.strictEqual(findings.length, 3);
        assert.ok(findings.every(f => f.id === 'typosquat/scope-confusion'));
      });
    });

    describe('pool-seeding (D-08, isolated synthetic allowlist)', () => {
      let tmpDir;
      let manifestPath;

      beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-typosquat-g1376-'));
        manifestPath = path.join(tmpDir, 'mini-manifest.json');
        fs.writeFileSync(manifestPath, JSON.stringify({
          manifestVersion: 1,
          updated: '2026-07-20',
          knownScopes: ['@acme'],
          servers: ['@acme/mcp-server', '@acme/distinctive-mcp'],
        }));
      });

      afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      });

      it('generic full-spec half (mcp-server) is excluded from scope-confusion under a foreign scope', () => {
        const servers = [makeServer({ command: 'npx', args: ['@evil/mcp-server'] })];
        const findings = run(servers, { manifestPath });
        assert.ok(!findings.some(f => f.id === 'typosquat/scope-confusion'),
          `expected no scope-confusion for the generic half, got: ${JSON.stringify(findings)}`);
      });

      it('generic full-spec half (mcp-server) STILL near-matches its typo (mcp-servr) — proves nameCandidates/class-1 untouched (D-03)', () => {
        const servers = [makeServer({ command: 'npx', args: ['mcp-servr'] })];
        const findings = run(servers, { manifestPath });
        assert.ok(findings.some(f => f.id === 'typosquat/near-known-name'),
          `expected near-known-name for the generic half's typo, got: ${JSON.stringify(findings)}`);
      });

      it('distinctive full-spec half (distinctive-mcp) is STILL included in scope-confusion under a foreign scope', () => {
        const servers = [makeServer({ command: 'npx', args: ['@evil/distinctive-mcp'] })];
        const findings = run(servers, { manifestPath });
        assert.ok(findings.some(f => f.id === 'typosquat/scope-confusion'),
          `expected scope-confusion for the distinctive half, got: ${JSON.stringify(findings)}`);
      });
    });
  });
});
