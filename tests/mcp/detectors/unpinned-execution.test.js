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

    const pinnedSpecs = ['pkg@1.2.3', '@scope/pkg@2.0.0', 'pkg@v1.2.3', 'pkg@1.2.3-beta.1'];
    for (const spec of pinnedSpecs) {
      it(`does NOT flag npx ${spec} (properly pinned)`, () => {
        const servers = [makeServer({ command: 'npx', args: [spec] })];
        assert.deepStrictEqual(run(servers, {}), []);
      });
    }

    describe('WR-02 regression: wildcards and floating ranges are UNPINNED', () => {
      const floatingSpecs = [
        'pkg@*', 'pkg@x', 'pkg@1.x', 'pkg@1.2.x',
        'pkg@^1.2.3', 'pkg@~1.0', 'pkg@>=1.0', 'pkg@<2', 'pkg@1', 'pkg@1.2',
        '@scope/pkg@*', '@scope/pkg@^2.0.0',
      ];
      for (const spec of floatingSpecs) {
        it(`flags npx ${spec} as unpinned`, () => {
          const servers = [makeServer({ command: 'npx', args: [spec] })];
          const findings = run(servers, {});
          assert.ok(findings.some(f => f.id === 'unpinned-execution/npx-no-version'), `expected finding for ${spec}`);
        });
      }

      it('flags uvx --from pkg>=0.1 as unpinned (range operator)', () => {
        const servers = [makeServer({ command: 'uvx', args: ['--from', 'pkg>=0.1', 'pkg'] })];
        const findings = run(servers, {});
        assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
      });

      it('flags uvx --from pkg~=1.4 as unpinned (compatible-release range)', () => {
        const servers = [makeServer({ command: 'uvx', args: ['--from', 'pkg~=1.4', 'pkg'] })];
        const findings = run(servers, {});
        assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
      });

      it('does NOT flag uvx --from pkg==2.0.0 (exact pin)', () => {
        const servers = [makeServer({ command: 'uvx', args: ['--from', 'pkg==2.0.0', 'pkg'] })];
        assert.deepStrictEqual(run(servers, {}), []);
      });

      it('F2: flags uvx --from pkg==1.* as unpinned (PEP 440 prefix match floats, despite the == operator)', () => {
        const servers = [makeServer({ command: 'uvx', args: ['--from', 'pkg==1.*', 'pkg'] })];
        const findings = run(servers, {});
        assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
      });
    });

    describe('F2 regression: PyPI == pins on the POSITIONAL uvx spec', () => {
      it('does NOT flag uvx mcp-server-fetch==1.0.0 (exact == pin was previously parsed as part of the name)', () => {
        const servers = [makeServer({ command: 'uvx', args: ['mcp-server-fetch==1.0.0'] })];
        assert.deepStrictEqual(run(servers, {}), []);
      });

      it('flags uvx pkg>=0.1 as unpinned (positional range operator)', () => {
        const servers = [makeServer({ command: 'uvx', args: ['pkg>=0.1'] })];
        const findings = run(servers, {});
        assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
      });
    });
  });

  describe('WR-03 regression: -p/--package value is the spec to version-check', () => {
    it('does NOT flag npx -p pkg@1.0.0 serve (pinned via -p, positional is just a binary name)', () => {
      const servers = [makeServer({ command: 'npx', args: ['-p', 'pkg@1.0.0', 'serve'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does NOT flag npx --package pkg@1.0.0 serve', () => {
      const servers = [makeServer({ command: 'npx', args: ['--package', 'pkg@1.0.0', 'serve'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does NOT flag npx --package=pkg@1.0.0 serve', () => {
      const servers = [makeServer({ command: 'npx', args: ['--package=pkg@1.0.0', 'serve'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('flags npx -p pkg@latest serve (unpinned -p value)', () => {
      const servers = [makeServer({ command: 'npx', args: ['-p', 'pkg@latest', 'serve'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/npx-no-version'));
    });

    it('flags npx -p pkg serve (bare-name -p value)', () => {
      const servers = [makeServer({ command: 'npx', args: ['-p', 'pkg', 'serve'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/npx-no-version'));
    });

    it('a dangling trailing -p with no value produces no finding and does not throw', () => {
      const servers = [makeServer({ command: 'npx', args: ['-p'] })];
      assert.doesNotThrow(() => run(servers, {}));
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('WR-06 unified semantics: a -p with a NON-STRING value refuses to derive a spec (no finding, never falls back to the trailing token)', () => {
      // Pre-consolidation this detector's local copy skipped the pair and
      // version-checked 'cmd' (a binary name, not the installed package);
      // the shared extractSpec() refuses instead — consistent with
      // derivePackageName()'s behavior in every other detector.
      const servers = [makeServer({ command: 'npx', args: ['-p', 123, 'cmd'] })];
      assert.doesNotThrow(() => run(servers, {}));
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('F5: -p followed by a flag-shaped token refuses (no unpinned FP against the flag, no fallback to the positional)', () => {
      const servers = [makeServer({ command: 'npx', args: ['-p', '--yes', 'cowsay@1.0.0'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });
  });

  describe('F1 regression: known value-taking flags never masquerade as the spec', () => {
    it('does NOT flag npx --loglevel warn pkg@1.2.3 (flag value skipped, pinned positional found)', () => {
      const servers = [makeServer({ command: 'npx', args: ['--loglevel', 'warn', 'pkg@1.2.3'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('flags uvx --python 3.12 bare-pkg as unpinned (the Python version is not the spec)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--python', '3.12', 'bare-pkg'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
    });

    it('does NOT flag uvx --python 3.12 pkg==2.0.0 (pinned positional after a skipped flag value)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--python', '3.12', 'pkg==2.0.0'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a uvx --from with a non-string value refuses to derive (no finding, no throw) — F5 unified refusal semantics', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', 123, 'cmd'] })];
      assert.doesNotThrow(() => run(servers, {}));
      assert.deepStrictEqual(run(servers, {}), []);
    });
  });

  describe('G-1368 regression: git direct-reference specs (uvx --from git+..., npx git URLs)', () => {
    const FULL_SHA = 'd2f6f8b0c3a94ef7f4b8c19aa2f0e3d4c5b6a798';

    it('flags uvx --from git+https://... with NO ref as unpinned', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', 'git+https://github.com/oraios/serena', 'serena'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
    });

    it('flags a @main branch ref as unpinned (mutable)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', 'git+https://github.com/oraios/serena@main', 'serena'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
    });

    it('flags a @v1.2.3 tag ref as unpinned (tags can be re-pointed)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', 'git+https://github.com/oraios/serena@v1.2.3', 'serena'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
    });

    it('does NOT flag a full 40-hex commit SHA ref (the G-1368 false positive)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', `git+https://github.com/oraios/serena@${FULL_SHA}`, 'serena'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('flags a short 12-hex SHA as unpinned (prefix-ambiguous)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', `git+https://github.com/oraios/serena@${FULL_SHA.slice(0, 12)}`, 'serena'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
    });

    it('does NOT flag a git+ssh spec pinned to a full SHA (authority git@ is not the ref separator)', () => {
      const servers = [makeServer({ command: 'uvx', args: ['--from', `git+ssh://git@github.com/org/repo@${FULL_SHA}`, 'cmd'] })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('real-world shape: the SHA-pinned serena invocation produces no finding', () => {
      const servers = [makeServer({
        name: 'serena',
        command: 'uvx',
        args: ['--from', `git+https://github.com/oraios/serena@${FULL_SHA}`, 'serena', 'start-mcp-server', '--context', 'claude-code', '--project-from-cwd'],
      })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('npx positional git URLs get the same classification (unpinned without a SHA, pinned with one)', () => {
      const bare = [makeServer({ command: 'npx', args: ['git+https://github.com/org/repo'] })];
      assert.ok(run(bare, {}).some(f => f.id === 'unpinned-execution/npx-no-version'));
      const pinned = [makeServer({ command: 'npx', args: [`git+https://github.com/org/repo@${FULL_SHA}`] })];
      assert.deepStrictEqual(run(pinned, {}), []);
    });

    it('the git-spec finding message never contains the spec (a git URL authority can carry credentials — CR-01)', () => {
      const SECRET = 'ghp_SECRETtoken1234';
      const servers = [makeServer({ command: 'uvx', args: ['--from', `git+https://x-access-token:${SECRET}@github.com/org/repo@main`, 'cmd'] })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/uvx-no-version'));
      for (const f of findings) {
        assert.ok(!JSON.stringify(f).includes(SECRET), `credential leaked: ${JSON.stringify(f)}`);
      }
    });
  });

  describe('D-07 boundary: no transport findings from this detector', () => {
    it('a plain http:// remote URL only yields the version-binding rule, never a transport rule', () => {
      const servers = [makeServer({ url: 'http://mcp.example.com/server' })];
      const findings = run(servers, {});
      assert.ok(findings.every(f => f.id === 'unpinned-execution/url-no-version-binding'));
      assert.ok(findings.every(f => !f.id.includes('insecure-endpoint')));
    });
  });

  describe('CR-01 regression: raw server.url secrets never leak into finding messages', () => {
    // Credential-shaped URL: secrets in BOTH userinfo and the query string.
    // No version/integrity binding, so url-no-version-binding must fire.
    const USERINFO_PASSWORD = 'hunter2userinfoSECRET';
    const QUERY_SECRET = 'qsSECRETvalue12345';
    const LEAKY_URL = `https://alice:${USERINFO_PASSWORD}@mcp.internal:8443/sse?api_key=${QUERY_SECRET}#frag`;

    it('no finding (message or any field) contains the userinfo or query-string secret', () => {
      const servers = [makeServer({ url: LEAKY_URL })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'unpinned-execution/url-no-version-binding'));
      for (const f of findings) {
        assert.ok(!f.message.includes(USERINFO_PASSWORD), `userinfo secret leaked: ${f.message}`);
        assert.ok(!f.message.includes(QUERY_SECRET), `query secret leaked: ${f.message}`);
        assert.ok(!JSON.stringify(f).includes(USERINFO_PASSWORD));
        assert.ok(!JSON.stringify(f).includes(QUERY_SECRET));
      }
    });

    it('the message still carries the sanitized protocol + host + path label', () => {
      const servers = [makeServer({ url: LEAKY_URL })];
      const findings = run(servers, {});
      assert.ok(findings.length > 0);
      for (const f of findings) {
        assert.ok(f.message.includes('https://mcp.internal:8443/sse'), `sanitized label missing: ${f.message}`);
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
