'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { id, requirement, run } = require('../../../lib/mcp/detectors/credential-passthrough.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'credential-passthrough');

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

// The raw AWS-key-shaped test string from bad.json, kept here ONLY as a
// substring to assert against — never printed, never logged.
const BAD_FIXTURE_SECRET_SUBSTRING = 'AKIAFAKE1234567890AB';

describe('credential-passthrough detector (MCPD-04)', () => {
  it('exports id "credential-passthrough" and requirement "MCPD-04"', () => {
    assert.strictEqual(id, 'credential-passthrough');
    assert.strictEqual(requirement, 'MCPD-04');
  });

  it('flags an inlined secret matching a known SECRET_PATTERNS entry (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'credential-passthrough/inlined-secret'));
    const finding = findings.find(f => f.id === 'credential-passthrough/inlined-secret');
    assert.strictEqual(finding.severity, 'critical');
  });

  it('flags a literal under a sensitive-sounding key name (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'credential-passthrough/sensitive-name-literal'));
    const finding = findings.find(f => f.id === 'credential-passthrough/sensitive-name-literal');
    assert.strictEqual(finding.severity, 'high');
  });

  it('flags a high-entropy literal under a non-sensitive key name (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'credential-passthrough/high-entropy-literal'));
    const finding = findings.find(f => f.id === 'credential-passthrough/high-entropy-literal');
    assert.strictEqual(finding.severity, 'high');
  });

  it('flags a wildcard/whole-environment passthrough token (known-bad fixture)', () => {
    const servers = loadFixture('bad');
    const findings = run(servers, {});
    assert.ok(findings.some(f => f.id === 'credential-passthrough/broad-inheritance'));
    const finding = findings.find(f => f.id === 'credential-passthrough/broad-inheritance');
    assert.strictEqual(finding.severity, 'low');
  });

  it('produces zero findings on a clean fixture (named interpolation + short non-secret literal)', () => {
    const servers = loadFixture('clean');
    assert.deepStrictEqual(run(servers, {}), []);
  });

  it('every emitted finding carries confidence "verified"', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.confidence, 'verified');
  });

  it('every emitted finding carries detector "credential-passthrough" (D-16)', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) assert.strictEqual(f.detector, 'credential-passthrough');
  });

  it('D-15 regression: no finding message includes the raw secret substring from bad.json', () => {
    const findings = run(loadFixture('bad'), {});
    assert.ok(findings.length > 0);
    for (const f of findings) {
      assert.ok(!f.message.includes(BAD_FIXTURE_SECRET_SUBSTRING));
      assert.ok(!JSON.stringify(f).includes(BAD_FIXTURE_SECRET_SUBSTRING));
    }
  });

  describe('entropy threshold boundary (D-05 pinned thresholds)', () => {
    it('a 19-char mixed-case+digit value is NOT flagged as high-entropy', () => {
      const nineteen = 'Ab3'.repeat(7).slice(0, 19);
      assert.strictEqual(nineteen.length, 19);
      const servers = [makeServer({ env: { NON_SENSITIVE: nineteen } })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a 20-char mixed-case+digit value IS flagged as high-entropy', () => {
      const twenty = 'Ab3'.repeat(7).slice(0, 20);
      assert.strictEqual(twenty.length, 20);
      const servers = [makeServer({ env: { NON_SENSITIVE: twenty } })];
      const findings = run(servers, {});
      assert.ok(findings.some(f => f.id === 'credential-passthrough/high-entropy-literal'));
    });
  });

  describe('WR-04 regression: sensitive-name-literal requires a secret-like value', () => {
    const nonSecretValues = {
      AUTH_TYPE: 'oauth', // short enum-like value
      CREDENTIAL_PROCESS: 'aws-vault', // legitimate AWS pattern
      TOKEN_ENDPOINT: 'https://auth.example.com/oauth2/token', // URL-shaped
      PASSWORD_MIN_LENGTH: '12', // pure integer
      AUTH_REQUIRED: 'true', // boolean
    };
    for (const [key, value] of Object.entries(nonSecretValues)) {
      it(`does NOT flag ${key}=${value} (non-secret value under a sensitive key)`, () => {
        const servers = [makeServer({ env: { [key]: value } })];
        const findings = run(servers, {});
        assert.ok(
          !findings.some(f => f.id === 'credential-passthrough/sensitive-name-literal'),
          `false positive on ${key}=${value}`,
        );
      });
    }

    it('still flags a secret-like literal under a sensitive key', () => {
      const servers = [makeServer({ env: { AUTH_TOKEN: 'myinlinedtokenvalue42' } })];
      const findings = run(servers, {});
      const finding = findings.find(f => f.id === 'credential-passthrough/sensitive-name-literal');
      assert.ok(finding, 'expected sensitive-name-literal finding');
      assert.strictEqual(finding.severity, 'high');
    });

    it('a wildcard under a sensitive key is classified as broad-inheritance (low), not sensitive-name-literal (high)', () => {
      const servers = [makeServer({ env: { AUTH_PASSTHROUGH: '*' } })];
      const findings = run(servers, {});
      assert.ok(!findings.some(f => f.id === 'credential-passthrough/sensitive-name-literal'));
      const finding = findings.find(f => f.id === 'credential-passthrough/broad-inheritance');
      assert.ok(finding, 'expected broad-inheritance finding');
      assert.strictEqual(finding.severity, 'low');
    });

    it('a whole-env passthrough token under a sensitive key is broad-inheritance (low)', () => {
      const servers = [makeServer({ env: { SECRET_ENV: '${env:*}' } })];
      const findings = run(servers, {});
      assert.ok(!findings.some(f => f.id === 'credential-passthrough/sensitive-name-literal'));
      assert.ok(findings.some(f => f.id === 'credential-passthrough/broad-inheritance'));
    });
  });

  describe('D-14: named interpolation is the clean pattern', () => {
    it('${env:NAME} yields zero findings', () => {
      const servers = [makeServer({ env: { API_KEY: '${env:API_KEY}' } })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('${input:NAME} yields zero findings', () => {
      const servers = [makeServer({ env: { TOKEN: '${input:token}' } })];
      assert.deepStrictEqual(run(servers, {}), []);
    });
  });

  describe('WR-05 regression: remediation tokens render in matched backticks', () => {
    it('the inlined-secret message wraps the interpolation token in a matched backtick pair', () => {
      const findings = run(loadFixture('bad'), {});
      const finding = findings.find(f => f.id === 'credential-passthrough/inlined-secret');
      assert.ok(finding);
      assert.ok(finding.message.includes('`${env:AWS_ACCESS_KEY_ID}`'), `unbalanced token formatting: ${finding.message}`);
    });

    it('the sensitive-name-literal message wraps both interpolation tokens in matched backtick pairs', () => {
      const servers = [makeServer({ env: { AUTH_TOKEN: 'myinlinedtokenvalue42' } })];
      const findings = run(servers, {});
      const finding = findings.find(f => f.id === 'credential-passthrough/sensitive-name-literal');
      assert.ok(finding);
      assert.ok(finding.message.includes('`${env:AUTH_TOKEN}`'), `unbalanced env token: ${finding.message}`);
      assert.ok(finding.message.includes('`${input:AUTH_TOKEN}`'), `unbalanced input token: ${finding.message}`);
    });

    it('no finding message contains a dangling (odd-count) backtick', () => {
      const findings = run(loadFixture('bad'), {});
      assert.ok(findings.length > 0);
      for (const f of findings) {
        const backticks = (f.message.match(/`/g) || []).length;
        assert.strictEqual(backticks % 2, 0, `odd backtick count in: ${f.message}`);
      }
    });
  });

  describe('hostile / edge-case handling', () => {
    it('empty servers array returns [] and does not throw', () => {
      assert.deepStrictEqual(run([], {}), []);
    });

    it('a server with an empty env object produces no findings, no throw', () => {
      const servers = [makeServer({ env: {} })];
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('a non-string env value is skipped without throwing', () => {
      const servers = [makeServer({ env: { WEIRD: 123 } })];
      assert.doesNotThrow(() => run(servers, {}));
      assert.deepStrictEqual(run(servers, {}), []);
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'credential-passthrough.js'), 'utf8');
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });
  });
});
