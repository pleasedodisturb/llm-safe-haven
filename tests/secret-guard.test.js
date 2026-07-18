'use strict';

// In-process unit coverage for hooks/secret-guard.js (TQ-03, D-08). All
// exported functions are pure (no I/O) — imported via module.exports only,
// the hook file itself is never modified (D-09, byte-identity enforced by
// `git diff --exit-code hooks/` and tests/integrity.test.js).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  SECRET_PATTERNS,
  ALLOWLISTED_PATHS,
  isAllowlisted,
  scanContent,
  extractFromToolInput,
  checkForSecrets,
} = require('../hooks/secret-guard.js');

// ---------------------------------------------------------------------------
// SECRET_PATTERNS — one positive match + one clean miss per family
// ---------------------------------------------------------------------------
describe('SECRET_PATTERNS', () => {
  it('is a non-empty array of pattern entries', () => {
    assert.ok(Array.isArray(SECRET_PATTERNS));
    assert.ok(SECRET_PATTERNS.length > 0);
  });

  const cases = [
    { name: 'AWS Access Key ID', hit: 'AKIAABCDEFGHIJKLMNOP', miss: 'AKIA-not-a-real-key' },
    { name: 'GitHub Personal Access Token', hit: 'ghp_' + 'a'.repeat(36), miss: 'ghp_short' },
    { name: 'GitHub OAuth Token', hit: 'gho_' + 'b'.repeat(36), miss: 'gho_short' },
    { name: 'GitHub Fine-Grained PAT', hit: 'github_pat_' + 'c'.repeat(22), miss: 'github_pat_short' },
    { name: 'GitHub Server Token', hit: 'ghs_' + 'd'.repeat(36), miss: 'ghs_short' },
    { name: 'GitHub Refresh Token', hit: 'ghr_' + 'e'.repeat(36), miss: 'ghr_short' },
    { name: 'Slack Bot Token', hit: 'xoxb-1234567890-1234567890-' + 'f'.repeat(24), miss: 'xoxb-not-a-token' },
    { name: 'Slack User Token', hit: 'xoxp-1234567890-1234567890-' + 'g'.repeat(24), miss: 'xoxp-not-a-token' },
    { name: 'OpenAI API Key', hit: 'sk-' + 'h'.repeat(20) + 'T3BlbkFJ' + 'h'.repeat(20), miss: 'sk-not-an-openai-key' },
    { name: 'OpenAI API Key (project)', hit: 'sk-proj-' + 'i'.repeat(44), miss: 'sk-proj-short' },
    { name: 'Anthropic API Key', hit: 'sk-ant-' + 'j'.repeat(84), miss: 'sk-ant-short' },
    { name: 'Stripe Live Secret Key', hit: 'sk_live_' + 'k'.repeat(28), miss: 'sk_live_short' },
    { name: 'Stripe Live Restricted Key', hit: 'rk_live_' + 'l'.repeat(28), miss: 'rk_live_short' },
    { name: 'Private Key', hit: '-----BEGIN RSA PRIVATE KEY-----', miss: '-----BEGIN CERTIFICATE-----' },
    { name: 'Generic API Key/Token assignment', hit: 'api_key = "abcdefghij0123456789"', miss: 'api_key = "short"' },
    { name: 'Hardcoded password', hit: 'password = "supersecret1"', miss: 'password = "x"' },
    { name: 'Connection string with embedded credentials', hit: 'postgres://user:pass@host.example.com/db', miss: 'postgres://host.example.com/db' },
  ];

  for (const { name, hit, miss } of cases) {
    const entry = SECRET_PATTERNS.find((p) => p.name === name);

    it(`${name}: matches a realistic positive example`, () => {
      assert.ok(entry, `pattern entry for ${name} must exist`);
      assert.ok(entry.pattern.test(hit), `expected ${name} pattern to match: ${hit}`);
    });

    it(`${name}: does not match a clean miss`, () => {
      assert.ok(!entry.pattern.test(miss), `expected ${name} pattern to NOT match: ${miss}`);
    });
  }
});

// ---------------------------------------------------------------------------
// isAllowlisted — allowlist breadth regression (M-3)
// ---------------------------------------------------------------------------
describe('isAllowlisted', () => {
  it('is a non-empty array of regexes', () => {
    assert.ok(Array.isArray(ALLOWLISTED_PATHS));
    assert.ok(ALLOWLISTED_PATHS.length > 0);
  });

  it('returns false for a falsy filePath', () => {
    assert.equal(isAllowlisted(''), false);
    assert.equal(isAllowlisted(undefined), false);
    assert.equal(isAllowlisted(null), false);
  });

  it('is true for a tests/ path (deliberately broad per M-3)', () => {
    assert.equal(isAllowlisted('/repo/tests/fixtures/x.js'), true);
  });

  it('is false for a src/ path (allowlist is not too broad)', () => {
    assert.equal(isAllowlisted('/repo/src/config.js'), false);
  });

  it('is true for its own hook source (self-allowlist)', () => {
    assert.equal(isAllowlisted('/repo/hooks/secret-guard.js'), true);
  });

  it('is true for .env.example/.template/.sample', () => {
    assert.equal(isAllowlisted('/repo/.env.example'), true);
    assert.equal(isAllowlisted('/repo/.env.template'), true);
    assert.equal(isAllowlisted('/repo/.env.sample'), true);
  });
});

// ---------------------------------------------------------------------------
// scanContent
// ---------------------------------------------------------------------------
describe('scanContent', () => {
  it('returns [] for empty/falsy content', () => {
    assert.deepEqual(scanContent(''), []);
    assert.deepEqual(scanContent(null), []);
    assert.deepEqual(scanContent(undefined), []);
  });

  it('returns [] for clean content', () => {
    assert.deepEqual(scanContent('const x = 1;\nfunction foo() {}\n'), []);
  });

  it('reports the correct line number for a match', () => {
    const content = 'line one\nline two\nconst key = "AKIAABCDEFGHIJKLMNOP"\nline four';
    const findings = scanContent(content);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].name, 'AWS Access Key ID');
    assert.equal(findings[0].line, 3);
  });

  it('reports multiple findings across multiple lines', () => {
    const content = [
      'const aws = "AKIAABCDEFGHIJKLMNOP"',
      'const pk = "-----BEGIN RSA PRIVATE KEY-----"',
    ].join('\n');
    const findings = scanContent(content);
    assert.equal(findings.length, 2);
  });
});

// ---------------------------------------------------------------------------
// extractFromToolInput — Write/Edit/MultiEdit/unknown shapes
// ---------------------------------------------------------------------------
describe('extractFromToolInput', () => {
  it('returns null for a falsy toolInput', () => {
    assert.equal(extractFromToolInput('Write', null), null);
    assert.equal(extractFromToolInput('Write', undefined), null);
  });

  it('Write: extracts content and file_path', () => {
    const result = extractFromToolInput('Write', { content: 'hello', file_path: '/a/b.js' });
    assert.deepEqual(result, { content: 'hello', filePath: '/a/b.js' });
  });

  it('Write: defaults content/file_path to empty string when missing', () => {
    const result = extractFromToolInput('Write', {});
    assert.deepEqual(result, { content: '', filePath: '' });
  });

  it('Edit: extracts new_string and file_path', () => {
    const result = extractFromToolInput('Edit', { new_string: 'updated', file_path: '/a/b.js' });
    assert.deepEqual(result, { content: 'updated', filePath: '/a/b.js' });
  });

  it('MultiEdit: joins new_string across the edits array', () => {
    const result = extractFromToolInput('MultiEdit', {
      file_path: '/a/b.js',
      edits: [{ new_string: 'first' }, { new_string: 'second' }],
    });
    assert.deepEqual(result, { content: 'first\nsecond', filePath: '/a/b.js' });
  });

  it('MultiEdit: handles a missing/empty edits array', () => {
    const result = extractFromToolInput('MultiEdit', { file_path: '/a/b.js' });
    assert.deepEqual(result, { content: '', filePath: '/a/b.js' });
  });

  it('unknown tool: returns null', () => {
    assert.equal(extractFromToolInput('Bash', { command: 'ls' }), null);
    assert.equal(extractFromToolInput('Read', { file_path: '/a/b.js' }), null);
  });
});

// ---------------------------------------------------------------------------
// checkForSecrets — end-to-end
// ---------------------------------------------------------------------------
describe('checkForSecrets', () => {
  it('blocks a Write containing a secret and includes the file path + pattern name', () => {
    const reason = checkForSecrets('Write', {
      file_path: '/repo/src/config.js',
      content: 'const key = "AKIAABCDEFGHIJKLMNOP";',
    });
    assert.ok(reason);
    assert.match(reason, /\/repo\/src\/config\.js/);
    assert.match(reason, /AWS Access Key ID/);
  });

  it('passes a clean Write (returns null)', () => {
    const reason = checkForSecrets('Write', {
      file_path: '/repo/src/config.js',
      content: 'const x = 1;',
    });
    assert.equal(reason, null);
  });

  it('does not scan an allowlisted path even with a secret-shaped payload', () => {
    const reason = checkForSecrets('Write', {
      file_path: '/repo/tests/fixtures/secrets.js',
      content: 'const key = "AKIAABCDEFGHIJKLMNOP";',
    });
    assert.equal(reason, null);
  });

  it('returns null for a non-scannable tool (Bash)', () => {
    assert.equal(checkForSecrets('Bash', { command: 'echo hi' }), null);
  });

  it('blocks an Edit new_string carrying a secret', () => {
    const reason = checkForSecrets('Edit', {
      file_path: '/repo/src/app.js',
      new_string: 'password = "supersecret1"',
    });
    assert.ok(reason);
    assert.match(reason, /Hardcoded password/);
  });
});
