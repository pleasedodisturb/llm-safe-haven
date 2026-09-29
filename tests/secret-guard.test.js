'use strict';

// In-process unit coverage for hooks/secret-guard.js (TQ-03, D-08), plus
// end-to-end runs of the real hook process (tests/helpers/hook-runner.js).
// The hook was originally frozen here (D-09); quick task 260928-ojp changes it
// on purpose (G-668 allowlist anchoring, G-1799 size cap and linear patterns),
// and tests/integrity.test.js keeps hooks/checksums.json in step with it.
//
// Determinism: every call passes an explicit env object / project root. No
// test reads the ambient CLAUDE_PROJECT_DIR or LSH_* values of the session
// that runs the suite. Secret-shaped values are assembled at runtime and
// assertion messages print case labels only, never the built string.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const {
  SECRET_PATTERNS,
  ALLOWLISTED_PATHS,
  TEST_DIR_SEGMENTS,
  DOC_BASENAMES,
  MAX_CONTENT_CHARS,
  resolveProjectRoot,
  isAllowlisted,
  scanContent,
  extractFromToolInput,
  checkForSecrets,
} = require('../hooks/secret-guard.js');
const { runHook, defaultEnv } = require('./helpers/hook-runner.js');

const REPO_ROOT = path.join(__dirname, '..');

// Runtime-built secret-shaped values: never one source literal, so this file
// stays clean for gitleaks and for secret-guard itself.
function awsShapedKey() {
  const tail = Array.from({ length: 16 }, (_, i) => String.fromCharCode(65 + ((i * 7 + 3) % 26))).join('');
  return ['AK', 'IA'].join('') + tail;
}
function secretLine() {
  return `const key = "${awsShapedKey()}";`;
}

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
// isAllowlisted — anchored to path segments below the project root (G-668).
// These rows replace the pre-G-668 "deliberately broad per M-3" assertions:
// an intended behaviour change, not a deleted test.
// ---------------------------------------------------------------------------
describe('isAllowlisted', () => {
  it('is a non-empty array of regexes', () => {
    assert.ok(Array.isArray(ALLOWLISTED_PATHS));
    assert.ok(ALLOWLISTED_PATHS.length > 0);
  });

  it('returns false for a falsy filePath', () => {
    assert.equal(isAllowlisted('', '/repo'), false);
    assert.equal(isAllowlisted(undefined, '/repo'), false);
    assert.equal(isAllowlisted(null, '/repo'), false);
  });

  it('is true for a tests/ path inside the project root', () => {
    assert.equal(isAllowlisted('/repo/tests/fixtures/x.js', '/repo'), true);
  });

  // Would fail if the allowlist ignored the project root: the same path with
  // no root known must NOT be allowlisted (fail closed).
  it('is false for the same tests/ path when no project root is known', () => {
    assert.equal(isAllowlisted('/repo/tests/fixtures/x.js'), false);
    assert.equal(isAllowlisted('/repo/tests/fixtures/x.js', null), false);
    assert.equal(isAllowlisted('/repo/tests/fixtures/x.js', ''), false);
  });

  it('is false for a relative project root', () => {
    assert.equal(isAllowlisted('/repo/tests/fixtures/x.js', 'repo'), false);
  });

  it('is false for a src/ path (allowlist is not too broad)', () => {
    assert.equal(isAllowlisted('/repo/src/config.js', '/repo'), false);
  });

  it('is true for its own hook source inside the root (self-allowlist)', () => {
    assert.equal(isAllowlisted('/repo/hooks/secret-guard.js', '/repo'), true);
  });

  it('is true for .env.example/.template/.sample inside the root', () => {
    assert.equal(isAllowlisted('/repo/.env.example', '/repo'), true);
    assert.equal(isAllowlisted('/repo/.env.template', '/repo'), true);
    assert.equal(isAllowlisted('/repo/.env.sample', '/repo'), true);
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
    }, { CLAUDE_PROJECT_DIR: '/repo' });
    assert.ok(reason);
    assert.match(reason, /\/repo\/src\/config\.js/);
    assert.match(reason, /AWS Access Key ID/);
  });

  it('passes a clean Write (returns null)', () => {
    const reason = checkForSecrets('Write', {
      file_path: '/repo/src/config.js',
      content: 'const x = 1;',
    }, { CLAUDE_PROJECT_DIR: '/repo' });
    assert.equal(reason, null);
  });

  it('does not scan an allowlisted path inside the project root even with a secret-shaped payload', () => {
    const reason = checkForSecrets('Write', {
      file_path: '/repo/tests/fixtures/secrets.js',
      content: 'const key = "AKIAABCDEFGHIJKLMNOP";',
    }, { CLAUDE_PROJECT_DIR: '/repo' });
    assert.equal(reason, null);
  });

  it('returns null for a non-scannable tool (Bash)', () => {
    assert.equal(checkForSecrets('Bash', { command: 'echo hi' }, {}), null);
  });

  it('blocks an Edit new_string carrying a secret', () => {
    const reason = checkForSecrets('Edit', {
      file_path: '/repo/src/app.js',
      new_string: 'password = "supersecret1"',
    }, { CLAUDE_PROJECT_DIR: '/repo' });
    assert.ok(reason);
    assert.match(reason, /Hardcoded password/);
  });
});

// ---------------------------------------------------------------------------
// G-668 allowlist anchoring (quick task 260928-ojp)
//
// Would fail if: the allowlist matched a test/fixture/mock SUBSTRING anywhere
// in the absolute path (latest/, contests/, /tmp/tests/), ignored the project
// root (no root, root-part segment, traversal out of the root), matched the
// basename allowlist outside the root, or exempted CLAUDE.md/README.md without
// the exact LSH_SECRET_GUARD_ALLOW_DOCS=1 opt-in. Every BLOCKED row has a
// clean-content twin that must still be allowed, and the ALLOWED rows keep
// real in-root fixtures working.
// ---------------------------------------------------------------------------
describe('G-668 allowlist anchoring', () => {
  const ROOT = '/repo';
  const withRoot = (extra = {}) => ({ CLAUDE_PROJECT_DIR: ROOT, ...extra });

  it('exports TEST_DIR_SEGMENTS as the exact directory-segment set', () => {
    assert.deepEqual(TEST_DIR_SEGMENTS, ['test', 'tests', '__tests__', 'fixtures', '__fixtures__', 'mocks', '__mocks__']);
  });

  it('exports DOC_BASENAMES as CLAUDE.md and README.md only', () => {
    assert.deepEqual(DOC_BASENAMES, ['CLAUDE.md', 'README.md']);
  });

  it('resolveProjectRoot accepts only an absolute, non-empty CLAUDE_PROJECT_DIR', () => {
    assert.equal(typeof resolveProjectRoot, 'function', 'resolveProjectRoot must be exported');
    assert.equal(resolveProjectRoot({ CLAUDE_PROJECT_DIR: '/repo' }), '/repo');
    assert.equal(resolveProjectRoot({ CLAUDE_PROJECT_DIR: '/repo/' }), '/repo');
    assert.equal(resolveProjectRoot({ CLAUDE_PROJECT_DIR: 'repo' }), null);
    assert.equal(resolveProjectRoot({ CLAUDE_PROJECT_DIR: '' }), null);
    assert.equal(resolveProjectRoot({}), null);
    assert.equal(resolveProjectRoot(undefined), null);
  });

  const BLOCKED = [
    { label: 'AC4a/tmp-tests-outside-root', file: '/tmp/tests/evil.env', env: withRoot() },
    { label: 'AC4b/claude-md-default', file: '/repo/CLAUDE.md', env: withRoot() },
    { label: 'AC4b/readme-md-default', file: '/repo/README.md', env: withRoot() },
    { label: 'AC4b/global-claude-md-default', file: '/home/u/.claude/CLAUDE.md', env: withRoot() },
    { label: 'substring/latest-dir-inside-root', file: '/Users/x/Documents/latest/leak', env: { CLAUDE_PROJECT_DIR: '/Users/x' } },
    { label: 'substring/contests-dir', file: '/repo/contests/x.js', env: withRoot() },
    { label: 'substring/hammocks-dir', file: '/repo/hammocks/x.js', env: withRoot() },
    { label: 'substring/notes-on-fixtures', file: '/repo/src/notes-on-fixtures.md', env: withRoot() },
    { label: 'legacy-singular/fixture-dir', file: '/repo/fixture/x.json', env: withRoot() },
    { label: 'legacy-singular/mock-dir', file: '/repo/mock/x.js', env: withRoot() },
    { label: 'root-part/tests-segment-in-root', file: '/w/tests/proj/src/leak.js', env: { CLAUDE_PROJECT_DIR: '/w/tests/proj' } },
    { label: 'traversal/tests-dotdot-src', file: '/repo/tests/../src/leak.js', env: withRoot() },
    { label: 'traversal/relative-outside', file: '../outside/tests/x.js', env: withRoot() },
    { label: 'traversal/sibling-prefix-root', file: '/repo-evil/tests/x.js', env: withRoot() },
    { label: 'no-root/absent', file: '/repo/tests/x.js', env: {} },
    { label: 'no-root/relative-root', file: '/repo/tests/x.js', env: { CLAUDE_PROJECT_DIR: 'repo' } },
    { label: 'no-root/empty-root', file: '/repo/tests/x.js', env: { CLAUDE_PROJECT_DIR: '' } },
    { label: 'outside-root/self-name', file: '/tmp/secret-guard.js', env: withRoot() },
    { label: 'outside-root/test-suffix', file: '/tmp/app.test.js', env: withRoot() },
    { label: 'outside-root/env-example', file: '/tmp/.env.example', env: withRoot() },
    { label: 'basename/self-name-near-miss', file: '/repo/src/my-secret-guard.js', env: withRoot() },
    { label: 'opt-in/value-true-not-1', file: '/repo/CLAUDE.md', env: withRoot({ LSH_SECRET_GUARD_ALLOW_DOCS: 'true' }) },
    { label: 'opt-in/other-doc-not-covered', file: '/repo/NOTES.md', env: withRoot({ LSH_SECRET_GUARD_ALLOW_DOCS: '1' }) },
  ];

  const ALLOWED = [
    { label: 'AC4c/tests-fixture-abs', file: '/repo/tests/fixture.json', env: withRoot() },
    { label: 'AC4c/tests-fixture-relative', file: 'tests/fixture.json', env: withRoot() },
    { label: 'segment/test', file: '/repo/test/x.json', env: withRoot() },
    { label: 'segment/__tests__', file: '/repo/src/__tests__/a.js', env: withRoot() },
    { label: 'segment/test-fixtures', file: '/repo/test/fixtures/x.json', env: withRoot() },
    { label: 'segment/fixtures', file: '/repo/fixtures/f.json', env: withRoot() },
    { label: 'segment/__fixtures__', file: '/repo/__fixtures__/f.json', env: withRoot() },
    { label: 'segment/mocks', file: '/repo/mocks/m.js', env: withRoot() },
    { label: 'segment/__mocks__', file: '/repo/__mocks__/m.js', env: withRoot() },
    { label: 'root-part/tests-segment-below-root', file: '/w/tests/proj/tests/x.js', env: { CLAUDE_PROJECT_DIR: '/w/tests/proj' } },
    { label: 'root/trailing-slash', file: '/repo/tests/x.js', env: { CLAUDE_PROJECT_DIR: '/repo/' } },
    { label: 'basename/test-suffix-in-root', file: '/repo/src/app.test.js', env: withRoot() },
    { label: 'basename/spec-suffix-in-root', file: '/repo/src/app.spec.ts', env: withRoot() },
    { label: 'basename/env-example-in-root', file: '/repo/.env.example', env: withRoot() },
    { label: 'basename/env-template-in-root', file: '/repo/.env.template', env: withRoot() },
    { label: 'basename/env-sample-in-root', file: '/repo/.env.sample', env: withRoot() },
    { label: 'basename/self-hook-in-root', file: '/repo/hooks/secret-guard.js', env: withRoot() },
    { label: 'basename/firewall-hook-in-root', file: '/repo/hooks/bash-firewall.js', env: withRoot() },
    { label: 'AC4d/claude-md-opt-in', file: '/repo/CLAUDE.md', env: withRoot({ LSH_SECRET_GUARD_ALLOW_DOCS: '1' }) },
    { label: 'AC4d/readme-md-opt-in', file: '/repo/README.md', env: withRoot({ LSH_SECRET_GUARD_ALLOW_DOCS: '1' }) },
    { label: 'AC4d/global-claude-md-opt-in', file: '/home/u/.claude/CLAUDE.md', env: withRoot({ LSH_SECRET_GUARD_ALLOW_DOCS: '1' }) },
    { label: 'AC4d/claude-md-opt-in-no-root', file: '/home/u/.claude/CLAUDE.md', env: { LSH_SECRET_GUARD_ALLOW_DOCS: '1' } },
  ];

  it('has non-empty case tables (non-vacuity)', () => {
    assert.ok(BLOCKED.length >= 20, `BLOCKED has ${BLOCKED.length} rows`);
    assert.ok(ALLOWED.length >= 20, `ALLOWED has ${ALLOWED.length} rows`);
  });

  for (const { label, file, env } of BLOCKED) {
    it(`blocks a secret write: ${label}`, () => {
      const reason = checkForSecrets('Write', { file_path: file, content: secretLine() }, env);
      assert.ok(reason, `${label}: expected a block, got allow`);
      assert.match(reason, /Secret detected in /, `${label}: reason format`);
      assert.match(reason, /AWS Access Key ID \(line 1\)/, `${label}: finding named`);
    });

    it(`twin: still allows clean content: ${label}`, () => {
      const reason = checkForSecrets('Write', { file_path: file, content: 'const x = 1;\n' }, env);
      assert.equal(reason, null, `${label}: clean content must stay allowed`);
    });
  }

  for (const { label, file, env } of ALLOWED) {
    it(`allows a secret-shaped fixture write: ${label}`, () => {
      const reason = checkForSecrets('Write', { file_path: file, content: secretLine() }, env);
      assert.equal(reason, null, `${label}: expected allow, got block`);
    });
  }

  it('applies the same anchoring to Edit and MultiEdit', () => {
    const env = withRoot();
    assert.ok(checkForSecrets('Edit', { file_path: '/repo/CLAUDE.md', new_string: secretLine() }, env), 'Edit/CLAUDE.md default');
    assert.ok(checkForSecrets('MultiEdit', { file_path: '/tmp/tests/x.js', edits: [{ new_string: secretLine() }] }, env), 'MultiEdit/tmp-tests');
    assert.equal(checkForSecrets('Edit', { file_path: '/repo/tests/x.js', new_string: secretLine() }, env), null, 'Edit/in-root tests');
  });
});

// ---------------------------------------------------------------------------
// G-668 ticket PoC shapes, through the REAL hook process with env overrides.
// Would fail if main() did not read the project root and the opt-in from the
// hook process environment.
// ---------------------------------------------------------------------------
describe('G-668 PoC shapes through the real hook', () => {
  const write = (file, content) => ({ tool_name: 'Write', tool_input: { file_path: file, content } });
  const env = (extra) => ({ ...defaultEnv(), ...extra });

  it('PoC 1: /tmp/tests/leak.env is blocked with a project root set', () => {
    const res = runHook('secret-guard.js', write('/tmp/tests/leak.env', awsShapedKey()), { env: env({ CLAUDE_PROJECT_DIR: '/repo' }) });
    assert.equal(res.decision, 'block', `poc1: decision ${res.decision}`);
  });

  it('PoC 1b: /tmp/tests/leak.env is blocked with no project root', () => {
    const res = runHook('secret-guard.js', write('/tmp/tests/leak.env', awsShapedKey()), { env: env({}) });
    assert.equal(res.decision, 'block', `poc1b: decision ${res.decision}`);
  });

  it('PoC 2: a global CLAUDE.md is blocked by default', () => {
    const res = runHook('secret-guard.js', write('/home/u/.claude/CLAUDE.md', `key: ${awsShapedKey()}`), { env: env({ CLAUDE_PROJECT_DIR: '/repo' }) });
    assert.equal(res.decision, 'block', `poc2: decision ${res.decision}`);
  });

  it('PoC 3: LSH_SECRET_GUARD_ALLOW_DOCS=1 re-allows the global CLAUDE.md', () => {
    const res = runHook('secret-guard.js', write('/home/u/.claude/CLAUDE.md', `key: ${awsShapedKey()}`), {
      env: env({ CLAUDE_PROJECT_DIR: '/repo', LSH_SECRET_GUARD_ALLOW_DOCS: '1' }),
    });
    assert.equal(res.decision, 'allow', `poc3: decision ${res.decision}`);
  });

  it('twin: a real fixture write under <project>/tests/ is allowed', () => {
    const file = path.join(REPO_ROOT, 'tests', 'fixtures', 'g668-fixture.json');
    const res = runHook('secret-guard.js', write(file, secretLine()), { env: env({ CLAUDE_PROJECT_DIR: REPO_ROOT }) });
    assert.equal(res.decision, 'allow', `real-fixture: decision ${res.decision}`);
  });

  it('twin: an ordinary non-secret write is allowed', () => {
    const res = runHook('secret-guard.js', write('/repo/src/app.js', 'export const answer = 42;\n'), { env: env({ CLAUDE_PROJECT_DIR: '/repo' }) });
    assert.equal(res.decision, 'allow', `clean-write: decision ${res.decision}`);
  });

  it('control: a secret write to src/ is blocked by the real hook', () => {
    const res = runHook('secret-guard.js', write('/repo/src/app.js', secretLine()), { env: env({ CLAUDE_PROJECT_DIR: '/repo' }) });
    assert.equal(res.decision, 'block', `control: decision ${res.decision}`);
  });
});

// ---------------------------------------------------------------------------
// G-1799 secret-guard cap and linear time (quick task 260928-ojp)
//
// A hook killed by Claude Code's per-hook timeout (the installer sets 5 s)
// renders no decision and the Write proceeds, so a slow regex is a bypass.
// Would fail if: content over MAX_CONTENT_CHARS were scanned or allowed
// instead of blocked; the cap were applied as a prefix-only scan (a secret at
// the far end of a large under-cap file must still be found); or any SECRET_PATTERNS
// entry were super-linear on a one-line adversarial run (the spawned hook
// must render a decision in under 1000 ms, and a SIGKILL at 4500 ms reads as
// 'error', never 'allow').
// ---------------------------------------------------------------------------
describe('G-1799 secret-guard cap and linear time', () => {
  const CAP = 1000000;
  const ENV = { CLAUDE_PROJECT_DIR: '/repo' };
  const FILE = '/repo/src/data.txt';
  const hookEnv = () => ({ ...defaultEnv(), ...ENV });
  const fill = (unit, len) => unit.repeat(Math.ceil(len / unit.length)).slice(0, len);
  const cleanContent = (len) => fill('const value = 42;\n', len);

  it('exports MAX_CONTENT_CHARS equal to 1000000', () => {
    assert.equal(MAX_CONTENT_CHARS, CAP);
  });

  it('blocks clean content of CAP+1 chars (checkForSecrets and the real hook)', () => {
    const content = cleanContent(CAP + 1);
    const reason = checkForSecrets('Write', { file_path: FILE, content }, ENV);
    assert.ok(reason, 'over-cap content must be blocked by checkForSecrets');
    assert.match(reason, /too large|exceeds/);
    const res = runHook('secret-guard.js', { tool_name: 'Write', tool_input: { file_path: FILE, content } }, { env: hookEnv() });
    assert.equal(res.decision, 'block', `over-cap: real hook decision ${res.decision}`);
    assert.match(res.reason, /too large|exceeds/);
  });

  it('blocks over-cap Edit and MultiEdit content', () => {
    const big = cleanContent(CAP + 1);
    assert.ok(checkForSecrets('Edit', { file_path: FILE, new_string: big }, ENV), 'Edit over cap');
    const half = cleanContent(CAP / 2 + 1);
    assert.ok(checkForSecrets('MultiEdit', { file_path: FILE, edits: [{ new_string: half }, { new_string: half }] }, ENV), 'MultiEdit combined over cap');
  });

  it('twin: clean content of exactly CAP chars is scanned and allowed', () => {
    assert.equal(checkForSecrets('Write', { file_path: FILE, content: cleanContent(CAP) }, ENV), null);
  });

  it('twin: clean 500,000-char content is allowed', () => {
    assert.equal(checkForSecrets('Write', { file_path: FILE, content: cleanContent(500000) }, ENV), null);
  });

  it('finds a secret on the last line of a 900,000-char file (no prefix-only scan)', () => {
    const body = cleanContent(900000);
    const lastLine = body.split('\n').length;
    const reason = checkForSecrets('Write', { file_path: FILE, content: body + secretLine() }, ENV);
    assert.ok(reason, 'far-end secret must be reported');
    assert.match(reason, new RegExp(`AWS Access Key ID \\(line ${lastLine}\\)`));
  });

  const LEN = 200000;
  const TIMING_GENERATORS = [
    { label: 'conn-string-fragment-repeat', build: () => fill(['://', 'a:'].join(''), LEN) },
    { label: 'colon-run', build: () => fill(':', LEN) },
    { label: 'scheme-then-word-run', build: () => 'postgres://' + fill('a', LEN) },
    { label: 'scheme-then-userinfo-run', build: () => 'postgres://' + fill('a', LEN / 2) + ':' + fill('b', LEN / 2) },
    { label: 'api-key-assignment-prefix-repeat', build: () => fill(['api', '_key = "'].join(''), LEN) },
    { label: 'password-assignment-prefix-repeat', build: () => fill(['pass', 'word = "'].join(''), LEN) },
    { label: 'private-key-header-fragment-repeat', build: () => fill(['-----BEGIN', ' '].join(''), LEN) },
    { label: 'sk-prefix-repeat', build: () => fill(['s', 'k-'].join(''), LEN) },
    { label: 'ghp-prefix-repeat', build: () => fill(['gh', 'p_'].join(''), LEN) },
    { label: 'conn-string-fragment-repeat-at-cap-16', build: () => fill(['://', 'a:'].join(''), CAP - 16) },
  ];

  it('has at least 9 timing generators (non-vacuity)', () => {
    assert.ok(TIMING_GENERATORS.length >= 9, `only ${TIMING_GENERATORS.length} generators`);
  });

  for (const { label, build } of TIMING_GENERATORS) {
    it(`timing: ${label} finishes in the real hook under 1000 ms`, () => {
      const content = build();
      const res = runHook('secret-guard.js', { tool_name: 'Write', tool_input: { file_path: FILE, content } }, { timeoutMs: 4500, env: hookEnv() });
      const ms = Math.round(res.elapsedMs);
      assert.notEqual(res.decision, 'error', `${label}: hook ${res.signal ? `killed by ${res.signal}` : 'errored'} after ${ms} ms`);
      assert.ok(res.elapsedMs < 1000, `${label}: ${ms} ms`);
    });
  }
});
