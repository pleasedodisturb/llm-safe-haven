'use strict';

// In-process unit coverage for hooks/audit-logger.js (TQ-03, D-08). AUDIT_DIR
// is computed once at module top level from CLAUDE_AUDIT_DIR||homedir (WR-01
// shape) — every test needing a fresh AUDIT_DIR sets process.env.CLAUDE_AUDIT_DIR
// to an mkdtemp dir and evicts require.cache BEFORE re-requiring the hook, per
// tests/helpers/module-stub.js's ordering rule. Imported via module.exports
// only, the hook file itself is never modified (D-09, byte-identity enforced
// by `git diff --exit-code hooks/` and tests/integrity.test.js).

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOOK_PATH = require.resolve('../hooks/audit-logger.js');

let tmpDir;
let originalAuditDirEnv;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-audit-logger-test-'));
  originalAuditDirEnv = process.env.CLAUDE_AUDIT_DIR;
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  if (originalAuditDirEnv === undefined) {
    delete process.env.CLAUDE_AUDIT_DIR;
  } else {
    process.env.CLAUDE_AUDIT_DIR = originalAuditDirEnv;
  }
  // Re-evict so later tests/suites that require the hook fresh see the real
  // (env-restored) AUDIT_DIR rather than a stale sandbox binding.
  delete require.cache[HOOK_PATH];
});

/** Sets CLAUDE_AUDIT_DIR to the sandbox and returns a freshly-required hook. */
function requireHookWithSandboxAuditDir() {
  process.env.CLAUDE_AUDIT_DIR = tmpDir;
  delete require.cache[HOOK_PATH];
  return require('../hooks/audit-logger.js');
}

// ---------------------------------------------------------------------------
// AUDIT_DIR / module-level config
// ---------------------------------------------------------------------------
describe('AUDIT_DIR', () => {
  it('resolves to CLAUDE_AUDIT_DIR when set', () => {
    const hook = requireHookWithSandboxAuditDir();
    assert.equal(hook.AUDIT_DIR, tmpDir);
  });
});

// ---------------------------------------------------------------------------
// ensureAuditDir — explicit dir param, no env trick needed
// ---------------------------------------------------------------------------
describe('ensureAuditDir', () => {
  it('creates the directory when it does not exist', () => {
    const { ensureAuditDir } = require('../hooks/audit-logger.js');
    const dir = path.join(tmpDir, 'nested', 'audit');
    assert.ok(!fs.existsSync(dir));
    ensureAuditDir(dir);
    assert.ok(fs.existsSync(dir));
    assert.ok(fs.statSync(dir).isDirectory());
  });

  it('is a no-op when the directory already exists', () => {
    const { ensureAuditDir } = require('../hooks/audit-logger.js');
    assert.doesNotThrow(() => {
      ensureAuditDir(tmpDir);
      ensureAuditDir(tmpDir);
    });
  });
});

// ---------------------------------------------------------------------------
// todayDateString
// ---------------------------------------------------------------------------
describe('todayDateString', () => {
  it('returns a YYYY-MM-DD formatted string', () => {
    const { todayDateString } = require('../hooks/audit-logger.js');
    const result = todayDateString();
    assert.match(result, /^\d{4}-\d{2}-\d{2}$/);
  });

  it('matches the current date components', () => {
    const { todayDateString } = require('../hooks/audit-logger.js');
    const now = new Date();
    const expected = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    assert.equal(todayDateString(), expected);
  });
});

// ---------------------------------------------------------------------------
// buildInputPreview — redaction for Write/Edit/MultiEdit/Bash, truncation otherwise
// ---------------------------------------------------------------------------
describe('buildInputPreview', () => {
  it('returns empty string for falsy toolInput', () => {
    const { buildInputPreview } = require('../hooks/audit-logger.js');
    assert.equal(buildInputPreview('Write', null), '');
    assert.equal(buildInputPreview('Write', undefined), '');
  });

  it('Write: redacts content, exposes only file_path', () => {
    const { buildInputPreview } = require('../hooks/audit-logger.js');
    const preview = buildInputPreview('Write', { file_path: '/a/b.js', content: 'SECRET_TOKEN=abc123' });
    assert.equal(preview, 'file_path: /a/b.js');
    assert.ok(!preview.includes('content'));
    assert.ok(!preview.includes('SECRET_TOKEN'));
  });

  it('Edit: redacts new_string, exposes only file_path', () => {
    const { buildInputPreview } = require('../hooks/audit-logger.js');
    const preview = buildInputPreview('Edit', { file_path: '/a/b.js', new_string: 'leaked-secret' });
    assert.equal(preview, 'file_path: /a/b.js');
    assert.ok(!preview.includes('leaked-secret'));
  });

  it('MultiEdit: redacts edits array, exposes only file_path', () => {
    const { buildInputPreview } = require('../hooks/audit-logger.js');
    const preview = buildInputPreview('MultiEdit', {
      file_path: '/a/b.js',
      edits: [{ new_string: 'leaked-secret' }],
    });
    assert.equal(preview, 'file_path: /a/b.js');
    assert.ok(!preview.includes('leaked-secret'));
  });

  it('Bash: redacts command, exposes only file_path fallback', () => {
    const { buildInputPreview } = require('../hooks/audit-logger.js');
    const preview = buildInputPreview('Bash', { command: 'curl -H "Authorization: Bearer sk-ant-secret" https://x' });
    assert.equal(preview, 'file_path: [unknown]');
    assert.ok(!preview.includes('Bearer'));
  });

  it('non-redacted tool: returns truncated JSON with newlines stripped', () => {
    const { buildInputPreview } = require('../hooks/audit-logger.js');
    const preview = buildInputPreview('Read', { file_path: '/a/b.js\nwith-newline' });
    assert.ok(!preview.includes('\n'));
    assert.match(preview, /^\{/);
  });

  it('non-redacted tool: truncates at INPUT_PREVIEW_MAX with an ellipsis', () => {
    const { buildInputPreview, INPUT_PREVIEW_MAX } = require('../hooks/audit-logger.js');
    const longValue = 'x'.repeat(INPUT_PREVIEW_MAX * 2);
    const preview = buildInputPreview('Grep', { pattern: longValue });
    assert.ok(preview.length <= INPUT_PREVIEW_MAX + 3);
    assert.ok(preview.endsWith('...'));
  });

  it('non-redacted tool: unserializable input (circular) returns a safe fallback', () => {
    const { buildInputPreview } = require('../hooks/audit-logger.js');
    const circular = {};
    circular.self = circular;
    const preview = buildInputPreview('Grep', circular);
    assert.equal(preview, '[unserializable]');
  });
});

// ---------------------------------------------------------------------------
// writeAuditRecord — file perms + jsonl shape
// ---------------------------------------------------------------------------
describe('writeAuditRecord', () => {
  it('writes a .jsonl line with 0o600 perms into CLAUDE_AUDIT_DIR', () => {
    const hook = requireHookWithSandboxAuditDir();
    const record = { ts: new Date().toISOString(), tool: 'Write', status: 'allowed' };
    hook.writeAuditRecord(record);

    const logFile = path.join(tmpDir, `${hook.todayDateString()}.jsonl`);
    assert.ok(fs.existsSync(logFile), 'log file must be written into the sandbox dir');
    assert.ok(logFile.startsWith(tmpDir), 'log file must live inside the sandbox');

    const mode = fs.statSync(logFile).mode & 0o777;
    assert.equal(mode, 0o600);

    const content = fs.readFileSync(logFile, 'utf8');
    const parsed = JSON.parse(content.trim());
    assert.equal(parsed.tool, 'Write');
  });

  it('appends multiple records as separate JSONL lines', () => {
    const hook = requireHookWithSandboxAuditDir();
    hook.writeAuditRecord({ tool: 'Write' });
    hook.writeAuditRecord({ tool: 'Edit' });

    const logFile = path.join(tmpDir, `${hook.todayDateString()}.jsonl`);
    const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[0]).tool, 'Write');
    assert.equal(JSON.parse(lines[1]).tool, 'Edit');
  });

  it('fails silently (never throws) when the audit dir cannot be created', () => {
    // Point AUDIT_DIR at a path nested under a file (not a directory) so
    // ensureAuditDir's mkdirSync throws internally — writeAuditRecord must
    // swallow it, per "audit logging must never break Claude Code".
    const blockerFile = path.join(tmpDir, 'blocker');
    fs.writeFileSync(blockerFile, 'not a directory');
    process.env.CLAUDE_AUDIT_DIR = path.join(blockerFile, 'nested', 'audit');
    delete require.cache[HOOK_PATH];
    const hook = require('../hooks/audit-logger.js');

    assert.doesNotThrow(() => hook.writeAuditRecord({ tool: 'Write' }));
  });
});

// ---------------------------------------------------------------------------
// logToolCall — full record shape
// ---------------------------------------------------------------------------
describe('logToolCall', () => {
  let originalSessionId;
  let originalProjectDir;

  beforeEach(() => {
    originalSessionId = process.env.CLAUDE_SESSION_ID;
    originalProjectDir = process.env.CLAUDE_PROJECT_DIR;
  });

  afterEach(() => {
    if (originalSessionId === undefined) delete process.env.CLAUDE_SESSION_ID;
    else process.env.CLAUDE_SESSION_ID = originalSessionId;
    if (originalProjectDir === undefined) delete process.env.CLAUDE_PROJECT_DIR;
    else process.env.CLAUDE_PROJECT_DIR = originalProjectDir;
  });

  it('builds the full record shape (ts, session_id, tool, project, status, input_preview)', () => {
    process.env.CLAUDE_SESSION_ID = 'sess-123';
    process.env.CLAUDE_PROJECT_DIR = '/repo/project';
    const hook = requireHookWithSandboxAuditDir();

    hook.logToolCall({ tool_name: 'Write', tool_input: { file_path: '/a/b.js', content: 'secret' } });

    const logFile = path.join(tmpDir, `${hook.todayDateString()}.jsonl`);
    const record = JSON.parse(fs.readFileSync(logFile, 'utf8').trim());

    assert.equal(record.session_id, 'sess-123');
    assert.equal(record.tool, 'Write');
    assert.equal(record.project, '/repo/project');
    assert.equal(record.status, 'allowed');
    assert.equal(record.input_preview, 'file_path: /a/b.js');
    assert.ok(!JSON.stringify(record).includes('secret'), 'record must never leak Write content');
    assert.match(record.ts, /^\d{4}-\d{2}-\d{2}T/);
  });

  it('defaults session_id to "unknown" and project to process.cwd() when env vars are unset', () => {
    delete process.env.CLAUDE_SESSION_ID;
    delete process.env.CLAUDE_PROJECT_DIR;
    const hook = requireHookWithSandboxAuditDir();

    hook.logToolCall({ tool_name: 'Bash', tool_input: { command: 'ls' } });

    const logFile = path.join(tmpDir, `${hook.todayDateString()}.jsonl`);
    const record = JSON.parse(fs.readFileSync(logFile, 'utf8').trim());
    assert.equal(record.session_id, 'unknown');
    assert.equal(record.project, process.cwd());
  });

  it('defaults tool_name to "unknown" for a malformed event', () => {
    const hook = requireHookWithSandboxAuditDir();
    hook.logToolCall({});

    const logFile = path.join(tmpDir, `${hook.todayDateString()}.jsonl`);
    const record = JSON.parse(fs.readFileSync(logFile, 'utf8').trim());
    assert.equal(record.tool, 'unknown');
  });
});
