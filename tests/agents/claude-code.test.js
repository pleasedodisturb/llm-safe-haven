'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { installStub } = require('../helpers/module-stub.js');

const claudeCode = require('../../lib/agents/claude-code.js');

describe('claude-code agent', () => {
  describe('detect', () => {
    it('returns an object with a found boolean', () => {
      const result = claudeCode.detect();
      assert.ok(typeof result === 'object' && result !== null, 'detect() should return an object');
      assert.ok(typeof result.found === 'boolean', 'result.found should be a boolean');
    });
  });

  describe('harden', () => {
    it('with dryRun returns actions containing [dry-run]', () => {
      const result = claudeCode.harden('/tmp/lsh-test-nonexistent', { dryRun: true });
      assert.ok(typeof result === 'object' && result !== null);
      assert.ok(Array.isArray(result.actions), 'result.actions should be an array');
      assert.ok(result.actions.length > 0, 'should have at least one action');

      for (const action of result.actions) {
        assert.ok(action.includes('[dry-run]'),
          `expected action to contain "[dry-run]", got: ${action}`);
      }
    });
  });

  describe('audit', () => {
    it('returns checks array and level number', () => {
      const result = claudeCode.audit();
      assert.ok(typeof result === 'object' && result !== null);
      assert.ok(Array.isArray(result.checks), 'result.checks should be an array');
      assert.ok(typeof result.level === 'number', 'result.level should be a number');
    });

    it('checks include expected names', () => {
      const result = claudeCode.audit();
      const names = result.checks.map(c => c.name);

      assert.ok(names.some(n => /sandbox/i.test(n)),
        `expected a Sandbox check, got: ${names.join(', ')}`);
      assert.ok(names.some(n => /bash firewall/i.test(n)),
        `expected a bash firewall check, got: ${names.join(', ')}`);
      assert.ok(names.some(n => /secret guard/i.test(n)),
        `expected a secret guard check, got: ${names.join(', ')}`);
      assert.ok(names.some(n => /audit log/i.test(n)),
        `expected an audit log check, got: ${names.join(', ')}`);
    });

    it('each check has name, pass, and detail', () => {
      const result = claudeCode.audit();
      for (const check of result.checks) {
        assert.ok(typeof check.name === 'string' && check.name.length > 0,
          'check must have a non-empty name');
        assert.ok(typeof check.pass === 'boolean',
          `check "${check.name}" must have a boolean pass`);
        assert.ok(typeof check.detail === 'string',
          `check "${check.name}" must have a string detail`);
      }
    });
  });
});

// Real-fs coverage (extends the dry-run-only suite above, Open Question
// 1 / D-15): lib/agents/claude-code.js bakes HOOKS_DIR/SETTINGS_PATH/
// AUDIT_DIR from os.homedir() at module top level, so exercising the real
// hook-copy / settings-merge / backup-rotation behavior requires
// redirecting os.homedir() into an fs.mkdtempSync sandbox BEFORE the
// module is (re-)required — the same WR-01 stale-binding ordering rule
// tests/audit.test.js documents, applied to the `os` builtin instead of a
// project module (see tests/helpers/module-stub.js).
//
// Every write in this block lands under `tmpHome` (an mkdtemp sandbox),
// never the real ~/.claude — asserted explicitly below via the sandbox
// path-prefix checks (T-09-02).
describe('claude-code agent — real-fs harden/_mergeSettings/_backupFile (extends dry-run coverage)', () => {
  const osPath = require.resolve('os');
  const claudeCodePath = require.resolve('../../lib/agents/claude-code.js');

  let tmpHome;
  let claudeCodeReal;
  let originalOsEntry;
  let originalClaudeCodeEntry;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-claude-code-realfs-'));

    originalOsEntry = require.cache[osPath];
    originalClaudeCodeEntry = require.cache[claudeCodePath];

    // Spread the real os module first so unrelated os.* calls (used
    // transitively by lib/agents/base.js's macAppExists etc.) keep
    // working — only homedir() is redirected.
    installStub(osPath, { ...os, homedir: () => tmpHome });

    // Evict claude-code.js so its top-level HOOKS_DIR/SETTINGS_PATH/
    // AUDIT_DIR consts rebind against the stubbed os.homedir() on the
    // next require.
    delete require.cache[claudeCodePath];
    claudeCodeReal = require('../../lib/agents/claude-code.js');
  });

  afterEach(() => {
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;

    // Re-evict claude-code.js so later suites (and the dry-run describe
    // blocks above, if re-run) see the real os module again, not a
    // module instance still bound to this test's tmpHome.
    delete require.cache[claudeCodePath];
    if (originalClaudeCodeEntry !== undefined) require.cache[claudeCodePath] = originalClaudeCodeEntry;

    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('first-run harden(): creates HOOKS_DIR, copies HOOK_FILES, and merges settings.json — all under the sandbox', () => {
    const result = claudeCodeReal.harden(tmpHome, {});
    assert.ok(Array.isArray(result.actions));

    const hooksDir = path.join(tmpHome, '.claude', 'hooks');
    assert.ok(fs.existsSync(hooksDir), 'HOOKS_DIR should exist on disk');
    assert.ok(hooksDir.startsWith(tmpHome), 'HOOKS_DIR must live under the sandbox path prefix');

    for (const hook of ['bash-firewall.js', 'secret-guard.js', 'config-guard.js', 'audit-logger.js']) {
      const hookPath = path.join(hooksDir, hook);
      assert.ok(fs.existsSync(hookPath), `${hook} should be copied to the sandbox`);
      assert.ok(hookPath.startsWith(tmpHome), 'a written hook must live under the sandbox path prefix');
      assert.ok(result.actions.some((a) => a.includes(hook) && a.includes('installed')));
    }

    const settingsPath = path.join(tmpHome, '.claude', 'settings.json');
    assert.ok(fs.existsSync(settingsPath), 'settings.json should be written on first run');
    assert.ok(settingsPath.startsWith(tmpHome), 'settings.json must live under the sandbox path prefix');
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    assert.ok(settings.hooks && settings.hooks.PreToolUse && settings.hooks.PreToolUse.length > 0);
  });

  it('second-run idempotency: hooks report "already installed, skipped"; _mergeSettings reports "hooks already configured" with no rewrite', () => {
    claudeCodeReal.harden(tmpHome, {});
    const second = claudeCodeReal.harden(tmpHome, {});

    assert.ok(
      second.actions.some((a) => a.includes('already installed, skipped')),
      `expected an "already installed, skipped" action, got: ${second.actions.join(', ')}`
    );
    assert.ok(
      second.actions.some((a) => a.includes('hooks already configured')),
      `expected a "hooks already configured" action (no rewrite), got: ${second.actions.join(', ')}`
    );
  });

  it('corrupt settings.json: _mergeSettings catches the JSON.parse throw, returns a warning, never crashes', () => {
    fs.mkdirSync(path.join(tmpHome, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(tmpHome, '.claude', 'settings.json'), '{ this is not valid json');

    let result;
    assert.doesNotThrow(() => { result = claudeCodeReal._mergeSettings({}); });
    assert.deepEqual(result.actions, []);
    assert.ok(
      result.warnings.some((w) => /not valid JSON/i.test(w)),
      `expected a not-valid-JSON warning, got: ${result.warnings.join(', ')}`
    );
  });

  it('prototype-pollution guard: a __proto__/constructor-bearing settings.json payload never pollutes Object.prototype', () => {
    fs.mkdirSync(path.join(tmpHome, '.claude'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.claude', 'settings.json'),
      JSON.stringify({ '__proto__': { polluted: true }, constructor: { polluted: true }, hooks: {} })
    );

    claudeCodeReal._mergeSettings({});

    assert.equal(({}).polluted, undefined, 'Object.prototype must never be polluted by the merge');
    assert.equal(Object.prototype.polluted, undefined, 'Object.prototype must never be polluted by the merge');
  });

  it('backup rotation: writing 5 backups leaves only the 3 most recent (MAX_BACKUPS=3)', () => {
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    const settingsPath = path.join(claudeDir, 'settings.json');
    fs.writeFileSync(settingsPath, '{}');

    // Seed 4 older backups with deterministic, sortable timestamps so the
    // "3 most recent" assertion never races real Date() millisecond
    // resolution within a tight synchronous loop.
    const seeded = [
      'settings.json.bak.2020-01-01T00-00-00.000Z',
      'settings.json.bak.2020-01-02T00-00-00.000Z',
      'settings.json.bak.2020-01-03T00-00-00.000Z',
      'settings.json.bak.2020-01-04T00-00-00.000Z',
    ];
    for (const name of seeded) {
      fs.writeFileSync(path.join(claudeDir, name), '{}');
    }

    // A 5th, real-timestamped backup — its ISO date always sorts after
    // every seeded 2020 date, so it is guaranteed to survive rotation.
    const backupPath = claudeCodeReal._backupFile(settingsPath);
    assert.ok(backupPath, '_backupFile should return the new backup path');
    assert.ok(backupPath.startsWith(tmpHome), 'the backup must live under the sandbox path prefix');

    const remaining = fs.readdirSync(claudeDir)
      .filter((f) => f.startsWith('settings.json.bak.'))
      .sort();
    assert.equal(remaining.length, 3, `expected exactly 3 backups to survive rotation, got: ${remaining.join(', ')}`);
    assert.deepEqual(remaining, [
      'settings.json.bak.2020-01-03T00-00-00.000Z',
      'settings.json.bak.2020-01-04T00-00-00.000Z',
      path.basename(backupPath),
    ].sort());
  });

  it('copy-failure: harden() throws when HOOKS_DIR is read-only', () => {
    const hooksDir = path.join(tmpHome, '.claude', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.chmodSync(hooksDir, 0o500);

    try {
      assert.throws(() => claudeCodeReal.harden(tmpHome, {}), /EACCES|EPERM/);
    } finally {
      // Restore write permission before afterEach's rmSync cleanup runs,
      // or cleanup itself would fail on the read-only directory.
      fs.chmodSync(hooksDir, 0o700);
    }
  });
});
