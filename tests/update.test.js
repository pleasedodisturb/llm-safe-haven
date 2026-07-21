'use strict';

// TQ-02: coverage for lib/update.js's copy/idempotency/copy-failure paths.
//
// lib/update.js bakes HOOKS_DIR from os.homedir() at module top level
// (same WR-01-shaped ordering trap as lib/audit.js's destructured
// requires, just against the `os` builtin) — the stub MUST land in
// require.cache BEFORE lib/update.js is (re-)required, so update.js's
// top-level HOOKS_DIR const rebinds against the sandbox HOME instead of
// the real ~/.claude/hooks. See 09-PATTERNS.md "tests/update.test.js".

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { stubHomedir } = require('./helpers/module-stub.js');
const { captureLog } = require('./helpers/capture-log.js');

const osPath = require.resolve('os');
const updatePath = require.resolve('../lib/update.js');
const HOOK_FILES = ['bash-firewall.js', 'secret-guard.js', 'audit-logger.js'];

// Root portability: mode bits do not block uid 0, so permission-denied
// tests can only pass as non-root (containers/CI sometimes run as root).
const runningAsRoot = typeof process.getuid === 'function' && process.getuid() === 0;

describe('update()', () => {
  let tmpHome;
  let originalOsEntry;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-update-test-'));
    originalOsEntry = require.cache[osPath];
  });

  afterEach(() => {
    // Restore the real os module and evict the stub-bound update.js so
    // later suites in this process never see the sandboxed HOOKS_DIR.
    if (originalOsEntry === undefined) delete require.cache[osPath];
    else require.cache[osPath] = originalOsEntry;
    delete require.cache[updatePath];

    // Restore write permissions before rmSync so the copy-failure test's
    // chmod doesn't make its own cleanup fail.
    try {
      fs.chmodSync(path.join(tmpHome, '.claude', 'hooks'), 0o755);
    } catch {
      // Directory may not exist in every test — fine.
    }
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('happy path: copies and chmods hook files into a populated sandbox HOOKS_DIR', async () => {
    const { update } = stubHomedir(tmpHome, updatePath);
    const hooksDir = path.join(tmpHome, '.claude', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    // update() only copies over an EXISTING dest file (it skips hooks that
    // were never installed) — pre-seed stale content so the copy branch
    // (srcContent !== destContent) actually fires.
    for (const hook of HOOK_FILES) {
      fs.writeFileSync(path.join(hooksDir, hook), '// stale content\n');
    }

    await captureLog(() => update({})); // suppress update()'s human-readable output

    const realHooksSource = path.join(__dirname, '..', 'hooks');
    for (const hook of HOOK_FILES) {
      const destPath = path.join(hooksDir, hook);
      assert.ok(destPath.startsWith(tmpHome), 'every write must stay inside the mkdtemp sandbox');
      assert.ok(fs.existsSync(destPath), `${hook} should exist after update()`);

      const destContent = fs.readFileSync(destPath, 'utf8');
      const srcContent = fs.readFileSync(path.join(realHooksSource, hook), 'utf8');
      assert.equal(destContent, srcContent, `${hook} content should now match the shipped hook`);

      const mode = fs.statSync(destPath).mode & 0o777;
      assert.equal(mode, 0o755, `${hook} should be chmod'd 0755 after copy`);
    }
  });

  it('idempotent re-run: a second update() against an already-populated destination completes without error', async () => {
    const { update } = stubHomedir(tmpHome, updatePath);
    const hooksDir = path.join(tmpHome, '.claude', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    for (const hook of HOOK_FILES) {
      fs.writeFileSync(path.join(hooksDir, hook), '// stale content\n');
    }

    await captureLog(() => update({})); // first run copies real content over the stale content
    await captureLog(() => assert.doesNotThrow(() => update({}), 'a second run against already-synced content must not throw'));

    const realHooksSource = path.join(__dirname, '..', 'hooks');
    for (const hook of HOOK_FILES) {
      const destContent = fs.readFileSync(path.join(hooksDir, hook), 'utf8');
      const srcContent = fs.readFileSync(path.join(realHooksSource, hook), 'utf8');
      assert.equal(destContent, srcContent, `${hook} should still match after the idempotent re-run`);
    }
  });

  it('copy-failure: a read-only destination file makes update() throw synchronously (assert.throws, not assert.rejects)', { skip: runningAsRoot }, async () => {
    const { update } = stubHomedir(tmpHome, updatePath);
    const hooksDir = path.join(tmpHome, '.claude', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    for (const hook of HOOK_FILES) {
      fs.writeFileSync(path.join(hooksDir, hook), '// stale content\n');
    }

    // lib/update.js has no try/catch around fs.copyFileSync/fs.chmodSync —
    // a copy failure propagates synchronously, so assert.throws is correct
    // here (there is no settleCommand wrapper for `update`, unlike
    // install/audit/scan).
    const readOnlyTarget = path.join(hooksDir, HOOK_FILES[0]);
    fs.chmodSync(readOnlyTarget, 0o400);

    await captureLog(() => assert.throws(() => update({}), /EACCES|EPERM/));
  });

  // hooksSource-missing branch (lib/update.js ~line 18-21) calls the real
  // process.exit(1) directly — per RESEARCH.md Pitfall 3 / Open Question 3
  // this is intentionally left uncovered rather than monkeypatching
  // process.exit: hooks/ always ships in the published tarball, so this
  // branch is unreachable in practice, and stubbing process.exit would
  // test a scenario that can't occur outside a broken install.
});
