'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { installStub } = require('../helpers/module-stub.js');

const TIER2_AGENTS = [
  { file: '../../lib/agents/cursor.js', id: 'cursor' },
  { file: '../../lib/agents/windsurf.js', id: 'windsurf' },
  { file: '../../lib/agents/cline.js', id: 'cline' },
  { file: '../../lib/agents/continue-dev.js', id: 'continue-dev' },
  { file: '../../lib/agents/aider.js', id: 'aider' },
  { file: '../../lib/agents/codex-cli.js', id: 'codex-cli' },
  { file: '../../lib/agents/goose.js', id: 'goose' },
  { file: '../../lib/agents/antigravity.js', id: 'antigravity' },
];

for (const { file, id } of TIER2_AGENTS) {
  const agent = require(file);

  describe(`${agent.name} (${id})`, () => {
    it('exports required interface (name, id, tier, detect, harden, audit)', () => {
      assert.ok(typeof agent.name === 'string' && agent.name.length > 0, 'must have a name');
      assert.ok(typeof agent.id === 'string' && agent.id.length > 0, 'must have an id');
      assert.strictEqual(agent.id, id, `id should be "${id}"`);
      assert.ok(typeof agent.tier === 'number', 'must have a numeric tier');
      assert.ok(typeof agent.detect === 'function', 'must have a detect function');
      assert.ok(typeof agent.harden === 'function', 'must have a harden function');
      assert.ok(typeof agent.audit === 'function', 'must have an audit function');
    });

    describe('harden with dryRun', () => {
      let tmpDir;

      beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `lsh-${id}-test-`));
      });

      afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      });

      it('does not create files when dryRun is true', () => {
        const result = agent.harden(tmpDir, { dryRun: true });

        assert.ok(typeof result === 'object' && result !== null, 'harden() should return an object');
        assert.ok(Array.isArray(result.actions), 'result.actions should be an array');
        assert.ok(Array.isArray(result.warnings), 'result.warnings should be an array');

        // Verify no files were created in tmpDir
        const files = fs.readdirSync(tmpDir);
        assert.strictEqual(files.length, 0,
          `dryRun should not create files, but found: ${files.join(', ')}`);
      });
    });

    describe('audit', () => {
      it('returns expected shape (checks array and level number)', () => {
        const result = agent.audit();
        assert.ok(typeof result === 'object' && result !== null, 'audit() should return an object');
        assert.ok(Array.isArray(result.checks), 'result.checks should be an array');
        assert.ok(typeof result.level === 'number', 'result.level should be a number');

        for (const check of result.checks) {
          assert.ok(typeof check.name === 'string' && check.name.length > 0,
            'each check must have a non-empty name');
          assert.ok(typeof check.pass === 'boolean',
            `check "${check.name}" must have a boolean pass`);
          assert.ok(typeof check.detail === 'string',
            `check "${check.name}" must have a string detail`);
        }
      });
    });
  });
}

// D-09 hermetic both-branch detect() tests for the two new Phase 12 agents
// (goose, antigravity). lib/agents/base.js requires child_process/fs INSIDE
// each helper function body (commandExists/macAppExists), not at module top
// level, so there is no WR-01 stale-binding ordering requirement here — the
// stub can be installed at any point before detect() runs, and goose.js /
// antigravity.js can be safely required once at the top of this file.
describe('goose detect() (hermetic, both branches — D-09)', () => {
  const childProcessPath = require.resolve('child_process');
  let originalEntry;

  afterEach(() => {
    if (originalEntry === undefined) delete require.cache[childProcessPath];
    else require.cache[childProcessPath] = originalEntry;
  });

  it('found branch: reports found=true when commandExists("goose") succeeds', () => {
    originalEntry = require.cache[childProcessPath];
    installStub(childProcessPath, { execFileSync: () => Buffer.from('1.0.0\n') });
    delete require.cache[require.resolve('../../lib/agents/goose.js')];
    const goose = require('../../lib/agents/goose.js');
    const result = goose.detect();
    assert.strictEqual(result.found, true);
    assert.strictEqual(result.path, 'goose');
  });

  it('not-found branch: reports found=false when commandExists("goose") throws', () => {
    originalEntry = require.cache[childProcessPath];
    installStub(childProcessPath, {
      execFileSync: () => { throw new Error('not installed'); },
    });
    delete require.cache[require.resolve('../../lib/agents/goose.js')];
    const goose = require('../../lib/agents/goose.js');
    const result = goose.detect();
    assert.strictEqual(result.found, false);
    assert.strictEqual(result.version, null);
    assert.strictEqual(result.path, null);
  });
});

describe('antigravity detect() (hermetic, both branches — D-09)', () => {
  const childProcessPath = require.resolve('child_process');
  const fsPath = require.resolve('fs');
  let originalChildProcessEntry;
  let originalFsEntry;

  afterEach(() => {
    if (originalChildProcessEntry === undefined) delete require.cache[childProcessPath];
    else require.cache[childProcessPath] = originalChildProcessEntry;
    if (originalFsEntry === undefined) delete require.cache[fsPath];
    else require.cache[fsPath] = originalFsEntry;
  });

  it('found branch: reports found=true when either commandExists("antigravity") or the .app bundle exists', () => {
    originalChildProcessEntry = require.cache[childProcessPath];
    installStub(childProcessPath, { execFileSync: () => Buffer.from('') });
    originalFsEntry = require.cache[fsPath];
    installStub(fsPath, { ...fs, existsSync: () => false });
    delete require.cache[require.resolve('../../lib/agents/antigravity.js')];
    const antigravity = require('../../lib/agents/antigravity.js');
    const result = antigravity.detect();
    assert.strictEqual(result.found, true);
    assert.strictEqual(result.path, 'antigravity');
  });

  it('not-found branch: reports found=false when both commandExists("antigravity") and the .app bundle check miss', () => {
    originalChildProcessEntry = require.cache[childProcessPath];
    installStub(childProcessPath, {
      execFileSync: () => { throw new Error('not installed'); },
    });
    originalFsEntry = require.cache[fsPath];
    installStub(fsPath, { ...fs, existsSync: () => false });
    delete require.cache[require.resolve('../../lib/agents/antigravity.js')];
    const antigravity = require('../../lib/agents/antigravity.js');
    const result = antigravity.detect();
    assert.strictEqual(result.found, false);
    assert.strictEqual(result.path, null);
  });
});
