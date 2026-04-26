'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const TIER2_AGENTS = [
  { file: '../../lib/agents/cursor.js', id: 'cursor' },
  { file: '../../lib/agents/windsurf.js', id: 'windsurf' },
  { file: '../../lib/agents/cline.js', id: 'cline' },
  { file: '../../lib/agents/continue-dev.js', id: 'continue-dev' },
  { file: '../../lib/agents/aider.js', id: 'aider' },
  { file: '../../lib/agents/codex-cli.js', id: 'codex-cli' },
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
