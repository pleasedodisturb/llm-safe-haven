'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

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
