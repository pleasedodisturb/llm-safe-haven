'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { loadAgents, detectAll } = require('../../lib/agents/index.js');

describe('loadAgents', () => {
  it('returns an array', () => {
    const agents = loadAgents();
    assert.ok(Array.isArray(agents), 'loadAgents() should return an array');
  });

  it('all agents have required fields (name, id, tier, detect, harden, audit)', () => {
    const agents = loadAgents();
    assert.ok(agents.length > 0, 'should load at least one agent');

    for (const agent of agents) {
      assert.ok(typeof agent.name === 'string' && agent.name.length > 0,
        `agent ${agent.id || '?'} must have a non-empty name`);
      assert.ok(typeof agent.id === 'string' && agent.id.length > 0,
        `agent ${agent.name || '?'} must have a non-empty id`);
      assert.ok(typeof agent.tier === 'number',
        `agent ${agent.id} must have a numeric tier`);
      assert.ok(typeof agent.detect === 'function',
        `agent ${agent.id} must have a detect function`);
      assert.ok(typeof agent.harden === 'function',
        `agent ${agent.id} must have a harden function`);
      assert.ok(typeof agent.audit === 'function',
        `agent ${agent.id} must have an audit function`);
    }
  });

  it('all agents have tier 1, 2, or 3', () => {
    const agents = loadAgents();
    for (const agent of agents) {
      assert.ok([1, 2, 3].includes(agent.tier),
        `agent ${agent.id} has tier ${agent.tier}, expected 1, 2, or 3`);
    }
  });

  it('no duplicate IDs', () => {
    const agents = loadAgents();
    const ids = agents.map(a => a.id);
    const unique = new Set(ids);
    assert.strictEqual(ids.length, unique.size,
      `duplicate IDs found: ${ids.filter((id, i) => ids.indexOf(id) !== i).join(', ')}`);
  });
});

describe('detectAll', () => {
  it('returns results for each agent without crashing', () => {
    const results = detectAll();
    assert.ok(Array.isArray(results), 'detectAll() should return an array');
    assert.ok(results.length > 0, 'should have at least one result');

    for (const result of results) {
      assert.ok(typeof result.id === 'string', 'each result must have an id');
      assert.ok(result.detected !== undefined, `result for ${result.id} must have a detected property`);
      assert.ok(typeof result.detected.found === 'boolean',
        `detected.found for ${result.id} must be a boolean`);
    }
  });
});
