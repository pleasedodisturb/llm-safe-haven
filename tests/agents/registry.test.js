'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { installStub } = require('../helpers/module-stub.js');

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
  // Hermeticity (D-04/D-05, T-09-10/T-09-11): stub child_process so
  // detectAll() never spawns a real `which`/`--version` subprocess for any
  // installed CLI on the machine running the suite — deterministic on a
  // machine with zero agents installed AND on one where e.g. Cursor exists.
  // lib/agents/base.js requires `child_process` INSIDE each function body
  // (commandExists/getVersion), not at module top level, so there is no
  // WR-01 stale-binding ordering requirement here — the stub can be
  // installed at any point before detectAll() runs.
  const childProcessPath = require.resolve('child_process');
  let originalChildProcessEntry;

  function installThrowingChildProcessStub() {
    originalChildProcessEntry = require.cache[childProcessPath];
    installStub(childProcessPath, {
      execFileSync: () => { throw new Error('nope — simulate not installed everywhere'); },
    });
  }

  function restoreChildProcess() {
    if (originalChildProcessEntry === undefined) delete require.cache[childProcessPath];
    else require.cache[childProcessPath] = originalChildProcessEntry;
  }

  it('returns results for each agent without crashing', () => {
    installThrowingChildProcessStub();
    let results;
    try {
      results = detectAll();
    } finally {
      restoreChildProcess();
    }
    assert.ok(Array.isArray(results), 'detectAll() should return an array');
    assert.ok(results.length > 0, 'should have at least one result');

    for (const result of results) {
      assert.ok(typeof result.id === 'string', 'each result must have an id');
      assert.ok(result.detected !== undefined, `result for ${result.id} must have a detected property`);
      assert.ok(typeof result.detected.found === 'boolean',
        `detected.found for ${result.id} must be a boolean`);
    }
  });

  it('never spawns a real CLI subprocess (child_process.execFileSync throws for every agent)', () => {
    let callCount = 0;
    originalChildProcessEntry = require.cache[childProcessPath];
    installStub(childProcessPath, {
      execFileSync: () => { callCount += 1; throw new Error('stubbed — must never actually be called on a real binary'); },
    });
    try {
      detectAll();
    } finally {
      restoreChildProcess();
    }
    // Agents that rely on commandExists()/getVersion() must have routed
    // through the stub at least once — proving no unstubbed execFileSync
    // reference leaked through (D-04/D-05). Scope honesty: only SUBPROCESS
    // execution is stubbed here. The fs-based detection probes — base.js's
    // macAppExists (fs.existsSync under /Applications) and
    // vscodeExtensionExists (fs.readdirSync of ~/.vscode/extensions) —
    // still hit the real filesystem: bounded existsSync/readdirSync calls,
    // no subprocess and thus no coverage pollution from child processes,
    // but the resulting `found` flags remain machine-dependent.
    assert.ok(callCount > 0, 'at least one Tier 1/2 agent must call commandExists/getVersion via the stubbed child_process');
  });
});
