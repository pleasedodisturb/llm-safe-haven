'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');

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

  // Hermeticity (TESTQ-01, D-01/D-03): stub fs so base.js's macAppExists()
  // (fs.existsSync under /Applications) and vscodeExtensionExists()
  // (fs.readdirSync of ~/.vscode/extensions) produce deterministic `found`
  // flags regardless of what is really installed on the machine running the
  // suite. Spread-and-override (Pitfall 2): writeIgnoreFile() in the same
  // base.js file uses fs.realpathSync/fs.writeFileSync, never
  // existsSync/readdirSync, so spreading the real fs module first keeps
  // those calls real for any other test in this process.
  const fsPath = require.resolve('fs');
  let originalFsEntry;

  function installFsProbeStub({ appExists, extDirEntries }) {
    originalFsEntry = require.cache[fsPath];
    installStub(fsPath, {
      ...fs,
      existsSync: (p) => (appExists ? p.includes('.app') : false),
      readdirSync: (p) => {
        if (extDirEntries === undefined) {
          throw Object.assign(new Error('ENOENT — simulate no ~/.vscode/extensions dir'), { code: 'ENOENT' });
        }
        return extDirEntries;
      },
    });
  }

  function restoreFs() {
    if (originalFsEntry === undefined) delete require.cache[fsPath];
    else require.cache[fsPath] = originalFsEntry;
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

  // D-03 both-branch hermeticity: these two tests assert OPPOSITE outcomes
  // (found vs not-found) from the same stubbed fs, so neither can pass by
  // accident on any particular machine — they can only both pass if
  // macAppExists()/vscodeExtensionExists() actually honor the require.cache
  // stub, proving the fs-probe seam is closed (T-11-02-02 non-vacuity).
  it('found branch: reports found for agents whose macAppExists/vscodeExtensionExists probes match the stubbed fs', () => {
    installThrowingChildProcessStub();
    installFsProbeStub({ appExists: true, extDirEntries: ['continue.continue-1.2.3'] });
    let results;
    try {
      results = detectAll();
    } finally {
      restoreChildProcess();
      restoreFs();
    }
    const cursor = results.find(r => r.id === 'cursor');
    const continueDev = results.find(r => r.id === 'continue-dev');
    assert.ok(cursor, 'cursor agent result must be present');
    assert.ok(continueDev, 'continue-dev agent result must be present');
    assert.strictEqual(cursor.detected.found, true,
      'cursor.detect() must report found=true when macAppExists() matches the stubbed fs (CLI stubbed absent, so this proves the fs branch)');
    assert.strictEqual(continueDev.detected.found, true,
      'continue-dev.detect() must report found=true when vscodeExtensionExists() matches the stubbed extension dir');
  });

  it('not-found branch: reports not-found for agents whose macAppExists/vscodeExtensionExists probes miss the stubbed fs', () => {
    installThrowingChildProcessStub();
    installFsProbeStub({ appExists: false, extDirEntries: undefined });
    let results;
    try {
      results = detectAll();
    } finally {
      restoreChildProcess();
      restoreFs();
    }
    const cursor = results.find(r => r.id === 'cursor');
    const continueDev = results.find(r => r.id === 'continue-dev');
    assert.ok(cursor, 'cursor agent result must be present');
    assert.ok(continueDev, 'continue-dev agent result must be present');
    assert.strictEqual(cursor.detected.found, false,
      'cursor.detect() must report found=false when macAppExists() misses the stubbed fs and the CLI is stubbed absent');
    assert.strictEqual(continueDev.detected.found, false,
      'continue-dev.detect() must report found=false when vscodeExtensionExists() throws ENOENT against the stubbed fs');
  });
});
