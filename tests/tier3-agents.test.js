'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

const { installStub } = require('./helpers/module-stub.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
    passed++;
  } catch (err) {
    console.log(`  FAIL  ${name}`);
    console.log(`        ${err.message}`);
    failed++;
  }
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tier3-test-'));
}

// ---------------------------------------------------------------------------
// Hermeticity (D-04/D-05, T-09-10/T-09-11): stub child_process ONCE, before
// any detect()/harden() call below, so no Tier 3 module ever spawns a real
// CLI subprocess (e.g. `which gemini`). Scope honesty: only subprocess
// execution is stubbed — base.js's fs-based detection probes (macAppExists
// via fs.existsSync under /Applications, vscodeExtensionExists via
// fs.readdirSync of ~/.vscode/extensions) still hit the real filesystem.
// Those are bounded existsSync/readdirSync calls (no subprocess, no
// coverage pollution from child processes), but detect()'s `found` flags
// remain machine-dependent — which is fine here, since the shape-only
// assertions below never depend on a specific found value. lib/agents/
// base.js requires `child_process` INSIDE each function body (commandExists/
// getVersion), not at module top level, so there is no WR-01 stale-binding
// ordering requirement — installing the stub here, before the loops run, is
// sufficient (module-load order of the Tier 3 agent files themselves does
// not matter either, since they call commandExists()/getVersion() lazily at
// detect()-call time, not at require()-time).
installStub(require.resolve('child_process'), {
  execFileSync: () => { throw new Error('stubbed — must never actually spawn a real CLI binary'); },
});

// Hermeticity (TESTQ-01, D-01/D-03): stub fs ONCE, immediately after the
// child_process stub above, so base.js's macAppExists() (fs.existsSync
// under /Applications) and vscodeExtensionExists() (fs.readdirSync of
// ~/.vscode/extensions) produce deterministic, machine-independent `found`
// flags for the Tier 3 modules below. This is a hand-rolled single-pass
// runner (Pitfall 4) with no per-test setup/teardown lifecycle, so — matching
// the file's own child_process precedent — the stub is installed once and
// never restored; spread-and-override (Pitfall 2) keeps writeIgnoreFile's
// realpathSync/writeFileSync real so the IGNORE_FILE_MODULES harden() loop
// below is unaffected.
//
// Fixture is deliberately mixed so both D-03 branches are exercised across
// the Tier 3 modules that call these probes: existsSync only matches a
// "Zed.app" path (zed-ai's macAppExists('Zed') finds it; replit-agent's
// macAppExists('Replit') does not), and readdirSync returns extension-dir
// entries that match amazon-q and github-copilot's extension IDs but not
// augment's.
const VSCODE_EXT_DIR_SUFFIX = path.join('.vscode', 'extensions');
installStub(require.resolve('fs'), {
  ...fs,
  existsSync: (p) => p.endsWith('Zed.app'),
  readdirSync: (p) => {
    // Only the ~/.vscode/extensions probe is stubbed — other readdirSync
    // callers in-process (notably lib/agents/index.js's own auto-discovery
    // scan of this directory) must keep hitting the real filesystem, or
    // loadAgents()/detectAll() below would break entirely.
    if (p.endsWith(VSCODE_EXT_DIR_SUFFIX)) {
      return ['amazonwebservices.amazon-q-vscode-1.2.3', 'github.copilot-1.90.0'];
    }
    return fs.readdirSync(p);
  },
});

// ---------------------------------------------------------------------------
// Module list — every Tier 3 agent we just added
// ---------------------------------------------------------------------------

const TIER3_MODULES = [
  { file: 'gemini-cli.js', id: 'gemini-cli', name: 'Gemini CLI' },
  { file: 'jetbrains-ai.js', id: 'jetbrains-ai', name: 'JetBrains AI' },
  { file: 'zed-ai.js', id: 'zed-ai', name: 'Zed AI' },
  { file: 'amazon-q.js', id: 'amazon-q', name: 'Amazon Q' },
  { file: 'augment.js', id: 'augment', name: 'Augment' },
  { file: 'replit-agent.js', id: 'replit-agent', name: 'Replit Agent' },
  { file: 'github-copilot.js', id: 'github-copilot', name: 'GitHub Copilot' },
];

console.log('tier3-agents.test.js');
console.log('');

// ---------------------------------------------------------------------------
// Contract tests — every module exports the required interface
// ---------------------------------------------------------------------------

for (const { file, id, name } of TIER3_MODULES) {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', file));

  test(`${id}: exports name "${name}"`, () => {
    assert.strictEqual(mod.name, name);
  });

  test(`${id}: exports id "${id}"`, () => {
    assert.strictEqual(mod.id, id);
  });

  test(`${id}: tier is 3`, () => {
    assert.strictEqual(mod.tier, 3);
  });

  test(`${id}: detect is a function`, () => {
    assert.strictEqual(typeof mod.detect, 'function');
  });

  test(`${id}: harden is a function`, () => {
    assert.strictEqual(typeof mod.harden, 'function');
  });

  test(`${id}: audit is a function`, () => {
    assert.strictEqual(typeof mod.audit, 'function');
  });
}

// ---------------------------------------------------------------------------
// detect() tests — returns correct shape
// ---------------------------------------------------------------------------

for (const { file, id } of TIER3_MODULES) {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', file));

  test(`${id}: detect() returns { found: boolean }`, () => {
    const result = mod.detect();
    assert.strictEqual(typeof result.found, 'boolean');
  });
}

// ---------------------------------------------------------------------------
// fs-probe hermeticity (TESTQ-01, D-03 both-branch): these cases assert
// OPPOSITE outcomes from the single fs stub installed above, so they cannot
// all pass unless macAppExists()/vscodeExtensionExists() actually honor the
// require.cache stub — proving the fix is non-vacuous and machine-independent
// (T-11-02-02). child_process is stubbed to throw for every module in this
// file, so commandExists() is false everywhere and cannot mask these results.
// ---------------------------------------------------------------------------

test('zed-ai: macAppExists finds the stubbed Zed.app (found branch)', () => {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', 'zed-ai.js'));
  assert.strictEqual(mod.detect().found, true);
});

test('replit-agent: macAppExists misses when the app name does not match the stub (not-found branch)', () => {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', 'replit-agent.js'));
  assert.strictEqual(mod.detect().found, false);
});

test('amazon-q: vscodeExtensionExists finds a matching stubbed extension-dir entry (found branch)', () => {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', 'amazon-q.js'));
  assert.strictEqual(mod.detect().found, true);
});

test('github-copilot: vscodeExtensionExists finds a matching stubbed extension-dir entry (found branch)', () => {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', 'github-copilot.js'));
  assert.strictEqual(mod.detect().found, true);
});

test('augment: vscodeExtensionExists misses when no stubbed extension-dir entry matches (not-found branch)', () => {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', 'augment.js'));
  assert.strictEqual(mod.detect().found, false);
});

// ---------------------------------------------------------------------------
// harden() tests — returns { actions: [], warnings: [] }
// ---------------------------------------------------------------------------

for (const { file, id } of TIER3_MODULES) {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', file));

  test(`${id}: harden() returns actions and warnings arrays`, () => {
    const dir = tmpDir();
    const result = mod.harden(dir, { dryRun: true });
    assert.ok(Array.isArray(result.actions), 'actions should be an array');
    assert.ok(Array.isArray(result.warnings), 'warnings should be an array');
    assert.ok(result.warnings.length > 0, 'Tier 3 modules should produce at least one warning');
    fs.rmSync(dir, { recursive: true });
  });
}

// ---------------------------------------------------------------------------
// audit() tests — returns { checks: [], level: number }
// ---------------------------------------------------------------------------

for (const { file, id } of TIER3_MODULES) {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', file));

  test(`${id}: audit() returns checks array and level number`, () => {
    const result = mod.audit();
    assert.ok(Array.isArray(result.checks), 'checks should be an array');
    assert.strictEqual(typeof result.level, 'number');
  });
}

// ---------------------------------------------------------------------------
// Ignore-file dry-run tests (modules that create ignore files)
// ---------------------------------------------------------------------------

const IGNORE_FILE_MODULES = [
  { file: 'gemini-cli.js', id: 'gemini-cli', ignoreFile: '.geminiignore' },
  { file: 'github-copilot.js', id: 'github-copilot', ignoreFile: '.copilotignore' },
];

for (const { file, id, ignoreFile } of IGNORE_FILE_MODULES) {
  const mod = require(path.join(__dirname, '..', 'lib', 'agents', file));

  test(`${id}: dry-run does not create ${ignoreFile}`, () => {
    const dir = tmpDir();
    const result = mod.harden(dir, { dryRun: true });
    assert.ok(!fs.existsSync(path.join(dir, ignoreFile)), `${ignoreFile} should not exist in dry-run`);
    assert.ok(result.actions.some(a => a.includes('dry-run')), 'Should have dry-run action');
    fs.rmSync(dir, { recursive: true });
  });

  test(`${id}: non-dry-run creates ${ignoreFile}`, () => {
    const dir = tmpDir();
    const result = mod.harden(dir, { dryRun: false });
    assert.ok(fs.existsSync(path.join(dir, ignoreFile)), `${ignoreFile} should be created`);
    assert.ok(result.actions.some(a => a.includes('created')), 'Should have created action');

    const content = fs.readFileSync(path.join(dir, ignoreFile), 'utf8');
    assert.ok(content.includes('.env'), 'Ignore file should contain .env pattern');
    fs.rmSync(dir, { recursive: true });
  });

  test(`${id}: skips if ${ignoreFile} already exists`, () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, ignoreFile), '# existing');
    const result = mod.harden(dir, { dryRun: false });
    assert.ok(result.actions.some(a => a.includes('already exists')), 'Should report already exists');

    const content = fs.readFileSync(path.join(dir, ignoreFile), 'utf8');
    assert.strictEqual(content, '# existing', 'Should not overwrite existing file');
    fs.rmSync(dir, { recursive: true });
  });
}

// ---------------------------------------------------------------------------
// Registry integration test
// ---------------------------------------------------------------------------

test('loadAgents includes all 7 Tier 3 modules', () => {
  const { loadAgents } = require(path.join(__dirname, '..', 'lib', 'agents', 'index.js'));
  const agents = loadAgents();
  const tier3 = agents.filter(a => a.tier === 3);
  assert.strictEqual(tier3.length, 7, `Expected 7 Tier 3 agents, got ${tier3.length}`);
});

test('loadAgents returns 14 total agents', () => {
  const { loadAgents } = require(path.join(__dirname, '..', 'lib', 'agents', 'index.js'));
  const agents = loadAgents();
  assert.strictEqual(agents.length, 14, `Expected 14 total agents, got ${agents.length}`);
});

test('loadAgents sorts Tier 3 after Tier 1 and Tier 2', () => {
  const { loadAgents } = require(path.join(__dirname, '..', 'lib', 'agents', 'index.js'));
  const agents = loadAgents();
  const tiers = agents.map(a => a.tier);

  // Every tier value should be >= the previous one
  for (let i = 1; i < tiers.length; i++) {
    assert.ok(tiers[i] >= tiers[i - 1], `Agent ${agents[i].id} (tier ${tiers[i]}) should not come before tier ${tiers[i - 1]}`);
  }
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('');
console.log(`${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
