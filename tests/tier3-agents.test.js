'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

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
