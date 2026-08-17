'use strict';

// In-process unit tests for lib/install.js — install() orchestration and
// its CR-01 unified-level wiring (TQ-02, D-13). lib/install.js has zero
// file I/O of its own (RESEARCH correction #1): every observable side
// effect is console.log plus calls into its stubbed collaborators, so this
// suite never touches real fs, network, or spawns a real agent CLI.
//
// Stub strategy (avoiding the WR-01 stale-binding trap, mirrored from
// tests/audit.test.js): lib/install.js captures detectAll/getByIds and
// scanForEnvFiles in top-level destructured requires, and reaches
// buildEnvelope transitively through lib/audit.js's computeScorecardLevel
// (also a top-level destructured require) — so all three stubs MUST land
// in require.cache BEFORE lib/install.js is first required in this
// process.

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { installStub } = require('./helpers/module-stub.js');

// ---- mutable stub state (reset in beforeEach) ----
let currentBuildEnvelope;
let currentAgents;
let currentEnvFiles;
// D-11 (G-1545, plan 18-04 Task 4): lib/install.js (and transitively
// lib/audit.js, reached via computeScorecardLevel) now import
// scanForEnvFilesDetailed/printEnvScanResult instead of the
// incomplete-discarding scanForEnvFiles/printEnvScan pair -- same stub
// extension as tests/audit.test.js, and for the same reason (the stub
// replaces lib/scan.js wholesale).
let currentEnvIncomplete;
let currentEnvDetail;

// The REAL printEnvScanResult renderer, captured BEFORE lib/scan.js is
// stubbed below, so the D-11 guard tests exercise actual rendering.
const { printEnvScanResult: realPrintEnvScanResult } = require('../lib/scan.js');

installStub(require.resolve('../lib/scan-mcp.js'), {
  buildEnvelope: (...args) => currentBuildEnvelope(...args),
  scanMcp: () => Promise.reject(new Error('unused by install — present for shape parity')),
  findingsExitCode: () => 0,
});
installStub(require.resolve('../lib/agents/index.js'), {
  detectAll: () => currentAgents,
  getByIds: () => [],
});
installStub(require.resolve('../lib/scan.js'), {
  scanForEnvFiles: () => currentEnvFiles,
  scanForEnvFilesDetailed: () => currentEnvDetail || {
    files: currentEnvFiles,
    incomplete: currentEnvIncomplete,
    anomalyCount: currentEnvIncomplete ? 1 : 0,
    anomalyReasons: { unreadable: currentEnvIncomplete ? 1 : 0, budget: 0 },
    rootFailures: { missing: 0, unreadable: 0 },
  },
  printEnvScanResult: (...args) => realPrintEnvScanResult(...args),
});

// install() is required AFTER the stubs exist, so its own top-level
// bindings — and lib/audit.js's, reached transitively via
// computeScorecardLevel — resolve to the stubs above.
const { install } = require('../lib/install.js');

// Real (non-stubbed) collaborators: mcp/base.js frozen enums (EXIT only —
// fakeAgent/mcpFinding/envelope now live in the shared fixtures helper,
// tests/helpers/audit-fixtures.js, alongside the byte-identical copy in
// tests/audit.test.js).
const { EXIT } = require('../lib/mcp/base.js');
const { fakeAgent, mcpFinding, envelope } = require('./helpers/audit-fixtures.js');
const { captureLog } = require('./helpers/capture-log.js');

describe('install() orchestration (TQ-02, D-13)', () => {
  beforeEach(() => {
    currentBuildEnvelope = () => Promise.resolve(envelope());
    currentAgents = [fakeAgent()];
    currentEnvFiles = [];
    currentEnvIncomplete = false;
    currentEnvDetail = undefined;
  });

  it('zero-agents path: prints "No AI coding agents detected." and resolves undefined (bare return, not { code })', async () => {
    currentAgents = [];
    const { logs, result } = await captureLog(() => install({}));
    assert.equal(result, undefined, 'install() must bare-return on the zero-agents path, never a { code } object');
    assert.ok(logs.some((l) => l.includes('No AI coding agents detected.')), `expected the zero-agents message, got: ${logs.join('\n')}`);
  });

  it('unknown-agent selection: install({ agent: "nope" }) prints an "Unknown agent(s): nope" warning', async () => {
    const { logs, result } = await captureLog(() => install({ agent: 'nope' }));
    assert.equal(result, undefined);
    assert.ok(logs.some((l) => /Unknown agent\(s\): nope/.test(l)), `expected an unknown-agent warning, got: ${logs.join('\n')}`);
  });

  it('throwing harden() is contained: install() resolves and prints a "Hardening failed" warning, never rejects', async () => {
    currentAgents = [fakeAgent({ harden: () => { throw new Error('harden blew up'); } })];
    const { logs } = await captureLog(() => assert.doesNotReject(() => install({})));
    assert.ok(
      logs.some((l) => l.includes('Hardening failed') && l.includes('harden blew up')),
      `expected a contained hardening-failure warning, got: ${logs.join('\n')}`
    );
  });

  it('level aggregation: multiple agents feed computeScorecardLevel, printed scorecard reflects the max agent level', async () => {
    currentAgents = [
      fakeAgent({ id: 'low', audit: () => ({ checks: [], level: 2 }) }),
      fakeAgent({ id: 'high', audit: () => ({ checks: [], level: 4 }) }),
    ];
    const { logs } = await captureLog(() => install({}));
    assert.ok(
      logs.some((l) => l.includes('Security Level: 4 of 4')),
      `expected the aggregated (max) level 4 to render, got: ${logs.join('\n')}`
    );
  });

  it('CR-01: a verified capping MCP finding demotes the printed level (base 3 -> capped 2)', async () => {
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.FINDINGS,
      findings: [mcpFinding()],
    }));

    const { logs } = await captureLog(() => install({}));
    assert.ok(
      logs.some((l) => l.includes('Security Level: 2 of 4')),
      `expected the capped level 2 to render, got: ${logs.join('\n')}`
    );
    assert.ok(
      logs.some((l) => /Level capped at 2 \(was 3\)/.test(l)),
      `expected the cap explanation line, got: ${logs.join('\n')}`
    );
  });

  it('CR-01 incomplete: a rejecting buildEnvelope degrades to the incomplete-scan path, install() still resolves', async () => {
    currentBuildEnvelope = () => Promise.reject(new Error('hostile config engineered to crash discovery'));

    const { logs } = await captureLog(() => assert.doesNotReject(() => install({})));
    assert.ok(
      logs.some((l) => l.includes('Security Level: 2 of 4')),
      `expected the incomplete-scan ceiling (2) to render, got: ${logs.join('\n')}`
    );
    assert.ok(
      logs.some((l) => /could not complete/.test(l)),
      `expected the incomplete-scan warning to render, got: ${logs.join('\n')}`
    );
  });

  // D-11 (G-1545, plan 18-04 Task 4): install()'s env-scan render stops
  // printing a green check over an unread secret. install() has no exit
  // code of its own -- this is purely a render fix.
  it('D-11: an incomplete env scan prints no green line and renders the could-not-verify block instead', async () => {
    currentEnvDetail = {
      files: [],
      incomplete: true,
      anomalyCount: 1,
      anomalyReasons: { unreadable: 1, budget: 0 },
      rootFailures: { missing: 0, unreadable: 0 },
    };

    const { logs, result } = await captureLog(() => install({}));
    assert.equal(result, undefined, 'install() still bare-returns -- no exit-code change for this command');
    assert.ok(!logs.some((l) => l.includes('No .env files found')), 'no captured stdout line may print the green check');
    assert.ok(logs.some((l) => l.includes('could not verify')), `expected the could-not-verify line, got: ${logs.join('\n')}`);
  });

  it('D-11 PAIRED CONTROL: a complete, clean env detail still renders the green line and nothing extra', async () => {
    currentEnvDetail = {
      files: [],
      incomplete: false,
      anomalyCount: 0,
      anomalyReasons: { unreadable: 0, budget: 0 },
      rootFailures: { missing: 0, unreadable: 0 },
    };

    const { logs } = await captureLog(() => install({}));
    assert.ok(logs.some((l) => l.includes('No .env files found')), 'the green line must still print for a complete, clean env scan');
    assert.ok(!logs.some((l) => l.includes('could not verify')), 'a complete, clean env scan must never print the could-not-verify line');
  });
});

// EXIT-05 (G-1623, D-20-08): the human renderer must not print an uncapped
// `Security Level: N` line beneath the `◆ could not verify` env block --
// install() especially, since it has no exit code of its own and its render
// IS its verdict channel (D-20-03).
describe('EXIT-05 (G-1623): install() renders the capped level under an incomplete env scan', () => {
  beforeEach(() => {
    currentBuildEnvelope = () => Promise.resolve(envelope());
    // Agent level 4 -- well above the ceiling of 2 -- so an uncapped render
    // would print "Security Level: 4 of 4" if the cap failed to fire.
    currentAgents = [fakeAgent({ audit: () => ({ checks: [], level: 4 }) })];
    currentEnvFiles = [];
    currentEnvIncomplete = false;
    currentEnvDetail = undefined;
  });

  it('an incomplete env scan prints no uncapped level, prints the capped Security Level: 2, and the cap reason line', async () => {
    currentEnvDetail = {
      files: [], incomplete: true, anomalyCount: 1,
      anomalyReasons: { unreadable: 1, budget: 0 },
      rootFailures: { missing: 0, unreadable: 0 },
    };

    const { logs } = await captureLog(() => install({}));
    assert.ok(!logs.some((l) => l.includes('Security Level: 3')), `no uncapped Security Level: 3 line, got: ${logs.join('\n')}`);
    assert.ok(!logs.some((l) => l.includes('Security Level: 4')), `no uncapped Security Level: 4 line, got: ${logs.join('\n')}`);
    assert.ok(logs.some((l) => l.includes('Security Level: 2')), `expected the capped Security Level: 2 line, got: ${logs.join('\n')}`);
    assert.ok(logs.some((l) => /Level capped at 2/.test(l)), `expected the cap's reason line, got: ${logs.join('\n')}`);
    assert.ok(logs.some((l) => l.includes('could not verify')), 'the could-not-verify block must still print');
  });

  it('MUST-STILL-PASS TWIN: a complete, clean env detail still prints Security Level: 4 with no env cap line', async () => {
    currentEnvDetail = {
      files: [], incomplete: false, anomalyCount: 0,
      anomalyReasons: { unreadable: 0, budget: 0 },
      rootFailures: { missing: 0, unreadable: 0 },
    };

    const { logs } = await captureLog(() => install({}));
    assert.ok(logs.some((l) => l.includes('Security Level: 4 of 4')), `expected the uncapped Security Level: 4, got: ${logs.join('\n')}`);
    assert.ok(!logs.some((l) => /Level capped at/.test(l)), 'no cap line must print for a complete, clean env scan');
  });
});
