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

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { installStub } = require('./helpers/module-stub.js');

// ---- mutable stub state (reset in beforeEach) ----
let currentBuildEnvelope;
let currentAgents;
let currentEnvFiles;

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
});

// install() is required AFTER the stubs exist, so its own top-level
// bindings — and lib/audit.js's, reached transitively via
// computeScorecardLevel — resolve to the stubs above.
const { install } = require('../lib/install.js');

// Real (non-stubbed) collaborators: mcp/base.js frozen enums/Finding.
const { CONFIDENCE, EXIT, Finding, SEVERITY } = require('../lib/mcp/base.js');

function fakeAgent(overrides = {}) {
  return {
    id: 'fake-agent',
    name: 'Fake Agent',
    tier: 1,
    detected: { found: true, version: '1.2.3' },
    audit: () => ({ checks: [{ name: 'check', detail: 'ok', pass: true }], level: 3 }),
    ...overrides,
  };
}

function mcpFinding(overrides = {}) {
  return Finding({
    id: 'detector/rule',
    detector: 'detector',
    severity: SEVERITY.HIGH,
    confidence: CONFIDENCE.VERIFIED,
    agentId: 'fake-agent',
    scope: 'user',
    serverName: 'srv',
    message: 'a finding',
    ...overrides,
  });
}

function envelope({ exitCode = EXIT.CLEAN, findings = [] } = {}) {
  return { exitCode, findings, servers: [], sources: [] };
}

describe('install() orchestration (TQ-02, D-13)', () => {
  let originalLog;
  let logged;

  beforeEach(() => {
    currentBuildEnvelope = () => Promise.resolve(envelope());
    currentAgents = [fakeAgent()];
    currentEnvFiles = [];
    originalLog = console.log;
    logged = [];
    console.log = (...args) => logged.push(args.join(' '));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it('zero-agents path: prints "No AI coding agents detected." and resolves undefined (bare return, not { code })', async () => {
    currentAgents = [];
    const result = await install({});
    assert.equal(result, undefined, 'install() must bare-return on the zero-agents path, never a { code } object');
    assert.ok(logged.some((l) => l.includes('No AI coding agents detected.')), `expected the zero-agents message, got: ${logged.join('\n')}`);
  });

  it('unknown-agent selection: install({ agent: "nope" }) prints an "Unknown agent(s): nope" warning', async () => {
    const result = await install({ agent: 'nope' });
    assert.equal(result, undefined);
    assert.ok(logged.some((l) => /Unknown agent\(s\): nope/.test(l)), `expected an unknown-agent warning, got: ${logged.join('\n')}`);
  });

  it('throwing harden() is contained: install() resolves and prints a "Hardening failed" warning, never rejects', async () => {
    currentAgents = [fakeAgent({ harden: () => { throw new Error('harden blew up'); } })];
    await assert.doesNotReject(() => install({}));
    assert.ok(
      logged.some((l) => l.includes('Hardening failed') && l.includes('harden blew up')),
      `expected a contained hardening-failure warning, got: ${logged.join('\n')}`
    );
  });

  it('level aggregation: multiple agents feed computeScorecardLevel, printed scorecard reflects the max agent level', async () => {
    currentAgents = [
      fakeAgent({ id: 'low', audit: () => ({ checks: [], level: 2 }) }),
      fakeAgent({ id: 'high', audit: () => ({ checks: [], level: 4 }) }),
    ];
    await install({});
    assert.ok(
      logged.some((l) => l.includes('Security Level: 4 of 4')),
      `expected the aggregated (max) level 4 to render, got: ${logged.join('\n')}`
    );
  });

  it('CR-01: a verified capping MCP finding demotes the printed level (base 3 -> capped 2)', async () => {
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.FINDINGS,
      findings: [mcpFinding()],
    }));

    await install({});
    assert.ok(
      logged.some((l) => l.includes('Security Level: 2 of 4')),
      `expected the capped level 2 to render, got: ${logged.join('\n')}`
    );
    assert.ok(
      logged.some((l) => /Level capped at 2 \(was 3\)/.test(l)),
      `expected the cap explanation line, got: ${logged.join('\n')}`
    );
  });

  it('CR-01 incomplete: a rejecting buildEnvelope degrades to the incomplete-scan path, install() still resolves', async () => {
    currentBuildEnvelope = () => Promise.reject(new Error('hostile config engineered to crash discovery'));

    await assert.doesNotReject(() => install({}));
    assert.ok(
      logged.some((l) => l.includes('Security Level: 2 of 4')),
      `expected the incomplete-scan ceiling (2) to render, got: ${logged.join('\n')}`
    );
    assert.ok(
      logged.some((l) => /could not complete/.test(l)),
      `expected the incomplete-scan warning to render, got: ${logged.join('\n')}`
    );
  });
});
