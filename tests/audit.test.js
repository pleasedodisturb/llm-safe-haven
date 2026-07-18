'use strict';

// WR-06 (Phase 8 review fix): direct unit tests for lib/audit.js — the
// D-11 frozen additive `audit --json` contract, the getMcpInputs D-03
// containment, and the WR-03 plugin-boundary normalization.
//
// Stub strategy (avoiding the WR-01 stale-binding trap): lib/audit.js
// captures buildEnvelope/detectAll/scanForEnvFiles in top-level
// destructured requires, so the stubs MUST be installed in require.cache
// BEFORE lib/audit.js is first required in this process. Each stub
// delegates through a mutable `current*` binding so individual tests can
// swap behavior without re-requiring anything.
//
// Scope note (TQ-02): this is the minimal contract suite the Phase 8
// review demanded; the full audit test suite is Phase 9 work.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

function installStub(resolvedPath, exports) {
  const stub = new Module(resolvedPath);
  stub.filename = resolvedPath;
  stub.loaded = true;
  stub.exports = exports;
  require.cache[resolvedPath] = stub;
}

// ---- mutable stub state (reset in beforeEach) ----
let currentBuildEnvelope;
let currentAgents;
let currentEnvFiles;

installStub(require.resolve('../lib/scan-mcp.js'), {
  buildEnvelope: (...args) => currentBuildEnvelope(...args),
  scanMcp: () => Promise.reject(new Error('unused by audit — present for shape parity')),
  findingsExitCode: () => 0,
});
installStub(require.resolve('../lib/agents/index.js'), {
  detectAll: () => currentAgents,
  getByIds: () => [],
});
installStub(require.resolve('../lib/scan.js'), {
  scanForEnvFiles: () => currentEnvFiles,
});

// Real (non-stubbed) collaborators: scorecard.js (computeSecurityLevel —
// the unified path under test) and mcp/base.js (frozen enums).
const { CONFIDENCE, EXIT, Finding, SEVERITY } = require('../lib/mcp/base.js');

// audit.js is required AFTER the stubs exist, so its top-level bindings
// resolve to the stubs above.
const { audit, getMcpInputs, normalizeAuditResult } = require('../lib/audit.js');

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

describe('audit --json frozen contract (D-11) and containment', () => {
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

  function parseSingleJsonDocument() {
    assert.equal(logged.length, 1, `audit --json must emit EXACTLY one console.log call (stdout purity), got ${logged.length}`);
    let parsed;
    assert.doesNotThrow(() => { parsed = JSON.parse(logged[0]); }, 'audit --json stdout must parse as JSON');
    return parsed;
  }

  it('clean run: output is one parseable JSON document with the full frozen shape', async () => {
    const result = await audit({ json: true });

    const out = parseSingleJsonDocument();
    // Frozen pre-Phase-8 keys.
    assert.ok(Array.isArray(out.agents), 'agents[] key');
    assert.ok(Array.isArray(out.envFiles), 'envFiles[] key');
    assert.equal(out.envFileCount, 0);
    assert.equal(out.overallLevel, 3, 'base 3, no caps');
    // D-11 additive keys.
    assert.deepEqual(out.mcp, {
      ran: true,
      exitCode: EXIT.CLEAN,
      findingsCount: 0,
      verifiedCount: 0,
      unverifiedCount: 0,
    });
    assert.deepEqual(out.levelCaps, []);
    // Agent entry shape.
    assert.equal(out.agents[0].id, 'fake-agent');
    assert.equal(out.agents[0].level, 3);
    assert.equal(out.agents[0].checks.length, 1);
    // Exit-code contract: level 3 >= 2 -> 0.
    assert.deepEqual(result, { code: 0 });
  });

  it('verified MCP finding: level capped at 2 via the unified path, mcp-findings cap recorded', async () => {
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.FINDINGS,
      findings: [mcpFinding()],
    }));

    const result = await audit({ json: true });
    const out = parseSingleJsonDocument();

    assert.equal(out.overallLevel, 2, 'a verified finding must demote the audit level (base 3 -> 2)');
    assert.equal(out.levelCaps.length, 1);
    assert.equal(out.levelCaps[0].id, 'mcp-findings');
    assert.equal(out.levelCaps[0].cappedFrom, 3);
    assert.equal(out.levelCaps[0].cappedTo, 2);
    assert.deepEqual(out.mcp, {
      ran: true, exitCode: EXIT.FINDINGS, findingsCount: 1, verifiedCount: 1, unverifiedCount: 0,
    });
    assert.deepEqual(result, { code: 0 });
  });

  it('D-03: a rejecting buildEnvelope is contained — mcp.ran:false, mcp-incomplete cap, still one JSON document, exit 2', async () => {
    currentBuildEnvelope = () => Promise.reject(new Error('hostile config engineered to crash discovery'));

    const result = await audit({ json: true });
    const out = parseSingleJsonDocument();

    assert.deepEqual(out.mcp, {
      ran: false, exitCode: EXIT.INCOMPLETE, findingsCount: 0, verifiedCount: 0, unverifiedCount: 0,
    });
    assert.equal(out.overallLevel, 2, 'incomplete scan fails closed: base 3 capped at 2');
    assert.equal(out.levelCaps.length, 1);
    assert.equal(out.levelCaps[0].id, 'mcp-incomplete');
    // The throw is CONTAINED (no rejection, full JSON emitted), but the
    // exit code is 2 — audit initiated a scan that did not finish, and a
    // security tool must never exit 0/1 as if its verdict were complete
    // (locked security-gate-exit-codes rule).
    assert.equal(result.code, 2, 'an incomplete MCP scan must fail audit closed with exit 2');
  });

  it('incomplete-scan exit contract: an envelope with exitCode INCOMPLETE -> exit 2, still one valid JSON document', async () => {
    currentBuildEnvelope = () => Promise.resolve(envelope({ exitCode: EXIT.INCOMPLETE }));

    const result = await audit({ json: true });
    const out = parseSingleJsonDocument();

    assert.deepEqual(out.mcp, {
      ran: true, exitCode: EXIT.INCOMPLETE, findingsCount: 0, verifiedCount: 0, unverifiedCount: 0,
    });
    assert.equal(out.overallLevel, 2, 'incomplete scan fails closed: base 3 capped at 2');
    assert.equal(out.levelCaps[0].id, 'mcp-incomplete');
    assert.equal(result.code, 2, 'mcp.exitCode === INCOMPLETE must fail audit closed with exit 2 even though the envelope arrived');
  });

  it('incomplete-scan exit contract: the human path exits 2 too (rejecting buildEnvelope), scorecard still renders', async () => {
    currentBuildEnvelope = () => Promise.reject(new Error('crash'));

    const result = await audit({});
    assert.equal(result.code, 2, 'the human path must fail closed with exit 2 on an incomplete MCP scan');
    assert.ok(logged.length > 0, 'the human scorecard must still render fully before the exit code is decided');
    assert.ok(logged.some((l) => /could not complete/.test(l)), 'the incomplete state must be visible in the rendered scorecard');
  });

  it('verified findings are level-only: base level 2 + verified MCP finding -> still exit 0 (scan --mcp is the findings gate)', async () => {
    currentAgents = [fakeAgent({ audit: () => ({ checks: [], level: 2 }) })];
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.FINDINGS,
      findings: [mcpFinding()],
    }));

    const result = await audit({ json: true });
    const out = parseSingleJsonDocument();

    assert.equal(out.overallLevel, 2, 'ceiling equals base — no demotion below 2');
    assert.deepEqual(result, { code: 0 }, 'verified MCP findings demote the LEVEL only — audit exits 0 at Level 2; gate on scan --mcp (exit 1) for findings');
  });

  it('SCOR-02: an unverified-only envelope NEVER caps the level', async () => {
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.CLEAN,
      findings: [
        mcpFinding({ id: 'd/u1', confidence: CONFIDENCE.UNVERIFIED }),
        mcpFinding({ id: 'd/u2', confidence: CONFIDENCE.UNVERIFIED }),
      ],
    }));

    const result = await audit({ json: true });
    const out = parseSingleJsonDocument();

    assert.equal(out.overallLevel, 3, 'unverified-only findings must not demote the level');
    assert.deepEqual(out.levelCaps, []);
    assert.deepEqual(out.mcp, {
      ran: true, exitCode: EXIT.CLEAN, findingsCount: 2, verifiedCount: 0, unverifiedCount: 2,
    });
    assert.deepEqual(result, { code: 0 });
  });

  it('combined caps go through the unified path: env file + verified finding -> both caps, min ceiling wins', async () => {
    currentEnvFiles = ['/project/.env'];
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.FINDINGS,
      findings: [mcpFinding()],
    }));

    const result = await audit({ json: true });
    const out = parseSingleJsonDocument();

    assert.equal(out.overallLevel, 1, 'the lower ceiling (env-files at 1) must win');
    assert.equal(out.envFileCount, 1);
    const capIds = out.levelCaps.map((c) => c.id).sort();
    assert.deepEqual(capIds, ['env-files', 'mcp-findings']);
    assert.deepEqual(result, { code: 1 }, 'level 1 < 2 -> exit code 1');
  });

  it('WR-03: an agent audit() returning null still emits a full JSON envelope (never empty stdout)', async () => {
    currentAgents = [fakeAgent({ audit: () => null })];

    const result = await audit({ json: true });
    const out = parseSingleJsonDocument();

    assert.equal(out.agents[0].level, 0, 'a malformed audit() return normalizes to level 0');
    assert.deepEqual(out.agents[0].checks, []);
    assert.equal(typeof out.overallLevel, 'number');
    assert.ok(!Number.isNaN(out.overallLevel), 'the level math must never be NaN-poisoned');
    assert.equal(result.code, 1, 'level 0 (capped or not) is < 2 -> exit code 1');
  });

  it('WR-03: the human path with a null-returning agent audit() resolves with a numeric code (never rejects)', async () => {
    currentAgents = [fakeAgent({ audit: () => null })];

    const result = await audit({});
    assert.ok(result && typeof result.code === 'number', 'the human path must resolve, not reject, on a broken agent module');
    assert.ok([0, 1].includes(result.code));
    assert.ok(logged.length > 0, 'the human scorecard must still render');
  });

  it('getMcpInputs: resolving envelope maps to ran:true with correct counts; rejecting maps to ran:false/INCOMPLETE', async () => {
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.FINDINGS,
      findings: [mcpFinding(), mcpFinding({ id: 'd/u', confidence: CONFIDENCE.UNVERIFIED })],
    }));
    const ok = await getMcpInputs({});
    assert.deepEqual(ok.mcp, { ran: true, exitCode: EXIT.FINDINGS, verifiedCount: 1, unverifiedCount: 1 });
    assert.ok(ok.envelope, 'envelope passes through on success');

    currentBuildEnvelope = () => Promise.reject(new Error('crash'));
    const contained = await getMcpInputs({});
    assert.equal(contained.envelope, null);
    assert.deepEqual(contained.mcp, { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 });
  });

  it('F4: a truthy envelope WITHOUT a findings array is treated as incomplete — never a throw past the containment', async () => {
    // A malformed envelope (findings missing / non-array) previously hit
    // the count derivation OUTSIDE the try/catch, throwing past the D-03
    // containment the docblock promises. It must degrade to the same
    // incomplete result a rejecting buildEnvelope produces.
    currentBuildEnvelope = () => Promise.resolve({ exitCode: EXIT.CLEAN, servers: [], sources: [] });
    const degraded = await getMcpInputs({});
    assert.equal(degraded.envelope, null, 'a shapeless envelope must not pass through');
    assert.deepEqual(degraded.mcp, { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 });

    currentBuildEnvelope = () => Promise.resolve({ exitCode: EXIT.CLEAN, findings: 'not-an-array', servers: [], sources: [] });
    const degraded2 = await getMcpInputs({});
    assert.equal(degraded2.envelope, null);
    assert.deepEqual(degraded2.mcp, { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 });
  });

  it('audit is forced offline: buildEnvelope always receives online:false, even when the caller passed online:true', async () => {
    let seenFlags = null;
    currentBuildEnvelope = (flags) => { seenFlags = flags; return Promise.resolve(envelope()); };

    await audit({ json: true, online: true });
    assert.ok(seenFlags, 'buildEnvelope must have been called');
    assert.strictEqual(seenFlags.online, false, 'audit must never allow network on its MCP path (D-01/D-02)');
  });
});

describe('normalizeAuditResult (WR-03 boundary)', () => {
  it('null/undefined -> { checks: [], level: 0 }', () => {
    assert.deepEqual(normalizeAuditResult(null), { checks: [], level: 0 });
    assert.deepEqual(normalizeAuditResult(undefined), { checks: [], level: 0 });
  });

  it('non-numeric or NaN level -> { checks: [], level: 0 }', () => {
    assert.deepEqual(normalizeAuditResult({ checks: [], level: undefined }), { checks: [], level: 0 });
    assert.deepEqual(normalizeAuditResult({ checks: [], level: '3' }), { checks: [], level: 0 });
    assert.deepEqual(normalizeAuditResult({ checks: [], level: NaN }), { checks: [], level: 0 });
  });

  it('numeric level with non-array checks keeps the level, empties checks', () => {
    assert.deepEqual(normalizeAuditResult({ level: 3 }), { level: 3, checks: [] });
    assert.deepEqual(normalizeAuditResult({ level: 2, checks: 'oops' }), { level: 2, checks: [] });
  });

  it('a well-formed result passes through by reference (no needless copies)', () => {
    const good = { checks: [{ name: 'c', detail: 'd', pass: true }], level: 4 };
    assert.strictEqual(normalizeAuditResult(good), good);
  });
});
