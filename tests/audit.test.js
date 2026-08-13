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

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
// F10: shared require-cache stub helper — see the WR-01 ordering notes in
// tests/helpers/module-stub.js (stubs must land in require.cache BEFORE
// lib/audit.js is first required below).
const { installStub } = require('./helpers/module-stub.js');

// ---- mutable stub state (reset in beforeEach) ----
let currentBuildEnvelope;
let currentAgents;
let currentEnvFiles;
// D-11 (G-1545, plan 18-04 Task 4): lib/audit.js now imports
// scanForEnvFilesDetailed/printEnvScanResult instead of the
// incomplete-discarding scanForEnvFiles/printEnvScan pair. The stub below
// replaces lib/scan.js WHOLESALE, so it must provide both new exports too
// or audit() throws on an undefined call -- the single most likely way
// this task breaks the existing suite (per the plan's own warning).
// `currentEnvDetail` defaults to `undefined`, meaning "derive `.files` from
// `currentEnvFiles` (unchanged behaviour for every pre-existing test) and
// `.incomplete` from `currentEnvIncomplete`" -- explicitly set
// `currentEnvDetail` only in tests that need the anomaly-count/rootFailures
// fields too.
let currentEnvIncomplete;
let currentEnvDetail;
// Call counter for the asymmetry pin below -- counts INVOCATIONS of the
// stub, which is what "the env scan must never run on the zero-agents
// human path" actually needs to prove (reading a property off whatever
// currentEnvDetail happens to be would not distinguish "never called"
// from "called but its return value's fields went unread").
let scanForEnvFilesDetailedCallCount;

// The REAL printEnvScanResult renderer, captured BEFORE lib/scan.js is
// stubbed below, so the D-11 guard tests exercise the actual could-not-
// verify rendering (not a mock of it) -- required to assert "no captured
// stdout line contains the green text".
const { printEnvScanResult: realPrintEnvScanResult } = require('../lib/scan.js');

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
  scanForEnvFilesDetailed: () => {
    scanForEnvFilesDetailedCallCount += 1;
    return currentEnvDetail || {
      files: currentEnvFiles,
      incomplete: currentEnvIncomplete,
      anomalyCount: currentEnvIncomplete ? 1 : 0,
      anomalyReasons: { unreadable: currentEnvIncomplete ? 1 : 0, budget: 0 },
      rootFailures: { missing: 0, unreadable: 0 },
    };
  },
  printEnvScanResult: (...args) => realPrintEnvScanResult(...args),
});

// Real (non-stubbed) collaborators: scorecard.js (computeSecurityLevel —
// the unified path under test) and mcp/base.js (frozen enums). Only
// CONFIDENCE and EXIT are referenced directly below — Finding and
// SEVERITY were only used inside the now-removed local mcpFinding()
// factory (migrated to tests/helpers/audit-fixtures.js).
const { CONFIDENCE, EXIT } = require('../lib/mcp/base.js');
const { fakeAgent, mcpFinding, envelope } = require('./helpers/audit-fixtures.js');
const { captureLog } = require('./helpers/capture-log.js');

// audit.js is required AFTER the stubs exist, so its top-level bindings
// resolve to the stubs above.
const { audit, getMcpInputs, normalizeAuditResult, auditExitCode } = require('../lib/audit.js');

describe('audit --json frozen contract (D-11) and containment', () => {
  beforeEach(() => {
    currentBuildEnvelope = () => Promise.resolve(envelope());
    currentAgents = [fakeAgent()];
    currentEnvFiles = [];
    currentEnvIncomplete = false;
    currentEnvDetail = undefined;
  });

  function parseSingleJsonDocument(logs) {
    assert.equal(logs.length, 1, `audit --json must emit EXACTLY one console.log call (stdout purity), got ${logs.length}`);
    let parsed;
    assert.doesNotThrow(() => { parsed = JSON.parse(logs[0]); }, 'audit --json stdout must parse as JSON');
    return parsed;
  }

  it('clean run: output is one parseable JSON document with the full frozen shape', async () => {
    const { logs, result } = await captureLog(() => audit({ json: true }));

    const out = parseSingleJsonDocument(logs);
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

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

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

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

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

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

    assert.deepEqual(out.mcp, {
      ran: true, exitCode: EXIT.INCOMPLETE, findingsCount: 0, verifiedCount: 0, unverifiedCount: 0,
    });
    assert.equal(out.overallLevel, 2, 'incomplete scan fails closed: base 3 capped at 2');
    assert.equal(out.levelCaps[0].id, 'mcp-incomplete');
    assert.equal(result.code, 2, 'mcp.exitCode === INCOMPLETE must fail audit closed with exit 2 even though the envelope arrived');
  });

  it('incomplete-scan exit contract: the human path exits 2 too (rejecting buildEnvelope), scorecard still renders', async () => {
    currentBuildEnvelope = () => Promise.reject(new Error('crash'));

    const { logs, result } = await captureLog(() => audit({}));
    assert.equal(result.code, 2, 'the human path must fail closed with exit 2 on an incomplete MCP scan');
    assert.ok(logs.length > 0, 'the human scorecard must still render fully before the exit code is decided');
    assert.ok(logs.some((l) => /could not complete/.test(l)), 'the incomplete state must be visible in the rendered scorecard');
  });

  it('IN-03: zero-agents human path exits 1 without ever calling buildEnvelope (asymmetry pin)', async () => {
    currentAgents = [];
    let buildEnvelopeCalled = false;
    currentBuildEnvelope = () => { buildEnvelopeCalled = true; return Promise.resolve(envelope()); };

    const { result } = await captureLog(() => audit({}));

    assert.equal(result.code, 1);
    assert.equal(buildEnvelopeCalled, false, 'the human path must short-circuit before the MCP scan on zero agents (documented asymmetry)');
  });

  it('IN-03: zero-agents --json path still computes the full envelope (mcp/env keys present, asymmetry pin)', async () => {
    currentAgents = [];

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

    assert.equal(result.code, 1);
    assert.deepEqual(out.agents, [], 'zero agents still produces an (empty) agents[] key');
    assert.ok(Array.isArray(out.envFiles), '--json always computes envFiles even with zero agents');
    assert.deepEqual(out.mcp, {
      ran: true, exitCode: EXIT.CLEAN, findingsCount: 0, verifiedCount: 0, unverifiedCount: 0,
    }, '--json always computes the full mcp record even with zero agents (unlike the human short-circuit)');
  });

  it('IN-03: zero-agents --json path with an INCOMPLETE MCP scan exits 2, not 1 (fail-closed wins over zero-agents parity)', async () => {
    // The human path always exits 1 on zero agents (it short-circuits
    // before any scan). --json exits 1 only when its MCP scan completes;
    // a rejecting buildEnvelope must yield exit 2 per the locked
    // security-gate-exit-codes rule — pinning the documented divergence.
    currentAgents = [];
    currentBuildEnvelope = () => Promise.reject(new Error('hostile config engineered to crash discovery'));

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

    assert.deepEqual(out.agents, [], 'zero agents still produces an (empty) agents[] key');
    assert.deepEqual(out.mcp, {
      ran: false, exitCode: EXIT.INCOMPLETE, findingsCount: 0, verifiedCount: 0, unverifiedCount: 0,
    });
    assert.equal(result.code, 2, 'zero agents + incomplete MCP scan must fail closed with exit 2 on the --json path (unlike the human path, which always exits 1)');
  });

  it('verified findings are level-only: base level 2 + verified MCP finding -> still exit 0 (scan --mcp is the findings gate)', async () => {
    currentAgents = [fakeAgent({ audit: () => ({ checks: [], level: 2 }) })];
    currentBuildEnvelope = () => Promise.resolve(envelope({
      exitCode: EXIT.FINDINGS,
      findings: [mcpFinding()],
    }));

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

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

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

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

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

    assert.equal(out.overallLevel, 1, 'the lower ceiling (env-files at 1) must win');
    assert.equal(out.envFileCount, 1);
    const capIds = out.levelCaps.map((c) => c.id).sort();
    assert.deepEqual(capIds, ['env-files', 'mcp-findings']);
    assert.deepEqual(result, { code: 1 }, 'level 1 < 2 -> exit code 1');
  });

  it('WR-03: an agent audit() returning null still emits a full JSON envelope (never empty stdout)', async () => {
    currentAgents = [fakeAgent({ audit: () => null })];

    const { logs, result } = await captureLog(() => audit({ json: true }));
    const out = parseSingleJsonDocument(logs);

    assert.equal(out.agents[0].level, 0, 'a malformed audit() return normalizes to level 0');
    assert.deepEqual(out.agents[0].checks, []);
    assert.equal(typeof out.overallLevel, 'number');
    assert.ok(!Number.isNaN(out.overallLevel), 'the level math must never be NaN-poisoned');
    assert.equal(result.code, 1, 'level 0 (capped or not) is < 2 -> exit code 1');
  });

  it('WR-03: the human path with a null-returning agent audit() resolves with a numeric code (never rejects)', async () => {
    currentAgents = [fakeAgent({ audit: () => null })];

    const { logs, result } = await captureLog(() => audit({}));
    assert.ok(result && typeof result.code === 'number', 'the human path must resolve, not reject, on a broken agent module');
    assert.ok([0, 1].includes(result.code));
    assert.ok(logs.length > 0, 'the human scorecard must still render');
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

    await captureLog(() => audit({ json: true, online: true }));
    assert.ok(seenFlags, 'buildEnvelope must have been called');
    assert.strictEqual(seenFlags.online, false, 'audit must never allow network on its MCP path (D-01/D-02)');
  });
});

// ---------------------------------------------------------------------------
// EXIT-01 / review C-6 (G-1545) — the cross-check between scan() and
// audit() over a .env fixture. The first draft of this plan asked for raw
// exit-code EQUALITY between the two commands; that criterion is FALSE
// under normal conditions: lib/audit.js:132-135 returns { code: 1 } on zero
// detected agents, before the env scan ever runs, so on an empty fixture
// scan() legitimately returns 0 while audit() legitimately returns 1. The
// phase could be entirely correct and still fail an equality check, or pass
// it for the wrong reason. The real criterion, pinned here with agents and
// MCP PINNED so the asymmetry above cannot interfere: BOTH commands refuse
// a false all-clear over a .env fixture -- neither prints the green line,
// neither returns a code meaning clean.
// ---------------------------------------------------------------------------
describe('EXIT-01 / audit parity — both commands refuse a false all-clear (review C-6, G-1545)', () => {
  beforeEach(() => {
    currentBuildEnvelope = () => Promise.resolve(envelope());
    currentAgents = [fakeAgent()];
    currentEnvFiles = ['/project/.env'];
    currentEnvIncomplete = false;
    currentEnvDetail = undefined;
  });

  it('audit(), with at least one agent detected and a clean MCP scan, reports the .env finding and never returns a code meaning clean', async () => {
    const { logs, result } = await captureLog(() => audit({}));
    assert.ok(
      logs.some((l) => l.includes('.env file(s) found')),
      `audit must still report the .env finding, got: ${logs.join('\n')}`
    );
    assert.notEqual(
      result.code, 0,
      'audit must never return a code meaning clean when a .env is present -- the criterion is "refuses a false all-clear", not exit-code equality with scan() (lib/audit.js:132-135 is why raw equality would fail on entirely correct code, review C-6)'
    );
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

// ---------------------------------------------------------------------------
// D-11 (G-1545, plan 18-04 Task 4) — audit() and audit({json:true}) both
// stop printing a green check over an unread env-scan secret. Agents and
// MCP are PINNED (at least one detected agent, a clean completing MCP
// scan) so the ONLY remaining producer of exit code 2 is the env scan --
// exactly the distinction the operator's real reproduction could not make
// (the real audit() exits 2 on a mode-000 fixture today, but for MCP
// incompleteness, not the unreadable env path -- review C-6/D-11).
// ---------------------------------------------------------------------------
describe('D-11 — audit() and audit({json:true}) refuse the same false all-clear as scan() (G-1545)', () => {
  beforeEach(() => {
    currentBuildEnvelope = () => Promise.resolve(envelope());
    currentAgents = [fakeAgent()];
    currentEnvFiles = [];
    currentEnvIncomplete = false;
    currentEnvDetail = undefined;
    scanForEnvFilesDetailedCallCount = 0;
  });

  function incompleteZeroFilesDetail() {
    return {
      files: [],
      incomplete: true,
      anomalyCount: 1,
      anomalyReasons: { unreadable: 1, budget: 0 },
      rootFailures: { missing: 0, unreadable: 0 },
    };
  }

  it('audit(): an incomplete env scan prints no green line, reports the could-not-verify state, and returns code 2 -- with agents and MCP pinned, the ONLY remaining producer of 2 is the env scan', async () => {
    currentEnvDetail = incompleteZeroFilesDetail();

    const { logs, result } = await captureLog(() => audit({}));
    // The code assertion is checked FIRST (Task 1 break-proof 2's own
    // pattern): the exit code and the printed line are two independent
    // defects, and this ordering is what proves it -- a revert of only
    // the RENDER call must fail the render assertion while the code
    // assertion still passes, not throw before either is observed.
    assert.equal(
      result.code, 2,
      'with agents detected and MCP clean, the only remaining producer of exit 2 is the env scan -- exactly the distinction the real reproduction could not make'
    );
    assert.ok(!logs.some((l) => l.includes('No .env files found')), 'no captured stdout line may print the green check');
    assert.ok(logs.some((l) => l.includes('could not verify')), `expected the could-not-verify line, got: ${logs.join('\n')}`);
  });

  it('audit({json:true}): an incomplete env scan still emits exactly one parseable JSON document, with code 2', async () => {
    currentEnvDetail = incompleteZeroFilesDetail();

    const { logs, result } = await captureLog(() => audit({ json: true }));
    assert.equal(logs.length, 1, `audit --json must emit EXACTLY one console.log call, got ${logs.length}`);
    let parsed;
    assert.doesNotThrow(() => { parsed = JSON.parse(logs[0]); }, 'audit --json stdout must parse as JSON even when the env scan is incomplete');
    assert.deepEqual(parsed.envFiles, [], 'the frozen envFiles key is unaffected -- additive-only (D-11)');
    assert.equal(result.code, 2);
  });

  it('PAIRED CONTROL: a complete, clean env detail prints the green line, no could-not-verify line, and today\'s exit code (0)', async () => {
    currentEnvDetail = {
      files: [],
      incomplete: false,
      anomalyCount: 0,
      anomalyReasons: { unreadable: 0, budget: 0 },
      rootFailures: { missing: 0, unreadable: 0 },
    };

    const { logs, result } = await captureLog(() => audit({}));
    assert.ok(logs.some((l) => l.includes('No .env files found')), 'the green line must still print for a complete, clean env scan');
    assert.ok(!logs.some((l) => l.includes('could not verify')), 'a complete, clean env scan must never print the could-not-verify line');
    assert.deepEqual(result, { code: 0 }, 'unchanged from before this task: level 3 (fakeAgent), clean MCP -> exit 0');
  });

  it('PAIRED CONTROL: the zero-agents asymmetry pin (line ~157/168) is unaffected -- the env scan still never runs on the human short-circuit path', async () => {
    currentAgents = [];
    currentEnvDetail = incompleteZeroFilesDetail();

    const { result } = await captureLog(() => audit({}));
    assert.equal(result.code, 1, 'the human path must still short-circuit to exit 1 on zero agents, before the env scan is ever consulted');
    assert.equal(scanForEnvFilesDetailedCallCount, 0, 'scanForEnvFilesDetailed() must never be CALLED on the zero-agents human path (unchanged asymmetry)');
  });
});

// ---------------------------------------------------------------------
// G-1615: audit's exit ladder, unit-tested in ISOLATION.
//
// The inversion this suite pins survived every gate Phase 18 ran — the
// 1496-test suite, 96% coverage, a goal-backward verifier and four
// cross-AI reviewers' plan review — because `auditExitCode` was
// module-private and only ever exercised through `audit()`/`auditJson()`,
// where a stubbed fixture never combined "a .env WAS observed" with "and
// something could not be read". Testing the ladder directly is the point
// of this block, not a stylistic preference.
//
// The canonical ladder lives in ONE place, lib/traverse/index.js's
// computeExit(): fail -> 1, then incomplete -> 2, else 0 (D-04).
// ---------------------------------------------------------------------
describe('auditExitCode — the exit ladder (G-1615)', () => {
  const COMPLETE_MCP = { ran: true, exitCode: 0 };
  const INCOMPLETE_MCP = { ran: false, exitCode: 2 };

  // --- the defect this ticket fixed, both incompleteness sources --------
  it('G-1615: an OBSERVED .env plus an incomplete ENV scan exits 1, not 2 — a finding beats incompleteness', () => {
    assert.equal(
      auditExitCode(0, COMPLETE_MCP, true, 1), 1,
      'a tracked .env that was actually seen is ground truth; reporting it as "the scan did not finish" ' +
      'demotes a certain finding to an infrastructure warning and lets an unreadable sibling directory mask it'
    );
  });

  it('G-1615: an OBSERVED .env plus an incomplete MCP scan exits 1, not 2 (same rule, other incompleteness source)', () => {
    assert.equal(auditExitCode(0, INCOMPLETE_MCP, false, 1), 1);
  });

  // --- PAIRED CONTROL: the fail-closed contract is NOT weakened ---------
  // Without these, the test above would be satisfied by simply deleting
  // the incompleteness term altogether.
  it('PAIRED CONTROL: an incomplete scan with NO observed .env still exits 2 — fail-closed is intact (IN-03)', () => {
    assert.equal(
      auditExitCode(0, INCOMPLETE_MCP, false, 0), 2,
      'a LOW LEVEL is not a finding: level is also low when there are no agents to audit, so a posture ' +
      'computed from an unfinished scan must still fail closed rather than claim a verdict'
    );
    assert.equal(auditExitCode(3, COMPLETE_MCP, true, 0), 2, 'env-side incompleteness with no finding also stays 2');
  });

  it('PAIRED CONTROL: a fully complete, clean audit still exits 0 — this is not a blanket non-zero', () => {
    assert.equal(auditExitCode(3, COMPLETE_MCP, false, 0), 0);
  });

  it('PAIRED CONTROL: a complete scan with a low level still exits 1 — pre-existing behaviour unchanged', () => {
    assert.equal(auditExitCode(0, COMPLETE_MCP, false, 0), 1);
  });

  // --- D-04: ONE ladder, not two ---------------------------------------
  // This is the assertion that would have caught the original bug. It
  // compares against computeExit() itself rather than against a table of
  // expected numbers, so it cannot drift out of agreement the way a
  // hand-copied ladder did.
  it('D-04: audit never re-derives precedence — it agrees with computeExit() on every combination', () => {
    const { computeExit } = require('../lib/traverse/index.js');
    const mismatches = [];

    for (const envFileCount of [0, 1, 7]) {
      for (const mcp of [COMPLETE_MCP, INCOMPLETE_MCP]) {
        for (const envIncomplete of [false, true]) {
          const mcpIncomplete = mcp.ran === false || mcp.exitCode === 2;
          const canonical = computeExit({
            severityCounts: { fail: envFileCount > 0 ? 1 : 0 },
            incomplete: mcpIncomplete || envIncomplete,
          });
          // The level term only refines the CLEAN outcome (a complete scan
          // whose posture is below the pass threshold) — it must never
          // change a 1 into a 2 or vice versa.
          const expected = canonical === 0 ? [0, 1] : [canonical];
          const actual = auditExitCode(3, mcp, envIncomplete, envFileCount);
          if (!expected.includes(actual)) {
            mismatches.push(`envFiles=${envFileCount} mcpIncomplete=${mcpIncomplete} envIncomplete=${envIncomplete}: audit=${actual} computeExit=${canonical}`);
          }
        }
      }
    }

    assert.deepEqual(mismatches, [], `audit's exit code disagreed with the canonical ladder:\n  ${mismatches.join('\n  ')}`);
  });
});
