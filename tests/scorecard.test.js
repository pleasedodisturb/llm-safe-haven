'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

describe('scorecard', () => {
  // The scorecard module reads NO_COLOR at require time, so we need
  // a fresh require for each environment configuration. We also need
  // to suppress console.log output during tests.

  let originalLog;
  let logged;

  beforeEach(() => {
    originalLog = console.log;
    logged = [];
    console.log = (...args) => logged.push(args.join(' '));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it('NO_COLOR env var disables ANSI codes', () => {
    // Set NO_COLOR and re-require the module
    const originalNoColor = process.env.NO_COLOR;
    const originalTTY = process.stdout.isTTY;

    process.env.NO_COLOR = '1';

    // Clear the cached module so it re-evaluates the env check
    const modPath = require.resolve('../lib/scorecard.js');
    delete require.cache[modPath];
    const scorecard = require('../lib/scorecard.js');

    // With NO_COLOR, all color codes should be empty strings
    assert.strictEqual(scorecard.C.reset, '', 'C.reset should be empty with NO_COLOR');
    assert.strictEqual(scorecard.C.bold, '', 'C.bold should be empty with NO_COLOR');
    assert.strictEqual(scorecard.C.green, '', 'C.green should be empty with NO_COLOR');
    assert.strictEqual(scorecard.C.red, '', 'C.red should be empty with NO_COLOR');

    // Restore
    if (originalNoColor === undefined) {
      delete process.env.NO_COLOR;
    } else {
      process.env.NO_COLOR = originalNoColor;
    }
    // Re-clear cache so other tests get default behavior
    delete require.cache[modPath];
  });

  it('printHeader does not throw', () => {
    const modPath = require.resolve('../lib/scorecard.js');
    delete require.cache[modPath];
    const scorecard = require('../lib/scorecard.js');

    assert.doesNotThrow(() => {
      scorecard.printHeader();
    });
    delete require.cache[modPath];
  });

  it('printLevel does not throw for each level 0-4', () => {
    const modPath = require.resolve('../lib/scorecard.js');
    delete require.cache[modPath];
    const scorecard = require('../lib/scorecard.js');

    for (let level = 0; level <= 4; level++) {
      assert.doesNotThrow(() => {
        scorecard.printLevel(level);
      }, `printLevel(${level}) should not throw`);
    }
    delete require.cache[modPath];
  });
});

describe('printMcpScan', () => {
  const { Finding, SEVERITY, CONFIDENCE } = require('../lib/mcp/base.js');
  const { printMcpScan } = require('../lib/scorecard.js');

  let originalLog;
  let logged;

  beforeEach(() => {
    originalLog = console.log;
    logged = [];
    console.log = (...args) => logged.push(args.join(' '));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  function finding(overrides = {}) {
    return Finding({
      id: 'detector/rule-id',
      detector: 'detector',
      severity: SEVERITY.INFO,
      confidence: CONFIDENCE.VERIFIED,
      agentId: 'claude-code',
      scope: 'user',
      serverName: 'some-server',
      message: 'a finding message',
      ...overrides,
    });
  }

  it('zero servers/zero findings prints the existing friendly PASS line (stub behavior preserved)', () => {
    printMcpScan({ sources: [], servers: [], findings: [], summary: { bySeverity: {}, byDetector: {} } });
    assert.ok(logged.some((l) => l.includes('No MCP findings')));
  });

  it('handles a null/undefined envelope defensively without throwing', () => {
    assert.doesNotThrow(() => printMcpScan(undefined));
    assert.doesNotThrow(() => printMcpScan(null));
  });

  it('groups findings per server: agent > server-name (scope) header, sorted critical->high->medium->low->info', () => {
    const critical = finding({ id: 'd/critical', severity: SEVERITY.CRITICAL, message: 'critical msg' });
    const high = finding({ id: 'd/high', severity: SEVERITY.HIGH, message: 'high msg' });
    const medium = finding({ id: 'd/medium', severity: SEVERITY.MEDIUM, message: 'medium msg' });
    const low = finding({ id: 'd/low', severity: SEVERITY.LOW, message: 'low msg' });
    const info = finding({ id: 'd/info', severity: SEVERITY.INFO, message: 'info msg' });

    // Findings intentionally listed out of severity order to prove the
    // renderer sorts them, not just preserves input order.
    printMcpScan({
      sources: [],
      servers: [],
      findings: [info, low, medium, high, critical],
    });

    const headerIndex = logged.findIndex((l) => l.includes('claude-code') && l.includes('some-server') && l.includes('(user)'));
    assert.ok(headerIndex !== -1, 'expected an agent > server-name (scope) group header');

    const criticalIndex = logged.findIndex((l) => l.includes('critical msg'));
    const highIndex = logged.findIndex((l) => l.includes('high msg'));
    const mediumIndex = logged.findIndex((l) => l.includes('medium msg'));
    const lowIndex = logged.findIndex((l) => l.includes('low msg'));
    const infoIndex = logged.findIndex((l) => l.includes('info msg'));

    assert.ok(criticalIndex < highIndex, 'critical should render before high');
    assert.ok(highIndex < mediumIndex, 'high should render before medium');
    assert.ok(mediumIndex < lowIndex, 'medium should render before low');
    assert.ok(lowIndex < infoIndex, 'low should render before info');
  });

  it('agentId: null findings render in a final General group', () => {
    const attributed = finding({ id: 'd/attributed', severity: SEVERITY.HIGH, message: 'attributed msg' });
    const unattributed = Finding({
      id: 'typosquat/allowlist-unavailable',
      detector: 'typosquat',
      severity: SEVERITY.INFO,
      confidence: CONFIDENCE.UNVERIFIED,
      agentId: null,
      scope: null,
      serverName: null,
      message: 'allowlist unavailable',
    });

    printMcpScan({ sources: [], servers: [], findings: [attributed, unattributed] });

    const generalIndex = logged.findIndex((l) => l.includes('General'));
    assert.ok(generalIndex !== -1, 'expected a General group header');

    const unattributedIndex = logged.findIndex((l) => l.includes('allowlist unavailable'));
    assert.ok(unattributedIndex > generalIndex, 'unattributed finding should render under the General header');
  });

  it('unverified findings render in a distinct dim style, never red/yellow (D-06)', () => {
    // Force color on so red/yellow escape codes would appear if the
    // renderer used them for an unverified finding.
    const originalNoColor = process.env.NO_COLOR;
    const originalTTY = process.stdout.isTTY;
    delete process.env.NO_COLOR;
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

    const modPath = require.resolve('../lib/scorecard.js');
    delete require.cache[modPath];
    const scorecard = require('../lib/scorecard.js');

    try {
      const unverified = Finding({
        id: 'd/unverified-rule',
        detector: 'd',
        severity: SEVERITY.CRITICAL,
        confidence: CONFIDENCE.UNVERIFIED,
        agentId: 'claude-code',
        scope: 'user',
        serverName: 'some-server',
        message: 'unverified critical msg',
      });

      scorecard.printMcpScan({ sources: [], servers: [], findings: [unverified] });

      const unverifiedLine = logged.find((l) => l.includes('unverified critical msg'));
      assert.ok(unverifiedLine, 'expected the unverified finding line to be rendered');
      assert.ok(!unverifiedLine.includes(scorecard.C.red), 'unverified line must not contain the red ANSI code');
      assert.ok(!unverifiedLine.includes(scorecard.C.yellow), 'unverified line must not contain the yellow ANSI code');

      const separatorLine = logged.find((l) => l.includes('unverified') && l.includes('--online'));
      assert.ok(separatorLine, 'expected a dim "unverified -- run with --online to verify" sub-line');
    } finally {
      if (originalNoColor === undefined) delete process.env.NO_COLOR;
      else process.env.NO_COLOR = originalNoColor;
      Object.defineProperty(process.stdout, 'isTTY', { value: originalTTY, configurable: true });
      delete require.cache[modPath];
    }
  });

  describe('summary header mirrors D-14/D-08 exit-code semantics', () => {
    it('red FAIL header counts ONLY verified findings; unverified get a separate dim notice line (mixed)', () => {
      const verified1 = finding({ id: 'd/v1', severity: SEVERITY.HIGH, message: 'verified one' });
      const verified2 = finding({ id: 'd/v2', severity: SEVERITY.LOW, message: 'verified two' });
      const unverified = finding({ id: 'd/u1', confidence: CONFIDENCE.UNVERIFIED, message: 'unverified one' });

      printMcpScan({ sources: [], servers: [], findings: [verified1, unverified, verified2] });

      assert.ok(
        logged.some((l) => l.includes('2 finding(s)')),
        'the red header must count the 2 verified findings, not all 3'
      );
      assert.ok(
        !logged.some((l) => l.includes('3 finding(s)')),
        'the header must never count unverified findings into the FAIL total'
      );
      assert.ok(
        logged.some((l) => l.includes('1 unverified notice(s)') && l.includes('--online')),
        'expected a separate dim notice line for the unverified finding'
      );
    });

    it('unverified-only envelope prints NO red FAIL header — only the dim notice (consistent with exit 0)', () => {
      // Force color on so the red ANSI code would be detectable if the
      // renderer emitted a FAIL header for an unverified-only scan.
      const originalNoColor = process.env.NO_COLOR;
      const originalTTY = process.stdout.isTTY;
      delete process.env.NO_COLOR;
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

      const modPath = require.resolve('../lib/scorecard.js');
      delete require.cache[modPath];
      const scorecard = require('../lib/scorecard.js');

      try {
        const u1 = finding({ id: 'd/u1', confidence: CONFIDENCE.UNVERIFIED, severity: SEVERITY.HIGH, message: 'unverified a' });
        const u2 = finding({ id: 'd/u2', confidence: CONFIDENCE.UNVERIFIED, severity: SEVERITY.LOW, message: 'unverified b' });

        scorecard.printMcpScan({ sources: [], servers: [], findings: [u1, u2] });

        assert.ok(
          !logged.some((l) => l.includes('finding(s)')),
          'an unverified-only scan (exit 0) must not render the red "N finding(s)" FAIL header'
        );
        const noticeLine = logged.find((l) => l.includes('2 unverified notice(s)'));
        assert.ok(noticeLine, 'expected the dim "2 unverified notice(s)" header line');
        assert.ok(!noticeLine.includes(scorecard.C.red), 'the notice line must not contain the red ANSI code');
        assert.ok(!noticeLine.includes(scorecard.C.yellow), 'the notice line must not contain the yellow ANSI code');
      } finally {
        if (originalNoColor === undefined) delete process.env.NO_COLOR;
        else process.env.NO_COLOR = originalNoColor;
        Object.defineProperty(process.stdout, 'isTTY', { value: originalTTY, configurable: true });
        delete require.cache[modPath];
      }
    });

    it('zero findings keeps the existing PASS line', () => {
      printMcpScan({ sources: [], servers: [], findings: [] });
      assert.ok(logged.some((l) => l.includes('No MCP findings')));
      assert.ok(!logged.some((l) => l.includes('finding(s)')));
      assert.ok(!logged.some((l) => l.includes('unverified notice')));
    });
  });

  describe('CR-01: terminal escape injection via config-derived strings', () => {
    // A hostile MCP config controls server.name, which flows raw into
    // finding.serverName (group header) and finding.message (detector
    // messages interpolate `Server "${server.name}"`). ANSI/OSC escapes in
    // it could erase or spoof report lines on the operator's terminal
    // (CWE-150). The renderer must strip every C0/C1 control char and DEL.
    const HOSTILE_NAME = 'evil\x1b[2K\x1b[1A\x1b[2Khidden';

    it('strips ANSI escape sequences from the server name in the group header', () => {
      const hostile = finding({
        serverName: HOSTILE_NAME,
        message: 'plain msg',
      });

      printMcpScan({ sources: [], servers: [], findings: [hostile] });

      const headerLine = logged.find((l) => l.includes('evil'));
      assert.ok(headerLine, 'expected the group header naming the hostile server');
      assert.ok(!headerLine.includes('\x1b[2K'), 'erase-line escape must not reach the terminal');
      assert.ok(!headerLine.includes('\x1b[1A'), 'cursor-up escape must not reach the terminal');
      assert.ok(headerLine.includes('�'), 'stripped control chars are replaced with U+FFFD so the operator sees tampering');
      assert.ok(headerLine.includes('hidden'), 'the non-control text around the escapes is preserved');
    });

    it('strips control characters from finding.message (detector messages embed the raw server name)', () => {
      const hostile = finding({
        serverName: 'srv',
        message: `Server "${HOSTILE_NAME}" uses an unpinned spec\x07`,
      });

      printMcpScan({ sources: [], servers: [], findings: [hostile] });

      const msgLine = logged.find((l) => l.includes('unpinned spec'));
      assert.ok(msgLine, 'expected the finding message line to be rendered');
      assert.ok(!msgLine.includes('\x1b'), 'no raw ESC byte may survive in the message line');
      assert.ok(!msgLine.includes('\x07'), 'no BEL byte may survive in the message line');
      assert.ok(msgLine.includes('�'), 'stripped control chars are replaced with U+FFFD');
    });

    it('strips control characters on the unverified (dim) finding line too', () => {
      const hostile = finding({
        confidence: CONFIDENCE.UNVERIFIED,
        serverName: 'srv',
        message: `Server "${HOSTILE_NAME}" unverified`,
      });

      printMcpScan({ sources: [], servers: [], findings: [hostile] });

      const msgLine = logged.find((l) => l.includes('unverified') && l.includes('evil'));
      assert.ok(msgLine, 'expected the unverified finding line to be rendered');
      assert.ok(!msgLine.includes('\x1b[2K'), 'erase-line escape must not reach the terminal on the unverified path');
    });

    it('sanitizeForTerminal strips all C0, DEL, and C1 control chars and stringifies null/undefined safely', () => {
      const { sanitizeForTerminal } = require('../lib/scorecard.js');
      assert.strictEqual(sanitizeForTerminal('a\x00b\x1fc\x7fd\x9fe'), 'a�b�c�d�e');
      assert.strictEqual(sanitizeForTerminal('clean-name'), 'clean-name');
      assert.strictEqual(sanitizeForTerminal(null), '');
      assert.strictEqual(sanitizeForTerminal(undefined), '');
      // OSC-based escapes (ESC ] ... BEL) lose both ESC and BEL.
      assert.strictEqual(sanitizeForTerminal('\x1b]0;spoof\x07'), '�]0;spoof�');
    });

    it('sanitizeForTerminal strips Unicode format/bidi controls (\\p{Cf}) — RLO can visually reorder a report line', () => {
      const { sanitizeForTerminal } = require('../lib/scorecard.js');
      // U+202E RIGHT-TO-LEFT OVERRIDE — the classic filename/report spoof.
      assert.strictEqual(sanitizeForTerminal('safe‮gpj.exe'), 'safe�gpj.exe');
      assert.ok(!sanitizeForTerminal('a‮b').includes('‮'), 'RLO must never reach output');
      // Zero-width space, LTR mark, bidi isolate, BOM/ZWNBSP.
      assert.strictEqual(sanitizeForTerminal('a​b‎c⁦d﻿e'), 'a�b�c�d�e');
      // Plain non-ASCII text (letters, accents, CJK) passes through untouched.
      assert.strictEqual(sanitizeForTerminal('café-服务器'), 'café-服务器');
    });

    it('printMcpScan never lets U+202E from a hostile server name reach the rendered output', () => {
      const hostile = finding({
        serverName: 'evil‮name',
        message: 'msg with ‮ override',
      });
      printMcpScan({ sources: [], servers: [], findings: [hostile] });
      assert.ok(logged.length > 0);
      assert.ok(
        logged.every((l) => !l.includes('‮')),
        'no rendered line may contain the RLO character'
      );
    });
  });

  describe('hostile-envelope backstop: no control/format char in ANY rendered line', () => {
    // Generic assertion over the ENTIRE output — the backstop for future
    // call sites that forget sanitizeForTerminal. Every config-derived
    // field (serverName, message, scope, source status/agentId) is
    // poisoned with C0/C1 controls AND a U+202E bidi override, and every
    // logged line is checked wholesale. The renderer's own ANSI SGR
    // escapes (the C palette) are stripped first so only injected
    // controls can trip the assertion.
    const HOSTILE = 'x\x1b[2K\x07\x9b‮y'; // ESC, BEL, C1 CSI, RLO

    function stripSgr(line) {
      // Remove the renderer's own SGR sequences (\x1b[...m) — everything
      // the C palette legitimately emits.
      return line.replace(/\x1b\[[0-9;]*m/g, '');
    }

    it('every logged line is free of /[\\x00-\\x1f\\x7f-\\x9f]|\\p{Cf}/u after stripping renderer SGR', () => {
      const hostileEnvelope = {
        sources: [
          { agentId: `agent${HOSTILE}`, scope: `user${HOSTILE}`, path: '/p', format: 'json', status: `parse-error${HOSTILE}` },
        ],
        servers: [],
        findings: [
          finding({ id: 'd/one', severity: SEVERITY.CRITICAL, serverName: `srv${HOSTILE}`, message: `msg${HOSTILE}`, scope: `user${HOSTILE}` }),
          finding({ id: 'd/two', confidence: CONFIDENCE.UNVERIFIED, serverName: `srv${HOSTILE}`, message: `unv${HOSTILE}`, scope: `user${HOSTILE}` }),
          Finding({
            id: 'd/general', detector: 'd', severity: SEVERITY.HIGH, confidence: CONFIDENCE.VERIFIED,
            agentId: null, scope: null, serverName: null, message: `general${HOSTILE}`,
          }),
        ],
        summary: { bySeverity: {}, byDetector: {} },
      };

      printMcpScan(hostileEnvelope);

      assert.ok(logged.length > 0, 'expected rendered output');
      for (const line of logged) {
        const visible = stripSgr(line);
        assert.ok(
          !/[\x00-\x1f\x7f-\x9f]|\p{Cf}/u.test(visible),
          `rendered line contains an unsanitized control/format char: ${JSON.stringify(visible)}`
        );
      }
    });
  });

  it('non-parsed/not-found source statuses are listed so an exit-2 scan explains itself (D-07)', () => {
    printMcpScan({
      sources: [
        { agentId: 'claude-code', scope: 'user', path: '/some/path', format: 'json', status: 'parsed' },
        { agentId: 'cursor', scope: 'project', path: '/other/path', format: 'json', status: 'parse-error' },
        { agentId: 'windsurf', scope: 'user', path: '/missing/path', format: 'json', status: 'not-found' },
      ],
      servers: [],
      findings: [],
    });

    const errorSourceLine = logged.find((l) => l.includes('cursor') && l.includes('parse-error'));
    assert.ok(errorSourceLine, 'expected the parse-error source to be listed with its status');

    assert.ok(
      !logged.some((l) => l.includes('windsurf') && l.includes('not-found')),
      'a not-found source should not be listed (it is not an exit-2-explaining failure)'
    );
  });
});

describe('computeSecurityLevel', () => {
  const { EXIT, CONFIDENCE } = require('../lib/mcp/base.js');
  const { computeSecurityLevel } = require('../lib/scorecard.js');

  function assertCapShape(cap) {
    assert.equal(typeof cap.id, 'string');
    assert.ok(cap.id.length > 0);
    assert.equal(typeof cap.cappedFrom, 'number');
    assert.equal(typeof cap.cappedTo, 'number');
    assert.equal(typeof cap.reason, 'string');
    assert.ok(cap.reason.length > 0, 'cap.reason must be a non-empty string');
  }

  it('no caps: base 3, env 0, mcp clean -> level 3, caps []', () => {
    const result = computeSecurityLevel({
      agentLevels: [3],
      envFileCount: 0,
      mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
    });
    assert.deepStrictEqual(result, { level: 3, caps: [] });
  });

  it('env cap only: base 3, envFileCount 2, mcp clean -> level 1, one env-files cap', () => {
    const result = computeSecurityLevel({
      agentLevels: [3],
      envFileCount: 2,
      mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
    });
    assert.equal(result.level, 1);
    assert.equal(result.caps.length, 1);
    assert.equal(result.caps[0].id, 'env-files');
    assert.equal(result.caps[0].cappedFrom, 3);
    assert.equal(result.caps[0].cappedTo, 1);
    assertCapShape(result.caps[0]);
  });

  it('MCP verified cap only: base 4, env 0, verifiedCount 1, exit 1 -> level 2, mcp-findings cap', () => {
    const result = computeSecurityLevel({
      agentLevels: [4],
      envFileCount: 0,
      mcp: { ran: true, exitCode: EXIT.FINDINGS, verifiedCount: 1, unverifiedCount: 0 },
    });
    assert.equal(result.level, 2);
    assert.equal(result.caps.length, 1);
    assert.equal(result.caps[0].id, 'mcp-findings');
    assert.equal(result.caps[0].cappedFrom, 4);
    assert.equal(result.caps[0].cappedTo, 2);
    assertCapShape(result.caps[0]);
  });

  it('MCP incomplete cap via ran:false: base 3, env 0, ran false -> level 2, mcp-incomplete cap', () => {
    const result = computeSecurityLevel({
      agentLevels: [3],
      envFileCount: 0,
      mcp: { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 },
    });
    assert.equal(result.level, 2);
    assert.equal(result.caps.length, 1);
    assert.equal(result.caps[0].id, 'mcp-incomplete');
    assertCapShape(result.caps[0]);
  });

  it('MCP incomplete cap via exitCode: base 3, exitCode EXIT.INCOMPLETE -> level 2, mcp-incomplete cap', () => {
    const result = computeSecurityLevel({
      agentLevels: [3],
      envFileCount: 0,
      mcp: { ran: true, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 },
    });
    assert.equal(result.level, 2);
    assert.equal(result.caps.length, 1);
    assert.equal(result.caps[0].id, 'mcp-incomplete');
    assertCapShape(result.caps[0]);
  });

  it('SCOR-02 regression: unverified-only findings NEVER cap the level', () => {
    const result = computeSecurityLevel({
      agentLevels: [3],
      envFileCount: 0,
      mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 5 },
    });
    assert.equal(result.level, 3);
    assert.equal(result.caps.length, 0, 'unverified-only findings must never produce a cap');
  });

  it('combined env+MCP: both caps present, min wins, both reasons non-empty', () => {
    const result = computeSecurityLevel({
      agentLevels: [3],
      envFileCount: 1,
      mcp: { ran: true, exitCode: EXIT.FINDINGS, verifiedCount: 1, unverifiedCount: 0 },
    });
    assert.equal(result.level, 1, 'the lower ceiling (env-files at 1) must win');
    assert.equal(result.caps.length, 2);
    const envCap = result.caps.find((c) => c.id === 'env-files');
    const mcpCap = result.caps.find((c) => c.id === 'mcp-findings');
    assert.ok(envCap, 'expected an env-files cap');
    assert.ok(mcpCap, 'expected an mcp-findings cap');
    assertCapShape(envCap);
    assertCapShape(mcpCap);
  });

  it('cap no-op when base already below ceiling: base 2, verifiedCount 1 -> level 2, no mcp cap recorded', () => {
    const result = computeSecurityLevel({
      agentLevels: [2],
      envFileCount: 0,
      mcp: { ran: true, exitCode: EXIT.FINDINGS, verifiedCount: 1, unverifiedCount: 0 },
    });
    assert.equal(result.level, 2);
    assert.equal(result.caps.length, 0, 'a ceiling equal to or above base fires no cap');
  });

  it('boundary: base 0 with any caps -> level 0, no caps recorded (nothing to reduce)', () => {
    const result = computeSecurityLevel({
      agentLevels: [0],
      envFileCount: 3,
      mcp: { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 5, unverifiedCount: 0 },
    });
    assert.equal(result.level, 0);
    assert.equal(result.caps.length, 0);
  });

  it('boundary: base 4 clean -> level 4', () => {
    const result = computeSecurityLevel({
      agentLevels: [1, 4, 2],
      envFileCount: 0,
      mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
    });
    assert.equal(result.level, 4);
    assert.equal(result.caps.length, 0);
  });

  it('incomplete precedence: incomplete + verifiedCount>0 records ONLY mcp-incomplete', () => {
    const result = computeSecurityLevel({
      agentLevels: [3],
      envFileCount: 0,
      mcp: { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 4, unverifiedCount: 0 },
    });
    assert.equal(result.level, 2);
    assert.equal(result.caps.length, 1, 'exactly one cap must be recorded on incomplete precedence');
    assert.equal(result.caps[0].id, 'mcp-incomplete');
  });

  it('confidence enum sanity: CONFIDENCE.VERIFIED/UNVERIFIED are distinct strings (guards the mcp.verifiedCount contract)', () => {
    assert.notEqual(CONFIDENCE.VERIFIED, CONFIDENCE.UNVERIFIED);
  });
});

describe('computeSecurityLevel + printLevel/printMcpAuditSection render smoke', () => {
  const { printLevel, printMcpAuditSection } = require('../lib/scorecard.js');

  let originalLog;
  let logged;

  beforeEach(() => {
    originalLog = console.log;
    logged = [];
    console.log = (...args) => logged.push(args.join(' '));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it('printLevel(2, [oneCap]) emits a line matching /capped at/', () => {
    printLevel(2, [{ id: 'mcp-findings', cappedFrom: 3, cappedTo: 2, reason: '1 MCP finding(s) — run npx llm-safe-haven scan --mcp for details' }]);
    assert.ok(logged.some((l) => /capped at/.test(l)));
  });

  it('printLevel(level) with no caps emits zero "capped at" lines (backward compatible)', () => {
    printLevel(3);
    assert.ok(!logged.some((l) => /capped at/.test(l)));
  });

  it('printMcpAuditSection with an unverified-only envelope never renders a red FAIL "finding(s)" line', () => {
    const { Finding, SEVERITY, CONFIDENCE } = require('../lib/mcp/base.js');
    const unverified = Finding({
      id: 'd/unverified',
      detector: 'd',
      severity: SEVERITY.HIGH,
      confidence: CONFIDENCE.UNVERIFIED,
      agentId: 'claude-code',
      scope: 'user',
      serverName: 'srv',
      message: 'unverified msg',
    });
    printMcpAuditSection({ exitCode: 0, servers: [{}], findings: [unverified], sources: [] });
    assert.ok(!logged.some((l) => /\d+ MCP finding\(s\)/.test(l)), 'unverified-only must not render as a FAIL finding line');
    assert.ok(logged.some((l) => l.includes('unverified notice')));
  });

  it('printMcpAuditSection(null) renders the incomplete state', () => {
    printMcpAuditSection(null);
    assert.ok(logged.some((l) => /could not complete/.test(l)));
  });
});
