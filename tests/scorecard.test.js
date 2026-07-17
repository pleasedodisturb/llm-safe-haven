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
