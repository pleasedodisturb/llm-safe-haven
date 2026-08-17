'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { captureLog } = require('./helpers/capture-log.js');

describe('scorecard', () => {
  // The scorecard module reads NO_COLOR at require time, so we need
  // a fresh require for each environment configuration.

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

  it('printHeader does not throw', async () => {
    const modPath = require.resolve('../lib/scorecard.js');
    delete require.cache[modPath];
    const scorecard = require('../lib/scorecard.js');

    await captureLog(() => {
      assert.doesNotThrow(() => {
        scorecard.printHeader();
      });
    });
    delete require.cache[modPath];
  });

  it('printLevel does not throw for each level 0-4', async () => {
    const modPath = require.resolve('../lib/scorecard.js');
    delete require.cache[modPath];
    const scorecard = require('../lib/scorecard.js');

    await captureLog(() => {
      for (let level = 0; level <= 4; level++) {
        assert.doesNotThrow(() => {
          scorecard.printLevel(level);
        }, `printLevel(${level}) should not throw`);
      }
    });
    delete require.cache[modPath];
  });
});

describe('printMcpScan', () => {
  const { Finding, SEVERITY, CONFIDENCE } = require('../lib/mcp/base.js');
  const { printMcpScan } = require('../lib/scorecard.js');

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

  it('zero servers/zero findings prints the existing friendly PASS line (stub behavior preserved)', async () => {
    const { logs } = await captureLog(() =>
      printMcpScan({ sources: [], servers: [], findings: [], summary: { bySeverity: {}, byDetector: {} } })
    );
    assert.ok(logs.some((l) => l.includes('No MCP findings')));
  });

  it('handles a null/undefined envelope defensively without throwing', async () => {
    await captureLog(() => {
      assert.doesNotThrow(() => printMcpScan(undefined));
      assert.doesNotThrow(() => printMcpScan(null));
    });
  });

  it('groups findings per server: agent > server-name (scope) header, sorted critical->high->medium->low->info', async () => {
    const critical = finding({ id: 'd/critical', severity: SEVERITY.CRITICAL, message: 'critical msg' });
    const high = finding({ id: 'd/high', severity: SEVERITY.HIGH, message: 'high msg' });
    const medium = finding({ id: 'd/medium', severity: SEVERITY.MEDIUM, message: 'medium msg' });
    const low = finding({ id: 'd/low', severity: SEVERITY.LOW, message: 'low msg' });
    const info = finding({ id: 'd/info', severity: SEVERITY.INFO, message: 'info msg' });

    // Findings intentionally listed out of severity order to prove the
    // renderer sorts them, not just preserves input order.
    const { logs } = await captureLog(() =>
      printMcpScan({
        sources: [],
        servers: [],
        findings: [info, low, medium, high, critical],
      })
    );

    const headerIndex = logs.findIndex((l) => l.includes('claude-code') && l.includes('some-server') && l.includes('(user)'));
    assert.ok(headerIndex !== -1, 'expected an agent > server-name (scope) group header');

    const criticalIndex = logs.findIndex((l) => l.includes('critical msg'));
    const highIndex = logs.findIndex((l) => l.includes('high msg'));
    const mediumIndex = logs.findIndex((l) => l.includes('medium msg'));
    const lowIndex = logs.findIndex((l) => l.includes('low msg'));
    const infoIndex = logs.findIndex((l) => l.includes('info msg'));

    assert.ok(criticalIndex < highIndex, 'critical should render before high');
    assert.ok(highIndex < mediumIndex, 'high should render before medium');
    assert.ok(mediumIndex < lowIndex, 'medium should render before low');
    assert.ok(lowIndex < infoIndex, 'low should render before info');
  });

  it('agentId: null findings render in a final General group', async () => {
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

    const { logs } = await captureLog(() =>
      printMcpScan({ sources: [], servers: [], findings: [attributed, unattributed] })
    );

    const generalIndex = logs.findIndex((l) => l.includes('General'));
    assert.ok(generalIndex !== -1, 'expected a General group header');

    const unattributedIndex = logs.findIndex((l) => l.includes('allowlist unavailable'));
    assert.ok(unattributedIndex > generalIndex, 'unattributed finding should render under the General header');
  });

  it('unverified findings render in a distinct dim style, never red/yellow (D-06)', async () => {
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

      const { logs } = await captureLog(() =>
        scorecard.printMcpScan({ sources: [], servers: [], findings: [unverified] })
      );

      const unverifiedLine = logs.find((l) => l.includes('unverified critical msg'));
      assert.ok(unverifiedLine, 'expected the unverified finding line to be rendered');
      assert.ok(!unverifiedLine.includes(scorecard.C.red), 'unverified line must not contain the red ANSI code');
      assert.ok(!unverifiedLine.includes(scorecard.C.yellow), 'unverified line must not contain the yellow ANSI code');

      const separatorLine = logs.find((l) => l.includes('unverified') && l.includes('--online'));
      assert.ok(separatorLine, 'expected a dim "unverified -- run with --online to verify" sub-line');
    } finally {
      if (originalNoColor === undefined) delete process.env.NO_COLOR;
      else process.env.NO_COLOR = originalNoColor;
      Object.defineProperty(process.stdout, 'isTTY', { value: originalTTY, configurable: true });
      delete require.cache[modPath];
    }
  });

  describe('summary header mirrors D-14/D-08 exit-code semantics', () => {
    it('red FAIL header counts ONLY verified findings; unverified get a separate dim notice line (mixed)', async () => {
      const verified1 = finding({ id: 'd/v1', severity: SEVERITY.HIGH, message: 'verified one' });
      const verified2 = finding({ id: 'd/v2', severity: SEVERITY.LOW, message: 'verified two' });
      const unverified = finding({ id: 'd/u1', confidence: CONFIDENCE.UNVERIFIED, message: 'unverified one' });

      const { logs } = await captureLog(() =>
        printMcpScan({ sources: [], servers: [], findings: [verified1, unverified, verified2] })
      );

      assert.ok(
        logs.some((l) => l.includes('2 finding(s)')),
        'the red header must count the 2 verified findings, not all 3'
      );
      assert.ok(
        !logs.some((l) => l.includes('3 finding(s)')),
        'the header must never count unverified findings into the FAIL total'
      );
      assert.ok(
        logs.some((l) => l.includes('1 unverified notice(s)') && l.includes('--online')),
        'expected a separate dim notice line for the unverified finding'
      );
    });

    it('unverified-only envelope prints NO red FAIL header — only the dim notice (consistent with exit 0)', async () => {
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

        const { logs } = await captureLog(() =>
          scorecard.printMcpScan({ sources: [], servers: [], findings: [u1, u2] })
        );

        assert.ok(
          !logs.some((l) => l.includes('finding(s)')),
          'an unverified-only scan (exit 0) must not render the red "N finding(s)" FAIL header'
        );
        const noticeLine = logs.find((l) => l.includes('2 unverified notice(s)'));
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

    it('zero findings keeps the existing PASS line', async () => {
      const { logs } = await captureLog(() =>
        printMcpScan({ sources: [], servers: [], findings: [] })
      );
      assert.ok(logs.some((l) => l.includes('No MCP findings')));
      assert.ok(!logs.some((l) => l.includes('finding(s)')));
      assert.ok(!logs.some((l) => l.includes('unverified notice')));
    });
  });

  describe('CR-01: terminal escape injection via config-derived strings', () => {
    // A hostile MCP config controls server.name, which flows raw into
    // finding.serverName (group header) and finding.message (detector
    // messages interpolate `Server "${server.name}"`). ANSI/OSC escapes in
    // it could erase or spoof report lines on the operator's terminal
    // (CWE-150). The renderer must strip every C0/C1 control char and DEL.
    const HOSTILE_NAME = 'evil\x1b[2K\x1b[1A\x1b[2Khidden';

    it('strips ANSI escape sequences from the server name in the group header', async () => {
      const hostile = finding({
        serverName: HOSTILE_NAME,
        message: 'plain msg',
      });

      const { logs } = await captureLog(() =>
        printMcpScan({ sources: [], servers: [], findings: [hostile] })
      );

      const headerLine = logs.find((l) => l.includes('evil'));
      assert.ok(headerLine, 'expected the group header naming the hostile server');
      assert.ok(!headerLine.includes('\x1b[2K'), 'erase-line escape must not reach the terminal');
      assert.ok(!headerLine.includes('\x1b[1A'), 'cursor-up escape must not reach the terminal');
      assert.ok(headerLine.includes('�'), 'stripped control chars are replaced with U+FFFD so the operator sees tampering');
      assert.ok(headerLine.includes('hidden'), 'the non-control text around the escapes is preserved');
    });

    it('strips control characters from finding.message (detector messages embed the raw server name)', async () => {
      const hostile = finding({
        serverName: 'srv',
        message: `Server "${HOSTILE_NAME}" uses an unpinned spec\x07`,
      });

      const { logs } = await captureLog(() =>
        printMcpScan({ sources: [], servers: [], findings: [hostile] })
      );

      const msgLine = logs.find((l) => l.includes('unpinned spec'));
      assert.ok(msgLine, 'expected the finding message line to be rendered');
      assert.ok(!msgLine.includes('\x1b'), 'no raw ESC byte may survive in the message line');
      assert.ok(!msgLine.includes('\x07'), 'no BEL byte may survive in the message line');
      assert.ok(msgLine.includes('�'), 'stripped control chars are replaced with U+FFFD');
    });

    it('strips control characters on the unverified (dim) finding line too', async () => {
      const hostile = finding({
        confidence: CONFIDENCE.UNVERIFIED,
        serverName: 'srv',
        message: `Server "${HOSTILE_NAME}" unverified`,
      });

      const { logs } = await captureLog(() =>
        printMcpScan({ sources: [], servers: [], findings: [hostile] })
      );

      const msgLine = logs.find((l) => l.includes('unverified') && l.includes('evil'));
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

    it('printMcpScan never lets U+202E from a hostile server name reach the rendered output', async () => {
      const hostile = finding({
        serverName: 'evil‮name',
        message: 'msg with ‮ override',
      });
      const { logs } = await captureLog(() =>
        printMcpScan({ sources: [], servers: [], findings: [hostile] })
      );
      assert.ok(logs.length > 0);
      assert.ok(
        logs.every((l) => !l.includes('‮')),
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

    it('every logged line is free of /[\\x00-\\x1f\\x7f-\\x9f]|\\p{Cf}/u after stripping renderer SGR', async () => {
      const hostileEnvelope = {
        sources: [
          { agentId: `agent${HOSTILE}`, scope: `user${HOSTILE}`, path: '/p', format: 'json', status: `parse-error${HOSTILE}` },
        ],
        servers: [],
        findings: [
          // IN-01: finding.id is poisoned too — a future detector that
          // interpolates config data into an id must not regress silently.
          finding({ id: `d/one${HOSTILE}`, severity: SEVERITY.CRITICAL, serverName: `srv${HOSTILE}`, message: `msg${HOSTILE}`, scope: `user${HOSTILE}` }),
          finding({ id: `d/two${HOSTILE}`, confidence: CONFIDENCE.UNVERIFIED, serverName: `srv${HOSTILE}`, message: `unv${HOSTILE}`, scope: `user${HOSTILE}` }),
          Finding({
            id: 'd/general', detector: 'd', severity: SEVERITY.HIGH, confidence: CONFIDENCE.VERIFIED,
            agentId: null, scope: null, serverName: null, message: `general${HOSTILE}`,
          }),
        ],
        summary: { bySeverity: {}, byDetector: {} },
      };

      const { logs } = await captureLog(() => printMcpScan(hostileEnvelope));

      assert.ok(logs.length > 0, 'expected rendered output');
      for (const line of logs) {
        const visible = stripSgr(line);
        assert.ok(
          !/[\x00-\x1f\x7f-\x9f]|\p{Cf}/u.test(visible),
          `rendered line contains an unsanitized control/format char: ${JSON.stringify(visible)}`
        );
      }
    });
  });

  it('non-parsed/not-found source statuses are listed so an exit-2 scan explains itself (D-07)', async () => {
    const { logs } = await captureLog(() =>
      printMcpScan({
        sources: [
          { agentId: 'claude-code', scope: 'user', path: '/some/path', format: 'json', status: 'parsed' },
          { agentId: 'cursor', scope: 'project', path: '/other/path', format: 'json', status: 'parse-error' },
          { agentId: 'windsurf', scope: 'user', path: '/missing/path', format: 'json', status: 'not-found' },
        ],
        servers: [],
        findings: [],
      })
    );

    const errorSourceLine = logs.find((l) => l.includes('cursor') && l.includes('parse-error'));
    assert.ok(errorSourceLine, 'expected the parse-error source to be listed with its status');

    assert.ok(
      !logs.some((l) => l.includes('windsurf') && l.includes('not-found')),
      'a not-found source should not be listed (it is not an exit-2-explaining failure)'
    );
  });
});

// ---------------------------------------------------------------------------
// D-08/G-1622: printEnvScan renders scanned-tree .env paths raw at
// lib/scorecard.js:76, one line below the tool's own
// "N .env file(s) found:" verdict -- a hostile directory name containing a
// carriage return plus an erase-line sequence can overwrite that verdict.
// lib/scan.js's printEnvScanResult doc comment already says paths are never
// printed BECAUSE sanitizeForTerminal is not applied here -- this is that
// gap closed at the renderer, plus reachability proof from all three
// commands that call it (scan/audit/install).
// ---------------------------------------------------------------------------
describe('printEnvScan (D-08/G-1622): scanned-tree .env paths must not repaint the tool\'s own verdict line', () => {
  const { printEnvScan } = require('../lib/scorecard.js');
  const { HOSTILE_NAMES } = require('./helpers/chaindrop-fixtures.js');

  it('a path carrying a real 0x0D followed by an erase-line sequence renders with zero raw CR/ESC bytes, U+FFFD visible, and the verdict line intact', async () => {
    // HOSTILE_NAMES sourced from the shared 19-01 corpus (real \u escapes,
    // never a bash printf round-trip) so the Node and bash halves of this
    // phase exercise one shared byte-class vocabulary.
    const hostileSegment = HOSTILE_NAMES.CR + HOSTILE_NAMES.ESC; // real 0x0D, then ESC[2K
    const hostilePath = `/Users/x/Projects/${hostileSegment}evil/.env`;

    const { logs } = await captureLog(() => printEnvScan([hostilePath]));

    const raw = Buffer.from(logs.join('\n'), 'utf8');
    assert.equal(raw.indexOf(0x0d), -1, 'no raw CR (0x0D) byte may reach the rendered output');
    assert.equal(raw.indexOf(0x1b), -1, 'no raw ESC (0x1B) byte may reach the rendered output');

    const pathLine = logs.find((l) => l.includes('evil') && l.includes('.env'));
    assert.ok(pathLine, `expected the rendered path line, got: ${logs.join('\n')}`);
    assert.ok(pathLine.includes('�'), 'stripped control bytes must be replaced with U+FFFD so the operator sees tampering');

    // Must-still-pass twin: the tool's OWN verdict line, printed immediately
    // before this path loop, must still be present and intact in the SAME
    // capture -- this is what makes the defect a verdict-forgery, not a
    // cosmetic one, and proves the fix did not simply suppress output.
    assert.ok(
      logs.some((l) => l.includes('1 .env file(s) found:')),
      `expected the intact verdict line in the same capture, got: ${logs.join('\n')}`
    );
  });

  it('printEnvScan([]) still prints the "No .env files found" pass line, unchanged', async () => {
    const { logs } = await captureLog(() => printEnvScan([]));
    assert.ok(logs.some((l) => l.includes('No .env files found')), `expected the pass line, got: ${logs.join('\n')}`);
  });

  it('more than 10 entries still prints the "...and N more" line, unchanged', async () => {
    const files = Array.from({ length: 13 }, (_, i) => `/tmp/root${i}/.env`);
    const { logs } = await captureLog(() => printEnvScan(files));

    assert.ok(logs.some((l) => l.includes('...and 3 more')), `expected the overflow line, got: ${logs.join('\n')}`);
    for (let i = 0; i < 10; i++) {
      assert.ok(logs.some((l) => l.includes(`/tmp/root${i}/.env`)), `expected path root${i} to be individually rendered`);
    }
    assert.ok(
      !logs.some((l) => l.includes('/tmp/root10/.env')),
      'the 11th path must NOT be individually rendered -- it is folded into "...and N more"'
    );
  });

  it('a path containing U+202E (RLO) is rendered with U+FFFD -- the Node side strips format/bidi code points, unlike the bash side', async () => {
    const hostilePath = `/Users/x/Projects/evil${HOSTILE_NAMES.RLO}name/.env`;
    const { logs } = await captureLog(() => printEnvScan([hostilePath]));

    assert.ok(logs.length > 0, 'expected rendered output');
    assert.ok(!logs.some((l) => l.includes(HOSTILE_NAMES.RLO)), 'no rendered line may contain the raw RLO character');
    assert.ok(logs.some((l) => l.includes('�')), 'the RLO must be replaced with U+FFFD');
    assert.ok(
      logs.some((l) => l.includes('1 .env file(s) found:')),
      `expected the intact verdict line, got: ${logs.join('\n')}`
    );
  });

  it('a path containing café-服务器 survives NFC-equal (this class is NOT hostile and must render intact)', async () => {
    const hostilePath = `/Users/x/Projects/${HOSTILE_NAMES.CJK}/.env`;
    const { logs } = await captureLog(() => printEnvScan([hostilePath]));

    const pathLine = logs.find((l) => l.includes('.env') && l.includes('Projects'));
    assert.ok(pathLine, `expected the rendered path line, got: ${logs.join('\n')}`);
    assert.ok(
      pathLine.normalize('NFC').includes(HOSTILE_NAMES.CJK.normalize('NFC')),
      'café-服务器 must survive NFC-equal, never be stripped or mangled by the sanitizer'
    );
    assert.ok(
      logs.some((l) => l.includes('1 .env file(s) found:')),
      `expected the intact verdict line, got: ${logs.join('\n')}`
    );
  });

  // Narrowly-scoped structural regression guard (review R1-6). A previous
  // revision of this plan asked for a FILE-WIDE claim (that printEnvScan
  // was the single remaining unsanitized console.log site in
  // lib/scorecard.js) via a bare-identifier regex; a reviewer showed that
  // cannot work, because the file also interpolates property accesses,
  // call results and ternaries a
  // bare-identifier regex cannot classify. That claim is retired. This
  // guard pins ONE site only -- printEnvScan's path-list console.log -- and
  // says, in its own title and failure message, exactly what it does NOT
  // establish: it is not evidence that no other unsanitized print site
  // remains anywhere else in this file.
  describe('regression guard scoped to the printEnvScan path-list site only (review R1-6 — not a file-wide claim)', () => {
    const fs = require('fs');
    const path = require('path');

    // Extracts the printEnvScan function body by brace-balancing from its
    // declaration. Returns '' if the declaration cannot be found at all --
    // a renamed or unparseable declaration must FAIL the guard below, not
    // silently pass it (hence the separate non-emptiness assertion, which
    // must run and pass BEFORE the wrapping assertion is even attempted).
    function extractPrintEnvScanBody(source) {
      const marker = 'function printEnvScan(';
      const startIdx = source.indexOf(marker);
      if (startIdx === -1) return '';
      const braceStart = source.indexOf('{', startIdx);
      if (braceStart === -1) return '';
      let depth = 0;
      let i = braceStart;
      for (; i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}') {
          depth--;
          if (depth === 0) {
            i++;
            break;
          }
        }
      }
      return source.slice(braceStart, i);
    }

    it('GUARD SCOPE: pins ONLY the printEnvScan path-list console.log -- this is NOT evidence that no unsanitized print site remains anywhere else in lib/scorecard.js (review R1-6)', () => {
      const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'scorecard.js'), 'utf8');
      const body = extractPrintEnvScanBody(source);

      // Positive control 1: extraction must be non-empty. A renamed or
      // unparseable declaration must FAIL here, not silently pass by
      // measuring an empty string (the exact vacuity class this repo has
      // already been burned by).
      assert.ok(
        body.length > 0,
        'printEnvScan\'s declaration could not be found/extracted from lib/scorecard.js -- a renamed or unparseable declaration must FAIL this guard, not silently pass it'
      );

      // Positive control 2: the path-list loop and its console.log call
      // must actually be present in the extracted body, BEFORE the wrapping
      // assertion runs -- otherwise a wrong extraction could let the guard
      // pass while measuring nothing.
      const loopMarker = 'for (const f of envFiles.slice(0, 10))';
      const loopIdx = body.indexOf(loopMarker);
      assert.ok(
        loopIdx !== -1,
        `expected the path-list loop ("${loopMarker}") inside printEnvScan -- if this line moved or was renamed, this guard must FAIL, not silently pass`
      );
      const logIdx = body.indexOf('console.log(', loopIdx);
      assert.ok(logIdx !== -1, 'expected a console.log(...) call inside the path-list loop');
      const logCallEnd = body.indexOf(');', logIdx);
      const logCall = body.slice(logIdx, logCallEnd);

      // The actual claim: that ONE console.log's interpolation is wrapped
      // in sanitizeForTerminal(. Not a claim about the rest of the file --
      // the file also interpolates property accesses, call results and
      // ternaries a bare-identifier regex cannot classify (review R1-6),
      // and establishing a file-wide sanitization property needs data-flow
      // reasoning this guard does not attempt.
      assert.ok(
        logCall.includes('sanitizeForTerminal('),
        `GUARD SCOPE: this only proves the printEnvScan path-list interpolation is wrapped in sanitizeForTerminal -- it establishes NOTHING about any other print site in lib/scorecard.js. Found unwrapped: ${logCall}`
      );
    });
  });
});

// ---------------------------------------------------------------------------
// D-08/G-1622: reachability. printEnvScanResult is called from THREE
// commands (lib/scan.js:418, lib/audit.js:163, lib/install.js:119), and two
// of its three branches call printEnvScan(detail.files) -- a fix proven only
// at the renderer would leave two of three commands unproven. Each case
// below drives the REAL command function, with its env-scan dependency
// stubbed to return a detail object whose files array holds one hostile
// path, using the require-cache stubbing order (WR-01) this repo already
// relies on for hermeticity -- audit's/install's own test suites use the
// identical pattern. scan()'s own scanForEnvFilesDetailed is a local
// function (not a destructured top-level import), so its case instead
// stubs os.homedir() (the existing stubHomedir seam, also already used
// throughout tests/scan.test.js) and writes one real hostile-named
// directory under the sandboxed HOME -- no new seam invented either way.
// ---------------------------------------------------------------------------
describe('D-08/G-1622: printEnvScan is reachable (and sanitized) from all three commands that call printEnvScanResult', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { installStub, stubHomedir } = require('./helpers/module-stub.js');
  const { HOSTILE_NAMES } = require('./helpers/chaindrop-fixtures.js');
  const { fakeAgent, envelope } = require('./helpers/audit-fixtures.js');

  // Captured once, BEFORE any lib/scan.js require-cache stubbing happens
  // below, so the audit/install cases can delegate to the REAL renderer
  // (the code under test) rather than a mock of it -- same pattern as
  // tests/audit.test.js / tests/install.test.js.
  const { printEnvScanResult: realPrintEnvScanResult, buildCauseClauses: realBuildCauseClauses } = require('../lib/scan.js');

  it('scan: a hostile .env path discovered under a scanned root is sanitized in the rendered report', async () => {
    const scanPath = require.resolve('../lib/scan.js');
    const osPath = require.resolve('os');
    const originalOsEntry = require.cache[osPath];
    const sandboxHome = fs.mkdtempSync(path.join(os.tmpdir(), 'scorecard-scan-cmd-'));

    try {
      const hostileDirName = HOSTILE_NAMES.CR + HOSTILE_NAMES.ESC + 'evil';
      const hostileDirAbs = path.join(sandboxHome, 'Projects', hostileDirName);
      fs.mkdirSync(hostileDirAbs, { recursive: true });
      fs.writeFileSync(path.join(hostileDirAbs, '.env'), 'SECRET=1\n');

      const { scan } = stubHomedir(sandboxHome, scanPath);
      const { logs } = await captureLog(() => scan({}, {}));

      const raw = Buffer.from(logs.join('\n'), 'utf8');
      assert.equal(raw.indexOf(0x0d), -1, 'scan: no raw CR (0x0D) byte may reach stdout');
      assert.equal(raw.indexOf(0x1b), -1, 'scan: no raw ESC (0x1B) byte may reach stdout');
      assert.ok(
        logs.some((l) => l.includes('1 .env file(s) found:')),
        `scan: expected the intact verdict line, got: ${logs.join('\n')}`
      );
      assert.ok(
        logs.some((l) => l.includes('�') && l.includes('evil')),
        `scan: expected the sanitized path line with U+FFFD, got: ${logs.join('\n')}`
      );
    } finally {
      if (originalOsEntry === undefined) delete require.cache[osPath];
      else require.cache[osPath] = originalOsEntry;
      delete require.cache[scanPath];
      fs.rmSync(sandboxHome, { recursive: true, force: true });
    }
  });

  it('audit: a hostile .env path from the env scan is sanitized in the rendered report', async () => {
    const scanPath = require.resolve('../lib/scan.js');
    const agentsPath = require.resolve('../lib/agents/index.js');
    const scanMcpPath = require.resolve('../lib/scan-mcp.js');
    const auditPath = require.resolve('../lib/audit.js');
    const hostilePath = `/Users/x/Code/${HOSTILE_NAMES.CR}${HOSTILE_NAMES.ESC}evil/.env`;

    delete require.cache[scanPath];
    delete require.cache[agentsPath];
    delete require.cache[scanMcpPath];
    delete require.cache[auditPath];

    try {
      installStub(scanPath, {
        scanForEnvFiles: () => [hostilePath],
        scanForEnvFilesDetailed: () => ({
          files: [hostilePath],
          incomplete: false,
          anomalyCount: 0,
          anomalyReasons: { unreadable: 0, budget: 0, swapped: 0 },
          rootFailures: { missing: 0, unreadable: 0 },
        }),
        printEnvScanResult: (...args) => realPrintEnvScanResult(...args),
        buildCauseClauses: (...args) => realBuildCauseClauses(...args),
      });
      installStub(agentsPath, {
        detectAll: () => [fakeAgent()],
        getByIds: () => [],
      });
      installStub(scanMcpPath, {
        buildEnvelope: () => Promise.resolve(envelope()),
        scanMcp: () => Promise.reject(new Error('unused by audit — present for shape parity')),
        findingsExitCode: () => 0,
      });

      const { audit } = require('../lib/audit.js');
      const { logs } = await captureLog(() => audit({}));

      const raw = Buffer.from(logs.join('\n'), 'utf8');
      assert.equal(raw.indexOf(0x0d), -1, 'audit: no raw CR (0x0D) byte may reach stdout');
      assert.equal(raw.indexOf(0x1b), -1, 'audit: no raw ESC (0x1B) byte may reach stdout');
      assert.ok(
        logs.some((l) => l.includes('1 .env file(s) found:')),
        `audit: expected the intact verdict line, got: ${logs.join('\n')}`
      );
      assert.ok(
        logs.some((l) => l.includes('�') && l.includes('evil')),
        `audit: expected the sanitized path line with U+FFFD, got: ${logs.join('\n')}`
      );
    } finally {
      delete require.cache[scanPath];
      delete require.cache[agentsPath];
      delete require.cache[scanMcpPath];
      delete require.cache[auditPath];
    }
  });

  it('install: a hostile .env path from the env scan is sanitized in the rendered report', async () => {
    const scanPath = require.resolve('../lib/scan.js');
    const agentsPath = require.resolve('../lib/agents/index.js');
    const scanMcpPath = require.resolve('../lib/scan-mcp.js');
    const auditPath = require.resolve('../lib/audit.js');
    const installPath = require.resolve('../lib/install.js');
    const hostilePath = `/Users/x/src/${HOSTILE_NAMES.CR}${HOSTILE_NAMES.ESC}evil/.env`;

    delete require.cache[scanPath];
    delete require.cache[agentsPath];
    delete require.cache[scanMcpPath];
    delete require.cache[auditPath];
    delete require.cache[installPath];

    try {
      installStub(scanPath, {
        scanForEnvFiles: () => [hostilePath],
        scanForEnvFilesDetailed: () => ({
          files: [hostilePath],
          incomplete: false,
          anomalyCount: 0,
          anomalyReasons: { unreadable: 0, budget: 0, swapped: 0 },
          rootFailures: { missing: 0, unreadable: 0 },
        }),
        printEnvScanResult: (...args) => realPrintEnvScanResult(...args),
        buildCauseClauses: (...args) => realBuildCauseClauses(...args),
      });
      installStub(agentsPath, {
        detectAll: () => [fakeAgent()],
        getByIds: () => [],
      });
      installStub(scanMcpPath, {
        buildEnvelope: () => Promise.resolve(envelope()),
        scanMcp: () => Promise.reject(new Error('unused by install — present for shape parity')),
        findingsExitCode: () => 0,
      });

      const { install } = require('../lib/install.js');
      const { logs } = await captureLog(() => install({}));

      const raw = Buffer.from(logs.join('\n'), 'utf8');
      assert.equal(raw.indexOf(0x0d), -1, 'install: no raw CR (0x0D) byte may reach stdout');
      assert.equal(raw.indexOf(0x1b), -1, 'install: no raw ESC (0x1B) byte may reach stdout');
      assert.ok(
        logs.some((l) => l.includes('1 .env file(s) found:')),
        `install: expected the intact verdict line, got: ${logs.join('\n')}`
      );
      assert.ok(
        logs.some((l) => l.includes('�') && l.includes('evil')),
        `install: expected the sanitized path line with U+FFFD, got: ${logs.join('\n')}`
      );
    } finally {
      delete require.cache[scanPath];
      delete require.cache[agentsPath];
      delete require.cache[scanMcpPath];
      delete require.cache[auditPath];
      delete require.cache[installPath];
    }
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

  describe('WR-02: fail closed when mcp input is absent or shapeless', () => {
    it('omitted mcp: base 4, env 0 -> level 2 with an mcp-incomplete cap (never an uncapped 4)', () => {
      const result = computeSecurityLevel({ agentLevels: [4], envFileCount: 0 });
      assert.equal(result.level, 2, 'unknown MCP state must never be scored as scanned-and-clean');
      assert.equal(result.caps.length, 1);
      assert.equal(result.caps[0].id, 'mcp-incomplete');
      assertCapShape(result.caps[0]);
    });

    it('shapeless mcp ({} — no boolean ran): base 3 -> level 2 with an mcp-incomplete cap', () => {
      const result = computeSecurityLevel({ agentLevels: [3], envFileCount: 0, mcp: {} });
      assert.equal(result.level, 2);
      assert.equal(result.caps.length, 1);
      assert.equal(result.caps[0].id, 'mcp-incomplete');
    });

    it('no-args call fails closed too (base 0 -> level 0, no cap fires below the ceiling)', () => {
      const result = computeSecurityLevel();
      assert.equal(result.level, 0);
      assert.equal(result.caps.length, 0);
    });
  });

  // EXIT-05 (G-1623, D-20-06): the `env` input is a structural clone of the
  // `mcp` input above -- same fail-closed-on-absence shape (WR-02), same
  // ceiling (2), same "only one of two caps recorded when both fire"
  // independence. Named as the sibling of "WR-02: fail closed when mcp
  // input is absent or shapeless" because it IS that same guarantee, for
  // the other half of the scan.
  describe('WR-02 for env: fail closed when env input is absent or shapeless, mirrors mcp exactly (D-20-06, EXIT-05)', () => {
    it('env cap fires: base 4, mcp clean, env ran+incomplete -> level 2 with an env-incomplete cap', () => {
      const result = computeSecurityLevel({
        agentLevels: [4],
        envFileCount: 0,
        mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
        env: { ran: true, incomplete: true },
      });
      assert.equal(result.level, 2, 'an incomplete .env scan must cap the level at 2');
      assert.equal(result.caps.length, 1);
      assert.equal(result.caps[0].id, 'env-incomplete');
      assert.equal(result.caps[0].cappedFrom, 4);
      assert.equal(result.caps[0].cappedTo, 2);
      assertCapShape(result.caps[0]);
    });

    it('MUST-STILL-PASS TWIN: base 4, mcp clean, env ran and NOT incomplete -> level 4, no env-incomplete cap', () => {
      const result = computeSecurityLevel({
        agentLevels: [4],
        envFileCount: 0,
        mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
        env: { ran: true, incomplete: false },
      });
      assert.equal(result.level, 4);
      assert.equal(result.caps.length, 0, 'a complete env scan must never produce an env-incomplete cap');
    });

    it('fail-closed on absence: env omitted entirely, base 4, mcp clean -> level 2 with an env-incomplete cap', () => {
      const result = computeSecurityLevel({
        agentLevels: [4],
        envFileCount: 0,
        mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
      });
      assert.equal(result.level, 2, 'unknown env-scan state must never be scored as scanned-and-clean');
      assert.equal(result.caps.length, 1);
      assert.equal(result.caps[0].id, 'env-incomplete');
      assertCapShape(result.caps[0]);
    });

    it('fail-closed on shapeless env ({} — no boolean ran): base 3, mcp clean -> level 2 with an env-incomplete cap', () => {
      const result = computeSecurityLevel({
        agentLevels: [3],
        envFileCount: 0,
        mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
        env: {},
      });
      assert.equal(result.level, 2);
      assert.equal(result.caps.length, 1);
      assert.equal(result.caps[0].id, 'env-incomplete');
    });

    it('both caps active: env incomplete AND mcp incomplete each record their OWN cap, level is 2, neither swallows the other', () => {
      const result = computeSecurityLevel({
        agentLevels: [4],
        envFileCount: 0,
        mcp: { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 },
        env: { ran: true, incomplete: true },
      });
      assert.equal(result.level, 2);
      assert.equal(result.caps.length, 2);
      const envCap = result.caps.find((c) => c.id === 'env-incomplete');
      const mcpCap = result.caps.find((c) => c.id === 'mcp-incomplete');
      assert.ok(envCap, 'expected an env-incomplete cap');
      assert.ok(mcpCap, 'expected an mcp-incomplete cap');
      assertCapShape(envCap);
      assertCapShape(mcpCap);
    });

    it('ceiling does not fire below base: base 2, env incomplete -> level 2, no env-incomplete cap recorded', () => {
      const result = computeSecurityLevel({
        agentLevels: [2],
        envFileCount: 0,
        mcp: { ran: true, exitCode: EXIT.CLEAN, verifiedCount: 0, unverifiedCount: 0 },
        env: { ran: true, incomplete: true },
      });
      assert.equal(result.level, 2, 'a ceiling equal to or above base fires no cap, but level is still at most the ceiling');
      assert.equal(result.caps.length, 0, 'a ceiling equal to or above base must not be recorded as a cap -- nothing to reduce');
    });
  });
});

describe('computeSecurityLevel + printLevel/printMcpAuditSection render smoke', () => {
  const { printLevel, printMcpAuditSection } = require('../lib/scorecard.js');

  it('printLevel(2, [oneCap]) emits a line matching /capped at/', async () => {
    const { logs } = await captureLog(() =>
      printLevel(2, [{ id: 'mcp-findings', cappedFrom: 3, cappedTo: 2, reason: '1 MCP finding(s) — run npx llm-safe-haven scan --mcp for details' }])
    );
    assert.ok(logs.some((l) => /capped at/.test(l)));
  });

  it('printLevel(level) with no caps emits zero "capped at" lines (backward compatible)', async () => {
    const { logs } = await captureLog(() => printLevel(3));
    assert.ok(!logs.some((l) => /capped at/.test(l)));
  });

  it('IN-01: a hostile cap.reason is sanitized at the print site (no control chars reach the terminal)', async () => {
    const { logs } = await captureLog(() =>
      printLevel(2, [{ id: 'mcp-findings', cappedFrom: 3, cappedTo: 2, reason: 'evil\x1b[2K\x07reason‮spoof' }])
    );
    const capLine = logs.find((l) => /capped at/.test(l));
    assert.ok(capLine, 'expected the cap line to render');
    assert.ok(!capLine.includes('\x1b[2K'), 'erase-line escape must not reach the terminal');
    assert.ok(!capLine.includes('\x07'), 'BEL must not reach the terminal');
    assert.ok(!capLine.includes('‮'), 'RLO must not reach the terminal');
    assert.ok(capLine.includes('�'), 'stripped chars are replaced with U+FFFD so tampering is visible');
  });

  it('printMcpAuditSection with an unverified-only envelope never renders a red FAIL "finding(s)" line', async () => {
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
    // F8 signature: the production callers pass getMcpInputs' counts.
    const { logs } = await captureLog(() =>
      printMcpAuditSection(
        { exitCode: 0, servers: [{}], findings: [unverified], sources: [] },
        { ran: true, exitCode: 0, verifiedCount: 0, unverifiedCount: 1 }
      )
    );
    assert.ok(!logs.some((l) => /\d+ MCP finding\(s\)/.test(l)), 'unverified-only must not render as a FAIL finding line');
    assert.ok(logs.some((l) => l.includes('unverified notice')));
  });

  it('F8 fallback: omitting the mcp counts arg re-derives them from the envelope (no throw, same render)', async () => {
    const { Finding, SEVERITY, CONFIDENCE } = require('../lib/mcp/base.js');
    const verified = Finding({
      id: 'd/v', detector: 'd', severity: SEVERITY.HIGH, confidence: CONFIDENCE.VERIFIED,
      agentId: 'claude-code', scope: 'user', serverName: 'srv', message: 'verified msg',
    });
    const { logs } = await captureLog(() =>
      printMcpAuditSection({ exitCode: 1, servers: [{}], findings: [verified], sources: [] })
    );
    assert.ok(logs.some((l) => /1 MCP finding\(s\)/.test(l)), 'the fallback derivation must still count the verified finding');
  });

  it('printMcpAuditSection(null) renders the incomplete state', async () => {
    const { logs } = await captureLog(() => printMcpAuditSection(null));
    assert.ok(logs.some((l) => /could not complete/.test(l)));
  });

  it('F2: incomplete + verified + unverified renders ALL THREE lines — the warning must never mask partial findings', async () => {
    const { Finding, SEVERITY, CONFIDENCE, EXIT } = require('../lib/mcp/base.js');
    const verified = Finding({
      id: 'd/v', detector: 'd', severity: SEVERITY.HIGH, confidence: CONFIDENCE.VERIFIED,
      agentId: 'claude-code', scope: 'user', serverName: 'srv', message: 'verified msg',
    });
    const unverified = Finding({
      id: 'd/u', detector: 'd', severity: SEVERITY.LOW, confidence: CONFIDENCE.UNVERIFIED,
      agentId: 'claude-code', scope: 'user', serverName: 'srv', message: 'unverified msg',
    });

    const { logs } = await captureLog(() =>
      printMcpAuditSection(
        { exitCode: EXIT.INCOMPLETE, servers: [], findings: [verified, unverified], sources: [] },
        { ran: true, exitCode: EXIT.INCOMPLETE, verifiedCount: 1, unverifiedCount: 1 }
      )
    );

    assert.ok(logs.some((l) => /could not complete/.test(l)), 'the incomplete WARN line must render');
    assert.ok(logs.some((l) => /1 MCP finding\(s\)/.test(l)), 'the verified-findings count must render too — partial findings are a floor, not maskable');
    assert.ok(logs.some((l) => /1 unverified notice\(s\)/.test(l)), 'the dim unverified notice must render too');
  });

  it('F2 guard: single-state outputs are unchanged — incomplete with zero findings prints ONLY the warning', async () => {
    const { EXIT } = require('../lib/mcp/base.js');
    const { logs } = await captureLog(() =>
      printMcpAuditSection({ exitCode: EXIT.INCOMPLETE, servers: [], findings: [], sources: [] })
    );
    assert.ok(logs.some((l) => /could not complete/.test(l)));
    assert.ok(!logs.some((l) => /MCP finding\(s\)/.test(l)));
    assert.ok(!logs.some((l) => /unverified notice/.test(l)));
  });
});

// ---------------------------------------------------------------------------
// The MCP composite grouping key (TOOL-01 / G-1573, CONTEXT D-05).
//
// G-1573 replaced two LITERAL 0x00 bytes in lib/scorecard.js with their escape
// sequence. That is an ENCODING change only: the escape and the literal byte are
// the same string value, so no behavioural test can tell them apart. The byte
// scan in tests/no-nul-source.test.js is the "did the thing" half of the proof;
// everything below is the "did not break anything" half. Both halves are needed,
// and neither substitutes for the other.
//
// Every assertion here is on the BUILT STRING, never on the source text — the
// source text is exactly what a printable delimiter would still satisfy.
// ---------------------------------------------------------------------------
describe('mcpGroupKey: the composite MCP grouping key (G-1573 / D-05)', () => {
  const fs = require('fs');
  const path = require('path');
  const { Finding, SEVERITY, CONFIDENCE } = require('../lib/mcp/base.js');
  const { mcpGroupKey, printMcpScan } = require('../lib/scorecard.js');

  // Built from char codes, never typed as literals: a real NUL must not enter
  // this file (tests/no-nul-source.test.js scans it too), and typing the escape
  // risks a tool interpolating it into the actual byte — which happened twice
  // while this plan was being written.
  const NUL = String.fromCharCode(0);
  const NUL_ESCAPE = String.fromCharCode(92, 117, 48, 48, 48, 48); // backslash u 0 0 0 0

  const SCORECARD_PATH = path.join(__dirname, '..', 'lib', 'scorecard.js');

  function mcpFinding(overrides = {}) {
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

  // ---- runtime: the delimiter is still a real NUL --------------------------

  it('builds exactly three segments separated by two real NUL bytes', () => {
    const k = mcpGroupKey({ agentId: 'claude-code', scope: 'user', serverName: 'srv' });
    assert.equal(k.split(NUL).length, 3, 'the key must carry exactly two delimiters');
  });

  it('the two delimiters are code point ZERO at the two expected positions', () => {
    const k = mcpGroupKey({ agentId: 'claude-code', scope: 'user', serverName: 'srv' });
    assert.equal(
      k.charCodeAt('claude-code'.length),
      0,
      'first delimiter must be code point 0 — this is the assertion a printable delimiter fails'
    );
    assert.equal(
      k.charCodeAt('claude-code'.length + 1 + 'user'.length),
      0,
      'second delimiter must be code point 0 — this is the assertion a printable delimiter fails'
    );
  });

  it('round-trips to its three components', () => {
    const k = mcpGroupKey({ agentId: 'claude-code', scope: 'user', serverName: 'srv' });
    assert.deepEqual(k.split(NUL), ['claude-code', 'user', 'srv']);
  });

  it('a hostile serverName full of printable delimiters still yields exactly three segments', () => {
    // serverName is the only attacker-controlled component (agentId comes from
    // the fixed 10-item KNOWN_AGENT_IDS behind a fail-closed dispatch guard,
    // scope from a fixed 4-value vocabulary). This is the case that pins WHY a
    // printable delimiter is refused (D-05(b)): under a colon, space or pipe
    // delimiter this exact server name would forge a group boundary and
    // attribute findings to a different agent or scope in the operator's report.
    const k = mcpGroupKey({ agentId: 'claude-code', scope: 'user', serverName: 'a:b c|d' });
    assert.equal(
      k.split(NUL).length,
      3,
      'a NUL delimiter is uncollidable with attacker-chosen printable text; a printable one is not'
    );
    assert.deepEqual(k.split(NUL), ['claude-code', 'user', 'a:b c|d']);
  });

  // ---- paired control: the render path still groups the same way -----------

  it('CONTROL: printMcpScan renders findings sharing (agentId, scope, serverName) as ONE group', async () => {
    const { logs } = await captureLog(() =>
      printMcpScan({
        sources: [],
        servers: [],
        findings: [mcpFinding({ id: 'd/one', message: 'first msg' }), mcpFinding({ id: 'd/two', message: 'second msg' })],
      })
    );
    const headers = logs.filter((l) => l.includes('›'));
    assert.equal(headers.length, 1, `expected exactly one group header, got ${headers.length}`);
  });

  it('CONTROL: printMcpScan renders findings differing only in serverName as TWO groups', async () => {
    const { logs } = await captureLog(() =>
      printMcpScan({
        sources: [],
        servers: [],
        findings: [
          mcpFinding({ id: 'd/one', serverName: 'server-a', message: 'first msg' }),
          mcpFinding({ id: 'd/two', serverName: 'server-b', message: 'second msg' }),
        ],
      })
    );
    const headers = logs.filter((l) => l.includes('›'));
    assert.equal(headers.length, 2, `expected exactly two group headers, got ${headers.length}`);
  });

  // ---- structural: mcpGroupKey is the ONLY implementation ------------------
  //
  // The two behavioural controls above are NOT sufficient, and review A-3 said
  // so. A refactor that leaves mcpGroupKey correct, exported and unit-tested
  // while printMcpScan keeps its OWN inline key builder using the same delimiter
  // produces byte-identical grouping and passes every assertion above — a
  // behavioural control can see the key's SHAPE, never which code built it.
  //
  // A runtime module seam was REJECTED for this. Routing the call through
  // module.exports.mcpGroupKey so a test could spy on it would make a security
  // renderer's grouping key swappable at runtime by anything that can reach the
  // module object — a worse property than the one being proven, in the one file
  // that renders hostile MCP config data to the operator's terminal. The
  // structural assertion buys the same guarantee with no production weakening.

  function printMcpScanSource() {
    const src = fs.readFileSync(SCORECARD_PATH, 'utf8');
    const start = src.indexOf('\nfunction printMcpScan(');
    if (start === -1) return { src, slice: '' };
    // printMcpScan is currently the LAST top-level function in the file, so the
    // terminator is whichever comes first: the next column-0 `function `
    // declaration or the column-0 `module.exports`.
    const rest = src.slice(start + 1);
    const nextDecl = rest.slice(1).search(/^(function |module\.exports)/m);
    const slice = nextDecl === -1 ? rest : rest.slice(0, nextDecl + 1);
    return { src, slice };
  }

  it('STRUCTURAL: printMcpScan calls mcpGroupKey and builds no composite key of its own', () => {
    const { slice } = printMcpScanSource();

    // Asserted FIRST and on its own: if the anchor were renamed, every
    // assertion below would pass vacuously against an empty string.
    assert.ok(
      slice.length > 0,
      'could not locate printMcpScan\'s source region — an anchor rename would make every ' +
        'assertion in this test pass vacuously against an empty slice, so this is checked first'
    );
    assert.ok(slice.includes('function printMcpScan('), 'the slice must actually start at printMcpScan');

    assert.equal(
      slice.split('mcpGroupKey(').length - 1,
      1,
      'printMcpScan must call the extracted builder exactly once'
    );

    assert.equal(
      slice.split(NUL_ESCAPE).length - 1,
      0,
      'printMcpScan must contain ZERO occurrences of the NUL escape. This is the load-bearing ' +
        'half: a second inline key builder using the same delimiter has to spell that delimiter ' +
        'somewhere, and after the byte guard in tests/no-nul-source.test.js it can no longer spell ' +
        'it as a raw byte. The two guards compose; neither closes this hole alone.'
    );
  });

  it('STRUCTURAL: the NUL escape occurs exactly twice in lib/scorecard.js, both inside mcpGroupKey', () => {
    const { src } = printMcpScanSource();

    assert.equal(src.split(NUL_ESCAPE).length - 1, 2, 'exactly two delimiters, and nowhere else in the file');

    const bodyStart = src.indexOf('\nfunction mcpGroupKey(');
    assert.ok(bodyStart !== -1, 'could not locate mcpGroupKey — checked before asserting on its extent');
    const bodyEnd = src.indexOf('\n}', bodyStart);
    assert.ok(bodyEnd > bodyStart, 'could not locate the end of mcpGroupKey');

    let at = -1;
    const positions = [];
    while ((at = src.indexOf(NUL_ESCAPE, at + 1)) !== -1) positions.push(at);
    for (const pos of positions) {
      assert.ok(
        pos > bodyStart && pos < bodyEnd,
        `a NUL escape at offset ${pos} sits outside mcpGroupKey's body (${bodyStart}..${bodyEnd}) — ` +
          'the delimiter must be spelled in exactly one place'
      );
    }
  });
});
