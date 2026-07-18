'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { parseArgs, run } = require('../lib/cli.js');

describe('parseArgs', () => {
  it('parses --help flag', () => {
    const result = parseArgs(['--help']);
    assert.strictEqual(result.flags.help, true);
  });

  it('parses -h shorthand for help', () => {
    const result = parseArgs(['-h']);
    assert.strictEqual(result.flags.help, true);
  });

  it('parses --version flag', () => {
    const result = parseArgs(['--version']);
    assert.strictEqual(result.flags.version, true);
  });

  it('parses -v shorthand for version', () => {
    const result = parseArgs(['-v']);
    assert.strictEqual(result.flags.version, true);
  });

  it('parses --dry-run flag', () => {
    const result = parseArgs(['--dry-run']);
    assert.strictEqual(result.flags.dryRun, true);
  });

  it('parses --agent with value', () => {
    const result = parseArgs(['--agent', 'claude-code']);
    assert.strictEqual(result.flags.agent, 'claude-code');
  });

  it('parses --json flag', () => {
    const result = parseArgs(['--json']);
    assert.strictEqual(result.flags.json, true);
  });

  it('defaults command to install', () => {
    const result = parseArgs([]);
    assert.strictEqual(result.command, 'install');
  });

  it('parses subcommand: audit', () => {
    const result = parseArgs(['audit']);
    assert.strictEqual(result.command, 'audit');
  });

  it('parses subcommand: scan', () => {
    const result = parseArgs(['scan']);
    assert.strictEqual(result.command, 'scan');
  });

  it('parses subcommand: update', () => {
    const result = parseArgs(['update']);
    assert.strictEqual(result.command, 'update');
  });

  it('combines subcommand with flags', () => {
    const result = parseArgs(['audit', '--json', '--agent', 'cursor']);
    assert.strictEqual(result.command, 'audit');
    assert.strictEqual(result.flags.json, true);
    assert.strictEqual(result.flags.agent, 'cursor');
  });

  it('parses --online flag', () => {
    const result = parseArgs(['--online']);
    assert.strictEqual(result.flags.online, true);
  });

  it('defaults --online to falsy when absent', () => {
    const result = parseArgs([]);
    assert.ok(!result.flags.online);
  });

  it('combines scan --mcp --online', () => {
    const result = parseArgs(['scan', '--mcp', '--online']);
    assert.strictEqual(result.command, 'scan');
    assert.strictEqual(result.flags.mcp, true);
    assert.strictEqual(result.flags.online, true);
  });

  it('parses --quiet flag (and never records it as unknown)', () => {
    const result = parseArgs(['scan', '--mcp', '--quiet']);
    assert.strictEqual(result.flags.quiet, true);
    assert.deepStrictEqual(result.unknownFlags, [], '--quiet is a known flag — it must not trip the WR-01 fail-closed guard');
  });

  describe('WR-05: unknown flags are never silently ignored', () => {
    function captureStderr(fn) {
      const original = console.error;
      const lines = [];
      console.error = (msg) => { lines.push(String(msg)); };
      try {
        return { result: fn(), lines };
      } finally {
        console.error = original;
      }
    }

    it('a typo\'d --onlien produces a stderr warning and is recorded in unknownFlags', () => {
      const { result, lines } = captureStderr(() => parseArgs(['scan', '--mcp', '--onlien']));
      assert.deepStrictEqual(result.unknownFlags, ['--onlien']);
      assert.ok(!result.flags.online, 'the typo must not set the real flag');
      assert.ok(lines.some(l => l.includes('--onlien')), `expected a warning naming the typo, got: ${lines}`);
    });

    it('a typo\'d --supply-chian produces a stderr warning and is recorded in unknownFlags', () => {
      const { result, lines } = captureStderr(() => parseArgs(['scan', '--supply-chian']));
      assert.deepStrictEqual(result.unknownFlags, ['--supply-chian']);
      assert.ok(!result.flags.supplyChain);
      assert.ok(lines.some(l => l.includes('--supply-chian')));
    });

    it('known flags never warn and unknownFlags stays empty', () => {
      const { result, lines } = captureStderr(() => parseArgs(['scan', '--mcp', '--online', '--json']));
      assert.deepStrictEqual(result.unknownFlags, []);
      assert.deepStrictEqual(lines, []);
    });
  });

  describe('WR-01: scan fails closed (exit 2) on unknown flags', () => {
    function captureStderr(fn) {
      const original = console.error;
      const lines = [];
      console.error = (msg) => { lines.push(String(msg)); };
      try {
        return { result: fn(), lines };
      } finally {
        console.error = original;
      }
    }

    it('run(["scan","--mpc"]) (typo\'d --mcp) refuses with exit code 2 instead of silently running the env scan', async () => {
      const originalExitCode = process.exitCode;
      const originalLog = console.log;
      const loggedStdout = [];
      console.log = (...a) => loggedStdout.push(a.join(' '));
      try {
        const { lines } = captureStderr(() => run(['scan', '--mpc']));
        await new Promise(setImmediate);
        assert.strictEqual(process.exitCode, 2, 'a typo\'d security flag must never masquerade as a clean scan');
        assert.ok(lines.some(l => l.includes('Refusing to run scan') && l.includes('--mpc')), `expected a refusal naming the typo on stderr, got: ${lines}`);
        assert.deepStrictEqual(loggedStdout, [], 'no scan output — the scan must not have run at all');
      } finally {
        console.log = originalLog;
        process.exitCode = originalExitCode;
      }
    });

    it('run(["scan","--mcp","--onlien"]) (typo\'d --online) refuses with exit code 2 instead of running the wrong scan', async () => {
      const originalExitCode = process.exitCode;
      const originalLog = console.log;
      console.log = () => {};
      try {
        const { lines } = captureStderr(() => run(['scan', '--mcp', '--onlien']));
        await new Promise(setImmediate);
        assert.strictEqual(process.exitCode, 2);
        assert.ok(lines.some(l => l.includes('Refusing to run scan') && l.includes('--onlien')));
      } finally {
        console.log = originalLog;
        process.exitCode = originalExitCode;
      }
    });
  });

  describe('run() scan --mcp exit-code propagation (D-01)', () => {
    it('sets process.exitCode from the async scanMcp() result before the process would naturally exit', async () => {
      // This invokes real discovery/parsing/detectors against the actual
      // machine (no injected opts channel reaches run() at the CLI
      // boundary) — --json/--quiet keep stdout to a single JSON blob and
      // suppress the human report. Only a numeric exit code is asserted
      // here; the exact-value (0/1/2) assertions live in scan-mcp.test.js's
      // injected-fixture e2e suite (Task 2).
      const originalExitCode = process.exitCode;
      const originalLog = console.log;
      const originalError = console.error;
      const stderrLines = [];
      console.log = () => {}; // suppress the real --json envelope output
      console.error = (msg) => { stderrLines.push(String(msg)); };
      try {
        run(['scan', '--mcp', '--json', '--quiet']);
        // Let lib/cli.js's Promise.resolve(result).then(...) chain run —
        // buildEnvelope()'s awaited detector loop (runAll()) chains
        // several microtask ticks even when every detector resolves
        // synchronously, so a single `await Promise.resolve()` is not
        // enough. setImmediate() only fires after ALL pending microtasks
        // (including ones enqueued while draining the queue) are drained.
        await new Promise(setImmediate);
        // The scan must actually RUN — a previously self-defeating
        // version of this test passed '--quiet' while parseArgs did not
        // recognize it, so the WR-01 guard refused the scan with exit 2
        // and `typeof === 'number'` was trivially satisfied by the
        // refusal. Assert the refusal path was NOT taken and the exit
        // code is one of the scan contract values (0/1/2).
        assert.ok(
          !stderrLines.some(l => l.includes('Refusing to run scan')),
          `the scan must not be refused — every flag is known; stderr: ${stderrLines}`
        );
        assert.ok(
          [0, 1, 2].includes(process.exitCode),
          `exit code must be a scan contract value (0=clean/1=findings/2=incomplete), got ${process.exitCode}`
        );
      } finally {
        console.log = originalLog;
        console.error = originalError;
        process.exitCode = originalExitCode; // never pollute the real test-runner exit code
      }
    });
  });

  describe('IN-01: a rejecting scan promise fails closed to exit code 2', () => {
    it('run(["scan"]) with a scan() that rejects sets process.exitCode = 2 (never a silent false-clean 0)', async () => {
      // scanMcp() is contractually written to never reject, but the
      // dispatch must not depend on that invariant forever — a future
      // refactor letting a rejection escape would otherwise leave
      // exitCode 0 plus an unhandled-rejection warning. Stub lib/scan.js
      // in the require cache so scan() rejects, and assert the .catch
      // fails closed.
      const Module = require('module');
      const scanPath = require.resolve('../lib/scan.js');
      const originalCacheEntry = require.cache[scanPath];
      const stub = new Module(scanPath);
      stub.filename = scanPath;
      stub.loaded = true;
      stub.exports = { scan: () => Promise.reject(new Error('escaped rejection')) };
      require.cache[scanPath] = stub;

      const originalExitCode = process.exitCode;
      const originalError = console.error;
      const stderrLines = [];
      console.error = (msg) => { stderrLines.push(String(msg)); };
      try {
        process.exitCode = 0;
        run(['scan']);
        await new Promise(setImmediate);
        assert.strictEqual(process.exitCode, 2, 'an escaped rejection must fail closed to 2, never stay 0');
        // F3/WR-04 parity: scan's fail-closed catch previously set the
        // exit code with ZERO bytes of explanation — the shared
        // settleCommand helper now prints the diagnostic (incl. stack).
        assert.ok(
          stderrLines.some(l => l.includes('scan failed') && l.includes('escaped rejection')),
          `expected a stderr diagnostic naming the failure, got: ${stderrLines}`
        );
      } finally {
        console.error = originalError;
        process.exitCode = originalExitCode;
        if (originalCacheEntry === undefined) delete require.cache[scanPath];
        else require.cache[scanPath] = originalCacheEntry;
      }
    });
  });

  describe('F3/F6: a rejecting install promise fails closed to exit code 1 with a stack trace on stderr', () => {
    it('run(["install"]) with an install() that rejects sets process.exitCode = 1 and prints the error stack', async () => {
      const Module = require('module');
      const installPath = require.resolve('../lib/install.js');
      const originalCacheEntry = require.cache[installPath];
      const stub = new Module(installPath);
      stub.filename = installPath;
      stub.loaded = true;
      stub.exports = { install: () => Promise.reject(new Error('install blew up')) };
      require.cache[installPath] = stub;

      const originalExitCode = process.exitCode;
      const originalError = console.error;
      const stderrLines = [];
      console.error = (msg) => { stderrLines.push(String(msg)); };
      try {
        process.exitCode = 0;
        run(['install']);
        await new Promise(setImmediate);
        assert.strictEqual(process.exitCode, 1, 'an escaped install rejection must fail with exit code 1');
        assert.ok(
          stderrLines.some(l => l.includes('install failed') && l.includes('install blew up')),
          `expected a stderr diagnostic naming the failure, got: ${stderrLines}`
        );
        // F6: err.stack (not just err.message) — a bare message with no
        // frames made install failures undebuggable.
        assert.ok(
          stderrLines.some(l => /at .+\(.+\)|at .+:\d+:\d+/.test(l)),
          `expected the stack frames in the diagnostic, got: ${stderrLines}`
        );
      } finally {
        console.error = originalError;
        process.exitCode = originalExitCode;
        if (originalCacheEntry === undefined) delete require.cache[installPath];
        else require.cache[installPath] = originalCacheEntry;
      }
    });
  });

  describe('synchronous scan results assign process.exitCode synchronously (main-parity)', () => {
    it('a sync scan() result (supply-chain/env path shape) sets process.exitCode BEFORE run() returns, and run() returns a promise', () => {
      // Pre-Phase-7, the sync paths (env-scan, --supply-chain) assigned
      // the exit code synchronously. A blanket Promise.resolve().then()
      // wrapper deferred that by a microtask tick — a behavior change for
      // programmatic callers of the exported run() that read
      // process.exitCode right after it returns. Stub lib/scan.js in the
      // require cache (same technique as the IN-01 test) with a scan()
      // returning a plain sync object and assert NO await is needed.
      const Module = require('module');
      const scanPath = require.resolve('../lib/scan.js');
      const originalCacheEntry = require.cache[scanPath];
      const stub = new Module(scanPath);
      stub.filename = scanPath;
      stub.loaded = true;
      stub.exports = { scan: () => ({ ran: true, code: 1 }) };
      require.cache[scanPath] = stub;

      const originalExitCode = process.exitCode;
      try {
        process.exitCode = 0;
        const returned = run(['scan', '--supply-chain']);
        // No await, no setImmediate — the assignment must already be done.
        assert.strictEqual(process.exitCode, 1, 'a synchronous scan result must set process.exitCode synchronously');
        assert.ok(returned && typeof returned.then === 'function', 'run() must return a promise embedders/tests can await');
      } finally {
        process.exitCode = originalExitCode;
        if (originalCacheEntry === undefined) delete require.cache[scanPath];
        else require.cache[scanPath] = originalCacheEntry;
      }
    });
  });

  describe('IN-04: --agent value parsing', () => {
    function captureStderr(fn) {
      const original = console.error;
      const lines = [];
      console.error = (msg) => { lines.push(String(msg)); };
      try {
        return { result: fn(), lines };
      } finally {
        console.error = original;
      }
    }

    it('--agent --json warns, leaves agent unset, and still parses --json', () => {
      const { result, lines } = captureStderr(() => parseArgs(['--agent', '--json']));
      assert.strictEqual(result.flags.agent, undefined);
      assert.strictEqual(result.flags.json, true, 'the following flag must not be consumed as the --agent value');
      assert.ok(lines.some(l => l.includes('--agent requires a value')));
    });

    it('a trailing valueless --agent warns instead of being silently dropped', () => {
      const { result, lines } = captureStderr(() => parseArgs(['audit', '--agent']));
      assert.strictEqual(result.flags.agent, undefined);
      assert.ok(lines.some(l => l.includes('--agent requires a value')));
    });
  });

  describe('run() audit exit-code propagation', () => {
    it('sets process.exitCode from the async audit() result (human path)', async () => {
      // Phase 8: audit() is async (D-04/D-05) and returns { code } instead
      // of calling process.exit(). This invokes real agent detection/env
      // scan/MCP scan against the actual machine (no injected opts channel
      // reaches run() at the CLI boundary) — only a numeric exit code is
      // asserted here.
      const originalExitCode = process.exitCode;
      const originalLog = console.log;
      console.log = () => {}; // suppress the real human-readable report
      try {
        run(['audit']);
        // buildEnvelope()'s awaited detector loop (runAll()) chains several
        // microtask ticks even when every detector resolves synchronously —
        // a single `await Promise.resolve()` under-drains it (same gotcha
        // as the scan --mcp propagation test above).
        await new Promise(setImmediate);
        assert.ok(
          [0, 1, 2].includes(process.exitCode),
          `audit exit code must be a contract value (0=Level 2+/1=Level<2/2=MCP scan incomplete), got ${process.exitCode}`
        );
      } finally {
        console.log = originalLog;
        process.exitCode = originalExitCode; // never pollute the real test-runner exit code
      }
    });

    it('sets process.exitCode from the async audit() result (--json path)', async () => {
      const originalExitCode = process.exitCode;
      const originalLog = console.log;
      console.log = () => {}; // suppress the real --json envelope output
      try {
        run(['audit', '--json']);
        await new Promise(setImmediate);
        assert.ok(
          [0, 1, 2].includes(process.exitCode),
          `audit --json exit code must be a contract value (0/1, or 2 when the MCP scan can't complete), got ${process.exitCode}`
        );
      } finally {
        console.log = originalLog;
        process.exitCode = originalExitCode;
      }
    });
  });

  describe('D-03: a buildEnvelope() throw is contained, never crashes audit', () => {
    it('run(["audit"]) with a rejecting buildEnvelope() renders the scorecard and exits 2 (incomplete-scan contract), never crashes', async () => {
      // audit() wraps its buildEnvelope() call in try/catch and treats a
      // throw as an incomplete MCP scan (computeSecurityLevel's incomplete
      // ceiling caps the level at <=2, and auditExitCode() fails closed to
      // audit's own DELIBERATE exit 2) — it must never let the throw
      // escape into an uncaught rejection. Both paths land on exit 2 here,
      // so the containment proof is stubCalled + the full render + no
      // rejection, not the exit code alone.
      //
      // WR-01 (review fix): the previous version of this test was VACUOUS.
      // lib/audit.js captures buildEnvelope in a top-level destructured
      // require, and audit.js was already in the require cache (loaded by
      // the propagation tests above) — replacing scan-mcp.js's cache entry
      // afterwards never reached audit.js's already-bound reference, so
      // the real buildEnvelope ran against the real machine and the stub
      // never executed. Fix: (1) evict lib/audit.js from the cache BEFORE
      // stubbing, so cli.js's lazy require('./audit.js') at run() time
      // loads audit.js fresh and binds the stub; (2) track stubCalled and
      // assert it, so a silent no-run can never pass; (3) pre-set an
      // out-of-range sentinel (42, outside {0,1,2}) so the assertion fails
      // loudly if the promise chain never runs; (4) stub detectAll with a
      // found agent, because on an agent-less machine (CI) the human path
      // early-returns BEFORE ever calling buildEnvelope — the containment
      // under test would otherwise silently not be exercised.
      const Module = require('module');
      function installStub(resolvedPath, exports) {
        const stub = new Module(resolvedPath);
        stub.filename = resolvedPath;
        stub.loaded = true;
        stub.exports = exports;
        require.cache[resolvedPath] = stub;
      }

      const scanMcpPath = require.resolve('../lib/scan-mcp.js');
      const agentsPath = require.resolve('../lib/agents/index.js');
      const auditPath = require.resolve('../lib/audit.js');
      const originalScanMcpEntry = require.cache[scanMcpPath];
      const originalAgentsEntry = require.cache[agentsPath];
      const originalAuditEntry = require.cache[auditPath];

      // Force audit.js to rebind the stubbed scan-mcp/agents on its next load.
      delete require.cache[auditPath];

      let stubCalled = false;
      installStub(scanMcpPath, {
        buildEnvelope: () => {
          stubCalled = true;
          return Promise.reject(new Error('hostile config engineered to crash discovery'));
        },
        scanMcp: () => Promise.reject(new Error('unused by audit — present for shape parity')),
        findingsExitCode: () => 0,
      });
      installStub(agentsPath, {
        detectAll: () => [{
          id: 'fake-agent', name: 'Fake Agent', tier: 1,
          detected: { found: true, version: '1.0.0' },
          audit: () => ({ checks: [], level: 3 }),
        }],
        getByIds: () => [],
      });

      const originalExitCode = process.exitCode;
      const originalLog = console.log;
      console.log = () => {};
      try {
        process.exitCode = 42; // sentinel outside {0,1,2} — a non-run fails loudly
        run(['audit']);
        await new Promise(setImmediate);
        assert.strictEqual(stubCalled, true, 'the rejecting buildEnvelope stub must actually execute — otherwise this test proves nothing (WR-01)');
        assert.strictEqual(
          process.exitCode, 2,
          `a contained buildEnvelope throw is an incomplete MCP scan — audit must deliberately exit 2 (never 0/1, never the 42 sentinel), got ${process.exitCode}`
        );
      } finally {
        console.log = originalLog;
        process.exitCode = originalExitCode;
        if (originalScanMcpEntry === undefined) delete require.cache[scanMcpPath];
        else require.cache[scanMcpPath] = originalScanMcpEntry;
        if (originalAgentsEntry === undefined) delete require.cache[agentsPath];
        else require.cache[agentsPath] = originalAgentsEntry;
        // The freshly-loaded audit.js is bound to the stubs — it must not
        // leak into later tests. Restore the pre-test entry (or evict).
        if (originalAuditEntry === undefined) delete require.cache[auditPath];
        else require.cache[auditPath] = originalAuditEntry;
      }
    });
  });
});
