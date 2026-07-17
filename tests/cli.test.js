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
      console.log = () => {}; // suppress the real --json envelope output
      try {
        run(['scan', '--mcp', '--json', '--quiet']);
        // Let lib/cli.js's Promise.resolve(result).then(...) chain run —
        // buildEnvelope()'s awaited detector loop (runAll()) chains
        // several microtask ticks even when every detector resolves
        // synchronously, so a single `await Promise.resolve()` is not
        // enough. setImmediate() only fires after ALL pending microtasks
        // (including ones enqueued while draining the queue) are drained.
        await new Promise(setImmediate);
        assert.strictEqual(typeof process.exitCode, 'number');
      } finally {
        console.log = originalLog;
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
      try {
        process.exitCode = 0;
        run(['scan']);
        await new Promise(setImmediate);
        assert.strictEqual(process.exitCode, 2, 'an escaped rejection must fail closed to 2, never stay 0');
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
});
