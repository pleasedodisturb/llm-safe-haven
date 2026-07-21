'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { scan, runSupplyChainScan, SUPPLY_CHAIN_SCANNER } = require('../lib/scan.js');
const { parseArgs } = require('../lib/cli.js');
const { captureLog } = require('./helpers/capture-log.js');

const REAL_SCRIPTS_DIR = path.join(__dirname, '..', 'scripts');

describe('parseArgs --supply-chain', () => {
  it('sets flags.supplyChain on the scan command', () => {
    const args = parseArgs(['scan', '--supply-chain']);
    assert.equal(args.command, 'scan');
    assert.equal(args.flags.supplyChain, true);
  });
  it('leaves supplyChain unset by default', () => {
    const args = parseArgs(['scan']);
    assert.notEqual(args.flags.supplyChain, true);
  });
});

describe('runSupplyChainScan', () => {
  it('does not spawn on Windows; returns win32 reason with non-zero code (not "clean")', async () => {
    let called = false;
    const { result: r } = await captureLog(() => runSupplyChainScan({}, {
      platform: 'win32',
      spawnSync: () => { called = true; return {}; },
    }));
    assert.equal(r.ran, false);
    assert.equal(r.reason, 'win32');
    assert.equal(r.code, 2);
    assert.equal(called, false);
  });

  it('returns missing with non-zero code when the scanner script is absent', async () => {
    let called = false;
    const { result: r } = await captureLog(() => runSupplyChainScan({}, {
      platform: 'linux',
      scriptsDir: '/no/such/dir',
      spawnSync: () => { called = true; return {}; },
    }));
    assert.equal(r.ran, false);
    assert.equal(r.reason, 'missing');
    assert.equal(r.code, 2);
    assert.equal(called, false);
  });

  it('dispatches from scan() when flags.supplyChain is set (forwards opts)', async () => {
    let called = false;
    const { result: r } = await captureLog(() => scan({ supplyChain: true }, {
      platform: 'win32',
      spawnSync: () => { called = true; return {}; },
    }));
    assert.equal(r.reason, 'win32');
    assert.equal(r.code, 2);
    assert.equal(called, false);
  });

  it('treats a signal-killed scan as incomplete (code 2), never clean', async () => {
    const { result: r } = await captureLog(() => runSupplyChainScan({}, {
      platform: 'linux',
      scriptsDir: REAL_SCRIPTS_DIR,
      spawnSync: () => ({ status: null, signal: 'SIGKILL' }),
    }));
    assert.equal(r.ran, false);
    assert.equal(r.reason, 'killed');
    assert.equal(r.code, 2);
  });

  it('spawns bash on the bundled scanner, network-free, and returns its code', async () => {
    let captured = null;
    const { result: r } = await captureLog(() => runSupplyChainScan({}, {
      platform: 'linux',
      scriptsDir: REAL_SCRIPTS_DIR,
      spawnSync: (cmd, argv, opts) => { captured = { cmd, argv, opts }; return { status: 0 }; },
    }));
    assert.equal(r.ran, true);
    assert.equal(r.code, 0);
    assert.equal(captured.cmd, 'bash');
    assert.equal(captured.argv[0], path.join(REAL_SCRIPTS_DIR, SUPPLY_CHAIN_SCANNER));
    assert.equal(captured.opts.env.LSH_NO_NETWORK, '1');
    assert.equal(captured.opts.stdio, 'inherit');
  });

  it('propagates a non-zero exit code (findings)', async () => {
    const { result: r } = await captureLog(() => runSupplyChainScan({}, {
      platform: 'linux',
      scriptsDir: REAL_SCRIPTS_DIR,
      spawnSync: () => ({ status: 1 }),
    }));
    assert.equal(r.ran, true);
    assert.equal(r.code, 1);
  });

  it('handles a spawn error (no bash) gracefully', async () => {
    const { result: r } = await captureLog(() => runSupplyChainScan({}, {
      platform: 'linux',
      scriptsDir: REAL_SCRIPTS_DIR,
      spawnSync: () => ({ error: new Error('bash not found') }),
    }));
    assert.equal(r.ran, false);
    assert.equal(r.reason, 'spawn-error');
    assert.equal(r.code, 2);
  });
});
