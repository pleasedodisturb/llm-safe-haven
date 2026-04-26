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
