'use strict';

// D-18 exit-precedence truth table (TRAV-04, T-17-04, T-17-04-03). Every
// row is asserted explicitly with a severity histogram -- see
// scripts/scan-chaindrop-aug2026.sh:72-78 for the ground truth this
// reproduces: fail() increments FINDINGS, warn()/info()/pass() do not, and
// the script exits 1 iff FINDINGS > 0. Exit 2 exists specifically for
// "looked clean but did not finish" -- the single most dangerous outcome
// this phase exists to prevent (a partial scan reported as clean).
//
// Non-vacuity (Q-02): two mutations were applied once during development
// and confirmed to break at least two tests each below, then reverted:
//   1. Returning EXIT.INCOMPLETE whenever `incomplete` is true, even when
//      fail > 0 -- breaks the "fail + incomplete => FINDINGS" row.
//   2. Counting `warn` toward EXIT.FINDINGS -- breaks the warn-only
//      "=> CLEAN" rows below, which pin the four real corpus cases
//      (variant-small, setup-bare, bun-staging, vscode-task-info) that
//      exit 0 today and must keep exiting 0.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { EXIT, computeExit } = require('../../lib/traverse/index.js');

describe('computeExit -- D-18 truth table', () => {
  it('no findings, complete => CLEAN (0)', () => {
    const exit = computeExit({ severityCounts: { fail: 0, warn: 0, info: 0 }, incomplete: false });
    assert.equal(exit, EXIT.CLEAN);
  });

  it('warn-only + info-only, complete => CLEAN (0) -- pins variant-small, setup-bare, bun-staging, vscode-task-info', () => {
    const exit = computeExit({ severityCounts: { fail: 0, warn: 4, info: 2 }, incomplete: false });
    assert.equal(exit, EXIT.CLEAN);
  });

  it('warn-only, incomplete => INCOMPLETE (2) -- the dangerous "looked clean but did not finish" case', () => {
    const exit = computeExit({ severityCounts: { fail: 0, warn: 4 }, incomplete: true });
    assert.equal(exit, EXIT.INCOMPLETE);
  });

  it('fail findings, complete => FINDINGS (1)', () => {
    const exit = computeExit({ severityCounts: { fail: 3, warn: 0 }, incomplete: false });
    assert.equal(exit, EXIT.FINDINGS);
  });

  it('fail findings, incomplete => FINDINGS (1) -- fail beats incomplete (D-18 precedence)', () => {
    const exit = computeExit({ severityCounts: { fail: 3, warn: 9 }, incomplete: true });
    assert.equal(exit, EXIT.FINDINGS);
  });

  it('missing severityCounts keys read as 0', () => {
    const exit = computeExit({ severityCounts: {}, incomplete: false });
    assert.equal(exit, EXIT.CLEAN);
  });
});

describe('computeExit -- the legacy severity-blind shape is refused', () => {
  it('throws a TypeError when called with a findingCount property', () => {
    assert.throws(() => computeExit({ findingCount: 3 }), TypeError);
  });

  it('throws a TypeError when called without severityCounts', () => {
    assert.throws(() => computeExit({ incomplete: false }), TypeError);
  });

  it('throws a TypeError when called with no argument at all', () => {
    assert.throws(() => computeExit(), TypeError);
  });
});

describe('computeExit -- EXIT enum matches the project 0/1/2 convention and is frozen', () => {
  it('EXIT.CLEAN=0, EXIT.FINDINGS=1, EXIT.INCOMPLETE=2, frozen', () => {
    assert.equal(EXIT.CLEAN, 0);
    assert.equal(EXIT.FINDINGS, 1);
    assert.equal(EXIT.INCOMPLETE, 2);
    assert.ok(Object.isFrozen(EXIT));
  });
});
