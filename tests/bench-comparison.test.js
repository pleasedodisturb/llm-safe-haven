'use strict';

// Unit tests for the provenance gate in scripts/bench-traverse.js's
// buildComparison() (G-1546, TOOL-02, plan 18-01).
//
// Why this file exists at all: `scripts/**` is excluded from the coverage
// denominator (package.json:42) and absent from the test glob (package.json:41),
// so nothing under scripts/ has ever had a path to a unit test. buildComparison
// is the one piece of real logic in that file — a pure function of a JSON file
// path plus two plain objects — and the repo's standing rule is that every piece
// of code has unit tests. Requiring the script is safe only because the same
// commit added a `require.main === module` guard; before that, requiring it ran
// a full benchmark and then called process.exit(0) on the test process.
//
// Every "must refuse" case below is paired with a "must still work" control, so
// a gate that simply refuses everything cannot pass this file.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildComparison, SCANNER_RETROFIT_ISO } = require('../scripts/bench-traverse.js');

// Fixture idiom copied from tests/traverse/read-pool.test.js:17-23 — collect
// every temp dir and remove them all in a single after() hook.
const dirs = [];
function mkFixtureDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-comparison-'));
  dirs.push(dir);
  return dir;
}
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function writeBaseline(baseline) {
  const file = path.join(mkFixtureDir(), 'baseline.json');
  fs.writeFileSync(file, JSON.stringify(baseline));
  return file;
}

// logErr() writes through process.stderr.write, NOT console.error
// (scripts/bench-traverse.js:76-78 — read before writing this helper). Silence
// that exact channel for the duration of a case and always restore it.
function quiet(fn) {
  const original = process.stderr.write;
  process.stderr.write = () => true;
  try {
    return fn();
  } finally {
    process.stderr.write = original;
  }
}

// A refusal must not leak half a comparison: the printer would happily render
// whichever numeric keys survived.
const RATIO_KEYS = ['speedupRatio', 'oldScannerWallClockMs', 'newScannerWallClockMs', 'budgetFired'];
function assertNoRatioKeys(result) {
  for (const key of RATIO_KEYS) {
    assert.ok(!(key in result), `a refusal must carry no "${key}" — half a comparison is still a fabricated number`);
  }
}

const OLD_MS = 2000;
const NEW_MS = 500;
const ENGINE_SCANNER = { wallClockMs: NEW_MS };
const ENGINE_RUN = { incomplete: false, tiers: null };

describe('bench-traverse buildComparison: baseline provenance gate (G-1546)', () => {
  it('refuses a baseline that declares itself engine-backed', () => {
    const file = writeBaseline({
      meta: { mode: 'baseline', scannerEngineBacked: true, timestamp: '2026-08-01T12:00:00Z' },
      oldScanner: { wallClockMs: OLD_MS },
    });

    const result = quiet(() => buildComparison(file, ENGINE_SCANNER, ENGINE_RUN));

    assert.equal(result.error, 'baseline-post-retrofit');
    assertNoRatioKeys(result);
  });

  it('refuses a baseline dated on or after the retrofit boundary', () => {
    const file = writeBaseline({
      meta: { mode: 'baseline', timestamp: '2026-08-10T12:00:00Z' },
      oldScanner: { wallClockMs: OLD_MS },
    });

    const result = quiet(() => buildComparison(file, ENGINE_SCANNER, ENGINE_RUN));

    assert.equal(result.error, 'baseline-post-retrofit');
    assertNoRatioKeys(result);
  });

  it('refuses an undatable baseline (no scannerEngineBacked key, no timestamp)', () => {
    const file = writeBaseline({
      meta: { mode: 'baseline' },
      oldScanner: { wallClockMs: OLD_MS },
    });

    const result = quiet(() => buildComparison(file, ENGINE_SCANNER, ENGINE_RUN));

    assert.equal(
      result.error,
      'baseline-post-retrofit',
      'failing CLOSED on an undatable baseline is deliberate: an artifact that cannot be placed ' +
        'relative to the 2026-08-07 retrofit cannot be shown to measure a pre-engine scanner, and ' +
        'a speedup nobody can date is exactly the unreproducible claim TOOL-02 exists to stop'
    );
    assertNoRatioKeys(result);
  });

  // ---- paired controls: the refusal must be SCOPED, not blanket -----------

  it('CONTROL: accepts a baseline whose timestamp predates the retrofit and reports a real ratio', () => {
    const file = writeBaseline({
      meta: { mode: 'baseline', timestamp: '2026-08-01T12:00:00Z' },
      oldScanner: { wallClockMs: OLD_MS },
    });

    const result = quiet(() => buildComparison(file, ENGINE_SCANNER, ENGINE_RUN));

    assert.equal(result.error, undefined);
    assert.equal(result.provenance, 'pre-retrofit-timestamp');
    assert.equal(typeof result.speedupRatio, 'number');
    // Real arithmetic, not assert.ok(ratio): 2000 / 500 === 4.
    assert.equal(result.speedupRatio, OLD_MS / NEW_MS);
    assert.equal(result.oldScannerWallClockMs, OLD_MS);
    assert.equal(result.newScannerWallClockMs, NEW_MS);
    assert.ok(
      Date.parse('2026-08-01T12:00:00Z') < Date.parse(SCANNER_RETROFIT_ISO),
      'this fixture is only a valid control while its timestamp really is before the retrofit constant'
    );
  });

  it('CONTROL: accepts a baseline that explicitly declares scannerEngineBacked: false', () => {
    const file = writeBaseline({
      // No timestamp at all — the explicit declaration must win over the
      // undatable fail-closed path, which is what makes it an escape hatch.
      meta: { mode: 'baseline', scannerEngineBacked: false },
      oldScanner: { wallClockMs: OLD_MS },
    });

    const result = quiet(() => buildComparison(file, ENGINE_SCANNER, ENGINE_RUN));

    assert.equal(result.error, undefined);
    assert.equal(result.provenance, 'declared-pre-retrofit');
    assert.equal(typeof result.speedupRatio, 'number');
    assert.equal(result.speedupRatio, OLD_MS / NEW_MS);
  });

  it('CONTROL: the two pre-existing error branches still fire before the provenance gate', () => {
    const missingPath = path.join(mkFixtureDir(), 'does-not-exist.json');
    const unreadable = quiet(() => buildComparison(missingPath, ENGINE_SCANNER, ENGINE_RUN));
    assert.match(unreadable.error, /^baseline-unreadable:/);

    // Engine-backed AND malformed. The shape error must win: a caller needs to
    // know the artifact is broken, not receive a provenance verdict about it.
    // This is what proves the new gate was inserted AFTER the existing guards.
    const shapeless = writeBaseline({
      meta: { mode: 'baseline', scannerEngineBacked: true },
      oldScanner: {},
    });
    const result = quiet(() => buildComparison(shapeless, ENGINE_SCANNER, ENGINE_RUN));
    assert.equal(
      result.error,
      'baseline-missing-oldScanner-wallClockMs',
      'the provenance gate must sit after the shape guards, not before them'
    );
  });
});
