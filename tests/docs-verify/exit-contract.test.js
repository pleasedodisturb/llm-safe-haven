'use strict';

// Tests for lib/docs-verify/index.js's exit-code contract (G-1570).
//
// Precedence 2 > 1 > 0: an incomplete sweep is never masked as clean OR
// as an ordinary findings run -- this gate is wired non-blocking in CI,
// so reporting "1 findings" for an incomplete sweep would hide the
// incompleteness entirely.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { runAll, tallySeverities, computeExit, formatReport, EXIT, isValidFinding } = require('../../lib/docs-verify/index.js');

function makeContext(overrides = {}) {
  return {
    root: process.cwd(),
    mdFiles: [{ path: 'a.md', abs: 'a.md', text: '' }],
    errors: [],
    readText: () => ({ text: '' }),
    listFiles: () => ({ files: [] }),
    pkg: { name: 'x', version: '0.0.0' },
    ...overrides,
  };
}

describe('computeExit -- 2 > 1 > 0 precedence, boundary triple', () => {
  const exitFor = (fail, incomplete) => computeExit({ severityCounts: { fail, warn: 0 }, incomplete });

  it('zero findings, zero incomplete: exit 0', () => {
    assert.equal(exitFor(0, []), EXIT.CLEAN);
  });

  it('exactly one finding, zero incomplete: exit 1', () => {
    assert.equal(exitFor(1, []), EXIT.FINDINGS);
  });

  it('exactly two findings, zero incomplete: still exit 1', () => {
    assert.equal(exitFor(2, []), EXIT.FINDINGS);
  });

  it('exactly one incomplete entry, zero findings: exit 2', () => {
    assert.equal(exitFor(0, [{ check: 'x', reason: 'y' }]), EXIT.INCOMPLETE);
  });

  it('one incomplete entry AND fifty findings: exit 2 -- incomplete outranks findings', () => {
    assert.equal(exitFor(50, [{ check: 'x', reason: 'y' }]), EXIT.INCOMPLETE);
  });

  it('EXIT enum is the canonical 0/1/2 mapping', () => {
    assert.equal(EXIT.CLEAN, 0);
    assert.equal(EXIT.FINDINGS, 1);
    assert.equal(EXIT.INCOMPLETE, 2);
  });

  it('a legacy { findingCount } shape raises TypeError, not a silent misread', () => {
    assert.throws(() => computeExit({ findingCount: 0 }), TypeError);
  });

  it('missing severityCounts raises TypeError', () => {
    assert.throws(() => computeExit({ incomplete: [] }), TypeError);
  });
});

describe('runAll -- a throwing check is contained, the sweep continues, exit 2', () => {
  it('a throwing check is recorded as incomplete AND a sibling well-behaved check still contributes its finding', () => {
    const boom = { id: 'boom', run: () => { throw new Error('kaboom'); } };
    const good = { id: 'good', run: () => [{ check: 'good', file: 'a.md', line: 1, message: 'm', severity: 'fail' }] };
    const ctx = makeContext();
    const r = runAll(ctx, [boom, good]);
    assert.ok(r.incomplete.length > 0, 'throwing check not recorded as incomplete');
    assert.equal(r.findings.length, 1, 'sweep aborted instead of continuing');
    assert.equal(computeExit({ severityCounts: tallySeverities(r.findings), incomplete: r.incomplete }), EXIT.INCOMPLETE);
  });
});

describe('runAll -- an empty registry is never a clean pass', () => {
  it("invoking runAll with an explicitly empty checks array records 'no-checks-loaded'", () => {
    const ctx = makeContext();
    const r = runAll(ctx, []);
    assert.ok(r.incomplete.some((i) => String(i.reason).includes('no-checks-loaded')));
    assert.equal(computeExit({ severityCounts: tallySeverities(r.findings), incomplete: r.incomplete }), EXIT.INCOMPLETE);
  });
});

describe("runAll -- a registry load error is never masked by the checks that DID load", () => {
  it("check-load-failed forces exit 2 even though the checks that loaded returned zero findings", () => {
    const ctx = makeContext();
    const zeroFindingCheck = { id: 'zero', run: () => [] };
    const r = runAll(ctx, [zeroFindingCheck], [{ file: 'broken.js', reason: 'require-failed' }]);
    assert.equal(r.findings.length, 0);
    assert.ok(r.incomplete.some((i) => String(i.reason).includes('check-load-failed')));
    assert.equal(computeExit({ severityCounts: tallySeverities(r.findings), incomplete: r.incomplete }), EXIT.INCOMPLETE);
  });
});

describe('runAll -- a malformed check.run() return is never silently treated as zero findings', () => {
  it('undefined, a plain object, and an async (Promise-returning) run() are each recorded as incomplete, sibling still contributes', () => {
    const ctx = makeContext();
    const good = { id: 'good', run: () => [{ check: 'good', file: 'a.md', line: 1, message: 'm', severity: 'fail' }] };
    const badChecks = [
      { id: 'u', run: () => undefined },
      { id: 'o', run: () => ({}) },
      { id: 'p', run: async () => [] },
    ];
    for (const bad of badChecks) {
      const r = runAll(ctx, [bad, good]);
      assert.ok(r.incomplete.length > 0, `non-array return from ${bad.id} must be incomplete`);
      assert.equal(r.findings.length, 1, `sibling check lost its finding for ${bad.id}`);
      assert.equal(
        computeExit({ severityCounts: tallySeverities(r.findings), incomplete: r.incomplete }),
        EXIT.INCOMPLETE,
        `non-array return must exit 2 for ${bad.id}`
      );
    }
  });
});

describe('runAll -- a malformed finding RECORD (not merely a malformed return type) is never silently accepted (F2, Codex review PR #105)', () => {
  it('a finding with no severity field is recorded as incomplete, not silently accepted -- RED before F2, GREEN after', () => {
    const ctx = makeContext();
    const good = { id: 'good', run: () => [{ check: 'good', file: 'a.md', line: 1, message: 'm', severity: 'fail' }] };
    const noSeverity = { id: 'no-severity', run: () => [{ check: 'no-severity', file: 'a.md', line: 1, message: 'broken' }] };
    const r = runAll(ctx, [noSeverity, good]);
    assert.ok(
      r.incomplete.some((i) => i.check === 'no-severity' && String(i.reason).includes('check-returned-malformed-finding')),
      `severity-less finding was not recorded as incomplete: ${JSON.stringify(r.incomplete)}`
    );
    assert.equal(r.findings.length, 1, 'severity-less finding must not be counted; sibling check must still contribute its finding');
    assert.equal(
      computeExit({ severityCounts: tallySeverities(r.findings), incomplete: r.incomplete }),
      EXIT.INCOMPLETE,
      'a broken check emitting a malformed finding record must never let computeExit report clean or findings-only'
    );
  });

  it("a finding with severity: 'error' (not fail/warn) is recorded as incomplete", () => {
    const ctx = makeContext();
    const bad = { id: 'bad-severity', run: () => [{ check: 'bad-severity', file: 'a.md', line: 1, message: 'm', severity: 'error' }] };
    const r = runAll(ctx, [bad]);
    assert.ok(r.incomplete.some((i) => i.check === 'bad-severity'), `not recorded incomplete: ${JSON.stringify(r.incomplete)}`);
    assert.equal(r.findings.length, 0, "an out-of-enum severity must never be counted as a real finding");
    assert.equal(computeExit({ severityCounts: tallySeverities(r.findings), incomplete: r.incomplete }), EXIT.INCOMPLETE);
  });

  it('must-still-pass twin: a well-formed warn finding is accepted normally, exit contract unchanged', () => {
    const ctx = makeContext();
    const wellFormed = { id: 'well-formed', run: () => [{ check: 'well-formed', file: 'a.md', line: 3, message: 'ok', severity: 'warn' }] };
    const r = runAll(ctx, [wellFormed]);
    assert.deepEqual(r.incomplete, [], `a well-formed finding was wrongly flagged as malformed: ${JSON.stringify(r.incomplete)}`);
    assert.equal(r.findings.length, 1);
    assert.equal(
      computeExit({ severityCounts: tallySeverities(r.findings), incomplete: r.incomplete }),
      EXIT.CLEAN,
      'a warn-only run must still exit 0 -- Check 7 depends on this (see the tallySeverities describe block below)'
    );
  });
});

describe('isValidFinding -- exported validator, one case per grammar rule plus its paired control (F2)', () => {
  it('non-vacuity: rejects every malformed shape derived from the finding grammar, accepts the well-formed controls', () => {
    const invalidCases = [
      ['not-an-object (null)', null],
      ['not-an-object (array)', []],
      ['missing-severity', { check: 'c', file: 'f.md', line: 1, message: 'm' }],
      ['severity-out-of-enum', { check: 'c', file: 'f.md', line: 1, message: 'm', severity: 'error' }],
      ['empty-check', { check: '', file: 'f.md', line: 1, message: 'm', severity: 'fail' }],
      ['non-string-check', { check: 7, file: 'f.md', line: 1, message: 'm', severity: 'fail' }],
      ['missing-file', { check: 'c', line: 1, message: 'm', severity: 'fail' }],
      ['empty-file', { check: 'c', file: '', line: 1, message: 'm', severity: 'fail' }],
      ['missing-message', { check: 'c', file: 'f.md', line: 1, severity: 'fail' }],
      ['empty-message', { check: 'c', file: 'f.md', line: 1, message: '', severity: 'fail' }],
      ['negative-line', { check: 'c', file: 'f.md', line: -1, message: 'm', severity: 'fail' }],
      ['non-integer-line', { check: 'c', file: 'f.md', line: 1.5, message: 'm', severity: 'fail' }],
      ['non-numeric-line', { check: 'c', file: 'f.md', line: '1', message: 'm', severity: 'fail' }],
    ];
    assert.ok(invalidCases.length > 0, 'non-vacuity guard: the invalid-case list itself must not be empty');
    for (const [name, value] of invalidCases) {
      assert.equal(isValidFinding(value), false, `expected case "${name}" to be rejected: ${JSON.stringify(value)}`);
    }

    // Must-still-pass twins: every real check in this repo emits exactly
    // this shape (verified: all seven checks always populate `line` as a
    // number), plus the one case the grammar explicitly allows to omit it.
    assert.equal(isValidFinding({ check: 'c', file: 'f.md', line: 1, message: 'm', severity: 'fail' }), true);
    assert.equal(isValidFinding({ check: 'c', file: 'f.md', line: 0, message: 'm', severity: 'warn' }), true, 'line 0 is a valid non-negative integer');
    assert.equal(isValidFinding({ check: 'c', file: 'f.md', message: 'm', severity: 'warn' }), true, 'line is optional per the grammar');
  });
});

describe('tallySeverities -- fail and warn counted independently, only fail gates the exit', () => {
  it('empty array returns zero counts, not undefined', () => {
    const t = tallySeverities([]);
    assert.deepEqual(t, { fail: 0, warn: 0 });
  });

  it('a fail-and-warn mix counts each bucket independently', () => {
    const t = tallySeverities([{ severity: 'fail' }, { severity: 'warn' }, { severity: 'fail' }, { severity: 'warn' }]);
    assert.equal(t.fail, 2);
    assert.equal(t.warn, 2);
  });

  it('a warn-only run exits 0 through computeExit -- Check 7 depends on this', () => {
    const warnOnly = [{ severity: 'warn' }, { severity: 'warn' }];
    assert.equal(computeExit({ severityCounts: tallySeverities(warnOnly), incomplete: [] }), EXIT.CLEAN);
  });
});

describe('formatReport -- deterministic, byte-sorted by (file, line, check)', () => {
  it('the same findings supplied in shuffled order produce a byte-identical report', () => {
    const findings = [
      { check: 'b', file: 'z.md', line: 9, message: 'm1', severity: 'fail' },
      { check: 'a', file: 'a.md', line: 2, message: 'm2', severity: 'fail' },
    ];
    const one = formatReport({ findings, incomplete: [] });
    assert.ok(one.length > 0, 'empty report');
    const two = formatReport({ findings: findings.slice().reverse(), incomplete: [] });
    assert.equal(one, two, 'report ordering is not deterministic');
  });
});
