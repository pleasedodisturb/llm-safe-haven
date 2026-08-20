'use strict';

// Tests for lib/docs-verify/index.js's exit-code contract (G-1570).
//
// Precedence 2 > 1 > 0: an incomplete sweep is never masked as clean OR
// as an ordinary findings run -- this gate is wired non-blocking in CI,
// so reporting "1 findings" for an incomplete sweep would hide the
// incompleteness entirely.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { runAll, tallySeverities, computeExit, formatReport, EXIT } = require('../../lib/docs-verify/index.js');

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
