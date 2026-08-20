'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { computeExpectedTier } = require('../../lib/agents/base.js');

function make(installsEnforcedHooks, writesIgnoreFile, ignoreFileHonored) {
  return { installsEnforcedHooks, writesIgnoreFile, ignoreFileHonored };
}

describe('computeExpectedTier() — the codified Solid-vs-Advise predicate (G-1661)', () => {
  describe('coherent states', () => {
    it('hooks only -> 1', () => {
      assert.equal(computeExpectedTier(make(true, false, null)), 1);
    });

    it('hooks plus an honored ignore file -> 1 (hook installation dominates)', () => {
      // This is the discriminating case for the branch-order break-proof: with
      // ONLY the mis-tiered/well-tiered fixtures (neither declares both
      // capabilities), swapping branch 1 and branch 2 in the implementation
      // would be invisible. This case is what makes that swap detectable.
      assert.equal(computeExpectedTier(make(true, true, true)), 1);
    });

    it('hooks plus an inert ignore file -> 1 (hook installation still dominates)', () => {
      assert.equal(computeExpectedTier(make(true, true, false)), 1);
    });

    it('honored ignore file only -> 2', () => {
      assert.equal(computeExpectedTier(make(false, true, true)), 2);
    });

    it('inert ignore file (writes but not honored) -> 3, never 2', () => {
      assert.equal(computeExpectedTier(make(false, true, false)), 3);
    });

    it('no persistent artifact -> 3', () => {
      assert.equal(computeExpectedTier(make(false, false, null)), 3);
    });
  });

  describe('presence — a missing field throws, never defaults', () => {
    const REQUIRED = ['installsEnforcedHooks', 'writesIgnoreFile', 'ignoreFileHonored'];
    const complete = { installsEnforcedHooks: false, writesIgnoreFile: true, ignoreFileHonored: true };

    for (const field of REQUIRED) {
      it(`omitting "${field}" throws a TypeError naming it`, () => {
        const input = { ...complete };
        delete input[field];
        assert.throws(
          () => computeExpectedTier(input),
          (err) => err instanceof TypeError && err.message.includes(field)
        );
      });
    }
  });

  describe('type — a wrong-type field throws', () => {
    it('installsEnforcedHooks not a boolean throws', () => {
      assert.throws(
        () => computeExpectedTier({ installsEnforcedHooks: 'yes', writesIgnoreFile: false, ignoreFileHonored: null }),
        TypeError
      );
    });

    it('writesIgnoreFile not a boolean throws', () => {
      assert.throws(
        () => computeExpectedTier({ installsEnforcedHooks: false, writesIgnoreFile: 1, ignoreFileHonored: null }),
        TypeError
      );
    });

    it('ignoreFileHonored neither boolean nor null throws', () => {
      assert.throws(
        () => computeExpectedTier({ installsEnforcedHooks: false, writesIgnoreFile: true, ignoreFileHonored: 'true' }),
        TypeError
      );
    });

    it('ignoreFileHonored truthy-non-boolean never reaches the tier-2 branch (strict === true, not truthy)', () => {
      assert.throws(
        () => computeExpectedTier({ installsEnforcedHooks: false, writesIgnoreFile: true, ignoreFileHonored: 1 }),
        TypeError
      );
    });
  });

  describe('relational coherence — contradictions throw, never resolve to a tier', () => {
    it('Contradiction A: writesIgnoreFile false, ignoreFileHonored true — throws naming both fields, not 3', () => {
      assert.throws(
        () => computeExpectedTier(make(false, false, true)),
        (err) => err instanceof TypeError
          && err.message.includes('writesIgnoreFile')
          && err.message.includes('ignoreFileHonored')
      );
    });

    it('Contradiction B: writesIgnoreFile false, ignoreFileHonored false — throws', () => {
      assert.throws(
        () => computeExpectedTier(make(false, false, false)),
        (err) => err instanceof TypeError
          && err.message.includes('writesIgnoreFile')
          && err.message.includes('ignoreFileHonored')
      );
    });

    it('Contradiction C: writesIgnoreFile true, ignoreFileHonored null — throws', () => {
      assert.throws(
        () => computeExpectedTier(make(false, true, null)),
        (err) => err instanceof TypeError
          && err.message.includes('writesIgnoreFile')
          && err.message.includes('ignoreFileHonored')
      );
    });
  });

  describe('exhaustive partition — all 12 type-valid combinations of the three fields', () => {
    it('splits into exactly 6 coherent tiers and 6 contradictory throws (both counts asserted)', () => {
      const bools = [true, false];
      const honoredValues = [true, false, null];
      let tiers = 0;
      let threw = 0;

      // Non-vacuity guard: this loop must actually iterate 12 times.
      let iterations = 0;

      for (const h of bools) {
        for (const w of bools) {
          for (const o of honoredValues) {
            iterations++;
            const coherent = (w === false && o === null) || (w === true && o !== null);
            let result;
            let error = null;
            try {
              result = computeExpectedTier(make(h, w, o));
            } catch (err) {
              error = err;
            }
            if (coherent) {
              assert.equal(
                error,
                null,
                `expected a tier for ${JSON.stringify([h, w, o])}, got a throw: ${error && error.message}`
              );
              assert.ok(
                Number.isInteger(result) && [1, 2, 3].includes(result),
                `out-of-contract return ${result} for ${JSON.stringify([h, w, o])}`
              );
              tiers++;
            } else {
              assert.ok(
                error instanceof TypeError,
                `expected a TypeError for contradictory input ${JSON.stringify([h, w, o])}, got ${result}`
              );
              threw++;
            }
          }
        }
      }

      assert.equal(iterations, 12, 'non-vacuity guard: the partition loop must actually run over all 12 combinations');
      assert.equal(tiers, 6, 'expected exactly 6 coherent states to resolve to a tier (throw-for-everything must fail this)');
      assert.equal(threw, 6, 'expected exactly 6 contradictory states to throw (throw-for-nothing must fail this)');
    });
  });

  describe('return type', () => {
    it('every coherent input returns an integer that is one of 1, 2, 3', () => {
      const cases = [
        make(true, false, null),
        make(true, true, true),
        make(true, true, false),
        make(false, true, true),
        make(false, true, false),
        make(false, false, null),
      ];
      for (const c of cases) {
        const r = computeExpectedTier(c);
        assert.ok(Number.isInteger(r), `expected an integer, got ${typeof r} (${r})`);
        assert.ok([1, 2, 3].includes(r), `expected 1, 2 or 3, got ${r}`);
      }
    });
  });

  describe('fixture break-proof — mis-tiered vs well-tiered twin', () => {
    it('the mis-tiered fixture does NOT match its stated tier', () => {
      const fixture = require('../fixtures/agents/mis-tiered-agent.js');
      assert.notEqual(computeExpectedTier(fixture), fixture.tier);
    });

    it('the well-tiered control fixture DOES match its stated tier (proves the guard distinguishes, not just rejects)', () => {
      const fixture = require('../fixtures/agents/well-tiered-agent.js');
      assert.equal(computeExpectedTier(fixture), fixture.tier);
    });

    it('neither fixture leaked into the production registry directory', () => {
      for (const f of ['mis-tiered-agent.js', 'well-tiered-agent.js']) {
        const shipped = path.join(__dirname, '..', '..', 'lib', 'agents', f);
        assert.equal(fs.existsSync(shipped), false, `fixture ${f} leaked into lib/agents/`);
      }
    });
  });
});
