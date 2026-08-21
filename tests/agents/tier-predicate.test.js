'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { computeExpectedTier } = require('../../lib/agents/base.js');
const { loadAgents } = require('../../lib/agents/index.js');

function make(installsEnforcedHooks, writesIgnoreFile, ignoreFileHonored) {
  return { installsEnforcedHooks, writesIgnoreFile, ignoreFileHonored };
}

// Reads the operator's checkpoint-approved tier outcome (plan 21-06, disposition
// apply-all, 2026-08-20) from the TRACKED fixture
// tests/fixtures/agents/approved-tier-outcome.json. The fixture is a verbatim
// copy of the `## Approved tier outcome` JSON block in 21-06-SUMMARY.md; it
// lives under tests/ because .planning/ is gitignored and a CI clone never has
// it (reading the SUMMARY directly made npm test fail on every fresh checkout).
// This is the single source of truth for every expected tier this plan does
// NOT hardcode. A missing or unparseable fixture throws (HALTS the test run)
// rather than falling back to any anticipated outcome -- see plan 21-07's
// "Derived, not hardcoded" section and Threat T-21-07-06.
function readApprovedOutcome() {
  const fixturePath = path.join(__dirname, '..', 'fixtures', 'agents', 'approved-tier-outcome.json');
  let text;
  try {
    text = fs.readFileSync(fixturePath, 'utf8');
  } catch (err) {
    throw new Error(
      `readApprovedOutcome: could not read approved-tier-outcome.json at ${fixturePath}: ` +
      `${err && err.message} -- HALT, do not fall back to the anticipated gemini-only outcome`
    );
  }
  let outcome;
  try {
    outcome = JSON.parse(text);
  } catch (err) {
    throw new Error(`readApprovedOutcome: could not parse approved-tier-outcome.json: ${err && err.message}`);
  }
  if (!outcome || typeof outcome !== 'object') {
    throw new Error('readApprovedOutcome: approved-outcome block did not parse to an object');
  }
  if (!outcome.disposition) {
    throw new Error('readApprovedOutcome: approved-outcome block missing "disposition"');
  }
  if (!outcome.expectedTiers || typeof outcome.expectedTiers !== 'object' || Array.isArray(outcome.expectedTiers)) {
    throw new Error('readApprovedOutcome: approved-outcome block missing an "expectedTiers" object');
  }
  const tierCount = Object.keys(outcome.expectedTiers).length;
  if (tierCount !== 16) {
    throw new Error(`readApprovedOutcome: "expectedTiers" must cover 16 modules, got ${tierCount}`);
  }
  if (!Array.isArray(outcome.deltas)) {
    throw new Error('readApprovedOutcome: approved-outcome block missing a "deltas" array');
  }
  if (!Array.isArray(outcome.exemptions)) {
    throw new Error('readApprovedOutcome: approved-outcome block missing an "exemptions" array (present, possibly empty)');
  }
  return outcome;
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

describe('Registry-wide meta-test — every loaded module matches the predicate AND the approved outcome (G-1661, plan 21-07)', () => {
  const approvedOutcome = readApprovedOutcome();
  const agents = loadAgents();

  it('non-vacuity: loadAgents() returns a non-empty set of exactly 16 modules', () => {
    assert.ok(agents.length > 0, 'non-vacuity guard: loadAgents() returned zero modules');
    assert.equal(agents.length, 16, `expected 16 loaded agent modules, got ${agents.length}`);
  });

  describe('Layer 1 — shape: every module declares the three capability fields plus ignoreFileCitation', () => {
    for (const agent of agents) {
      it(`${agent.id}: declares installsEnforcedHooks, writesIgnoreFile, ignoreFileHonored, ignoreFileCitation as own properties of the correct types`, () => {
        for (const field of ['installsEnforcedHooks', 'writesIgnoreFile', 'ignoreFileHonored', 'ignoreFileCitation']) {
          assert.ok(
            Object.prototype.hasOwnProperty.call(agent, field),
            `${agent.id} is missing capability field "${field}"`
          );
        }
        assert.equal(typeof agent.installsEnforcedHooks, 'boolean', `${agent.id}.installsEnforcedHooks must be a boolean`);
        assert.equal(typeof agent.writesIgnoreFile, 'boolean', `${agent.id}.writesIgnoreFile must be a boolean`);
        assert.ok(
          agent.ignoreFileHonored === null || typeof agent.ignoreFileHonored === 'boolean',
          `${agent.id}.ignoreFileHonored must be a boolean or null`
        );
      });
    }
  });

  describe('Citation structure — every non-null ignoreFileHonored carries a structured { url, retrievedAt, claim } object, never a nearby comment', () => {
    for (const agent of agents) {
      it(`${agent.id}: ignoreFileCitation matches its ignoreFileHonored nullness`, () => {
        if (agent.ignoreFileHonored === null) {
          assert.equal(agent.ignoreFileCitation, null, `${agent.id}: a null honored value requires a null citation`);
          return;
        }
        const c = agent.ignoreFileCitation;
        assert.ok(c && typeof c === 'object', `${agent.id}: a non-null honored value requires a structured citation object`);
        assert.match(String(c.url || ''), /^https?:\/\/\S+/, `${agent.id}: citation url missing or not a URL`);
        assert.match(String(c.retrievedAt || ''), /^\d{4}-\d{2}-\d{2}$/, `${agent.id}: citation retrievedAt must be an ISO date`);
        assert.ok(String(c.claim || '').trim().length > 0, `${agent.id}: citation claim is empty`);
      });
    }

    it('non-vacuity: at least two modules carry a structured citation', () => {
      const cited = agents.filter((a) => a.ignoreFileHonored !== null);
      assert.ok(cited.length >= 2, `expected at least 2 cited modules, found ${cited.length}`);
    });
  });

  describe('Layer 2 — tier comparison: predicate agreement and approved-outcome agreement (two independent oracles)', () => {
    it('every module tier equals computeExpectedTier(module) -- all mismatches collected into one message', () => {
      const mismatches = [];
      for (const agent of agents) {
        const expected = computeExpectedTier(agent);
        if (agent.tier !== expected) {
          mismatches.push(`${agent.id}: stated tier ${agent.tier}, predicate says ${expected}`);
        }
      }
      assert.equal(mismatches.length, 0, `predicate mismatches:\n${mismatches.join('\n')}`);
    });

    it('every module tier equals the approved-outcome expectedTiers value -- all mismatches collected into one message', () => {
      const mismatches = [];
      for (const agent of agents) {
        const expected = approvedOutcome.expectedTiers[agent.id];
        if (agent.tier !== expected) {
          mismatches.push(`${agent.id}: stated tier ${agent.tier}, approved outcome says ${expected}`);
        }
      }
      assert.equal(mismatches.length, 0, `approved-outcome mismatches:\n${mismatches.join('\n')}`);
    });

    it('the approved-outcome expectedTiers module-id set matches the loaded registry exactly', () => {
      const loadedIds = agents.map((a) => a.id).slice().sort();
      const approvedIds = Object.keys(approvedOutcome.expectedTiers).slice().sort();
      assert.deepEqual(loadedIds, approvedIds, 'the approved-outcome block does not cover exactly the loaded module set');
    });
  });

  describe('D-01-fixed outcomes -- the only hardcoded tier values in this file (ROADMAP criterion 6)', () => {
    // gemini-cli and github-copilot are fixed by D-01, never derived from the approved-outcome block.
    const FIXED = { 'gemini-cli': 2, 'github-copilot': 3 };
    for (const [id, expected] of Object.entries(FIXED)) {
      it(`${id} matches its D-01-fixed outcome`, () => {
        const mod = agents.find((a) => a.id === id);
        assert.ok(mod, `${id} not found in the loaded registry`);
        assert.equal(mod.tier, expected, `${id} must match its D-01-fixed outcome`);
      });
    }
  });

  describe('Group counts derived from the approved outcome, never a literal', () => {
    it('every tier-group size in the live registry matches the size derived from expectedTiers', () => {
      const derivedCounts = { 1: 0, 2: 0, 3: 0 };
      for (const value of Object.values(approvedOutcome.expectedTiers)) {
        derivedCounts[value] = (derivedCounts[value] || 0) + 1;
      }
      const liveCounts = { 1: 0, 2: 0, 3: 0 };
      for (const agent of agents) {
        liveCounts[agent.tier] = (liveCounts[agent.tier] || 0) + 1;
      }
      assert.ok(agents.length > 0, 'non-vacuity guard: live registry must be non-empty before comparing group sizes');
      assert.deepEqual(liveCounts, derivedCounts, 'live tier-group sizes diverge from the approved outcome');
    });
  });

  describe('Ordering invariance -- the mismatch verdict does not depend on loadAgents() traversal order', () => {
    it('the mismatch id set is identical over the forward and reversed module lists', () => {
      function mismatchIds(list) {
        const ids = [];
        for (const agent of list) {
          if (agent.tier !== computeExpectedTier(agent)) ids.push(agent.id);
        }
        return ids.slice().sort();
      }
      assert.ok(agents.length > 0, 'non-vacuity guard: ordering-invariance case needs a non-empty module list');
      const forward = mismatchIds(agents);
      const reversedList = agents.slice().reverse();
      const reversed = mismatchIds(reversedList);
      assert.equal(forward.length, reversed.length, 'mismatch set size changed under module-list reversal');
      assert.deepEqual(forward, reversed, 'mismatch verdict changed under module-list reversal');
    });
  });

  describe('Fixture controls re-asserted alongside the registry-wide guard', () => {
    it('the mis-tiered fixture from plan 21-06 still fails the comparison', () => {
      const fixture = require('../fixtures/agents/mis-tiered-agent.js');
      assert.notEqual(computeExpectedTier(fixture), fixture.tier);
    });

    it('the well-tiered control fixture from plan 21-06 still passes the comparison', () => {
      const fixture = require('../fixtures/agents/well-tiered-agent.js');
      assert.equal(computeExpectedTier(fixture), fixture.tier);
    });
  });

  describe('Exemption mechanism -- exercised in every disposition, including empty (apply-all)', () => {
    it('reads and validates the approved-outcome exemptions array', () => {
      assert.ok(Array.isArray(approvedOutcome.exemptions), 'exemptions must be an array (present, possibly empty)');
      for (const exemption of approvedOutcome.exemptions) {
        assert.match(
          String((exemption && exemption.ticket) || ''),
          /^G-\d+$/,
          `exemption ${JSON.stringify(exemption)} missing a valid ticket id`
        );
        const found = agents.some((a) => a.id === (exemption && exemption.id));
        assert.ok(found, `exemption references unknown module id "${exemption && exemption.id}"`);
        // Printed for CI visibility -- an exempted module is never silently skipped.
        console.log(`  exemption on record: ${exemption.id} (${exemption.ticket})`);
      }
    });

    it('unit case: a synthetic one-entry exemption array both excludes the right module and rejects an entry with no ticket', () => {
      function applyExemptions(moduleIds, exemptions) {
        for (const ex of exemptions) {
          if (!ex.ticket || !/^G-\d+$/.test(String(ex.ticket))) {
            throw new Error(`exemption for "${ex.id}" is missing a valid ticket reference`);
          }
        }
        const exemptIds = new Set(exemptions.map((e) => e.id));
        return moduleIds.filter((id) => !exemptIds.has(id));
      }

      const syntheticIds = ['aaa', 'bbb', 'ccc'];
      const filtered = applyExemptions(syntheticIds, [{ id: 'bbb', ticket: 'G-9999' }]);
      assert.deepEqual(filtered, ['aaa', 'ccc'], 'exemption filter did not exclude the exempted module');

      assert.throws(
        () => applyExemptions(syntheticIds, [{ id: 'bbb' }]),
        /missing a valid ticket reference/,
        'exemption filter accepted an entry with no ticket'
      );
    });
  });
});
