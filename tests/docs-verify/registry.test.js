'use strict';

// Registry completeness meta-test for docs:verify (G-1570, 21-05).
//
// This file is the SOLE OWNER of the exactly-seven registry assertion for
// the whole phase. Wave-2 plans (21-01..21-04) assert membership only —
// exactly-seven is true only once all three of them have landed, so
// putting the total in a Wave-2 plan would make it a race on merge order.
// See tests/docs-verify/{anchors,links,commands,count-claims,slug}.test.js
// for the membership-only precedent this file supersedes with a total.
//
// Assertion order is deliberate: non-vacuity guard FIRST (an empty
// registry must not silently pass an exactly-seven count check by never
// entering a loop), then the load-error gate, then the count gate, then
// the exact-set gate, then the per-check fixture/test-file loop. Without
// that ordering a registry that loaded nothing would iterate nothing and
// pass every subsequent assertion vacuously.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { loadChecks } = require('../../lib/docs-verify/index.js');

const TESTS_DIR = __dirname;
const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'docs-verify');

// The pinned expected id set (ROADMAP Phase 21 criterion 2 — a check with
// no planted-defect test does not count as shipped). Sorted for a stable
// deep-equality comparison against the loaded, sorted registry.
const EXPECTED_IDS = ['anchors', 'commands', 'count-claims', 'identifiers', 'links', 'mcp-rule-ids', 'version'];

describe('docs:verify registry completeness (G-1570, 21-05)', () => {
  it('non-vacuity: loadChecks() returns a non-empty check set before any per-check loop runs', () => {
    const { checks } = loadChecks();
    assert.ok(
      Array.isArray(checks) && checks.length > 0,
      'the loaded check set must be non-empty -- an empty registry would otherwise let every ' +
        'downstream per-check assertion iterate nothing and pass vacuously'
    );
  });

  it('no load errors: loadChecks().errors is empty', () => {
    const { errors } = loadChecks();
    assert.deepEqual(
      errors,
      [],
      'a check module that failed to require() would otherwise be silently absent from a set ' +
        `this test then declares complete: ${JSON.stringify(errors)}`
    );
  });

  it('exactly seven checks are registered (count gate)', () => {
    // Deliberately written as a plain length comparison, not folded into
    // the exact-set deep-equality test below -- this is the literal
    // count assertion the phase's own acceptance criteria scan for, and
    // the ONLY place in tests/docs-verify/ that may contain it.
    const { checks } = loadChecks();
    if (checks.length !== 7) {
      throw new Error(
        `loadChecks() must return exactly 7 checks, got ${checks.length}: ` +
          `[${checks.map((c) => c.id).join(', ')}]`
      );
    }
  });

  it('the registered id set matches the expected set exactly (deep equality on sorted arrays, not a subset check)', () => {
    // A subset check would silently accept a check that shipped without a
    // fixture corpus, which is exactly what criterion 2 forbids -- and it
    // would equally silently accept an UNEXPECTED extra check. Both a
    // missing check and an unexpected extra one must fail this assertion.
    const { checks } = loadChecks();
    const ids = checks.map((c) => c.id).slice().sort();
    const want = EXPECTED_IDS.slice().sort();
    assert.deepEqual(
      ids,
      want,
      `registry set mismatch: got [${ids.join(', ')}], expected [${want.join(', ')}]`
    );
  });

  it('every registered check module exports a non-empty string id and a function run (shape gate, asserted not assumed)', () => {
    const { checks } = loadChecks();
    const failures = [];
    for (const check of checks) {
      if (typeof check.id !== 'string' || check.id === '') {
        failures.push(`check has a non-string or empty id: ${JSON.stringify(check.id)}`);
      }
      if (typeof check.run !== 'function') {
        failures.push(`check '${check.id}' does not export a function run`);
      }
    }
    assert.deepEqual(failures, [], failures.join('; '));
  });

  it('every loaded check has a matching test file AND a populated clean+defect fixture corpus (collected report naming every failure at once, not fail-fast)', () => {
    const { checks } = loadChecks();
    assert.ok(checks.length > 0, 'non-vacuity: cannot loop over an empty check set');

    const failures = [];
    for (const check of checks) {
      const testFile = path.join(TESTS_DIR, `${check.id}.test.js`);
      if (!fs.existsSync(testFile)) {
        failures.push(`missing test file for check '${check.id}': tests/docs-verify/${check.id}.test.js`);
      }

      for (const kind of ['clean', 'defect']) {
        const dir = path.join(FIXTURES_DIR, check.id, kind);
        if (!fs.existsSync(dir)) {
          failures.push(`missing fixture dir for check '${check.id}': tests/fixtures/docs-verify/${check.id}/${kind}`);
          continue;
        }
        // An empty directory would otherwise satisfy an existence-only check.
        if (fs.readdirSync(dir).length === 0) {
          failures.push(`empty fixture dir for check '${check.id}': tests/fixtures/docs-verify/${check.id}/${kind}`);
        }
      }
    }

    assert.deepEqual(
      failures,
      [],
      `${failures.length} check(s) missing a test file or a populated planted-defect fixture corpus (all reported together, ` +
        `not one at a time -- a per-check report would cost a full CI round-trip per check):\n${failures.join('\n')}`
    );
  });
});
