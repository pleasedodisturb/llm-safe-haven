'use strict';

// ============================================================================
// DETECTION-PARITY ORACLE (Q-01, Phase 17 / TRAV-05, plan 17-05)
//
// THIS FILE IS THE PHASE'S DETECTION ORACLE. Plan 17-14 replaces
// scripts/scan-chaindrop-aug2026.sh's eight `find` passes with one
// traversal-engine invocation and MUST keep this file green WITHOUT editing
// any `expect` value in tests/helpers/chaindrop-corpus.js AND WITHOUT
// changing EXPECTATION_FINGERPRINT below. If a detection behaviour genuinely
// has to change, that is a product decision requiring explicit human
// sign-off recorded in the 17-14 plan summary — not a test edit. The single
// pre-approved exception is KNOWN_TIERING_TRADEOFFS[0] (the D-13 gitignore
// bulk-tier trade-off), asserted separately below.
// ============================================================================
//
// Every case in tests/helpers/chaindrop-corpus.js CASES was frozen by
// actually running the CURRENT, unmodified scripts/scan-chaindrop-aug2026.sh
// against the built fixture (2026-08-07) — this file asserts that captured
// behaviour, it does not re-derive it. See chaindrop-corpus.js's own header
// for the fixture-tension resolution (runtime-built, never committed) and
// the [FAIL]-anchored matchCounts rationale (the scanner's own report format
// prints every finding twice — once live, once in the summary reprint — so
// an unanchored substring count cannot distinguish "the report format" from
// "a genuinely duplicated detection").

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { newHome, runScanner, hasBash } = require('./helpers/chaindrop-fixtures.js');
const { CASES, KNOWN_TIERING_TRADEOFFS, buildCase, EXPECTATION_FINGERPRINT } = require('./helpers/chaindrop-corpus.js');

// This constant must be updated in the SAME commit as any expect-value edit
// in tests/helpers/chaindrop-corpus.js. It is a review aid, not a security
// control: a determined executor can update both, but an accidental or
// unreviewed expectation drift cannot silently pass a diff.
const FROZEN_FINGERPRINT = '7d72bdadf6a7a59a5e4fd472742ac8b3ffbf77f80725a5e9c0b5bbbaddfffa2b';

function findingCountOf(stdout) {
  const m = stdout.match(/(\d+) FINDING\(S\)/);
  return m ? parseInt(m[1], 10) : 0;
}

function countMatchingLines(stdout, patternSource) {
  const re = new RegExp(patternSource);
  return stdout.split('\n').filter((l) => re.test(l)).length;
}

const snapshot = {};
const snapshotPath = path.join(os.tmpdir(), `lsh-chaindrop-parity-snapshot-${Date.now()}.json`);

describe(
  'ChainDrop detection-parity oracle (Q-01) — frozen against the pre-refactor scanner',
  { skip: !hasBash ? 'bash unavailable' : false },
  () => {
    const built = [];
    after(() => {
      built.forEach((h) => fs.rmSync(h, { recursive: true, force: true }));
      fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));
      // eslint-disable-next-line no-console
      console.error(`[chaindrop-parity] verdict snapshot written to ${snapshotPath} (for manual before/after diffing during the plan 17-14 retrofit)`);
    });

    it('EXPECTATION_FINGERPRINT matches the frozen constant (tamper-evidence check)', () => {
      assert.equal(
        EXPECTATION_FINGERPRINT,
        FROZEN_FINGERPRINT,
        'tests/helpers/chaindrop-corpus.js expectations changed without updating FROZEN_FINGERPRINT in this file — if this is an intentional detection-behaviour change, it needs explicit human sign-off, not just a constant edit'
      );
    });

    for (const c of CASES) {
      it(`[${c.id}] ${c.ioc}`, () => {
        const home = newHome(built, (h) => buildCase(h, c));
        const runOpts = c.tmpSeed ? { tmpSeed: c.tmpSeed } : {};
        const r = runScanner(home, {}, undefined, runOpts);
        const findingCount = findingCountOf(r.stdout);

        snapshot[c.id] = {
          status: r.status,
          findingCount,
          matched: (c.expect.mustMatch || []).filter((re) => re.test(r.stdout)).map((re) => re.source),
        };

        assert.equal(r.status, c.expect.status, `[${c.id}] status mismatch\n${r.stdout}`);
        assert.equal(findingCount, c.expect.findingCount, `[${c.id}] findingCount mismatch (parsed from the %d FINDING(S) summary line)\n${r.stdout}`);

        for (const re of c.expect.mustMatch || []) {
          assert.match(r.stdout, re, `[${c.id}] expected stdout to match ${re}\n${r.stdout}`);
        }
        for (const re of c.expect.mustNotMatch || []) {
          assert.doesNotMatch(r.stdout, re, `[${c.id}] expected stdout NOT to match ${re}\n${r.stdout}`);
        }
        for (const [patternSource, expectedCount] of Object.entries(c.expect.matchCounts || {})) {
          const got = countMatchingLines(r.stdout, patternSource);
          assert.equal(
            got,
            expectedCount,
            `[${c.id}] expected EXACTLY ${expectedCount} stdout line(s) matching /${patternSource}/, got ${got} — presence-only matching cannot see a duplicated verdict, exact multiplicity can\n${r.stdout}`
          );
        }
      });
    }
  }
);

describe(
  'ChainDrop tiering trade-off (D-13/D-14) — the ONE case plan 17-14 is expected to flip',
  { skip: !hasBash ? 'bash unavailable' : false },
  () => {
    const built = [];
    after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

    for (const t of KNOWN_TIERING_TRADEOFFS) {
      it(`[${t.id}] asserts oldExpect against the CURRENT scanner (newExpect is plan 17-14's declared, human-signed-off flip, not a test edit)`, () => {
        const home = newHome(built, (h) => buildCase(h, t));
        const r = runScanner(home);
        const findingCount = findingCountOf(r.stdout);

        assert.equal(r.status, t.oldExpect.status, `[${t.id}] oldExpect.status mismatch\n${r.stdout}`);
        assert.equal(findingCount, t.oldExpect.findingCount, `[${t.id}] oldExpect.findingCount mismatch\n${r.stdout}`);
        for (const re of t.oldExpect.mustMatch || []) {
          assert.match(r.stdout, re, `[${t.id}] expected oldExpect stdout to match ${re}\n${r.stdout}`);
        }
      });
    }
  }
);
