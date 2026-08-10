'use strict';

// ============================================================================
// DETECTION-PARITY ORACLE (Q-01, Phase 17 / TRAV-05, plan 17-05)
//
// THIS FILE IS THE PHASE'S DETECTION ORACLE. Plan 17-14 replaces
// scripts/scan-chaindrop-aug2026.sh's eight `find` passes with one
// traversal-engine invocation and MUST keep this file green WITHOUT editing
// any `expect` value in tests/helpers/chaindrop-corpus.js AND WITHOUT
// changing FROZEN_FINGERPRINT below (computed from
// computeExpectationFingerprint(), see tests/helpers/chaindrop-corpus.js —
// TRAV-13/G-1505/D-04). If a detection behaviour genuinely has to change,
// that is a product decision requiring explicit human sign-off recorded in
// the 17-14 plan summary — not a test edit.
//
// 2026-08-07 REVISION: this file previously carried a
// KNOWN_TIERING_TRADEOFFS[0] describe block for the ONE pre-approved
// exception (the D-13 gitignore bulk-tier trade-off). Vitalik's review
// rejected that trade-off as a real regression, not an acceptable one (see
// the "widen the targeted marker-config class" fix in
// lib/traverse/classify.js), so KNOWN_TIERING_TRADEOFFS is now gone
// entirely and its one case (id: marker-gitignored-source) is an ORDINARY
// frozen CASES entry below, like every other. There is no longer any
// exception to this file's own "must pass with zero expect-value edits"
// rule.
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
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { newHome, runScanner, hasBash, write } = require('./helpers/chaindrop-fixtures.js');
const { CASES, buildCase, computeExpectationFingerprint, canonicalCase } = require('./helpers/chaindrop-corpus.js');
const { hasGit } = require('./helpers/git-fixture.js');

const REPO_ROOT = path.join(__dirname, '..');
const SPEC_RELATIVE = 'manifests/waves/chaindrop-aug2026.json';

// This constant must be updated in the SAME commit as any expect-value edit
// in tests/helpers/chaindrop-corpus.js OR any change to what a case's
// `build`/`tmpSeed` writes to disk. It is a review aid, not a security
// control: a determined executor can update both, but an accidental or
// unreviewed expectation/fixture drift cannot silently pass a diff.
//
// Updated 2026-08-10 (TRAV-13/G-1505/D-07, plan 17.1-02, Task 2 Part B/C):
// added six independent `fn-marker-<name>` cases (one per
// REVIEWED_FILE_MARKER_NAMES entry) and pinned a positive `[INFO]` line
// assertion on `vscode-task-info` (previously absence-only, and vacuous —
// see that case's `note`). CASES count: 40 -> 46. This file's total test
// count (both describe blocks: the CASES-driven detection-parity loop plus
// its 2 suite-level tests, plus the 4 Q-03 false-positive guards) went
// 45 -> 52 across this plan's two fingerprint-moving commits (Task 1's +1
// non-vacuity guard, Task 2's +6 marker cases).
//
// Updated 2026-08-10 (TRAV-13/G-1505/D-04, plan 17.1-02): the fingerprint
// now covers the BUILT FIXTURE TREE (computeExpectationFingerprint(),
// tests/helpers/chaindrop-corpus.js), not just the five canonicalCase()
// expectation fields — an earlier `String(c.build)` approach was rejected
// because it is blind to closure-captured module constants (27 of 40 cases
// close over one). This value therefore moved even though no `expect` field
// in the corpus changed. Depends on `hasGit` (tests/helpers/git-fixture.js):
// the `marker-gitignored-source` case's on-disk tree depends on the `git`
// binary being present, so both this test and the non-vacuity guard below
// are skipped when git is unavailable.
//
// Updated again 2026-08-10 (G-1512/D-02b, follow-on to plan 17.1-01 Task 3
// and its D-02a correction) in the SAME commit as tests/helpers/
// chaindrop-corpus.js's `marker-oversized` case change: D-02b (17.1-CONTEXT.md,
// FINAL, operator-approved) retires BOTH the blanket D-02 form and the
// D-02a candidate-scoping correction -- `oversized` is now classified a
// SCOPE reason and no longer folds into `incomplete` under any rule, so a
// marker string past the bulk-content size cap reverts to exit 0 (its
// pre-17.1-01 value), not 2. findingCount stays 0 -- the evidence found is
// unchanged; only whether the scan's own honest disclosure of a routine
// size boundary also flips the exit code changed (it no longer does). See
// 17.1-01-SUMMARY.md's "D-02b" section for the full account, including why
// G-1512's underlying premise was disproved by test.
//
// Previously updated 2026-08-10 in the SAME commit as tests/helpers/
// chaindrop-corpus.js's `marker-oversized` case change: G-1512/TRAV-15
// (17.1-CONTEXT.md decision D-02, operator-approved) folded
// `skips.counts().oversized > 0` into `incomplete`, so a marker string past
// the bulk-content size cap exited 2 (INCOMPLETE) instead of 0 (ALL CLEAR)
// for a time. See 17.1-01-SUMMARY.md for the original human sign-off
// record (17.1-CONTEXT.md D-01/D-02) -- now superseded by D-02b above.
const FROZEN_FINGERPRINT = '53693506d8087064ca4eb51f613cc98de163b96de1f46e6a8ddc463127caa628';

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

    it(
      'computeExpectationFingerprint() matches the frozen constant (tamper-evidence check)',
      { skip: !hasGit ? 'git unavailable — marker-gitignored-source\'s on-disk tree depends on it' : false },
      () => {
        assert.equal(
          computeExpectationFingerprint(),
          FROZEN_FINGERPRINT,
          'tests/helpers/chaindrop-corpus.js expectations OR fixtures changed without updating FROZEN_FINGERPRINT in this file — if this is an intentional detection-behaviour change, it needs explicit human sign-off, not just a constant edit'
        );
      }
    );

    // ------------------------------------------------------------------
    // Non-vacuity guard (TRAV-13 / G-1505 / D-04): proves the fingerprint
    // actually sees a fixture edit driven by a CLOSED-OVER CONSTANT, not
    // just a `build` function BODY edit. This is the exact defect (B8) the
    // rejected `String(c.build)` fix could not detect: 27 of 40 corpus
    // cases close over ALL_CAPS module constants, and `Function.prototype.
    // toString()` returns source text, not closure values.
    //
    // This guard does NOT mutate the real corpus. It recomputes a
    // fingerprint locally over a shallow copy of CASES in which exactly one
    // case's `build` is replaced by a wrapper that calls the ORIGINAL build
    // and then overwrites the same file with DIFFERENT content — exactly
    // what editing a closed-over constant (e.g. SAFE_KEYV) would produce on
    // disk, without touching chaindrop-corpus.js at all. It uses the same
    // sha256/JSON.stringify(map(...)) shape as computeExpectationFingerprint,
    // built from the exported `canonicalCase` plus a locally rebuilt fixture
    // digest (hashTree/fixtureDigest are module-private in chaindrop-corpus.js
    // by design — this file's own small reimplementation is deliberate, not
    // an oversight).
    // ------------------------------------------------------------------
    it(
      'non-vacuity: mutating a case fixture via a closed-over-constant-shaped edit changes the fingerprint; an unmutated recomputation matches (TRAV-13 / D-04 guard)',
      { skip: !hasGit ? 'git unavailable — marker-gitignored-source\'s on-disk tree depends on it' : false },
      () => {
        function hashTreeLocal(dir) {
          const hash = crypto.createHash('sha256');
          function walk(current) {
            const entries = fs
              .readdirSync(current, { withFileTypes: true })
              .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
            for (const entry of entries) {
              if (entry.name === '.git') continue;
              const abs = path.join(current, entry.name);
              const rel = path.relative(dir, abs).split(path.sep).join('/');
              if (entry.isSymbolicLink()) {
                hash.update(`l\0${rel}\0${fs.readlinkSync(abs)}\0`);
              } else if (entry.isDirectory()) {
                hash.update(`d\0${rel}\0`);
                walk(abs);
              } else {
                const fileHash = crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
                hash.update(`f\0${rel}\0${fileHash}\0`);
              }
            }
          }
          walk(dir);
          return hash.digest('hex');
        }

        function fixtureDigestLocal(c) {
          const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-fp-nonvacuity-'));
          let tmpDir;
          try {
            const p = (rel) => path.join(homeDir, rel);
            c.build(homeDir, p);
            const homeDigest = hashTreeLocal(homeDir);
            if (c.tmpSeed) {
              tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-fp-nonvacuity-'));
              c.tmpSeed(tmpDir);
              return `${homeDigest}:${hashTreeLocal(tmpDir)}`;
            }
            return homeDigest;
          } finally {
            fs.rmSync(homeDir, { recursive: true, force: true });
            if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
          }
        }

        function recompute(caseList) {
          return crypto
            .createHash('sha256')
            .update(JSON.stringify(caseList.map((c) => ({ ...canonicalCase(c), fixture: fixtureDigestLocal(c) }))))
            .digest('hex');
        }

        const unmutatedRecomputation = recompute(CASES);
        assert.equal(
          unmutatedRecomputation,
          computeExpectationFingerprint(),
          'a faithful local recomputation over the real, unmutated CASES must match computeExpectationFingerprint() exactly — if it does not, this guard\'s own recomputation is broken, not the fingerprint under test'
        );

        const targetId = 'installed-safe';
        const target = CASES.find((c) => c.id === targetId);
        assert.ok(target, `fixture case '${targetId}' must exist for this guard to mean anything`);

        const mutatedCases = CASES.map((c) => {
          if (c.id !== targetId) return c;
          return {
            ...c,
            build: (h, p) => {
              // Call the REAL build first (so every OTHER file it writes is
              // untouched), then overwrite the one file whose content is
              // driven by the closed-over SAFE_KEYV constant with a
              // different version string — the exact on-disk effect an edit
              // to `const SAFE_KEYV = ...;` in chaindrop-corpus.js would
              // have, without editing that constant or this case's `build`
              // BODY (source text) at all.
              c.build(h, p);
              write(p('Projects/g/node_modules/keyv/package.json'), JSON.stringify({ name: 'keyv', version: '999.999.999' }));
            },
          };
        });

        const mutatedRecomputation = recompute(mutatedCases);
        assert.notEqual(
          mutatedRecomputation,
          computeExpectationFingerprint(),
          `TRAV-13 / D-04 guard: mutating what case '${targetId}' writes to disk (a closed-over-constant-shaped edit) must change the fingerprint — if it does not, the fingerprint is blind to fixture content and has regressed to the rejected String(c.build) design`
        );
      }
    );

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

// The "ChainDrop tiering trade-off" describe block that used to live here
// (asserting KNOWN_TIERING_TRADEOFFS[0]'s newExpect) is REMOVED: Vitalik's
// review rejected that trade-off, lib/traverse/classify.js's
// isMarkerConfigMember was widened to close the gap, and the one case that
// exercised it (id: marker-gitignored-source) is now an ordinary CASES
// entry, covered by the main detection-parity loop above like every other
// case — there is no longer a separate exception to assert.

// ============================================================================
// False-positive / self-root guards (Q-03) — must stay green across the
// retrofit exactly like the detection-parity cases above.
// ============================================================================
describe('ChainDrop false-positive guards (Q-03) — stay clean across the retrofit', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

  it('self-root: scanning this repo (LSH_ROOTS=repo root) is ALL CLEAR, and cannot pass vacuously (the wave spec must actually exist)', () => {
    // Non-vacuity guard: this case must not pass because the repo happens not
    // to contain the IOC data yet — assert the spec file exists FIRST.
    assert.ok(
      fs.existsSync(path.join(REPO_ROOT, SPEC_RELATIVE)),
      `${SPEC_RELATIVE} must exist for this self-root case to be a meaningful proof — it is this repo's own bundled IOC data`
    );
    const home = newHome(built, () => {});
    const r = runScanner(home, { LSH_ROOTS: REPO_ROOT });
    assert.equal(r.status, 0, `scanner flagged its own detection data:\n${r.stdout}`);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
  });

  it('clean tree at scale: 600 files across 30 directories terminates and stays ALL CLEAR', () => {
    const home = newHome(built, (h, p) => {
      for (let i = 0; i < 600; i++) fs.mkdirSync(path.dirname(p(`Projects/big/pkg${i % 30}/file${i}.js`)), { recursive: true });
      for (let i = 0; i < 600; i++) fs.writeFileSync(p(`Projects/big/pkg${i % 30}/file${i}.js`), `// file ${i}\n`);
    });
    const r = runScanner(home);
    assert.notEqual(r.status, null, 'scanner timed out / was killed — traversal is not bounded');
    assert.equal(r.status, 0, r.stdout);
  });

  it('idempotency: the same corpus case run twice returns the same status AND the same findingCount', () => {
    const fnExact = CASES.find((c) => c.id === 'fn-exact');
    const home = newHome(built, (h) => buildCase(h, fnExact));
    const a = runScanner(home);
    const b = runScanner(home);
    assert.equal(a.status, b.status, 'status must be idempotent on an unchanged tree');
    assert.equal(findingCountOf(a.stdout), findingCountOf(b.stdout), 'findingCount must be idempotent on an unchanged tree');
  });

  it('LSH_ROOTS is honoured: an IOC inside an explicit LSH_ROOTS entry is found; the same IOC outside both HOME defaults and LSH_ROOTS is not', () => {
    const codeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-root-'));
    built.push(codeDir);
    fs.mkdirSync(path.join(codeDir, 'app', 'node_modules', 'keyv'), { recursive: true });
    fs.writeFileSync(path.join(codeDir, 'app', 'node_modules', 'keyv', 'math_init.js'), '//\n');

    const homeIn = newHome(built, () => {});
    const rIn = runScanner(homeIn, { LSH_ROOTS: codeDir });
    assert.equal(rIn.status, 1, `IOC inside LSH_ROOTS must be found\n${rIn.stdout}`);
    assert.match(rIn.stdout, /math_init\.js/);

    // The same fixture directory, scanned WITHOUT LSH_ROOTS pointing at it and
    // WITHOUT it being under any HOME-default root, must NOT be found — proves
    // the negative (out-of-scope roots are truly not walked), not just that
    // LSH_ROOTS exists.
    const homeOut = newHome(built, () => {});
    const rOut = runScanner(homeOut); // no LSH_ROOTS override; codeDir is outside HOME entirely
    assert.equal(rOut.status, 0, `IOC outside both HOME defaults and LSH_ROOTS must not be found\n${rOut.stdout}`);
  });
});
