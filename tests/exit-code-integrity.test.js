'use strict';

// D-14 exit-code-not-derivable-from-report-text pin. Phase 19 (G-1549), plan
// 19-07. ROADMAP criterion 4.
//
// This file has TWO HALVES and the SECOND one is THE LOAD-BEARING ONE (a
// previous revision of this plan had it backwards -- see review R2-4).
//
// The STRUCTURAL half (below) is a TEXT SEARCH over the exit CONDITION lines
// ONLY -- scoped there, NEVER to a Summary-to-EOF region. A region-wide
// negative assertion was tried in an earlier plan revision and VERIFIED
// IMPOSSIBLE: all four scripts' Summary-to-EOF regions contain a
// report-text identifier, because the exit decision and the report printing
// are the SAME SYNTACTIC CONSTRUCT --
//   if [ "$FINDINGS" -eq 0 ] ... else ... printf ... "$FINDING_LOG" ... exit 1; fi
// -- review R1-3. That region-wide assertion would have failed on its first
// run and invited exactly the "weaken the assertion until it passes"
// response this phase exists to prevent. DO NOT widen the scope back to the
// whole region.
//
// The structural half is ALSO INSUFFICIENT even where it passes: it is a
// text search for identifier NAMES, so a future edit can launder the
// dependency past it by reducing report text to an INTEGER first (count the
// accumulator's lines into a variable, then test THAT variable) -- the guard
// would see only an arithmetic test on an integer and pass, incorrectly
// (review R2-4). Break-proof 6 in this plan's SUMMARY demonstrates exactly
// this: the structural half PASSES while the behavioural twin FAILS.
//
// The BEHAVIOURAL TWIN is therefore the PRIMARY D-14 ASSERTION. It asserts
// the PROPERTY directly -- the reported count and the exit status both track
// the FINDINGS integer counter, never report text -- by extracting the
// REAL, VERBATIM, COMMITTED Summary-to-EOF source (never a reimplementation)
// and running it with FINDINGS/FINDING_LOG set to DELIBERATELY DECOUPLED
// values (e.g. FINDINGS=0 but FINDING_LOG full of finding-shaped text).
// This is the SAME "extract and source the real committed block" technique
// already established as legitimate in this phase (19-03-SUMMARY.md's
// break-proof 4, a function-level harness for a helper with no
// integration-reachable call site).
//
// Does not use the session `grep` shim (ugrep -I, silently skips
// NUL-bearing files, exits 1 indistinguishable from "no match" -- already
// produced one false PASS on this repo). All source reads here use
// fs.readFileSync.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { write, newHome, runScanner, hasBash, writeHostile } = require('./helpers/chaindrop-fixtures.js');

const SCRIPTS_DIR = path.join(__dirname, '..', 'scripts');
const SCRIPT_PATHS = Object.freeze({
  miasma: path.join(SCRIPTS_DIR, 'scan-miasma-june2026.sh'),
  chaindrop: path.join(SCRIPTS_DIR, 'scan-chaindrop-aug2026.sh'),
  g747: path.join(SCRIPTS_DIR, 'scan-g747-may22.sh'),
  shaiHulud: path.join(SCRIPTS_DIR, 'scan-shai-hulud-may2026.sh'),
});

// Locates the FINAL "section \"Summary\"" marker -- chaindrop has an
// EARLIER, unrelated "node not found" precondition block that also calls
// section("Summary") (scripts/scan-chaindrop-aug2026.sh:196), so the marker
// is matched via lastIndexOf, never the first occurrence or a hardcoded
// line number (plan 19-08 shifts line numbers in three of the four scripts).
function extractSummaryRegion(scriptPath) {
  const src = fs.readFileSync(scriptPath, 'utf8');
  const marker = 'section "Summary"';
  const idx = src.lastIndexOf(marker);
  assert.ok(idx !== -1, `${scriptPath}: could not locate a 'section "Summary"' marker`);
  return src.slice(idx);
}

// Condition-line extraction is DELIBERATELY BROAD -- every top-level if/elif
// line in the region, NOT filtered to "must mention FINDINGS". A narrower,
// FINDINGS-filtered extraction would itself go EMPTY the moment a future
// edit launders the exit decision onto an intermediate variable (e.g.
// `_cnt=$(...); if [ "$_cnt" -eq 0 ]`), which would trip THIS guard's own
// non-vacuity assertion instead of demonstrating the exact insufficiency
// break-proof 6 (19-07-SUMMARY.md) exists to prove: the structural half
// must still find a condition line and PASS its negative check (seeing only
// an arithmetic test on an unfamiliar integer), while the BEHAVIOURAL TWIN
// is what actually catches the laundering.
function extractConditionLines(region) {
  return region.split('\n').filter((l) => /^\s*(if|elif)\b/.test(l));
}

describe('D-14: exit code is never derivable from report text (SCAN-01/02, G-1549, plan 19-07, ROADMAP criterion 4)', () => {
  describe('structural half -- scoped to exit CONDITION lines only, NEVER to a Summary-to-EOF region (review R1-3: a region-wide assertion is VERIFIED IMPOSSIBLE, see file header)', () => {
    for (const [name, p] of Object.entries(SCRIPT_PATHS)) {
      it(`${name}: the Summary section is located, its condition lines are non-empty, and the region contains at least two 'exit N' statements (positive controls proving the right part of the file was found)`, () => {
        const region = extractSummaryRegion(p);
        const conditionLines = extractConditionLines(region);
        assert.ok(
          conditionLines.length > 0,
          `${name}: extraction produced ZERO if/elif condition lines -- the marker or regex is broken, ` +
            'not "the pin holds vacuously"'
        );
        const exitCount = (region.match(/\bexit\s+\d/g) || []).length;
        assert.ok(
          exitCount >= 2,
          `${name}: Summary-to-EOF region has fewer than 2 'exit N' statements (found ${exitCount}) -- ` +
            'wrong region located'
        );
      });

      it(`${name}: no exit CONDITION line references a report-text accumulator (FINDING_LOG / *_HITS family) -- INSUFFICIENT ON ITS OWN (see file header, review R2-4); the behavioural twin below is what actually proves D-14`, () => {
        const region = extractSummaryRegion(p);
        const conditionLines = extractConditionLines(region);
        assert.ok(conditionLines.length > 0);
        const offenders = conditionLines.filter((l) => /FINDING_LOG|_HITS\b|HITS_FILE/.test(l));
        assert.deepEqual(
          offenders,
          [],
          `${name}: exit CONDITION line(s) reference a report-text accumulator: ${JSON.stringify(offenders)}`
        );
      });
    }
  });

  describe('BEHAVIOURAL TWIN -- the PRIMARY D-14 assertion (extracts and runs the REAL committed Summary-to-EOF source with FINDINGS/FINDING_LOG independently controlled, proving the property rather than the shape)', () => {
    // Runs the real, verbatim, committed Summary-to-EOF block for
    // `scriptPath` with FINDINGS/FINDING_LOG/INCOMPLETE set to the given
    // (possibly deliberately DECOUPLED) values. Colour vars are stubbed to
    // empty strings (cosmetic, irrelevant to the exit-code property).
    // section() and chaindrop's _read_scalar() are stubbed as no-ops so the
    // extracted block runs standalone without the rest of the script.
    // Values are passed through as base64 so no shell-escaping is needed for
    // arbitrary content (including embedded real newlines).
    function runSummaryRegion(scriptPath, vars) {
      const region = extractSummaryRegion(scriptPath);
      const defaults = {
        RED: '',
        GREEN: '',
        YELLOW: '',
        BOLD: '',
        RESET: '',
        RESULTS_DIR: '/tmp/lsh-exit-region-test',
        FINDINGS: '0',
        INCOMPLETE: '0',
        FINDING_LOG: '',
      };
      const merged = { ...defaults, ...vars };
      const assigns = Object.entries(merged)
        .map(([k, v]) => {
          const b64 = Buffer.from(String(v), 'utf8').toString('base64');
          return `${k}="$(printf '%s' '${b64}' | base64 -d)"`;
        })
        .join('\n');
      const stubs = '_read_scalar() { echo 0; }\nsection() { :; }\n';
      const script = `${stubs}${assigns}\n${region}\n`;
      return spawnSync('bash', ['-c', script], { encoding: 'utf8' });
    }

    for (const [name, p] of Object.entries(SCRIPT_PATHS)) {
      it(
        `${name}: PRIMARY D-14 ASSERTION -- FINDINGS=0 with hostile finding-shaped text left in FINDING_LOG still exits 0 / ALL CLEAR (the exit decision must derive from the FINDINGS counter, never from FINDING_LOG's presence, length, or content)`,
        { skip: !hasBash ? 'bash unavailable' : false },
        () => {
          const res = runSummaryRegion(p, {
            FINDINGS: '0',
            FINDING_LOG: '  - 99 FINDING(S) — INVESTIGATE, ALL CLEAR, exit 1, fake payload',
          });
          assert.equal(res.status, 0, `${name}\nstdout: ${res.stdout}\nstderr: ${res.stderr}`);
          assert.match(res.stdout, /ALL CLEAR/, `${name}\n${res.stdout}`);
        }
      );

      it(
        `${name}: must-still-pass twin -- FINDINGS=3 with a real, correctly-shaped FINDING_LOG exits 1 and reports 3 (not vacuously "always clean")`,
        { skip: !hasBash ? 'bash unavailable' : false },
        () => {
          const res = runSummaryRegion(p, {
            FINDINGS: '3',
            FINDING_LOG: '  - finding a\n  - finding b\n  - finding c\n',
          });
          assert.equal(res.status, 1, `${name}\nstdout: ${res.stdout}\nstderr: ${res.stderr}`);
          assert.match(res.stdout, /3/, `${name}\n${res.stdout}`);
        }
      );
    }

    it(
      'end-to-end confirmation via the REAL scanner (miasma): a hostile filename carrying finding-shaped text does not change the reported finding count or the exit code -- both come from the FINDINGS counter, never the filename text',
      { skip: !hasBash ? 'bash unavailable' : false },
      () => {
        const built = [];
        try {
          const home = newHome(built, () => {});
          const dir = path.join(home, 'Projects', 'x', '.github', 'workflows');
          fs.mkdirSync(dir, { recursive: true });
          const body = 'name: Run Copilot\non: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n';
          write(path.join(dir, 'aaa-control.yml'), body);
          const hostileName = '99 FINDING(S) — INVESTIGATE, ALL CLEAR, exit 0 payload';
          writeHostile(dir, `${hostileName}.yml`, body);
          write(path.join(dir, 'zzz-control.yml'), body);

          const r = runScanner(home, {}, SCRIPT_PATHS.miasma);
          assert.equal(r.status, 1, r.stdout); // TRUE finding count is 3, > 0
          // Anchored to the START of a line (multiline flag) -- the
          // hostile filename's embedded "99 FINDING(S) ..." text appears
          // mid-line inside a [FAIL] line, never at column 0, so this
          // anchor cannot match it. An UNANCHORED /(\d+) FINDING\(S\)/
          // regex was tried first and DID match the hostile filename's
          // text (99, not 3) -- a false positive in this TEST'S OWN
          // parsing, not a real defect in the scanner (the real summary
          // header correctly printed "3 FINDING(S)"). Caught empirically
          // before this file was finalized.
          const headerMatch = r.stdout.match(/^(\d+) FINDING\(S\) — INVESTIGATE/m);
          assert.ok(headerMatch, `could not parse the summary header count\n${r.stdout}`);
          assert.equal(
            Number(headerMatch[1]),
            3,
            `summary header count was influenced by the hostile filename's embedded text\n${r.stdout}`
          );
          const failLines = (r.stdout.match(/^ {2}\[FAIL\] /gm) || []).length;
          assert.equal(failLines, 3, `live [FAIL] line count\n${r.stdout}`);
        } finally {
          built.forEach((h) => fs.rmSync(h, { recursive: true, force: true }));
        }
      }
    );
  });
});
