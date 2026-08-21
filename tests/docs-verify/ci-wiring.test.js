'use strict';

// CI-wiring assertions for the docs:verify step (G-1570, 21-05, D-06, G-1670).
//
// Every assertion here is scoped to the docs:verify step's OWN block --
// never a file-global pattern over the whole workflow. The first draft of
// this suite (Phase 21) asserted the non-blocking setting, the date, and
// the ticket ID as three independent regexes over the entire file; that is
// decorative, because ANY step anywhere in ci.yml carrying the
// non-blocking setting would satisfy it, even if the docs:verify step
// itself were blocking. assertDocsVerifyStep() below is a pure function
// over workflow text that extracts the docs:verify step's own line-range
// block (and its immediately-preceding comment block) and asserts
// entirely within those slices. It is exported so the plan's own
// acceptance criteria call the exact same function this suite calls,
// rather than re-deriving a weaker check.
//
// G-1670 INVERSION: Phase 21 shipped this step non-blocking
// (`continue-on-error: true`) with a dated TODO naming this ticket as the
// follow-up. Phase 22 made `npm run docs:verify` exit 0 against the
// repository, so this ticket flips the assertion: the step must now be
// REJECTED when it carries the non-blocking key, and ACCEPTED when it does
// not. The step-scoping property this suite exists to prove survives the
// inversion -- it is still a must-pass case, just with its expected
// outcome flipped, because a file-global `continue-on-error` scan would
// have been wrong in BOTH directions (Phase 21: could pass on an
// unrelated step's key; Phase 22: could fail on an unrelated step's key).
//
// Well-formedness as a serialisation format is NOT asserted anywhere in
// this file. Node has no YAML parser in its standard library and this
// package has zero runtime dependencies, so any such assertion here would
// either be a lie or a substring heuristic dressed up as parsing. If the
// workflow edit breaks the file, GitHub Actions fails to load it and
// every job disappears -- louder than anything this test could assert.
// That delegation is deliberate, not an oversight.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const WORKFLOW_PATH = path.join(__dirname, '..', '..', '.github', 'workflows', 'ci.yml');

function getIndent(line) {
  const m = line.match(/^(\s*)/);
  return m ? m[1].length : 0;
}

function isStepDashLine(line) {
  return /^\s*-\s/.test(line);
}

/**
 * Pure function over workflow text. Returns { ok, reason }.
 *
 * 1. Non-vacuity: the text is non-empty and contains the three
 *    pre-existing job keys. A gutted file must fail, not pass by
 *    absence.
 * 2. Locates the step invoking the docs:verify npm script by finding the
 *    line that runs it, then walking upward to that step's own leading
 *    dash (a list item at a fixed indent under a job's `steps:` key).
 * 3. Slices the step block FORWARD from that leading dash to the next
 *    line at the SAME indent beginning with a dash, or the next line at
 *    a SHALLOWER indent, whichever comes first.
 * 4. G-1670: asserts the non-blocking setting does NOT appear inside that
 *    slice -- the guard's own step must be blocking. A step-scoped
 *    negative, never a file-global one: a DIFFERENT step carrying
 *    `continue-on-error: true` does not fail this check.
 * 5. Asserts the step's own `name:` is inside the slice, no longer states
 *    the old "expected to report findings" intent, and reads as a gate.
 * 6. Slices the comment block BACKWARD from the step's leading dash to
 *    the nearest preceding non-comment line, and asserts the date the
 *    step became blocking and a ticket identifier are both inside THAT
 *    slice (not the file at large).
 */
function assertDocsVerifyStep(yamlText) {
  if (typeof yamlText !== 'string' || yamlText.trim() === '') {
    return { ok: false, reason: 'workflow text is empty' };
  }

  const REQUIRED_JOB_KEYS = ['test:', 'test-node18:', 'test-macos:'];
  for (const key of REQUIRED_JOB_KEYS) {
    if (!yamlText.includes(key)) {
      return { ok: false, reason: `workflow text is missing expected job key '${key}'` };
    }
  }

  const lines = yamlText.split('\n');

  const invokeIdx = lines.findIndex((l) => /run:\s*npm run docs:verify\b/.test(l));
  if (invokeIdx === -1) {
    return { ok: false, reason: 'no step invokes `npm run docs:verify`' };
  }

  let stepStart = -1;
  let stepIndent = -1;
  for (let i = invokeIdx; i >= 0; i -= 1) {
    if (isStepDashLine(lines[i])) {
      stepStart = i;
      stepIndent = getIndent(lines[i]);
      break;
    }
  }
  if (stepStart === -1) {
    return { ok: false, reason: 'could not locate the leading dash of the docs:verify step' };
  }

  let stepEnd = lines.length;
  for (let i = stepStart + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '') continue;
    const indent = getIndent(line);
    if (indent < stepIndent) {
      stepEnd = i;
      break;
    }
    if (indent === stepIndent && isStepDashLine(line)) {
      stepEnd = i;
      break;
    }
  }
  const stepBlock = lines.slice(stepStart, stepEnd).join('\n');

  // G-1670: inverted. The guard's OWN step must be blocking -- a
  // step-scoped positive assertion that the non-blocking key is ABSENT
  // from this slice. A different step carrying the key never reaches
  // this branch, because stepBlock is sliced to the docs:verify step
  // alone (see step 3 above) -- that is the whole reason this function
  // exists instead of a file-global regex.
  if (/continue-on-error:\s*true/.test(stepBlock)) {
    return {
      ok: false,
      reason: 'docs:verify step block still carries continue-on-error: true -- it must be a blocking gate',
    };
  }

  const nameMatch = stepBlock.match(/-?\s*name:\s*(.+)$/m);
  if (!nameMatch) {
    return { ok: false, reason: 'docs:verify step block has no name: key' };
  }
  if (/expected to report findings/i.test(nameMatch[1])) {
    return {
      ok: false,
      reason: 'docs:verify step name still states the old non-blocking expected-findings intent',
    };
  }
  if (!/blocking/i.test(nameMatch[1])) {
    return {
      ok: false,
      reason: 'docs:verify step name does not read as a blocking gate',
    };
  }

  let commentStart = stepStart;
  for (let i = stepStart - 1; i >= 0; i -= 1) {
    if (/^\s*#/.test(lines[i])) {
      commentStart = i;
    } else {
      break;
    }
  }
  const commentBlock = lines.slice(commentStart, stepStart).join('\n');

  if (!/2026-08-22/.test(commentBlock)) {
    return { ok: false, reason: 'no dated (2026-08-22) comment block precedes the docs:verify step' };
  }
  if (!/\bG-\d{3,}\b/.test(commentBlock)) {
    return { ok: false, reason: 'no Linear ticket id found in the comment block preceding the docs:verify step' };
  }

  return { ok: true, reason: null };
}

// --- Control A (must PASS): a DIFFERENT step is non-blocking; the -------
// docs:verify step itself is blocking, correctly named, and correctly
// commented. Under a file-global regex for `continue-on-error: true`,
// this fixture would have FAILED Phase 21's non-blocking assertion and
// would also be wrongly rejected under a naive file-global inversion here
// (some OTHER step still legitimately carries the key) -- that is the
// whole point of the case, in both directions. The step-scoped assertion
// must PASS this fixture.
const CONTROL_A_DIFFERENT_STEP_NON_BLOCKING = `name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      - run: npm run test:coverage
      # 2026-08-22 (G-1670): the doc-drift guard became a blocking CI gate
      # once Phase 22 landed and docs:verify reached zero findings on main.
      - name: Doc-drift guard (npm run docs:verify) -- blocking
        run: npm run docs:verify
      - run: npm run something-unrelated
        continue-on-error: true

  test-node18:
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  test-macos:
    runs-on: macos-latest
    steps:
      - run: npm test
`;

// --- Control (must FAIL): the guard's OWN step still carries the --------
// non-blocking key. This is the new must-fail control the inversion
// requires -- the case a file-global assertion could get right by
// accident but a step-scoped one must get right by construction.
const CONTROL_OWN_STEP_STILL_NON_BLOCKING = `name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      - run: npm run test:coverage
      # 2026-08-22 (G-1670): the doc-drift guard became a blocking CI gate
      # once Phase 22 landed and docs:verify reached zero findings on main.
      - name: Doc-drift guard (npm run docs:verify) -- blocking
        run: npm run docs:verify
        continue-on-error: true

  test-node18:
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  test-macos:
    runs-on: macos-latest
    steps:
      - run: npm test
`;

// --- Control B (must FAIL): the dated ticket-bearing comment sits above
// a DIFFERENT step. The docs:verify step itself is correctly blocking
// (no continue-on-error) and correctly named, but has no comment of its
// own immediately above it -- so it still fails, for a different reason
// than the still-non-blocking control above.
const CONTROL_B_MISPLACED_COMMENT = `name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      # 2026-08-22 (G-1670): this comment describes a DIFFERENT step, not
      # the one immediately below it.
      - run: npm run test:coverage
      - name: Doc-drift guard (npm run docs:verify) -- blocking
        run: npm run docs:verify

  test-node18:
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  test-macos:
    runs-on: macos-latest
    steps:
      - run: npm test
`;

describe('assertDocsVerifyStep(yamlText) -- step-scoped CI-wiring assertions (G-1570, 21-05, D-06, G-1670)', () => {
  it('is a non-vacuity gate: rejects empty text', () => {
    const r = assertDocsVerifyStep('');
    assert.equal(r.ok, false);
  });

  it('is a non-vacuity gate: rejects text missing a pre-existing job key', () => {
    const r = assertDocsVerifyStep('name: CI\njobs:\n  test:\n    steps: []\n');
    assert.equal(r.ok, false);
    assert.match(r.reason, /missing expected job key/);
  });

  describe('Control A (must PASS): a different step is non-blocking, docs:verify is blocking', () => {
    it('assertDocsVerifyStep returns ok: true', () => {
      const r = assertDocsVerifyStep(CONTROL_A_DIFFERENT_STEP_NON_BLOCKING);
      assert.equal(
        r.ok,
        true,
        `a file-global continue-on-error scan would have rejected this fixture -- the step-scoped assertion must not: ${r.reason}`,
      );
    });
  });

  describe('Control (must FAIL): the guard\'s own step still carries continue-on-error', () => {
    it('assertDocsVerifyStep returns ok: false', () => {
      const r = assertDocsVerifyStep(CONTROL_OWN_STEP_STILL_NON_BLOCKING);
      assert.equal(r.ok, false);
      assert.match(r.reason, /continue-on-error/);
    });
  });

  describe('Control B (must FAIL): the dated ticket comment precedes a different step', () => {
    it('assertDocsVerifyStep returns ok: false', () => {
      const r = assertDocsVerifyStep(CONTROL_B_MISPLACED_COMMENT);
      assert.equal(r.ok, false, 'a file-global date/ticket regex would have passed this fixture -- the step-scoped assertion must not');
      assert.match(r.reason, /comment block precedes the docs:verify step/);
    });
  });

  it('the two must-fail controls fail for DIFFERENT reasons (a function returning ok:false for everything cannot satisfy both)', () => {
    const stillNonBlocking = assertDocsVerifyStep(CONTROL_OWN_STEP_STILL_NON_BLOCKING);
    const misplacedComment = assertDocsVerifyStep(CONTROL_B_MISPLACED_COMMENT);
    assert.equal(stillNonBlocking.ok, false);
    assert.equal(misplacedComment.ok, false);
    assert.notEqual(
      stillNonBlocking.reason,
      misplacedComment.reason,
      `both controls failed with the identical reason '${stillNonBlocking.reason}' -- the function is not distinguishing the two defects`,
    );
  });

  describe('Control C (must PASS): the real workflow after the G-1670 edit', () => {
    it('assertDocsVerifyStep returns ok: true against the real .github/workflows/ci.yml', () => {
      const real = fs.readFileSync(WORKFLOW_PATH, 'utf8');
      const r = assertDocsVerifyStep(real);
      assert.equal(r.ok, true, `real workflow failed the step-scoped assertion: ${r.reason}`);
    });

    it('the real workflow still contains all three pre-existing job keys (no unrelated job removed)', () => {
      const real = fs.readFileSync(WORKFLOW_PATH, 'utf8');
      for (const job of ['test:', 'test-node18:', 'test-macos:']) {
        assert.ok(real.includes(job), `pre-existing job removed: ${job}`);
      }
    });
  });

  it('non-vacuity: assertDocsVerifyStep is actually exported (a file asserting nothing would still "pass")', () => {
    assert.equal(typeof assertDocsVerifyStep, 'function');
  });
});

// Well-formedness as a YAML serialisation format is intentionally never
// asserted in this file -- Node has no such parser built in and this
// package has zero runtime dependencies. Well-formedness is delegated to
// the CI run itself, which fails to load a malformed workflow far more
// loudly than any built-ins-only heuristic here ever could.

module.exports = { assertDocsVerifyStep };
