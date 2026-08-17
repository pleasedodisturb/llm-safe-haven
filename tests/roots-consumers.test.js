'use strict';

// G-1621 (EXIT-04, D-20-05, D-20-13) — the "we swept every getRoots()
// consumer" claim was wrong once already in this repo (19-REVIEW.md CR-01,
// the g747 case: a construct fixed in three places and missed in a fourth is
// worse than not fixing it, because it creates a false sense that the class
// is closed). This file checks that claim by DISCOVERY, not by a
// hand-maintained list: it walks lib/ at test-run time, finds every file
// that calls getRoots(, and asserts each one also wires the onNoDefaultRoots
// seam. A third consumer added later without wiring the seam fails this
// test until it is fixed — the mechanism is the point, not the current
// two-member answer.
//
// Implemented entirely in Node with fs, never by shelling out to grep: the
// session `grep` is a `ugrep -I` shim that silently skips NUL-bearing files
// and exits 1 — indistinguishable from "no match" — and has already
// produced one false PASS in this project (see
// ~/.claude/docs/reference_grep_nul_silent_skip equivalent memory note).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const LIB_DIR = path.join(__dirname, '..', 'lib');

/** Strips block and line comments the same way run-cli.test.js's own
 * stripComments() does, so a comment mentioning `getRoots(` or
 * `onNoDefaultRoots` (this very file's module header, or a doc comment in
 * lib/roots.js itself) can never be mistaken for a real call/reference. */
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

/** Recursively collects every `.js` file under `dir`, returning absolute
 * paths. No node_modules/.git pruning is needed today — lib/ has neither —
 * but directories are walked generically rather than assuming a flat
 * layout, since lib/traverse/ is already a subdirectory. */
function listJsFilesRecursive(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listJsFilesRecursive(full));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      out.push(full);
    }
  }
  return out;
}

/** Discovers the getRoots() consumer set: every .js file under lib/, other
 * than lib/roots.js itself, whose comment-stripped source contains a
 * `getRoots(` call. Returns paths relative to lib/, forward-slash
 * normalized, sorted — so the assertion below is platform-independent and
 * deterministic regardless of directory-walk order. */
function discoverGetRootsConsumers() {
  const rootsFile = path.join(LIB_DIR, 'roots.js');
  const consumers = [];
  for (const file of listJsFilesRecursive(LIB_DIR)) {
    if (file === rootsFile) continue;
    const stripped = stripComments(fs.readFileSync(file, 'utf8'));
    if (/getRoots\(/.test(stripped)) {
      consumers.push(path.relative(LIB_DIR, file).split(path.sep).join('/'));
    }
  }
  return consumers.sort();
}

describe('getRoots() consumer sweep (EXIT-04, G-1621, D-20-05) — discovery-based, not a hand-maintained list', () => {
  it('non-vacuity guard: the discovery walk over lib/ finds at least one .js file and at least one getRoots() consumer', () => {
    const allJsFiles = listJsFilesRecursive(LIB_DIR);
    assert.ok(
      allJsFiles.length > 0,
      'lib/ produced zero .js files — the discovery walk itself is broken (wrong path, or ran against an empty/unreadable directory), which is a scan bug, not a clean codebase'
    );
    const consumers = discoverGetRootsConsumers();
    assert.ok(
      consumers.length > 0,
      'zero getRoots() consumers were discovered — this means the sweep itself is broken (e.g. the regex or the comment-stripping ate every match), not that nothing calls getRoots() anymore; getRoots() is this scanner\'s only root-resolution entry point'
    );
  });

  it('the discovered consumer set equals the known set — lib/scan.js and lib/traverse/run.js — so a silently-added third consumer fails here until it is deliberately wired or added', () => {
    const consumers = discoverGetRootsConsumers();
    assert.deepEqual(
      consumers,
      ['scan.js', 'traverse/run.js'],
      `discovered getRoots() consumers changed from the known set. If a NEW file now calls getRoots(, it must wire onNoDefaultRoots (see lib/scan.js's own wiring) and be added to this list deliberately — do not silence this failure by widening the assertion without also verifying the seam.`
    );
  });

  it('every discovered consumer references onNoDefaultRoots in its own (comment-stripped) source', () => {
    const consumers = discoverGetRootsConsumers();
    assert.ok(consumers.length > 0, 'the non-vacuity guard above must already have caught an empty set — this assertion would otherwise vacuously pass over nothing');
    for (const relPath of consumers) {
      const absPath = path.join(LIB_DIR, relPath);
      const stripped = stripComments(fs.readFileSync(absPath, 'utf8'));
      assert.match(
        stripped,
        /onNoDefaultRoots/,
        `${relPath} calls getRoots( but its source never references onNoDefaultRoots — this consumer is not wired to the zero-default-root seam (D-20-05), and would silently report clean after resolving zero roots (the EXIT-04 defect class)`
      );
    }
  });
});

// ---------------------------------------------------------------------------
// PIN (sweep finding, out of scope by D-20-01): a non-empty LSH_ROOTS whose
// segments are ALL empty separators (':', ':::') parses to zero candidates
// via parseRootsEnv()'s empty-segment filter, so the getRoots() loop never
// runs at all — it fires neither onMissingRoot (nothing to iterate) nor
// onNoDefaultRoots (explicit mode never fires that seam, by design: an
// operator who set LSH_ROOTS keeps the existing per-entry signal instead).
// The result is the SAME false-clean shape this whole plan closes, but in
// EXPLICIT mode, which D-20-01 locks as unchanged for this phase. This is
// documented here as CURRENT, not endorsed, behaviour — not silently
// deferred (per this project's "never defer ticket creation" rule): the
// residual is filed as TICKET: (Task 3 fills in the real Linear ID here).
describe('getRoots() — explicit LSH_ROOTS zero-candidates pin (G-1621 sweep finding, out of scope by D-20-01)', () => {
  it('PIN: a non-empty LSH_ROOTS of only separators (":::" ) resolves to zero roots, firing neither onMissingRoot nor onNoDefaultRoots — TICKET: (filled by Task 3)', () => {
    const { getRoots } = require('../lib/roots.js');
    let missingFired = 0;
    let unreadableFired = 0;
    let noDefaultFired = 0;

    const result = getRoots({
      env: { LSH_ROOTS: ':::' },
      onMissingRoot: () => { missingFired += 1; },
      onUnreadableRoot: () => { unreadableFired += 1; },
      onNoDefaultRoots: () => { noDefaultFired += 1; },
    });

    assert.deepEqual(result, [], 'a colon-only LSH_ROOTS must still resolve to zero roots today (documenting current behaviour, not asserting it is correct)');
    assert.equal(missingFired, 0, 'no candidates survive parseRootsEnv()\'s empty-segment filter, so onMissingRoot has nothing to fire on');
    assert.equal(unreadableFired, 0);
    assert.equal(noDefaultFired, 0, 'onNoDefaultRoots is gated on !explicit — an explicitly-set LSH_ROOTS never fires it, even when it resolves to zero roots');
  });

  it('PAIRED CONTROL: a single-colon LSH_ROOTS (":") is the same shape — one empty segment, zero candidates, same silent-zero result', () => {
    const { getRoots } = require('../lib/roots.js');
    let noDefaultFired = 0;
    const result = getRoots({
      env: { LSH_ROOTS: ':' },
      onMissingRoot: () => {},
      onUnreadableRoot: () => {},
      onNoDefaultRoots: () => { noDefaultFired += 1; },
    });
    assert.deepEqual(result, []);
    assert.equal(noDefaultFired, 0);
  });
});
