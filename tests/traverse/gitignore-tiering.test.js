'use strict';

// D-13 false-negative probe (G-1482, TRAV-03, T-17-02/T-17-02-01): proves,
// against a REAL git repo, that every class fires despite .gitignore -- this
// is the security property the tiering design exists for, so it is proven
// in BOTH directions (every class fires despite being gitignored; a
// non-ignored mirror proves the test cannot pass by classifying everything
// as ignored, gitignored or not).
//
// 2026-08-07 REVISION (Vitalik review of plan 17-14): D-13's original
// design put marker-string scanning of ordinary source files (.js/.json/
// etc, i.e. the `bulk-content` class) behind gitignore, consulted through
// `lib/traverse/git-ignore.js`. The OLD bash scanner never did that
// (section 6b had no gitignore awareness at all), and that gap was ruled a
// real detection regression, not an acceptable trade-off: for a
// supply-chain scanner, deciding what NOT to read by consulting
// `.gitignore` -- a file inside the repository being scanned -- is an
// attacker-addressable blind spot. Measured cost of removing it: nothing
// (a full `$HOME` scan went from 11,040 ms to 7,862-10,714 ms after the
// removal, because `bulk-content`'s allowlist was narrow to begin with);
// worst-case protection was never this tier anyway -- the locked 60s /
// 1,000,000-file budget backstop provides that independently, and when it
// bites the scan exits 2, visibly incomplete, rather than silently
// narrowing what was read.
//
// The fix widened `marker-config` (classify.js's `isMarkerConfigMember`) to
// cover every name `spec.classes['bulk-content'].fileGlobs` lists, not
// just `.env`/`.env.*`/`.npmrc`, and `lib/traverse/git-ignore.js` -- the
// module that supplied the gitignore resolver, and its only consumer -- has
// been DELETED entirely, along with its two `lib/traverse/engine.js` call
// sites (see classify.js's module header for the full history, and
// tests/traverse/zero-git-subprocess.test.js for the committed proof that a
// real engine run spawns no git subprocess at all any more).
//
// This file is KEPT (not deleted) because the FN-probe property it proves
// -- "a marker string cannot be hidden from detection by an attacker-edited
// .gitignore" -- is still the load-bearing security property of the whole
// IOC-scanning design; it is simply stronger now (previously true for five
// of six classes, now true for all six, unconditionally, because there is
// no longer any mechanism left that could ever consult `.gitignore`).
//
// `classify()` no longer accepts an `ignore` field on `ctx` at all (it did,
// until this revision) -- there is nothing left to construct, wrap, stub,
// or count calls on here, which is why this file no longer imports
// `createIgnoreResolver` or exercises any degraded-git simulation: a
// degraded (or missing, or healthy) git binary can no longer affect
// classification in any way, because git is never consulted for it.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { classify } = require('../../lib/traverse/classify.js');
const { hasGit, initRepo } = require('../helpers/git-fixture.js');

const SPEC = require('../../manifests/waves/chaindrop-aug2026.json');

const MARKER = SPEC.markerStrings.find((s) => s === 'npm-cache.com');
const POISONED_KEYV = SPEC.poisonedVersions.keyv[0];

const dirs = [];
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function mkRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitignore-tiering-'));
  dirs.push(dir);
  return dir;
}

function classifyPath(absPath, repoRoot) {
  return classify({ absPath, dirent: null, depth: 2, repoRoot, isDirectory: false }, SPEC, { selfRoot: null, skips: { add() {} } });
}

const PLANTED = {
  'hidden/Math_Symbol.js': '/* stub stage-2 harvester */\n',
  'hidden/package.json': JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } }, null, 2),
  'hidden/package-lock.json': JSON.stringify({ name: 'x', lockfileVersion: 3, packages: { 'node_modules/keyv': { version: POISONED_KEYV } } }, null, 2),
  'hidden/.env': `SECRET=1\n# ${MARKER}\n`,
  'hidden/.npmrc': `registry=https://registry.npmjs.org/\n# ${MARKER}\n`,
  'hidden/notes.js': `// ${MARKER}\n`,
  'notes.js': `// ${MARKER}\n`, // non-ignored mirror, repo root
};

describe('gitignore-tiering — every class fires despite a gitignored directory (bulk-content is unreachable, see classify.test.js)', { skip: !hasGit ? 'git unavailable' : false }, () => {
  it('six classes classify DESPITE being under a gitignored directory', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });

    const mathResult = classifyPath(path.join(dir, 'hidden/Math_Symbol.js'), dir);
    assert.ok(mathResult.classes.includes('all-files'), 'all-files (filename marker)');
    assert.equal(mathResult.classes.includes('bulk-content'), false);

    const pkgResult = classifyPath(path.join(dir, 'hidden/package.json'), dir);
    assert.ok(pkgResult.classes.includes('no-prune'), 'no-prune (preinstall marker)');
    assert.equal(pkgResult.classes.includes('bulk-content'), false);

    const lockResult = classifyPath(path.join(dir, 'hidden/package-lock.json'), dir);
    assert.ok(lockResult.classes.includes('lockfiles'), 'lockfiles');
    assert.equal(lockResult.classes.includes('bulk-content'), false);

    const envResult = classifyPath(path.join(dir, 'hidden/.env'), dir);
    assert.ok(envResult.classes.includes('env-secrets'), 'env-secrets');
    assert.ok(envResult.classes.includes('marker-config'), 'marker-config (env)');
    assert.equal(envResult.skipReason, null);
    assert.equal(envResult.classes.includes('bulk-content'), false);

    const npmrcResult = classifyPath(path.join(dir, 'hidden/.npmrc'), dir);
    assert.ok(npmrcResult.classes.includes('marker-config'), 'marker-config (npmrc)');
    assert.equal(npmrcResult.skipReason, null);
    assert.equal(npmrcResult.classes.includes('bulk-content'), false);

    // notes.js: previously the ONE bulk-content-only case D-13 pruned under
    // a gitignored directory -- now marker-config (the widened predicate),
    // so it fires here too, matching the OLD bash scanner exactly.
    const notesResult = classifyPath(path.join(dir, 'hidden/notes.js'), dir);
    assert.ok(notesResult.classes.includes('marker-config'), 'marker-config (ordinary source file, widened tiering-fix)');
    assert.equal(notesResult.skipReason, null);
    assert.equal(notesResult.classes.includes('bulk-content'), false);
  });

  it('the non-ignored mirror (same filename + marker, OUTSIDE hidden/) ALSO classifies into marker-config (proves the test cannot pass by classifying everything the same way regardless of .gitignore)', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });

    const rootNotesResult = classifyPath(path.join(dir, 'notes.js'), dir);
    assert.ok(rootNotesResult.classes.includes('marker-config'));
    assert.equal(rootNotesResult.skipReason, null);
  });

  it('the gitignored .env appears in marker-config and env-secrets but NEVER bulk-content (no double marker-scan)', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });

    const envResult = classifyPath(path.join(dir, 'hidden/.env'), dir);
    assert.ok(envResult.classes.includes('marker-config'));
    assert.ok(envResult.classes.includes('env-secrets'));
    assert.equal(envResult.classes.includes('bulk-content'), false);
  });
});

// ---------------------------------------------------------------------------
// Non-vacuity (Q-02) -- each guard proven to actually bite by breaking it
// once during development, then restoring it.
//
//   1. Reverting `isMarkerConfigMember` to its pre-2026-08-07 scope
//      (`.env`/`.env.*`/`.npmrc` only, dropping the
//      `spec.classes['bulk-content'].fileGlobs` widening) broke the "six
//      classes classify" test's `marker-config (ordinary source file,
//      widened tiering-fix)` assertion -- `notes.js` under the gitignored
//      `hidden/` directory stopped classifying into marker-config at all,
//      reproducing exactly the regression this revision fixes.
// Applied once during development, confirmed to fail the relevant
// assertion above, and reverted.
//
// The two describe blocks this file carried before 2026-08-07 --
// "consulting isBulkEligible for a TARGETED class breaks it" and "a
// degraded git environment still classifies correctly" -- are gone, not
// rewritten: there is no `ignore` field left on `ctx` to consult, wrap, or
// degrade, so both properties are now enforced by classify()'s function
// SIGNATURE (it does not accept the parameter), not by runtime behaviour a
// test could meaningfully probe.
// ---------------------------------------------------------------------------
