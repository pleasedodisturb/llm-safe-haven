'use strict';

// D-13 false-negative probe (G-1482, TRAV-03, T-17-02/T-17-02-01): proves,
// against a REAL git repo, that every targeted-tier check fires despite
// .gitignore -- this is the security property the tiering design exists
// for, so it is proven in BOTH directions (targeted classes fire despite
// being gitignored; a non-ignored mirror proves the test cannot pass by
// classifying everything as ignored) plus a degraded-git case proving
// degradation never REDUCES detection.
//
// 2026-08-07 REVISION (Vitalik review of plan 17-14): D-13's original
// design put marker-string scanning of ordinary source files (.js/.json/
// etc, i.e. `bulk-content`) behind gitignore -- the OLD bash scanner never
// did that (section 6b had no gitignore awareness at all), and that gap
// was ruled a real detection regression, not an acceptable trade-off. The
// fix widened `marker-config` (classify.js's `isMarkerConfigMember`) to
// cover every name `spec.classes['bulk-content'].fileGlobs` lists, not
// just `.env`/`.env.*`/`.npmrc` -- which makes `bulk-content` permanently
// unreachable through `classify()` (see classify.test.js's "bulk-content
// class (now unreachable)" block) and means there is no longer a
// gitignore-consulting class left to probe here at all: EVERY class this
// engine assigns is now targeted-tier, matching the OLD bash scanner's
// total gitignore-blindness. This file is kept (not deleted) because the
// FN-probe property it proves -- "a marker string cannot be hidden from
// detection by an attacker-edited .gitignore" -- is still the load-bearing
// security property of the whole IOC-scanning design; it is simply
// stronger now (previously true for five of six classes, now true for all
// six, including the one that used to be the tiering exception).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { classify } = require('../../lib/traverse/classify.js');
const { createIgnoreResolver } = require('../../lib/traverse/git-ignore.js');
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

function ctxFor(resolver) {
  return {
    selfRoot: null,
    ignore: resolver,
    skips: { add() {} },
  };
}

function classifyPath(absPath, repoRoot, resolver) {
  return classify({ absPath, dirent: null, depth: 2, repoRoot, isDirectory: false }, SPEC, ctxFor(resolver));
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

describe('gitignore-tiering — every targeted class fires despite a gitignored directory (bulk-content is unreachable, see classify.test.js)', { skip: !hasGit ? 'git unavailable' : false }, () => {
  it('six targeted classes classify DESPITE being under a gitignored directory', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });
    const resolver = createIgnoreResolver({});

    const mathResult = classifyPath(path.join(dir, 'hidden/Math_Symbol.js'), dir, resolver);
    assert.ok(mathResult.classes.includes('all-files'), 'all-files (filename marker)');
    assert.equal(mathResult.classes.includes('bulk-content'), false);

    const pkgResult = classifyPath(path.join(dir, 'hidden/package.json'), dir, resolver);
    assert.ok(pkgResult.classes.includes('no-prune'), 'no-prune (preinstall marker)');
    assert.equal(pkgResult.classes.includes('bulk-content'), false);

    const lockResult = classifyPath(path.join(dir, 'hidden/package-lock.json'), dir, resolver);
    assert.ok(lockResult.classes.includes('lockfiles'), 'lockfiles');
    assert.equal(lockResult.classes.includes('bulk-content'), false);

    const envResult = classifyPath(path.join(dir, 'hidden/.env'), dir, resolver);
    assert.ok(envResult.classes.includes('env-secrets'), 'env-secrets');
    assert.ok(envResult.classes.includes('marker-config'), 'marker-config (env)');
    assert.equal(envResult.skipReason, null);
    assert.equal(envResult.classes.includes('bulk-content'), false);

    const npmrcResult = classifyPath(path.join(dir, 'hidden/.npmrc'), dir, resolver);
    assert.ok(npmrcResult.classes.includes('marker-config'), 'marker-config (npmrc)');
    assert.equal(npmrcResult.skipReason, null);
    assert.equal(npmrcResult.classes.includes('bulk-content'), false);

    // notes.js: previously the ONE bulk-content-only case D-13 pruned under
    // a gitignored directory -- now marker-config (the widened predicate),
    // so it fires here too, matching the OLD bash scanner exactly.
    const notesResult = classifyPath(path.join(dir, 'hidden/notes.js'), dir, resolver);
    assert.ok(notesResult.classes.includes('marker-config'), 'marker-config (ordinary source file, widened tiering-fix)');
    assert.equal(notesResult.skipReason, null);
    assert.equal(notesResult.classes.includes('bulk-content'), false);
  });

  it('the non-ignored mirror (same filename + marker, OUTSIDE hidden/) ALSO classifies into marker-config (proves the test cannot pass by classifying everything as ignored)', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });
    const resolver = createIgnoreResolver({});

    const rootNotesResult = classifyPath(path.join(dir, 'notes.js'), dir, resolver);
    assert.ok(rootNotesResult.classes.includes('marker-config'));
    assert.equal(rootNotesResult.skipReason, null);
  });

  it('the gitignored .env appears in marker-config and env-secrets but NEVER bulk-content (no double marker-scan)', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });
    const resolver = createIgnoreResolver({});

    const envResult = classifyPath(path.join(dir, 'hidden/.env'), dir, resolver);
    assert.ok(envResult.classes.includes('marker-config'));
    assert.ok(envResult.classes.includes('env-secrets'));
    assert.equal(envResult.classes.includes('bulk-content'), false);
  });

  it('the ignore resolver is never consulted for ANY of these files -- bulk-content is unreachable, so isBulkEligible has nothing left to gate', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });
    let called = false;
    const countingResolver = { isBulkEligible: () => { called = true; return { eligible: true, reason: null }; } };

    for (const rel of Object.keys(PLANTED)) {
      classifyPath(path.join(dir, rel), dir, countingResolver);
    }
    assert.equal(called, false);
  });
});

describe('gitignore-tiering — degraded git fails OPEN, never reduces detection (structural, even though bulk-content is unreachable)', { skip: !hasGit ? 'git unavailable' : false }, () => {
  it('with the ignore resolver forced into a no-git degradation, a gitignored ordinary source file is STILL classified (marker-config, not bulk-content)', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });

    // Force the resolver into the D-14 no-git degradation via a stubbed
    // spawnSync that behaves like a missing git binary (ENOENT). Retained
    // even though bulk-content (the class this resolver used to gate) is
    // now unreachable -- classify() must still behave identically whether
    // the resolver is healthy or degraded, since it is never consulted at
    // all for marker-config membership.
    const degradedResolver = createIgnoreResolver({
      spawnSync: () => ({ error: { code: 'ENOENT' } }),
    });

    const notesResult = classifyPath(path.join(dir, 'hidden/notes.js'), dir, degradedResolver);
    assert.ok(notesResult.classes.includes('marker-config'));
    assert.equal(notesResult.skipReason, null);
    assert.equal(notesResult.classes.includes('bulk-content'), false);
  });
});

// ---------------------------------------------------------------------------
// Non-vacuity (Q-02) -- each guard proven to actually bite by breaking it
// once during development, then restoring it.
//
//   1. Consulting `ctx.ignore.isBulkEligible` for a TARGETED class (wrapping
//      the `all-files` push in classify.js with an `isBulkEligible` check)
//      broke the "six targeted classes classify" test above at the
//      `all-files (filename marker)` assertion -- `Math_Symbol.js` under
//      the gitignored `hidden/` directory stopped being classified at all.
//   2. Reverting `isMarkerConfigMember` to its pre-2026-08-07 scope
//      (`.env`/`.env.*`/`.npmrc` only, dropping the
//      `spec.classes['bulk-content'].fileGlobs` widening) broke the "six
//      targeted classes classify" test's `marker-config (ordinary source
//      file, widened tiering-fix)` assertion -- `notes.js` under the
//      gitignored `hidden/` directory stopped classifying into
//      marker-config at all, reproducing exactly the regression this
//      revision fixes.
// Both mutations were applied once during development, confirmed to fail
// the relevant assertions above, and reverted.
// ---------------------------------------------------------------------------
