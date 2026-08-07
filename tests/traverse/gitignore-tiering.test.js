'use strict';

// D-13 false-negative probe (G-1482, TRAV-03, T-17-02/T-17-02-01): proves,
// against a REAL git repo, that .gitignore may prune only the bulk-content
// tier -- every targeted-tier check must still fire inside a gitignored
// directory. This is the security property the whole tiering design exists
// for, so it is proven in BOTH directions (targeted classes fire despite
// being gitignored; the bulk class does not) plus a non-ignored mirror so
// the test cannot pass by classifying everything as ignored, plus a
// degraded-git case proving degradation never REDUCES detection.

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

describe('gitignore-tiering — targeted classes fire inside a gitignored directory, bulk-content does not', { skip: !hasGit ? 'git unavailable' : false }, () => {
  it('five targeted classes classify DESPITE being under a gitignored directory', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });
    const resolver = createIgnoreResolver({});

    // Math_Symbol.js, package.json and package-lock.json ALSO carry a
    // bulk-content-allow-listed extension (.js / .json), so `skipReason`
    // legitimately reports 'gitignored' for the BULK-CONTENT sub-decision
    // on these same events (skipReason describes bulk-content specifically
    // -- see classify.js's return-shape doc comment) even though their
    // TARGETED class membership is completely unaffected. The security
    // property under test is that the targeted class is present AND
    // bulk-content is absent on the SAME event -- proving the two
    // decisions are independent, not that skipReason is globally null.
    const mathResult = classifyPath(path.join(dir, 'hidden/Math_Symbol.js'), dir, resolver);
    assert.ok(mathResult.classes.includes('all-files'), 'all-files (filename marker)');
    assert.equal(mathResult.classes.includes('bulk-content'), false);

    const pkgResult = classifyPath(path.join(dir, 'hidden/package.json'), dir, resolver);
    assert.ok(pkgResult.classes.includes('no-prune'), 'no-prune (preinstall marker)');
    assert.equal(pkgResult.classes.includes('bulk-content'), false);

    const lockResult = classifyPath(path.join(dir, 'hidden/package-lock.json'), dir, resolver);
    assert.ok(lockResult.classes.includes('lockfiles'), 'lockfiles');
    assert.equal(lockResult.classes.includes('bulk-content'), false);

    // .env and .npmrc are marker-config candidates, which SKIPS the
    // bulk-content branch entirely (isMarkerCandidate short-circuit in
    // classify.js) -- for these two, skipReason genuinely stays null.
    const envResult = classifyPath(path.join(dir, 'hidden/.env'), dir, resolver);
    assert.ok(envResult.classes.includes('env-secrets'), 'env-secrets');
    assert.ok(envResult.classes.includes('marker-config'), 'marker-config (env)');
    assert.equal(envResult.skipReason, null);
    assert.equal(envResult.classes.includes('bulk-content'), false);

    const npmrcResult = classifyPath(path.join(dir, 'hidden/.npmrc'), dir, resolver);
    assert.ok(npmrcResult.classes.includes('marker-config'), 'marker-config (npmrc)');
    assert.equal(npmrcResult.skipReason, null);
    assert.equal(npmrcResult.classes.includes('bulk-content'), false);
  });

  it('the bulk-only marker file under the SAME gitignored directory is NOT classified (skipReason gitignored)', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });
    const resolver = createIgnoreResolver({});

    const notesResult = classifyPath(path.join(dir, 'hidden/notes.js'), dir, resolver);
    assert.equal(notesResult.classes.includes('bulk-content'), false);
    assert.equal(notesResult.skipReason, 'gitignored');
    assert.equal(notesResult.bulkEligible, false);
  });

  it('the non-ignored mirror (same filename + marker, OUTSIDE hidden/) IS bulk-eligible (proves the test cannot pass by classifying everything as ignored)', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });
    const resolver = createIgnoreResolver({});

    const rootNotesResult = classifyPath(path.join(dir, 'notes.js'), dir, resolver);
    assert.ok(rootNotesResult.classes.includes('bulk-content'));
    assert.equal(rootNotesResult.bulkEligible, true);
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
});

describe('gitignore-tiering — degraded git fails OPEN, never reduces detection', { skip: !hasGit ? 'git unavailable' : false }, () => {
  it('with the ignore resolver forced into a no-git degradation, the SAME bulk-only file becomes bulk-eligible', () => {
    const dir = mkRepo();
    initRepo(dir, { gitignore: 'hidden/\n', untracked: PLANTED });

    // Force the resolver into the D-14 no-git degradation via a stubbed
    // spawnSync that behaves like a missing git binary (ENOENT).
    const degradedResolver = createIgnoreResolver({
      spawnSync: () => ({ error: { code: 'ENOENT' } }),
    });

    const notesResult = classifyPath(path.join(dir, 'hidden/notes.js'), dir, degradedResolver);
    assert.ok(notesResult.classes.includes('bulk-content'));
    assert.equal(notesResult.bulkEligible, true);
    assert.equal(notesResult.skipReason, null);
    assert.deepEqual(degradedResolver.degradations()[dir], 'no-git');
  });
});

// ---------------------------------------------------------------------------
// Non-vacuity (Q-02) -- each guard proven to actually bite by breaking it
// once during development, then restoring it.
//
//   1. Consulting `ctx.ignore.isBulkEligible` for a TARGETED class (wrapping
//      the `all-files` push in classify.js with an `isBulkEligible` check)
//      broke the "five targeted classes classify" test above at the
//      `all-files (filename marker)` assertion -- `Math_Symbol.js` under
//      the gitignored `hidden/` directory stopped being classified at all.
//   2. Moving `.npmrc` back into `bulk-content` (removing it from
//      `isMarkerConfigMember` AND widening the bulk-content extension
//      check to also match the literal `.npmrc` name -- the faithful
//      simulation of "no longer excluded", since `path.extname('.npmrc')`
//      is `''` and would never match the allowlist on its own) broke the
//      SAME test's `marker-config (npmrc)` assertion -- `.npmrc` stopped
//      being a marker-config candidate at all once it was no longer
//      excluded from bulk-content upstream.
// Both mutations were applied once during development, confirmed to fail
// the relevant assertions above, and reverted.
// ---------------------------------------------------------------------------
