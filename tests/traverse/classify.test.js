'use strict';

// Class-membership + per-class prune-scope tests for lib/traverse/classify.js
// (G-1482, TRAV-01/TRAV-03/TRAV-05). Every prune scope is proven in BOTH
// directions (a positive membership case AND a pruned-away negative case)
// so a guard cannot pass vacuously (17-VALIDATION.md Q-02).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { classify, isTargetedClass, PRUNE_COMMON_NAMES, MEDIA_EXTENSIONS } = require('../../lib/traverse/classify.js');

const SPEC = require('../../manifests/waves/chaindrop-aug2026.json');

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const SELF_ROOT = '/self/root';

function ctxWith(overrides = {}) {
  return {
    selfRoot: SELF_ROOT,
    ignore: {
      isBulkEligible: () => ({ eligible: true, reason: null }),
    },
    skips: { add() {} },
    ...overrides,
  };
}

function ev(absPath, extra = {}) {
  return { absPath, dirent: null, depth: 0, repoRoot: '/repo', isDirectory: false, ...extra };
}

function classesOf(absPath, ctx = ctxWith(), extra = {}) {
  return classify(ev(absPath, extra), SPEC, ctx).classes;
}

// ---------------------------------------------------------------------------
// Exports / constants
// ---------------------------------------------------------------------------

describe('classify.js — exported constants', () => {
  it('PRUNE_COMMON_NAMES reproduces the bash PRUNE_COMMON array (node_modules deliberately absent)', () => {
    assert.equal(PRUNE_COMMON_NAMES.has('node_modules'), false);
    for (const name of ['.git', 'target', 'dist', 'build', '.next', '.nuxt']) {
      assert.equal(PRUNE_COMMON_NAMES.has(name), true, name);
    }
  });

  it('MEDIA_EXTENSIONS contains binary/media extensions, not source extensions', () => {
    assert.equal(MEDIA_EXTENSIONS.has('.png'), true);
    assert.equal(MEDIA_EXTENSIONS.has('.js'), false);
  });

  it('isTargetedClass: true for every class except bulk-content (both branches)', () => {
    assert.equal(isTargetedClass('bulk-content'), false);
    for (const cls of ['all-files', 'no-prune', 'lockfiles', 'family-packages', 'agent-config', 'marker-config', 'env-secrets']) {
      assert.equal(isTargetedClass(cls), true, cls);
    }
  });
});

// ---------------------------------------------------------------------------
// Self-root exclusion
// ---------------------------------------------------------------------------

describe('classify.js — self-root exclusion', () => {
  it('a path under selfRoot yields no classes at all, even for an otherwise-matching filename', () => {
    const result = classify(ev(path.join(SELF_ROOT, 'package.json')), SPEC, ctxWith());
    assert.deepEqual(result.classes, []);
  });

  it('the SAME filename outside selfRoot DOES classify (proves the guard is not vacuous)', () => {
    const result = classify(ev('/elsewhere/package.json'), SPEC, ctxWith());
    assert.ok(result.classes.includes('no-prune'));
  });
});

// ---------------------------------------------------------------------------
// all-files (A1 1a/1a2/1b/5) — PRUNE_COMMON only, node_modules INCLUDED
// ---------------------------------------------------------------------------

describe('classify.js — all-files class', () => {
  it('an exact FAIL filename inside node_modules IS classified (node_modules not pruned)', () => {
    const classes = classesOf('/elsewhere/proj/node_modules/keyv/Math_Symbol.js');
    assert.ok(classes.includes('all-files'));
  });

  it('the SAME filename inside dist/ is NOT classified (PRUNE_COMMON applies)', () => {
    const classes = classesOf('/elsewhere/proj/dist/Math_Symbol.js');
    assert.equal(classes.includes('all-files'), false);
  });

  it('a variant name (Math_<guid>.js) matching the glob is classified', () => {
    const classes = classesOf('/elsewhere/proj/Math_abc123.js');
    assert.ok(classes.includes('all-files'));
  });

  it('an excluded exact name is not double-matched by the variant glob path (still classified once via fail list)', () => {
    const result = classify(ev('/elsewhere/proj/Math_Symbol.js'), SPEC, ctxWith());
    assert.equal(result.classes.filter((c) => c === 'all-files').length, 1);
  });

  it('setup.mjs is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/setup.mjs').includes('all-files'));
  });

  it('an unrelated filename is not classified', () => {
    assert.equal(classesOf('/elsewhere/proj/index.js').includes('all-files'), false);
  });
});

// ---------------------------------------------------------------------------
// no-prune (A1 row 2) — NO directory prune at all
// ---------------------------------------------------------------------------

describe('classify.js — no-prune class (D-25)', () => {
  it('package.json inside node_modules/<family>/ reaches no-prune (D-25 coverage)', () => {
    const classes = classesOf('/elsewhere/proj/node_modules/keyv/package.json');
    assert.ok(classes.includes('no-prune'));
  });

  it('package.json inside .git/, dist/, build/, .next/, target/ ALL reach no-prune (zero prune, proven per directory)', () => {
    for (const dir of ['.git', 'dist', 'build', '.next', 'target']) {
      const classes = classesOf(`/elsewhere/proj/${dir}/package.json`);
      assert.ok(classes.includes('no-prune'), dir);
    }
  });

  it('a non-package.json file is never in no-prune (proves the guard is not vacuous)', () => {
    assert.equal(classesOf('/elsewhere/proj/package.lock').includes('no-prune'), false);
  });
});

// ---------------------------------------------------------------------------
// lockfiles (A1 row 3a) — PRUNE_COMMON + node_modules excluded
// ---------------------------------------------------------------------------

describe('classify.js — lockfiles class', () => {
  it('a lockfile at a normal path is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/package-lock.json').includes('lockfiles'));
  });

  it('the SAME lockfile inside node_modules is NOT classified (node_modules excluded here, unlike all-files)', () => {
    assert.equal(classesOf('/elsewhere/proj/node_modules/foo/package-lock.json').includes('lockfiles'), false);
  });

  it('the SAME lockfile inside dist/ is NOT classified (PRUNE_COMMON applies)', () => {
    assert.equal(classesOf('/elsewhere/proj/dist/yarn.lock').includes('lockfiles'), false);
  });

  it('a non-lockfile name is never classified', () => {
    assert.equal(classesOf('/elsewhere/proj/random.lock').includes('lockfiles'), false);
  });
});

// ---------------------------------------------------------------------------
// family-packages (A1 row 3b) — ONLY .claude/worktrees excluded
// ---------------------------------------------------------------------------

describe('classify.js — family-packages class', () => {
  it('node_modules/<family>/package.json (unscoped family) is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/node_modules/keyv/package.json').includes('family-packages'));
  });

  it('node_modules/<scope>/<family>/package.json (scoped family) is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/node_modules/@keyv/redis/package.json').includes('family-packages'));
  });

  it('a package.json for a NON-compromised family is not classified (proves the guard is not vacuous)', () => {
    assert.equal(classesOf('/elsewhere/proj/node_modules/left-pad/package.json').includes('family-packages'), false);
  });

  it('the same compromised family, but under .claude/worktrees, is excluded (the only prune this class applies)', () => {
    const classes = classesOf('/elsewhere/proj/.claude/worktrees/x/node_modules/keyv/package.json');
    assert.equal(classes.includes('family-packages'), false);
  });

  it('the same compromised family, under dist/, is STILL classified (PRUNE_COMMON deliberately does not apply)', () => {
    const classes = classesOf('/elsewhere/proj/dist/node_modules/keyv/package.json');
    assert.ok(classes.includes('family-packages'));
  });

  it('a package.json one level too deep (not the direct child of the family dir) is not classified', () => {
    assert.equal(classesOf('/elsewhere/proj/node_modules/keyv/nested/package.json').includes('family-packages'), false);
  });
});

// ---------------------------------------------------------------------------
// agent-config (A1 4a/4b) — PRUNE_COMMON + node_modules excluded
// ---------------------------------------------------------------------------

describe('classify.js — agent-config class', () => {
  it('.claude/settings.json is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/.claude/settings.json').includes('agent-config'));
  });

  it('.claude/settings.local.json is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/.claude/settings.local.json').includes('agent-config'));
  });

  it('.vscode/tasks.json is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/.vscode/tasks.json').includes('agent-config'));
  });

  it('the same .claude/settings.json inside node_modules is NOT classified', () => {
    assert.equal(classesOf('/elsewhere/proj/node_modules/foo/.claude/settings.json').includes('agent-config'), false);
  });

  it('an unrelated json file in .claude/ is not classified', () => {
    assert.equal(classesOf('/elsewhere/proj/.claude/other.json').includes('agent-config'), false);
  });
});

// ---------------------------------------------------------------------------
// env-secrets (D-23) — byte-identical to lib/scan.js:40
// ---------------------------------------------------------------------------

describe('classify.js — env-secrets class', () => {
  it('.env is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/.env').includes('env-secrets'));
  });

  it('.env.production is classified', () => {
    assert.ok(classesOf('/elsewhere/proj/.env.production').includes('env-secrets'));
  });

  it('.env.example is NOT classified (exemption suffix)', () => {
    assert.equal(classesOf('/elsewhere/proj/.env.example').includes('env-secrets'), false);
  });

  it('.env.template and .env.sample are NOT classified', () => {
    assert.equal(classesOf('/elsewhere/proj/.env.template').includes('env-secrets'), false);
    assert.equal(classesOf('/elsewhere/proj/.env.sample').includes('env-secrets'), false);
  });

  it('env-secrets applies with no directory prune (reaches inside node_modules too)', () => {
    assert.ok(classesOf('/elsewhere/proj/node_modules/foo/.env').includes('env-secrets'));
  });
});

// ---------------------------------------------------------------------------
// marker-config — targeted tier for .env/.env.*/.npmrc
// ---------------------------------------------------------------------------

describe('classify.js — marker-config class', () => {
  it('.env is classified into marker-config', () => {
    assert.ok(classesOf('/elsewhere/proj/.env').includes('marker-config'));
  });

  it('.env.example IS classified into marker-config (no exemption suffixes here, unlike env-secrets)', () => {
    assert.ok(classesOf('/elsewhere/proj/.env.example').includes('marker-config'));
  });

  it('.npmrc is classified into marker-config', () => {
    assert.ok(classesOf('/elsewhere/proj/.npmrc').includes('marker-config'));
  });

  it('.env inside node_modules is NOT classified (node_modules excluded for marker-config)', () => {
    assert.equal(classesOf('/elsewhere/proj/node_modules/foo/.env').includes('marker-config'), false);
  });

  it('.env inside .cache is NOT classified (.cache excluded for marker-config)', () => {
    assert.equal(classesOf('/elsewhere/proj/.cache/.env').includes('marker-config'), false);
  });

  it('a .env file is in BOTH env-secrets and marker-config, but never bulk-content (no double marker-scan)', () => {
    const classes = classesOf('/elsewhere/proj/.env');
    assert.ok(classes.includes('env-secrets'));
    assert.ok(classes.includes('marker-config'));
    assert.equal(classes.includes('bulk-content'), false);
  });
});

// ---------------------------------------------------------------------------
// bulk-content — the ONE class consulting the ignore resolver
// ---------------------------------------------------------------------------

describe('classify.js — bulk-content class', () => {
  it('an allow-listed extension, bulk-eligible per the ignore resolver, is classified with bulkEligible true', () => {
    const ctx = ctxWith({ ignore: { isBulkEligible: () => ({ eligible: true, reason: null }) } });
    const result = classify(ev('/elsewhere/proj/notes.js'), SPEC, ctx);
    assert.ok(result.classes.includes('bulk-content'));
    assert.equal(result.bulkEligible, true);
    assert.equal(result.skipReason, null);
  });

  it('the SAME file, NOT eligible per the ignore resolver, is excluded with skipReason gitignored (proves the resolver is actually consulted)', () => {
    const ctx = ctxWith({ ignore: { isBulkEligible: () => ({ eligible: false, reason: 'gitignored' }) } });
    const result = classify(ev('/elsewhere/proj/notes.js'), SPEC, ctx);
    assert.equal(result.classes.includes('bulk-content'), false);
    assert.equal(result.skipReason, 'gitignored');
  });

  it('a media extension short-circuits to skipReason media without consulting the ignore resolver', () => {
    let called = false;
    const ctx = ctxWith({ ignore: { isBulkEligible: () => { called = true; return { eligible: true, reason: null }; } } });
    const result = classify(ev('/elsewhere/proj/photo.png'), SPEC, ctx);
    assert.equal(result.classes.includes('bulk-content'), false);
    assert.equal(result.skipReason, 'media');
    assert.equal(called, false);
  });

  it('a non-allow-listed, non-media extension is simply not a candidate (no skipReason)', () => {
    const result = classify(ev('/elsewhere/proj/binary.xyz'), SPEC, ctxWith());
    assert.equal(result.classes.includes('bulk-content'), false);
    assert.equal(result.skipReason, null);
  });

  it('node_modules and .cache are excluded from bulk-content', () => {
    assert.equal(classesOf('/elsewhere/proj/node_modules/foo/index.js').includes('bulk-content'), false);
    assert.equal(classesOf('/elsewhere/proj/.cache/index.js').includes('bulk-content'), false);
  });

  it('a file with no known repo (repoRoot null) is bulk-eligible without invoking the ignore resolver', () => {
    let called = false;
    const ctx = ctxWith({ ignore: { isBulkEligible: () => { called = true; return { eligible: true, reason: null }; } } });
    const result = classify(ev('/elsewhere/proj/notes.js', { repoRoot: null }), SPEC, ctx);
    assert.ok(result.classes.includes('bulk-content'));
    assert.equal(called, false);
  });
});
