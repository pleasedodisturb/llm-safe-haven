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

  // 2026-08-07 tiering-trade-off reversal (Vitalik review of plan 17-14):
  // marker-config now ALSO covers every name/extension spec.classes['bulk-
  // content'].fileGlobs lists, not just .env/.env.*/.npmrc -- matching the
  // OLD bash scanner's section 6b, which never consulted gitignore for ANY
  // of its allow-listed extensions. See docs/wave-spec.md and
  // tests/helpers/chaindrop-corpus.js's removal of KNOWN_TIERING_TRADEOFFS[0].
  it('an ordinary source extension (.js) is ALSO marker-config now -- the ignore resolver is never consulted for it', () => {
    let called = false;
    const ctx = ctxWith({ ignore: { isBulkEligible: () => { called = true; return { eligible: false, reason: 'gitignored' }; } } });
    const classes = classesOf('/elsewhere/proj/notes.js', ctx);
    assert.ok(classes.includes('marker-config'));
    assert.equal(called, false, 'the (now-vestigial) ignore resolver must never be consulted for a marker-config member');
  });

  it('every other bulk-content fileGlobs member (.mjs/.cjs/.ts/.json/.sh/.zsh/.bash/.yml/.yaml/.md/.lock) is also marker-config', () => {
    for (const name of ['a.mjs', 'a.cjs', 'a.ts', 'a.json', 'a.sh', 'a.zsh', 'a.bash', 'a.yml', 'a.yaml', 'a.md', 'a.lock']) {
      assert.ok(classesOf(`/elsewhere/proj/${name}`).includes('marker-config'), name);
    }
  });

  it('a media extension is still excluded (unaffected by the widening -- media extensions were never in bulk-content\'s allowlist)', () => {
    const classes = classesOf('/elsewhere/proj/photo.png');
    assert.equal(classes.includes('marker-config'), false);
    assert.equal(classes.includes('bulk-content'), false);
  });

  it('a non-allow-listed, non-media, non-marker-config extension is simply not a candidate for either class', () => {
    const classes = classesOf('/elsewhere/proj/binary.xyz');
    assert.equal(classes.includes('marker-config'), false);
    assert.equal(classes.includes('bulk-content'), false);
  });

  it('node_modules and .cache are STILL excluded for the widened marker-config (same prune scope bulk-content always used)', () => {
    assert.equal(classesOf('/elsewhere/proj/node_modules/foo/index.js').includes('marker-config'), false);
    assert.equal(classesOf('/elsewhere/proj/.cache/index.js').includes('marker-config'), false);
  });
});

// ---------------------------------------------------------------------------
// bulk-content class (now unreachable, kept as documented dead code)
// ---------------------------------------------------------------------------

describe('classify.js — bulk-content class (now unreachable)', () => {
  it('nothing classifies into bulk-content any more -- marker-config\'s widened predicate is a strict superset of bulk-content\'s own allowlist', () => {
    for (const name of ['notes.js', 'a.mjs', 'a.cjs', 'a.ts', 'a.json', 'a.sh', 'a.zsh', 'a.bash', 'a.yml', 'a.yaml', 'a.md', 'a.lock', '.npmrc', '.env']) {
      assert.equal(classesOf(`/elsewhere/proj/${name}`).includes('bulk-content'), false, name);
    }
  });

  it('a media extension and an unmatched extension both stay unclassified for bulk-content too (they never matched its allowlist either)', () => {
    assert.equal(classesOf('/elsewhere/proj/photo.png').includes('bulk-content'), false);
    assert.equal(classesOf('/elsewhere/proj/binary.xyz').includes('bulk-content'), false);
  });

  it('the ignore resolver (isBulkEligible) is never invoked by classify() any more, for any input', () => {
    let called = false;
    const ctx = ctxWith({ ignore: { isBulkEligible: () => { called = true; return { eligible: true, reason: null }; } } });
    for (const name of ['notes.js', 'photo.png', 'binary.xyz', '.env', '.npmrc']) {
      classesOf(`/elsewhere/proj/${name}`, ctx);
    }
    assert.equal(called, false);
  });
});
