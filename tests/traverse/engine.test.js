'use strict';

// Engine integration tests (G-1482, TRAV-01/TRAV-04/TRAV-05, plan 17-11).
// Proves the assembled Traversal (walk + classify + read-pool + budget) on
// real fixtures: detector ownership (T-17-15), exact finding multiplicity
// (never "at least one"), tier semantics (D-20) and exit precedence
// (D-18). Reuses the shared detection-parity corpus builders
// (tests/helpers/chaindrop-corpus.js) so this suite cannot silently drift
// from the frozen oracle plan 17-14 retrofit the bash scanner against.
//
// 2026-08-07: `lib/traverse/git-ignore.js` no longer exists -- it consulted
// `.gitignore` for the now-removed `bulk-content` class, and was deleted
// once nothing consumed its decisions any more (see classify.js's module
// header for the full tiering-trade-off-reversal history).
// tests/traverse/zero-git-subprocess.test.js is the committed proof that a
// real engine run spawns no `child_process.spawnSync` call at all any more.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { Traversal, traverse, DETECTOR_OWNERSHIP } = require('../../lib/traverse/engine.js');
const { CASES, buildCase } = require('../helpers/chaindrop-corpus.js');
const { write } = require('../helpers/chaindrop-fixtures.js');

const SPEC = require('../../manifests/waves/chaindrop-aug2026.json');

const dirs = [];
function mkFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'engine-test-'));
  dirs.push(dir);
  return dir;
}
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

// Finding ids this file asserts the PRESENCE of (populated as each
// corresponding `it()` runs) -- cross-checked against DETECTOR_OWNERSHIP's
// engine-owned rows at the very end of the file so the suite cannot drift
// from the matrix (T-17-15).
const COVERED_IDS = new Set();

function findingsOfId(result, id) {
  return result.findings.filter((f) => f.id === id);
}

function corpusCase(id) {
  const c = CASES.find((x) => x.id === id);
  assert.ok(c, `corpus case not found in tests/helpers/chaindrop-corpus.js: ${id}`);
  return c;
}

async function runCorpusCase(id, extraOpts = {}) {
  const home = mkFixture();
  buildCase(home, corpusCase(id));
  const t = new Traversal({ roots: [home], spec: SPEC, ...extraOpts });
  return t.run();
}

// A deterministic, injectable clock that survives exactly the SHARED
// budget's `noteDirectory()` calls made during a single-flat-directory walk
// (one call for the root itself) plus this file's engine.js phase-boundary
// recheck (the next call, immediately after phase 1 drains) -- see
// engine.js's "D-20 phase-boundary recheck" comment. The THIRD call (and
// every call after) reports a huge elapsed time, latching the shared
// budget exactly at the phase 1 / phase 2 boundary. Every test that uses
// this therefore needs a FLAT fixture root (no subdirectories) so the walk
// itself calls `noteDirectory()` exactly once.
function phaseBoundaryClock() {
  let calls = 0;
  return {
    now: () => {
      calls += 1;
      return calls <= 2 ? 0n : 60_000_000_000n; // 0 while walking, 60s once past the phase boundary
    },
    budgetSeconds: 5,
  };
}

// ---------------------------------------------------------------------------
// Corpus-driven detector coverage -- one it() per corpus case whose
// detector DETECTOR_OWNERSHIP assigns to the engine, exact multiplicity.
// ---------------------------------------------------------------------------

describe('engine — corpus-driven detector coverage (exact multiplicity)', () => {
  it('fn-exact -> file-marker (exactly 1, fail; exitCode 1)', async () => {
    const result = await runCorpusCase('fn-exact');
    const matches = findingsOfId(result, 'file-marker');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].severity, 'fail');
    assert.equal(result.exitCode, 1);
    COVERED_IDS.add('file-marker');
  });

  it('variant-large -> payload-variant (exactly 1, fail)', async () => {
    const result = await runCorpusCase('variant-large');
    const matches = findingsOfId(result, 'payload-variant');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].severity, 'fail');
    COVERED_IDS.add('payload-variant');
  });

  it('variant-small -> payload-variant-warn (exactly 1, warn; exitCode 0, no fail findings)', async () => {
    const result = await runCorpusCase('variant-small');
    const matches = findingsOfId(result, 'payload-variant-warn');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].severity, 'warn');
    assert.equal(result.findings.filter((f) => f.severity === 'fail').length, 0);
    assert.equal(result.exitCode, 0);
    COVERED_IDS.add('payload-variant-warn');
  });

  it('setup-bare -> setup-bare (exactly 1, warn)', async () => {
    const result = await runCorpusCase('setup-bare');
    const matches = findingsOfId(result, 'setup-bare');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].severity, 'warn');
    COVERED_IDS.add('setup-bare');
  });

  it('setup-paired -> setup-preinstall-pair AND install-marker (2 findings total, both fail)', async () => {
    const result = await runCorpusCase('setup-paired');
    assert.equal(result.findings.length, 2);
    assert.equal(findingsOfId(result, 'setup-preinstall-pair').length, 1);
    assert.equal(findingsOfId(result, 'install-marker').length, 1);
    assert.ok(result.findings.every((f) => f.severity === 'fail'));
    COVERED_IDS.add('setup-preinstall-pair');
    COVERED_IDS.add('install-marker');
  });

  it('preinstall-plain -> install-marker (exactly 1)', async () => {
    const result = await runCorpusCase('preinstall-plain');
    assert.equal(findingsOfId(result, 'install-marker').length, 1);
  });

  it('preinstall-node-modules (D-25) -> install-marker (exactly 1, no-prune reaches node_modules)', async () => {
    const result = await runCorpusCase('preinstall-node-modules');
    assert.equal(findingsOfId(result, 'install-marker').length, 1);
    // D-25: not also double-reported via family-packages (no version field).
    assert.equal(findingsOfId(result, 'poisoned-installed').length, 0);
    assert.equal(result.findings.length, 1);
  });

  it('preinstall-pruned-dirs -> install-marker x4 (dist/build/.next/target, no-prune scope)', async () => {
    const result = await runCorpusCase('preinstall-pruned-dirs');
    assert.equal(findingsOfId(result, 'install-marker').length, 4);
  });

  it('installed-poisoned -> poisoned-installed (exactly 1)', async () => {
    const result = await runCorpusCase('installed-poisoned');
    assert.equal(findingsOfId(result, 'poisoned-installed').length, 1);
    COVERED_IDS.add('poisoned-installed');
  });

  it('installed-safe -> zero findings (family presence at a non-poisoned version is not an IOC)', async () => {
    const result = await runCorpusCase('installed-safe');
    assert.equal(result.findings.length, 0);
  });

  it('claude-hook (static $HOME path shape) -> claude-hook (exactly 1)', async () => {
    const result = await runCorpusCase('claude-hook');
    assert.equal(findingsOfId(result, 'claude-hook').length, 1);
    COVERED_IDS.add('claude-hook');
  });

  it('claude-hook-project (per-root discovery shape) -> claude-hook (exactly 1)', async () => {
    const result = await runCorpusCase('claude-hook-project');
    assert.equal(findingsOfId(result, 'claude-hook').length, 1);
  });

  it('claude-hook-both -> claude-hook (exactly 2, multiplicity pin)', async () => {
    const result = await runCorpusCase('claude-hook-both');
    assert.equal(findingsOfId(result, 'claude-hook').length, 2);
  });

  it('vscode-task-fail -> vscode-task (exactly 1, fail)', async () => {
    const result = await runCorpusCase('vscode-task-fail');
    const matches = findingsOfId(result, 'vscode-task');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].severity, 'fail');
    COVERED_IDS.add('vscode-task');
  });

  it('vscode-task-info -> vscode-task-info (exactly 1, info; exitCode 0)', async () => {
    const result = await runCorpusCase('vscode-task-info');
    const matches = findingsOfId(result, 'vscode-task-info');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].severity, 'info');
    assert.equal(result.findings.filter((f) => f.severity === 'fail').length, 0);
    assert.equal(result.exitCode, 0);
    COVERED_IDS.add('vscode-task-info');
  });

  it('marker-source (ordinary .js file) -> marker-string (exactly 1)', async () => {
    // 2026-08-07 tiering-trade-off reversal: marker-config now covers every
    // bulk-content-allowlisted name too (see classify.js's widened
    // isMarkerConfigMember), so an ordinary .js file's marker-string
    // finding reports class 'marker-config', not 'bulk-content' -- proven
    // unreachable in tests/traverse/classify.test.js.
    const result = await runCorpusCase('marker-source');
    const matches = findingsOfId(result, 'marker-string');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].class, 'marker-config');
    COVERED_IDS.add('marker-string');
  });

  it('marker-npmrc (targeted marker-config, credential file) -> marker-string (exactly 1)', async () => {
    const result = await runCorpusCase('marker-npmrc');
    const matches = findingsOfId(result, 'marker-string');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].class, 'marker-config');
  });

  it('marker-env (targeted marker-config, credential file) -> marker-string (exactly 1)', async () => {
    const result = await runCorpusCase('marker-env');
    const matches = findingsOfId(result, 'marker-string');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].class, 'marker-config');
  });

  it('marker-oversized -> zero findings (bulk-content size cap, exclusion not truncation)', async () => {
    const result = await runCorpusCase('marker-oversized');
    assert.equal(result.findings.length, 0);
  });

  it('clean -> zero findings, exitCode 0, incomplete false', async () => {
    const result = await runCorpusCase('clean');
    assert.equal(result.findings.length, 0);
    assert.equal(result.exitCode, 0);
    assert.equal(result.incomplete, false);
  });
});

// ---------------------------------------------------------------------------
// known-hash (section 5) -- a real ChainDrop hash cannot be forged, so this
// uses a synthetic spec whose knownBadHashes contains a fixture file's OWN
// independently-computed digest, matching the established pattern in
// tests/traverse/hash-cap.test.js.
// ---------------------------------------------------------------------------

describe('engine — known-bad hash (synthetic spec)', () => {
  it('a setup.mjs whose hash matches a synthetic knownBadHashes entry fires BOTH known-hash and setup-hash', async () => {
    const home = mkFixture();
    const file = path.join(home, 'setup.mjs');
    write(file, 'export const setup = () => {};\n');
    const digest = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    const syntheticSpec = { ...SPEC, knownBadHashes: [{ sha256: digest, description: 'synthetic', sizeBytes: fs.statSync(file).size }] };

    const t = new Traversal({ roots: [home], spec: syntheticSpec });
    const result = await t.run();

    assert.equal(findingsOfId(result, 'known-hash').length, 1);
    assert.equal(findingsOfId(result, 'setup-hash').length, 1);
    assert.equal(result.findings.length, 2);
    assert.ok(result.findings.every((f) => f.severity === 'fail'));
    COVERED_IDS.add('known-hash');
    COVERED_IDS.add('setup-hash');
  });
});

// ---------------------------------------------------------------------------
// D-25 / section-2 scope, end to end -- the B1-guard corpus case.
// ---------------------------------------------------------------------------

describe('engine — D-25 no-prune scope, five locations', () => {
  it('a preinstall marker in node_modules/keyv, dist, build, .next AND target yields exactly 5 install-marker findings', async () => {
    const home = mkFixture();
    const pkg = JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } });
    for (const dir of ['node_modules/keyv', 'dist', 'build', '.next', 'target']) {
      write(path.join(home, 'Projects', 'y', dir, 'package.json'), pkg);
    }
    const t = new Traversal({ roots: [home], spec: SPEC });
    const result = await t.run();
    assert.equal(findingsOfId(result, 'install-marker').length, 5);
  });
});

// ---------------------------------------------------------------------------
// Tier ordering (D-20) -- the shared budget latching exactly at the phase 1
// / phase 2 boundary.
// ---------------------------------------------------------------------------

describe('engine — tier ordering (D-20)', () => {
  it('budget exhausts at the phase boundary -> targeted tier complete (findings survive), bulk tier incomplete', async () => {
    const home = mkFixture();
    write(path.join(home, 'package.json'), JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } }));
    const { now, budgetSeconds } = phaseBoundaryClock();
    const t = new Traversal({ roots: [home], spec: SPEC, now, budgetSeconds });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, true);
    assert.equal(result.tiers.bulk.complete, false);
    assert.equal(result.incomplete, true);
    assert.equal(findingsOfId(result, 'install-marker').length, 1);
  });

  it('paired opposite: with a generous (default) budget, both tiers are complete', async () => {
    const home = mkFixture();
    write(path.join(home, 'package.json'), JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } }));
    const t = new Traversal({ roots: [home], spec: SPEC });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, true);
    assert.equal(result.tiers.bulk.complete, true);
    assert.equal(result.incomplete, false);
  });
});

// ---------------------------------------------------------------------------
// Enumeration-phase exhaustion -- the case D-20's wording could be misread
// as excluding: the budget latches DURING the walk itself, cutting BOTH
// tiers, while findings discovered before the cut are still returned.
// ---------------------------------------------------------------------------

describe('engine — enumeration-phase exhaustion', () => {
  it('budget exhausts mid-walk (second root) -> both tiers incomplete, the marker found in the FIRST root survives', async () => {
    const homeA = mkFixture();
    const homeB = mkFixture();
    write(path.join(homeA, 'Math_Symbol.js'), '/* stub */\n');
    write(path.join(homeB, 'math_init.js'), '/* stub */\n');

    let calls = 0;
    const now = () => {
      calls += 1;
      return calls <= 2 ? 0n : 60_000_000_000n; // survives root A's own noteDirectory call, latches on root B's
    };

    const t = new Traversal({ roots: [homeA, homeB], spec: SPEC, now, budgetSeconds: 5 });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, false);
    assert.equal(result.tiers.bulk.complete, false);
    assert.equal(result.incomplete, true);
    assert.equal(findingsOfId(result, 'file-marker').length, 1);
    assert.equal(result.findings[0].absPath, path.join(homeA, 'Math_Symbol.js'));
  });
});

// ---------------------------------------------------------------------------
// Exit precedence end to end (D-18) -- all four rows, using the same
// phase-boundary technique above so a WARN-only fixture can still produce
// its finding before the shared budget latches.
// ---------------------------------------------------------------------------

describe('engine — exit precedence end to end', () => {
  it('fail findings AND an exhausted budget -> exitCode 1, incomplete true', async () => {
    const home = mkFixture();
    write(path.join(home, 'Math_Symbol.js'), '/* stub */\n');
    const { now, budgetSeconds } = phaseBoundaryClock();
    const t = new Traversal({ roots: [home], spec: SPEC, now, budgetSeconds });
    const result = await t.run();

    assert.equal(result.exitCode, 1);
    assert.equal(result.incomplete, true);
    assert.ok(result.findings.some((f) => f.severity === 'fail'));
  });

  it('a clean fixture with an exhausted budget -> exitCode 2, incomplete true', async () => {
    const home = mkFixture();
    const { now, budgetSeconds } = phaseBoundaryClock();
    const t = new Traversal({ roots: [home], spec: SPEC, now, budgetSeconds });
    const result = await t.run();

    assert.equal(result.findings.length, 0);
    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 2);
  });

  it('a clean, complete fixture -> exitCode 0, incomplete false', async () => {
    const home = mkFixture();
    const t = new Traversal({ roots: [home], spec: SPEC });
    const result = await t.run();

    assert.equal(result.findings.length, 0);
    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
  });

  it('a warn-only fixture with an exhausted budget -> exitCode 2 (no fail findings), incomplete true', async () => {
    const home = mkFixture();
    write(path.join(home, 'Math_Helper.js'), 'export const add = (a, b) => a + b;\n');
    const { now, budgetSeconds } = phaseBoundaryClock();
    const t = new Traversal({ roots: [home], spec: SPEC, now, budgetSeconds });
    const result = await t.run();

    assert.equal(findingsOfId(result, 'payload-variant-warn').length, 1);
    assert.equal(result.findings.filter((f) => f.severity === 'fail').length, 0);
    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 2);
  });
});

// ---------------------------------------------------------------------------
// Degradation reporting (D-14) -- retired 2026-08-07.
// ---------------------------------------------------------------------------
//
// This describe block previously simulated a no-git environment (a stubbed
// `spawnSync` returning ENOENT) and asserted the D-14 fail-open contract:
// a missing git binary degrades gitignore-based pruning without ever
// setting `incomplete`. That entire mechanism is gone -- `degradations`
// was populated exclusively through `isBulkEligible()` -> `indexFor()`
// (`lib/traverse/git-ignore.js`, now deleted), whose only caller was the
// now-removed `bulk-content` classification branch (see classify.js's
// module header for the 2026-08-07 tiering-trade-off-reversal history).
// Simulating "no git" via a `spawnSync` stub is provably vacuous now: `run()`
// never constructs a resolver, so nothing ever reads the stub. This is the
// correct consequence, not a regression -- the OLD bash scanner's
// marker-string scan (section 6b) never consulted git either.
//
// The no-git SIMULATION is deleted, not rewritten -- there is nothing left
// to simulate. What survives below is a much smaller, honest replacement:
// a plain assertion that `degradations` is a stable, empty array on an
// ordinary run (the results-directory protocol, `lib/traverse/results.js`,
// still writes `scalars/degradation-count` and `findings.json.degradations`
// for shape stability -- see the field's own doc comment in `engine.js`'s
// `run()`).

describe('engine — degradations field is a stable, empty array (git is never consulted)', () => {
  it('an ordinary run over a real repo boundary has degradations: []', async () => {
    const home = mkFixture();
    fs.mkdirSync(path.join(home, '.git')); // walk.js attributes repoRoot from the LITERAL name, no real git needed
    write(path.join(home, 'loader.js'), 'console.log("hello");\n');

    const t = new Traversal({ roots: [home], spec: SPEC });
    const result = await t.run();

    assert.equal(result.exitCode, 0);
    assert.equal(result.incomplete, false);
    assert.deepEqual(result.degradations, []);
  });
});

// ---------------------------------------------------------------------------
// Single-open contract (D-02).
// ---------------------------------------------------------------------------

describe('engine — single-open contract (D-02)', () => {
  it('a file needing BOTH hash and content, plus a content-only file, open exactly once each (2 total)', async () => {
    const home = mkFixture();
    write(path.join(home, 'setup.mjs'), 'export const setup = () => {};\n'); // all-files (hash) AND marker-config (.mjs allowlisted)
    write(path.join(home, 'loader.js'), 'console.log(1);\n'); // marker-config content only

    const realFs = require('fs');
    let opens = 0;
    const countingFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: (...args) => {
          opens += 1;
          return realFs.promises.open(...args);
        },
      },
    };

    const t = new Traversal({ roots: [home], spec: SPEC, fs: countingFs });
    await t.run();

    assert.equal(opens, 2);
  });
});

// ---------------------------------------------------------------------------
// Wave-driver guard.
// ---------------------------------------------------------------------------

describe('engine — wave-driver guard', () => {
  it('constructing with spec + skipDirs throws TypeError', () => {
    assert.throws(() => new Traversal({ roots: ['.'], spec: {}, skipDirs: ['node_modules'] }), TypeError);
  });

  it('constructing with spec + maxDepth throws TypeError', () => {
    assert.throws(() => new Traversal({ roots: ['.'], spec: {}, maxDepth: 3 }), TypeError);
  });

  it('constructing with spec + skipDotDirs throws TypeError', () => {
    assert.throws(() => new Traversal({ roots: ['.'], spec: {}, skipDotDirs: true }), TypeError);
  });

  it('constructing WITHOUT spec allows maxDepth/skipDirs (the lib/scan.js enumeration shape)', () => {
    assert.doesNotThrow(() => new Traversal({ roots: ['.'], classes: ['env-secrets'], maxDepth: 4, skipDirs: ['node_modules'] }));
  });

  it('run() without a spec rejects (a validated wave spec is required)', async () => {
    const t = new Traversal({ roots: ['.'] });
    await assert.rejects(() => t.run(), /validated wave spec is required/);
  });
});

// ---------------------------------------------------------------------------
// Repo attribution agreement -- DELETED 2026-08-07, not rewritten.
// ---------------------------------------------------------------------------
//
// This describe block used to prove that `ctx.ignore.isBulkEligible` was
// called with the SAME `repoRoot` the walk attributed to each path (D-26),
// over a nested-repo fixture, using ordinary .js files as bait because
// .js was the one class (`bulk-content`) that ever consulted the
// resolver. `Traversal` no longer reads a `rawOptions.ignore` option AT
// ALL (see `lib/traverse/engine.js`'s `run()`/`enumerateSync()`), so
// wrapping and passing one is now a complete no-op -- there is no
// parameter left to intercept, which makes a call-counting test of it
// vacuous by construction, not merely passing. The property this used to
// guard -- nothing in a real engine run ever calls into a gitignore
// resolver, over ANY fixture shape, nested repos included -- is now
// proven strictly more generally (every `child_process.spawnSync` call of
// any kind, not just one specific dead method) by
// tests/traverse/zero-git-subprocess.test.js, a real `run()` exercised
// against a synthetic nested-repo-shaped fixture with a counting
// `spawnSync` stub installed at the `child_process` module level.

// ---------------------------------------------------------------------------
// Self-root exclusion.
// ---------------------------------------------------------------------------

describe('engine — self-root exclusion', () => {
  it('a fixture pointed at itself as selfRoot produces zero findings despite containing every IOC string', async () => {
    const home = mkFixture();
    write(path.join(home, 'Math_Symbol.js'), '/* stub */\n');
    write(path.join(home, 'package.json'), JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } }));
    write(path.join(home, 'loader.js'), `const c2 = "${SPEC.markerStrings[0]}";\n`);

    const t = new Traversal({ roots: [home], spec: SPEC, selfRoot: home });
    const result = await t.run();

    assert.equal(result.findings.length, 0);
  });
});

// ---------------------------------------------------------------------------
// enumerateSync — subprocess-free for targeted-only consumers.
// ---------------------------------------------------------------------------

describe('engine — enumerateSync subprocess boundary', () => {
  it('requesting only env-secrets spawns NO subprocess even with a bulk-content-eligible sibling file present', () => {
    const home = mkFixture();
    write(path.join(home, '.env'), 'SECRET=1\n');
    write(path.join(home, 'loader.js'), 'console.log(1);\n'); // .js is bulk-content-allowlisted -- proves the class is never even consulted

    let calls = 0;
    const stubSpawnSync = () => {
      calls += 1;
      return { status: 0, stdout: '', stderr: '' };
    };

    const t = new Traversal({ roots: [home], classes: ['env-secrets'], spawnSync: stubSpawnSync });
    const r = t.enumerateSync();

    assert.equal(calls, 0);
    assert.deepEqual(r.byClass.get('env-secrets'), [path.join(home, '.env')]);
  });
});

// ---------------------------------------------------------------------------
// One walk per root -- the end-to-end version of the structural assertion.
// ---------------------------------------------------------------------------

describe('engine — one walk per root', () => {
  it('every directory is enumerated exactly once across BOTH tiers', async () => {
    const home = mkFixture();
    write(path.join(home, 'a', 'Math_Symbol.js'), '/* stub */\n');
    write(path.join(home, 'b', 'loader.js'), 'console.log(1);\n');

    const seen = [];
    const onReaddir = (dir) => seen.push(dir);
    const t = new Traversal({ roots: [home], spec: SPEC, onReaddir });
    await t.run();

    const counts = {};
    for (const d of seen) counts[d] = (counts[d] || 0) + 1;
    for (const [dir, n] of Object.entries(counts)) {
      assert.equal(n, 1, `directory ${dir} was enumerated ${n} times`);
    }
    assert.ok(seen.includes(home));
    assert.ok(seen.includes(path.join(home, 'a')));
    assert.ok(seen.includes(path.join(home, 'b')));
  });
});

// ---------------------------------------------------------------------------
// Bash-owned rows: the engine's whole contract for them is class listing
// (or spec-list data, out of this plan's scope) -- never a finding of its
// own. Section 3a (lockfiles) is the one bash-owned row whose class is
// meaningfully observable at this layer.
// ---------------------------------------------------------------------------

describe('engine — bash-owned rows produce class data, never a finding', () => {
  it('a poisoned-version lockfile is classified into the lockfiles class, with zero engine findings for it', async () => {
    const home = mkFixture();
    write(
      path.join(home, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: SPEC.poisonedVersions.keyv[0] } } }, null, 2)
    );

    const enumT = new Traversal({ roots: [home], classes: ['lockfiles'], spec: SPEC });
    const enumResult = enumT.enumerateSync();
    assert.deepEqual(enumResult.byClass.get('lockfiles'), [path.join(home, 'package-lock.json')]);

    const runT = new Traversal({ roots: [home], spec: SPEC });
    const runResult = await runT.run();
    assert.equal(runResult.findings.length, 0);
  });
});

// ---------------------------------------------------------------------------
// Results-writer accessors + the `traverse()` convenience function.
// ---------------------------------------------------------------------------

describe('engine — results-writer accessors and the traverse() convenience wrapper', () => {
  it('findingsOfClass / severityCounts / skipInventory reflect the most recent run(), and default empty before any run', () => {
    const t = new Traversal({ roots: ['.'], spec: SPEC });
    assert.deepEqual(t.findingsOfClass('all-files'), []);
    assert.deepEqual(t.severityCounts(), { fail: 0, warn: 0, info: 0 });
    assert.equal(t.skipInventory().total(), 0);
  });

  it('after run(), the accessors match the returned TraverseResult', async () => {
    const home = mkFixture();
    write(path.join(home, 'Math_Symbol.js'), '/* stub */\n');
    const t = new Traversal({ roots: [home], spec: SPEC });
    const result = await t.run();

    assert.deepEqual(t.findingsOfClass('all-files'), result.findings.filter((f) => f.class === 'all-files'));
    assert.deepEqual(t.severityCounts(), { fail: 1, warn: 0, info: 0 });
    assert.equal(t.skipInventory(), result.skips);
  });

  it('the traverse() convenience function is equivalent to new Traversal(opts).run()', async () => {
    const home = mkFixture();
    write(path.join(home, 'Math_Symbol.js'), '/* stub */\n');
    const result = await traverse({ roots: [home], spec: SPEC });
    assert.equal(findingsOfId(result, 'file-marker').length, 1);
    assert.equal(result.exitCode, 1);
  });
});

// ---------------------------------------------------------------------------
// DETECTOR_OWNERSHIP coverage (T-17-15) -- driven from the matrix itself so
// this suite cannot silently drift from it. MUST run last (COVERED_IDS is
// populated by every `it()` above, in file-registration order).
// ---------------------------------------------------------------------------

describe('engine — DETECTOR_OWNERSHIP coverage', () => {
  it('every engine-owned row has at least one covering case in this file', () => {
    assert.equal(DETECTOR_OWNERSHIP.length, 14);
    for (const row of DETECTOR_OWNERSHIP) {
      if (row.owner !== 'engine') continue;
      for (const id of row.findingIds) {
        assert.ok(COVERED_IDS.has(id), `finding id '${id}' (section ${row.section}) has no covering test in engine.test.js`);
      }
    }
  });
});
