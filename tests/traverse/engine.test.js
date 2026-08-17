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

const { Traversal, traverse, DETECTOR_OWNERSHIP, TARGETED_CONTENT_CLASSES, ANOMALY_SKIP_REASONS, SCOPE_SKIP_REASONS } = require('../../lib/traverse/engine.js');
const { createBudget } = require('../../lib/traverse/budget.js');
const { normalizeOptions, SKIP_REASONS } = require('../../lib/traverse/index.js');
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

// A phase-tagged budget harness (G-1506, decision D-05) -- replaces the
// former count-coupled clock (`calls <= 2 ? 0n : ...`), which five of nine
// cross-AI reviewers independently flagged: it asserted a call COUNT, which
// silently retunes the instant a clock read is added or removed anywhere in
// the engine or the read pool, and it required every caller to use a FLAT
// fixture root so the walk's own `noteDirectory()` calls stayed at exactly
// one. This harness arms on a PHASE TRANSITION instead, so it survives any
// number of clock reads made anywhere before the armed phase is entered --
// the previous FLAT-fixture requirement is GONE, because arming at
// `'targeted'`/`'bulk'` happens only after `engine.js`'s `run()` calls
// `budget.enterTier(armAt)`, which itself happens only after the walk has
// already finished; no walk-phase clock read can ever trip it.
//
// `armAt` names the tier whose `enterTier()` call should arm the injected
// clock to report far-past-budget from that point on: `'targeted'` arms
// immediately when the targeted tier begins (used by the mandatory 1/15
// -record over-budget cases below, which need the latch to land WHILE the
// targeted tier is current); `'bulk'` (the default) arms only when the bulk
// tier begins, so the targeted tier finishes normally and the latch lands at
// the phase-1/phase-2 boundary (used by the pre-existing D-20/D-18 cases).
function phaseBoundaryClock({ armAt = 'bulk', budgetSeconds = 5 } = {}) {
  let phase = 'walk';
  let armed = armAt === 'walk';
  let latchedDuring = null;
  const phaseLog = [];

  const now = () => (armed ? 60_000_000_000n : 0n);
  const real = createBudget(normalizeOptions({ budgetSeconds, now }));

  // Wraps a real clock-reading checkpoint (`noteDirectory`/`noteFile`),
  // recording the CURRENT phase the first time a call flips the real
  // budget from not-exhausted to exhausted. First write wins -- a later
  // checkpoint call in a different phase must never overwrite which phase
  // actually latched it.
  function wrapCheckpoint(fnName) {
    return (...args) => {
      const before = real.exhausted();
      const result = real[fnName](...args);
      if (!before && real.exhausted()) {
        if (latchedDuring === null) latchedDuring = phase;
        phaseLog.push(phase);
      }
      return result;
    };
  }

  const budget = {
    noteDirectory: wrapCheckpoint('noteDirectory'),
    noteFile: wrapCheckpoint('noteFile'),
    noteFiles: (...args) => real.noteFiles(...args),
    exhausted: (...args) => real.exhausted(...args),
    reason: (...args) => real.reason(...args),
    elapsedMs: (...args) => real.elapsedMs(...args),
    remainingMs: (...args) => real.remainingMs(...args),
    snapshot: (...args) => real.snapshot(...args),
    enterTier: (name) => {
      phase = name;
      if (name === armAt) armed = true;
      real.enterTier(name);
    },
    tierComplete: (name) => {
      phase = `${name}-complete`;
      real.tierComplete(name);
    },
  };

  return {
    budget,
    latchedDuring: () => latchedDuring,
    phaseLog,
  };
}

// ---------------------------------------------------------------------------
// phaseBoundaryClock() harness self-check -- a partial budget object is
// exactly the vacuity this phase exists to remove (T-17.1-01-05).
// ---------------------------------------------------------------------------

describe('engine.test.js — phaseBoundaryClock() harness self-check', () => {
  it('returns exactly { budget, latchedDuring, phaseLog }, and budget exposes all ten createBudget() members', () => {
    const clock = phaseBoundaryClock();
    assert.deepEqual(Object.keys(clock).sort(), ['budget', 'latchedDuring', 'phaseLog']);
    for (const k of ['noteDirectory', 'noteFile', 'noteFiles', 'exhausted', 'reason', 'elapsedMs', 'remainingMs', 'snapshot', 'enterTier', 'tierComplete']) {
      assert.equal(typeof clock.budget[k], 'function', `budget.${k} must be a function`);
    }
    assert.equal(clock.latchedDuring(), null, 'a freshly-built clock has not latched yet');
    assert.deepEqual(clock.phaseLog, []);
  });
});

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

  // G-1482 merge-blocking fix: commandPattern/failPattern are POSIX ERE
  // (`[[:space:]]`) for scripts/scan-chaindrop-aug2026.sh's bash `grep -E`
  // consumer. A JS `new RegExp()` does not understand a POSIX bracket
  // class -- `[[:space:]]` there compiles to a literal 8-character class,
  // not whitespace -- so feeding commandPattern/failPattern straight into
  // `new RegExp()` (as engine.js did before this fix) silently drops every
  // alternate containing embedded whitespace (`node -e`, `curl ... | sh`)
  // while the whitespace-free alternates (`setup.mjs`, `Math_Symbol`, ...)
  // keep matching -- which is exactly why the pre-existing claude-hook
  // corpus cases above (built from "node setup.mjs") never caught this.
  // The four cases below pin the engine to the `jsCommandPattern`/
  // `jsFailPattern` fields specifically.
  it('claude-hook-node-e -> claude-hook (exactly 1) — commandPattern\'s node -e alternate, the exact G-1482 regression', async () => {
    const result = await runCorpusCase('claude-hook-node-e');
    assert.equal(findingsOfId(result, 'claude-hook').length, 1);
  });

  it('claude-hook-curl-pipe -> claude-hook (exactly 1) — commandPattern\'s curl | sh alternate', async () => {
    const result = await runCorpusCase('claude-hook-curl-pipe');
    assert.equal(findingsOfId(result, 'claude-hook').length, 1);
  });

  it('claude-hook-safe-control -> zero findings (safe control, no IOC term)', async () => {
    const result = await runCorpusCase('claude-hook-safe-control');
    assert.equal(result.findings.length, 0);
  });

  it('vscode-task-node-e -> vscode-task (exactly 1, fail — not vscode-task-info) — failPattern\'s node -e alternate', async () => {
    const result = await runCorpusCase('vscode-task-node-e');
    assert.equal(findingsOfId(result, 'vscode-task').length, 1);
    assert.equal(findingsOfId(result, 'vscode-task-info').length, 0, 'pre-fix, this fixture was downgraded to vscode-task-info instead of being absent');
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
    const clock = phaseBoundaryClock({ armAt: 'bulk' });
    const t = new Traversal({ roots: [home], spec: SPEC, budget: clock.budget });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, true);
    assert.equal(result.tiers.bulk.complete, false);
    assert.equal(result.incomplete, true);
    assert.equal(findingsOfId(result, 'install-marker').length, 1);
    assert.equal(clock.latchedDuring(), 'bulk', 'the budget must latch while the BULK tier is current -- a latch recorded in any other phase means the engine\'s clock recheck moved relative to the tierComplete gates (defect B1)');
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
// A targeted drain that runs past the budget reports its OWN tier
// incomplete (G-1506, decision D-06) -- the mandatory 1-record and
// 15-record cases the previous version of this plan could not see, because
// its 30-record test only proved the read pool's OWN in-drain recheck
// (READ_POOL_CLOCK_INTERVAL = 16), never the engine's pre-gate recheck that
// backstops a drain BELOW that interval. Both cases here arm the clock at
// `armAt: 'targeted'`, so the latch must occur while the targeted tier
// itself is current -- proving the reorder in engine.js's run() (Task 2
// Part A), not the read pool's own in-drain cadence.
// ---------------------------------------------------------------------------

describe('engine — a targeted drain that runs past the budget reports its own tier incomplete (G-1506, D-06)', () => {
  it('1 record, over budget: targeted tier reports incomplete even though the record was fully read', async () => {
    const home = mkFixture();
    write(path.join(home, 'package.json'), JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } }));
    const clock = phaseBoundaryClock({ armAt: 'targeted' });
    const t = new Traversal({ roots: [home], spec: SPEC, budget: clock.budget });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, false);
    assert.equal(result.tiers.bulk.complete, false);
    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 1, 'D-18: a FAIL finding beats incompleteness');
    assert.equal(findingsOfId(result, 'install-marker').length, 1, 'the single record was read before the latch');
    assert.equal(clock.latchedDuring(), 'targeted');
  });

  it('1 record, within budget (paired control): both tiers complete', async () => {
    const home = mkFixture();
    write(path.join(home, 'package.json'), JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } }));
    const t = new Traversal({ roots: [home], spec: SPEC });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, true);
    assert.equal(result.tiers.bulk.complete, true);
    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 1);
    assert.equal(findingsOfId(result, 'install-marker').length, 1);
  });

  it('15 records, over budget: below READ_POOL_CLOCK_INTERVAL (16) -- the read pool\'s own in-drain recheck fires ZERO times, so this can only pass via the engine\'s pre-gate recheck (Task 2 Part A)', async () => {
    const home = mkFixture();
    const pkg = JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } });
    for (let i = 0; i < 15; i += 1) {
      write(path.join(home, `d${i}`, 'package.json'), pkg);
    }
    const clock = phaseBoundaryClock({ armAt: 'targeted' });
    const t = new Traversal({ roots: [home], spec: SPEC, budget: clock.budget });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, false);
    assert.equal(result.tiers.bulk.complete, false);
    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 1, 'D-18: a FAIL finding beats incompleteness');
    assert.equal(findingsOfId(result, 'install-marker').length, 15, 'all 15 records were read before the latch -- a lower count would be a separate, missing-findings defect');
    assert.equal(clock.latchedDuring(), 'targeted');
  });

  it('15 records, within budget (paired control): both tiers complete, and result.counts.dirsWalked matches the real directory count (proves noteDirectory() calls made by the engine/read-pool never leak into the reported counts)', async () => {
    const home = mkFixture();
    const pkg = JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } });
    for (let i = 0; i < 15; i += 1) {
      write(path.join(home, `d${i}`, 'package.json'), pkg);
    }
    const t = new Traversal({ roots: [home], spec: SPEC });
    const result = await t.run();

    assert.equal(result.tiers.targeted.complete, true);
    assert.equal(result.tiers.bulk.complete, true);
    assert.equal(result.incomplete, false);
    assert.equal(findingsOfId(result, 'install-marker').length, 15);
    assert.equal(result.counts.dirsWalked, 16, '15 subdirectories plus the root');
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
    const clock = phaseBoundaryClock({ armAt: 'bulk' });
    const t = new Traversal({ roots: [home], spec: SPEC, budget: clock.budget });
    const result = await t.run();

    assert.equal(result.exitCode, 1);
    assert.equal(result.incomplete, true);
    assert.ok(result.findings.some((f) => f.severity === 'fail'));
    assert.equal(clock.latchedDuring(), 'bulk', 'the budget must latch while the BULK tier is current -- a latch recorded in any other phase means the engine\'s clock recheck moved relative to the tierComplete gates (defect B1)');
  });

  it('a clean fixture with an exhausted budget -> exitCode 2, incomplete true', async () => {
    const home = mkFixture();
    const clock = phaseBoundaryClock({ armAt: 'bulk' });
    const t = new Traversal({ roots: [home], spec: SPEC, budget: clock.budget });
    const result = await t.run();

    assert.equal(result.findings.length, 0);
    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 2);
    assert.equal(clock.latchedDuring(), 'bulk', 'the budget must latch while the BULK tier is current -- a latch recorded in any other phase means the engine\'s clock recheck moved relative to the tierComplete gates (defect B1)');
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
    const clock = phaseBoundaryClock({ armAt: 'bulk' });
    const t = new Traversal({ roots: [home], spec: SPEC, budget: clock.budget });
    const result = await t.run();

    assert.equal(findingsOfId(result, 'payload-variant-warn').length, 1);
    assert.equal(result.findings.filter((f) => f.severity === 'fail').length, 0);
    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 2);
    assert.equal(clock.latchedDuring(), 'bulk', 'the budget must latch while the BULK tier is current -- a latch recorded in any other phase means the engine\'s clock recheck moved relative to the tierComplete gates (defect B1)');
  });
});

// ---------------------------------------------------------------------------
// ANOMALY reasons (budget, swapped, unreadable) make the scan incomplete;
// SCOPE reasons (oversized, symlink, other-device) never do (G-1501/G-1512,
// TRAV-15, decision D-02b -- FINAL, 17.1-CONTEXT.md; `swapped` added by
// D-01, G-1543/G-1544, 2026-08-12). `oversized` moved
// buckets in this decision -- it used to feed `incomplete` (D-02's blanket
// form, then D-02a's candidate-scoped form, both plan 17.1-01) and no
// longer does under any rule; Guard 3 below pins that directly. `symlink`/
// `other-device` were ALREADY excluded and stay excluded -- this is what
// stops a future agent from "completing the set" and folding all five
// SKIP_REASONS into `incomplete`. The SKIP_REASONS ANOMALY/SCOPE partition
// test further down in this file is what makes a SIXTH, unclassified skip
// reason fail loudly instead of silently doing nothing.
// ---------------------------------------------------------------------------

describe('engine — ANOMALY skip reasons (budget, swapped, unreadable) make the scan incomplete; SCOPE reasons (oversized, symlink, other-device) never do (G-1501/G-1512, D-02b, D-01)', () => {
  it('Guard 1: a chmod 000 subdirectory holding a real marker -> incomplete, exit 2, zero findings (the marker is invisible)', async (t) => {
    if (process.platform === 'win32' || !process.getuid || process.getuid() === 0) {
      t.skip('POSIX permission bits only meaningfully deny access as a non-root, non-Windows user');
      return;
    }
    const home = mkFixture();
    const subdir = path.join(home, 'locked');
    write(path.join(subdir, 'Math_Symbol.js'), '/* stub */\n');
    fs.chmodSync(subdir, 0o000);
    try {
      const t2 = new Traversal({ roots: [home], spec: SPEC });
      const result = await t2.run();

      assert.equal(result.incomplete, true);
      assert.equal(result.exitCode, 2);
      assert.ok(result.skips.counts().unreadable >= 1);
      assert.equal(result.findings.length, 0);
    } finally {
      fs.chmodSync(subdir, 0o755);
    }
  });

  it('Guard 1 paired control: identical fixture shape, permissions left at 0o755 -> incomplete false, exit 1, the marker IS found', async () => {
    const home = mkFixture();
    const subdir = path.join(home, 'unlocked');
    write(path.join(subdir, 'Math_Symbol.js'), '/* stub */\n');
    fs.chmodSync(subdir, 0o755);

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 1);
    assert.equal(result.skips.counts().unreadable, 0);
    assert.equal(findingsOfId(result, 'file-marker').length, 1);
  });

  it('Guard 2: an fs.promises.open() rejecting EACCES for one file -> incomplete, exit 2, even with ZERO findings', async () => {
    const home = mkFixture();
    const target = path.join(home, 'setup.mjs');
    write(target, 'export const setup = () => {};\n');
    const realFs = require('fs');
    const denyingFs = {
      ...realFs,
      promises: {
        ...realFs.promises,
        open: (p, ...rest) => {
          if (p === target) {
            const err = new Error('EACCES: permission denied');
            err.code = 'EACCES';
            return Promise.reject(err);
          }
          return realFs.promises.open(p, ...rest);
        },
      },
    };

    const t2 = new Traversal({ roots: [home], spec: SPEC, fs: denyingFs });
    const result = await t2.run();

    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 2);
    assert.equal(result.findings.filter((f) => f.severity === 'fail').length, 0);
    assert.equal(result.findings.filter((f) => f.severity === 'warn').length, 0);
    assert.equal(result.findings.filter((f) => f.severity === 'info').length, 0);
    assert.equal(result.skips.counts().unreadable, 1);
  });

  it('Guard 2 paired control: the same fixture with the unwrapped fs -> incomplete false, exit 0', async () => {
    const home = mkFixture();
    write(path.join(home, 'setup.mjs'), 'export const setup = () => {};\n');

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
  });

  it('Guard 3 (TRAV-15, D-02b -- FINAL): a marker-config file AT/OVER bulkReadCapBytes still records the oversized skip, but incomplete stays FALSE and exit stays 0 -- oversized is a disclosed SCOPE boundary, not an ANOMALY, superseding the exit-2 behaviour the D-02 blanket form and D-02a candidate-scoping correction both had', async () => {
    const home = mkFixture();
    const cap = normalizeOptions({}).bulkReadCapBytes;
    // .env is a marker-config (targeted-content) member -- benign content
    // (no marker string, no known pattern) padded past the cap, so the
    // read-pool's oversized exclusion fires rather than a content match.
    write(path.join(home, '.env'), `BENIGN=1\n${'#'.repeat(cap)}`);

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
    assert.ok(result.skips.counts().oversized >= 1);
  });

  it('Guard 3 paired control: the identical fixture with the file just UNDER the cap -> incomplete false, exit 0, skips.counts().oversized === 0', async () => {
    const home = mkFixture();
    const cap = normalizeOptions({}).bulkReadCapBytes;
    write(path.join(home, '.env'), `BENIGN=1\n${'#'.repeat(cap - 200)}`);

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
    assert.equal(result.skips.counts().oversized, 0);
  });

  it('Guard 4: symlink stays a deliberately NON-propagated skip reason -- incomplete stays false despite a recorded symlink skip', async () => {
    const home = mkFixture();
    write(path.join(home, 'real.js'), 'console.log(1);\n');
    fs.symlinkSync(path.join(home, 'real.js'), path.join(home, 'link.js'));

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.ok(result.skips.counts().symlink >= 1);
    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
  });
});

// ---------------------------------------------------------------------------
// D-01: a post-classification symlink swap is `swapped`, an ANOMALY, and
// drives exit 2 (G-1543/G-1544, EXIT-03). A symlink `walk.js` REFUSES
// during enumeration is a routine, disclosed SCOPE boundary (Guard 4
// above): the walk sees it, counts it, and moves on. This is the other
// case: a path that PASSED classification as a regular file and became a
// symlink before `lib/traverse/read-pool.js`'s open() ran -- a TOCTOU
// swap the shared `symlink` bucket could never distinguish, which is why
// this earned its own reason (D-03).
// ---------------------------------------------------------------------------

// The fs-seam construction Guard 2 (above) already uses for a targeted
// open() failure: `fs.promises.open` rejects with an ELOOP-coded error for
// exactly one path, delegating to the real implementation for everything
// else. A REAL on-disk symlink swap cannot be arranged deterministically
// without racing the walk itself -- the walk must classify the path as a
// REGULAR file and the pool must then open a SYMLINK at that same path,
// with no window in a single-process test to swap the file on disk between
// the two. The seam is honest as long as the errno and the code path it
// exercises (read-pool.js's ELOOP catch branch) are real, which they are:
// this is the exact errno the open() catch above branches on.
function swapFs(swapPath) {
  const realFs = require('fs');
  return {
    ...realFs,
    promises: {
      ...realFs.promises,
      open: (p, ...rest) => {
        if (p === swapPath) {
          const err = new Error('ELOOP: too many symbolic links encountered');
          err.code = 'ELOOP';
          return Promise.reject(err);
        }
        return realFs.promises.open(p, ...rest);
      },
    },
  };
}

describe('engine — D-01: a post-classification symlink swap is `swapped`, an ANOMALY, and drives exit 2 (G-1543/G-1544)', () => {
  it('a file that passed classification as a regular file but ELOOPs at open() -> incomplete true, exit 2, zero findings, swapped === 1', async () => {
    const home = mkFixture();
    const target = path.join(home, 'setup.mjs');
    write(target, 'export const setup = () => {};\n');

    const t2 = new Traversal({ roots: [home], spec: SPEC, fs: swapFs(target) });
    const result = await t2.run();

    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 2);
    assert.equal(result.findings.filter((f) => f.severity === 'fail').length, 0);
    assert.equal(result.findings.filter((f) => f.severity === 'warn').length, 0);
    assert.equal(result.findings.filter((f) => f.severity === 'info').length, 0);
    assert.equal(result.skips.counts().swapped, 1);
  });

  it('PAIRED CONTROL: the same fixture with the real fs (no ELOOP interception) -> incomplete false, exit 0, swapped === 0', async () => {
    const home = mkFixture();
    write(path.join(home, 'setup.mjs'), 'export const setup = () => {};\n');

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
    assert.equal(result.skips.counts().swapped, 0);
  });

  it('PAIRED CONTROL, the D-01 clean-tree proof: a symlink refused by the WALK (enumeration-time) still yields symlink >= 1, swapped === 0, incomplete false, exit 0 -- the 368-vs-0 measurement in miniature; this is what fails if a future change merges the two reasons or promotes symlink to ANOMALY', async () => {
    const home = mkFixture();
    write(path.join(home, 'real.js'), 'console.log(1);\n');
    fs.symlinkSync(path.join(home, 'real.js'), path.join(home, 'link.js'));

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.ok(result.skips.counts().symlink >= 1);
    assert.equal(result.skips.counts().swapped, 0);
    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
  });

  // Break-proof 1 (MANDATORY, D-12: four named cases -- the per-member
  // classification case, the ANOMALY+SCOPE arithmetic case, the literal-
  // membership pin, AND this end-to-end swap case). Revert ONLY
  // lib/traverse/engine.js's ANOMALY_SKIP_REASONS membership (remove
  // `swapped`, leaving it in SKIP_REASONS and leaving read-pool.js's ELOOP
  // branch recording it), re-run `node --test tests/traverse/engine.test.js
  // tests/traverse/read-pool.test.js`, and record the exact observed
  // failure verbatim (recorded in 18-05-SUMMARY.md). This `it()` above is
  // the fourth named case: it fails by reporting exitCode 0 instead of 2,
  // proving the classification reaches the exit code, not just the set.
  //
  // Break-proof 2 (MANDATORY, D-12: two named cases -- read-pool Case 1 on
  // all three reason assertions AND this end-to-end swap case). Restore
  // ANOMALY_SKIP_REASONS, then revert ONLY lib/traverse/read-pool.js's
  // ELOOP branch (record the old `symlink` reason again instead of
  // `swapped`), re-run, and record the failure verbatim (recorded in
  // 18-05-SUMMARY.md). This `it()` above fails because a `symlink` skip
  // is SCOPE, so exitCode stays 0.
  //
  // Blind spot (MANDATORY, see 18-05-SUMMARY.md for the full statement):
  // these break-proofs prove the post-classification ELOOP path is
  // counted and reaches the exit code. They do NOT prove a real TOCTOU
  // race is detectable -- no test races the walk against a swap, and the
  // guard rests on `O_NOFOLLOW` being kernel-enforced rather than on
  // winning a race. They do NOT prove the Linux errno (assumption A1: man7
  // and POSIX say ELOOP; the first green ubuntu CI leg IS the
  // measurement, and the failure mode if wrong is a failing test, not a
  // silent miss). They do NOT cover an intermediate-path-component
  // symlink, which is the walk's territory. And they say nothing about
  // `other-device`, which D-02 deliberately leaves as SCOPE.
});

// ---------------------------------------------------------------------------
// A short read makes the scan incomplete (exit 2), or exit 1 when the
// partial content still FAILs (D-18) (Task 2, SCAN-04/D-03, G-1541).
// End-to-end guard: pins that the pool-level `record.shortRead` accounting
// (tests/traverse/read-pool.test.js) actually reaches Traversal.run()'s
// incomplete/exitCode contract, and that the partial content is never
// silently dropped from finding generation.
// ---------------------------------------------------------------------------

// Half-then-zero, applied through the Traversal's own `fs` injectable seam:
// the FIRST read on any opened handle returns half the bytes the real read
// actually produced; every subsequent read on that SAME handle returns
// zero. Matches tests/traverse/read-pool.test.js's halfThenZeroFs() shape
// exactly (not shared via a helper module -- each file's local copy stays
// self-contained, matching this file's existing local-stub convention, e.g.
// Guard 2's `denyingFs` above).
function halfThenZeroFs() {
  const realFs = require('fs');
  return {
    ...realFs,
    promises: {
      ...realFs.promises,
      open: async (...args) => {
        const handle = await realFs.promises.open(...args);
        const originalRead = handle.read.bind(handle);
        let callCount = 0;
        return Object.assign(Object.create(Object.getPrototypeOf(handle)), handle, {
          read: async (buffer, offset, length, position) => {
            callCount += 1;
            if (callCount === 1) {
              const real = await originalRead(buffer, offset, length, position);
              return { bytesRead: Math.floor(real.bytesRead / 2), buffer };
            }
            return { bytesRead: 0, buffer };
          },
        });
      },
    },
  };
}

describe('engine — a short read makes the scan incomplete (exit 2), or exit 1 when the partial content still FAILs (D-18) (Task 2, SCAN-04/D-03, G-1541)', () => {
  it('benign fixture, truncating fs -> incomplete true, exit 2, zero findings, unreadable >= 1', async () => {
    const home = mkFixture();
    write(path.join(home, '.npmrc'), `registry=https://registry.npmjs.org/\n${'x'.repeat(200)}\n`);

    const t2 = new Traversal({ roots: [home], spec: SPEC, fs: halfThenZeroFs() });
    const result = await t2.run();

    assert.equal(result.incomplete, true);
    assert.equal(result.exitCode, 2);
    assert.equal(result.findings.filter((f) => f.severity === 'fail').length, 0);
    assert.equal(result.findings.filter((f) => f.severity === 'warn').length, 0);
    assert.equal(result.findings.filter((f) => f.severity === 'info').length, 0);
    assert.ok(result.skips.counts().unreadable >= 1);
  });

  it('PAIRED CONTROL: identical benign fixture, real fs -> incomplete false, exit 0, zero unreadable skips', async () => {
    const home = mkFixture();
    write(path.join(home, '.npmrc'), `registry=https://registry.npmjs.org/\n${'x'.repeat(200)}\n`);

    const t2 = new Traversal({ roots: [home], spec: SPEC });
    const result = await t2.run();

    assert.equal(result.incomplete, false);
    assert.equal(result.exitCode, 0);
    assert.equal(result.skips.counts().unreadable, 0);
  });

  // Marker-in-partial-content fixture: reuses the marker-npmrc corpus case
  // (`; ioc: ${MARKER}\nregistry=https://registry.npmjs.org/\n`, MARKER =
  // 'npm-cache.com'). Measured (node -e against the real corpus builder,
  // recorded in the plan SUMMARY): total file size 58 bytes, marker starts
  // at byte offset 7 and ends at byte offset 20. halfThenZeroFs's first
  // read here returns floor(58/2) = 29 bytes -- well past byte 20, so the
  // marker survives the truncation intact and marker matching still fires
  // over the partial content.
  it('marker-in-partial-content fixture (corpus case marker-npmrc, marker at byte offset 7-20 of a 58-byte file, half-read returns 29 bytes), truncating fs -> exit 1 (D-18: FAIL beats incompleteness), incomplete true, finding still present', async () => {
    const result = await runCorpusCase('marker-npmrc', { fs: halfThenZeroFs() });

    assert.equal(result.exitCode, 1, 'a FAIL finding derived from the partial content must beat incompleteness under D-18 -- this is the guard that fails if result.error had been set instead of result.shortRead');
    assert.equal(result.incomplete, true);
    assert.ok(result.skips.counts().unreadable >= 1);
    const matches = findingsOfId(result, 'marker-string');
    assert.equal(
      matches.length,
      1,
      'the marker-npmrc corpus case promises exactly one marker-string finding; if this count is not 1, STOP and report rather than relaxing the assertion'
    );
  });

  it('PAIRED CONTROL: the marker-npmrc corpus case, real fs -> exit 1, incomplete false, same finding count', async () => {
    const result = await runCorpusCase('marker-npmrc');

    assert.equal(result.exitCode, 1);
    assert.equal(result.incomplete, false);
    const matches = findingsOfId(result, 'marker-string');
    assert.equal(matches.length, 1);
  });

  // Break-proofs 1-3 and their blind spot are Task 2's, defined and
  // recorded alongside the pool-level cases they pair with in
  // tests/traverse/read-pool.test.js's "a short read records ONE
  // unreadable skip per record..." describe block -- the benign
  // end-to-end case above and the marker-in-partial-content case above are
  // the two NAMED cases break-proof 2 and break-proof 3 (respectively)
  // require to fail here; see that block for the full protocol and the
  // plan SUMMARY for the verbatim recorded output.
});

// ---------------------------------------------------------------------------
// SKIP_REASONS ANOMALY/SCOPE partition (D-02b -- FINAL, 17.1-CONTEXT.md,
// G-1512). This test IS the point of the D-02b change: it is what stops
// the "does `oversized` feed `incomplete`?" question from being
// re-litigated a third time (it was: the blanket D-02 form, then the
// D-02a candidate-scoping correction, both plan 17.1-01, both now
// superseded and removed -- see 17.1-01-SUMMARY.md's "D-02a Correction"
// and "D-02b" sections for the full history).
//
// Structural guarantee asserted below: every member of `SKIP_REASONS`
// belongs to EXACTLY ONE of `ANOMALY_SKIP_REASONS` / `SCOPE_SKIP_REASONS`
// -- no reason omitted, none in both. A future agent adding a sixth skip
// reason to `lib/traverse/index.js`'s `SKIP_REASONS` array without also
// classifying it in `lib/traverse/engine.js` fails THIS test, with a
// message naming exactly which reason is unclassified, rather than
// silently leaving the new reason's effect on `incomplete` ambiguous.
// ---------------------------------------------------------------------------
describe('engine — SKIP_REASONS ANOMALY/SCOPE partition (D-02b -- FINAL, supersedes D-02/D-02a)', () => {
  it('every SKIP_REASONS member belongs to EXACTLY ONE of ANOMALY_SKIP_REASONS / SCOPE_SKIP_REASONS', () => {
    for (const reason of SKIP_REASONS) {
      const inAnomaly = ANOMALY_SKIP_REASONS.has(reason);
      const inScope = SCOPE_SKIP_REASONS.has(reason);
      assert.ok(
        inAnomaly || inScope,
        `SKIP_REASONS member "${reason}" is not classified into ANOMALY_SKIP_REASONS or ` +
          'SCOPE_SKIP_REASONS -- D-02b (17.1-CONTEXT.md) requires every skip reason be explicitly ' +
          'classified before it can affect (ANOMALY) or be excluded from (SCOPE) `incomplete`. Add ' +
          'it to one of the two sets in lib/traverse/engine.js.'
      );
      assert.ok(
        !(inAnomaly && inScope),
        `SKIP_REASONS member "${reason}" is classified into BOTH ANOMALY_SKIP_REASONS and ` +
          'SCOPE_SKIP_REASONS -- a skip reason must mean exactly one of "I tried to look and could ' +
          'not" (ANOMALY) or "I deliberately did not look there" (SCOPE), never both.'
      );
    }
  });

  it('ANOMALY_SKIP_REASONS and SCOPE_SKIP_REASONS contain no stale entries outside SKIP_REASONS, and their sizes sum to SKIP_REASONS.length', () => {
    const reasonSet = new Set(SKIP_REASONS);
    for (const r of ANOMALY_SKIP_REASONS) {
      assert.ok(reasonSet.has(r), `ANOMALY_SKIP_REASONS has stale entry "${r}" no longer present in SKIP_REASONS`);
    }
    for (const r of SCOPE_SKIP_REASONS) {
      assert.ok(reasonSet.has(r), `SCOPE_SKIP_REASONS has stale entry "${r}" no longer present in SKIP_REASONS`);
    }
    assert.equal(
      ANOMALY_SKIP_REASONS.size + SCOPE_SKIP_REASONS.size,
      SKIP_REASONS.length,
      'ANOMALY_SKIP_REASONS.size + SCOPE_SKIP_REASONS.size must equal SKIP_REASONS.length -- a ' +
        'mismatch combined with the previous two assertions passing would mean an impossible state ' +
        '(duplicate membership within one set); this is a belt-and-suspenders arithmetic check'
    );
  });

  it('today\'s concrete classification matches D-02b\'s decision table exactly', () => {
    // Pins the CURRENT membership literally, not just the structural
    // partition property above -- a future agent could satisfy the
    // partition test by moving `unreadable` into SCOPE (structurally
    // valid, semantically wrong) without this second check catching it.
    assert.deepEqual([...ANOMALY_SKIP_REASONS].sort(), ['budget', 'swapped', 'unreadable']);
    assert.deepEqual([...SCOPE_SKIP_REASONS].sort(), ['other-device', 'oversized', 'symlink']);
  });

  // Non-vacuity proof (this describe block's own break-proof, recorded
  // verbatim in 17.1-01-SUMMARY.md's "D-02b" section): temporarily adding a
  // SIXTH, unclassified reason to a LOCAL copy of SKIP_REASONS (never
  // mutating the frozen real one, which would break every other test in
  // this suite) and asserting the exact same partition logic the first
  // `it` above runs, fails on that reason. This is the reusable half of the
  // "revert the guard, observe failure, quote it" discipline -- this
  // `it()` codifies the check as a permanent regression guard; the actual
  // break-proof (temporarily editing SKIP_REASONS itself and re-running
  // `node --test`) is recorded as verbatim output in the SUMMARY, since a
  // frozen exported array cannot be safely mutated from within a test file
  // without risking cross-test pollution (SKIP_REASONS is `Object.freeze`d
  // and shared by reference across every file that imports it).
  it('non-vacuity: a hypothetical sixth, unclassified reason fails the SAME partition assertion the real test above runs', () => {
    const hypotheticalReasons = [...SKIP_REASONS, 'quarantined'];
    let sawFailure = false;
    for (const reason of hypotheticalReasons) {
      const inAnomaly = ANOMALY_SKIP_REASONS.has(reason);
      const inScope = SCOPE_SKIP_REASONS.has(reason);
      if (reason === 'quarantined') {
        assert.ok(!inAnomaly && !inScope, 'the hypothetical reason must not already be classified (test setup sanity)');
        sawFailure = true;
      } else {
        assert.ok(inAnomaly || inScope, `real SKIP_REASONS member "${reason}" unexpectedly unclassified`);
      }
    }
    assert.ok(sawFailure, 'the hypothetical sixth reason must have been observed as unclassified -- proves this loop is not vacuous');
  });
});

// ---------------------------------------------------------------------------
// TARGETED_CONTENT_CLASSES -- D-02b (17.1-CONTEXT.md) retired the D-02a
// `countCandidateOversizedSkips` helper and its describe block (which used
// to pin this set's membership as a side effect of testing that helper),
// but `TARGETED_CONTENT_CLASSES` itself is UNCHANGED and still live
// production logic (`buildWorkFlags`'s `needTargetedContent`, above) -- so
// its membership stays pinned directly here rather than losing coverage
// when the helper that used to exercise it was removed.
// ---------------------------------------------------------------------------
describe('engine — TARGETED_CONTENT_CLASSES (live export, still drives buildWorkFlags\' needTargetedContent)', () => {
  it('is exactly the four targeted-content classes', () => {
    assert.deepEqual([...TARGETED_CONTENT_CLASSES].sort(), ['agent-config', 'family-packages', 'marker-config', 'no-prune']);
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
// enumerateSync() reports truncation (G-1511, TRAV-14) -- the sibling
// honesty defect to G-1501/G-1506 (17.1-01), in the read-free enumeration
// path lib/scan.js's `.env` secret scan is the sole real-tree consumer of.
// `walkResult.stopped` was computed by walk() and silently discarded by
// enumerateSync()'s final `return` -- a large tree could exhaust the
// DEFAULT budget (this path passes none of its own) and `llm-safe-haven
// scan` would report clean without having examined the whole tree.
// ---------------------------------------------------------------------------

describe('engine — enumerateSync() reports truncation (G-1511, TRAV-14)', () => {
  const ENV_FILE_COUNT = 5;
  const OTHER_FILE_COUNT = 15;

  // A FLAT fixture (all entries direct children of `home`) so `maxFiles`'s
  // clock-free, per-entry `noteFile()` enforcement latches deterministically
  // regardless of filesystem readdirSync ordering -- `maxFiles: 3` permits
  // exactly 3 of the 20 total entries to be emitted, so `byClass` can never
  // capture more than 3, strictly fewer than the 5 planted `.env` variants,
  // no matter which 3 entries the filesystem happens to return first.
  function buildFlatFixture() {
    const home = mkFixture();
    for (let i = 0; i < ENV_FILE_COUNT; i++) {
      write(path.join(home, `.env.variant${i}`), `SECRET_${i}=1\n`);
    }
    for (let i = 0; i < OTHER_FILE_COUNT; i++) {
      write(path.join(home, `noise-${i}.txt`), 'not a secret\n');
    }
    return home;
  }

  it('Guard 1: maxFiles: 3 latches the enumeration -- stopped === true, and byClass captures fewer than the 5 planted .env files', () => {
    const home = buildFlatFixture();
    const result = new Traversal({ roots: [home], classes: ['env-secrets'], maxFiles: 3 }).enumerateSync();
    assert.strictEqual(result.stopped, true, 'a maxFiles: 3 latch over 20 entries must report stopped === true');
    assert.ok(
      result.byClass.get('env-secrets').length < ENV_FILE_COUNT,
      `a truncated enumeration must capture fewer than the ${ENV_FILE_COUNT} planted .env files, got ${result.byClass.get('env-secrets').length}`
    );
  });

  it('Guard 2 (paired control): the identical fixture with no maxFiles override -- stopped === false, every planted .env file present', () => {
    const home = buildFlatFixture();
    const result = new Traversal({ roots: [home], classes: ['env-secrets'] }).enumerateSync();
    assert.strictEqual(result.stopped, false, 'an unbounded walk over 20 entries (far under the default 1,000,000-file backstop) must not latch');
    assert.strictEqual(
      result.byClass.get('env-secrets').length,
      ENV_FILE_COUNT,
      'the complete enumeration must capture every planted .env file -- without this control, Guard 1 would also pass against an enumeration that returns nothing at all'
    );
  });

  it('Guard 3: the returned object has exactly the keys [byClass, counts, skips, stopped]', () => {
    const home = buildFlatFixture();
    const result = new Traversal({ roots: [home], classes: ['env-secrets'] }).enumerateSync();
    assert.deepEqual(
      Object.keys(result).sort(),
      ['byClass', 'counts', 'skips', 'stopped'],
      "a future addition to enumerateSync()'s return value must be a deliberate, visible act, not a silent shape drift"
    );
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
