'use strict';

// Results-directory protocol tests (G-1482, TRAV-01, D-04/D-16, plan 17-12
// Task 3). Proves the B5 guard from 17-VALIDATION.md: a finding whose path
// contains a literal TAB and newline round-trips as exactly four
// NUL-delimited fields, with a paired negative proving a TAB-separated
// layout would have desynchronised on the SAME input -- the concrete
// evidence that NUL delimiting is load-bearing here, not cosmetic.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { RESULTS_SCHEMA_VERSION, writeResults } = require('../../lib/traverse/results.js');
const { createSkipInventory, SKIP_REASONS, FILE_CLASSES } = require('../../lib/traverse/index.js');
const { Traversal } = require('../../lib/traverse/engine.js');

const SPEC_PATH = path.join(__dirname, '..', '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
const REAL_SPEC = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));

function cloneSpec() {
  return JSON.parse(JSON.stringify(REAL_SPEC));
}

const dirs = [];
function mkResultsDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'results-protocol-'));
  dirs.push(dir);
  return dir;
}
function mkFixtureRoot(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}
function writeFixtureFile(filePath, contents) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, contents);
}
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

// Builds a synthetic TraverseResult -- the shape `Traversal.run()` returns.
function buildResult(overrides = {}) {
  const skips = createSkipInventory();
  for (const [reason, absPath] of overrides.skipEntries || []) {
    skips.add(reason, absPath);
  }
  return {
    findings: overrides.findings || [],
    skips,
    counts: overrides.counts || { filesWalked: 3, dirsWalked: 2, rootsWalked: 1 },
    degradations: overrides.degradations || [],
    tiers: overrides.tiers || { targeted: { complete: true }, bulk: { complete: true } },
    incomplete: overrides.incomplete || false,
    exitCode: typeof overrides.exitCode === 'number' ? overrides.exitCode : 0,
  };
}

function readNulEntries(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  if (raw === '') return [];
  const parts = raw.split('\0');
  // A trailing NUL after every entry means the split produces one trailing
  // empty string -- drop it.
  if (parts[parts.length - 1] === '') parts.pop();
  return parts;
}

// ---------------------------------------------------------------------------
describe('results.js — round-trip', () => {
  it('writes findings.json with every documented field, including resultsSchemaVersion and severityCounts', () => {
    const dir = mkResultsDir();
    const result = buildResult({
      findings: [
        { id: 'file-marker', class: 'all-files', absPath: '/x/Math_Symbol.js', detail: 'ChainDrop marker', severity: 'fail' },
        { id: 'setup-bare', class: 'all-files', absPath: '/x/setup.mjs', detail: 'benign', severity: 'warn' },
        { id: 'vscode-task-info', class: 'agent-config', absPath: '/x/.vscode/tasks.json', detail: 'info', severity: 'info' },
      ],
      degradations: ['no-git'],
      incomplete: false,
      exitCode: 1,
    });

    writeResults(dir, result, cloneSpec(), { roots: ['/x'], elapsedMs: 42 });

    const envelope = JSON.parse(fs.readFileSync(path.join(dir, 'findings.json'), 'utf8'));
    assert.equal(envelope.resultsSchemaVersion, RESULTS_SCHEMA_VERSION);
    assert.equal(envelope.resultsSchemaVersion, 1);
    assert.equal(envelope.wave, REAL_SPEC.wave);
    assert.equal(envelope.specVersion, REAL_SPEC.specVersion);
    assert.equal(envelope.exitCode, 1);
    assert.equal(envelope.incomplete, false);
    assert.deepEqual(envelope.tiers, { targeted: { complete: true }, bulk: { complete: true } });
    assert.equal(envelope.counts.filesWalked, 3);
    assert.equal(envelope.counts.dirsWalked, 2);
    assert.equal(envelope.counts.rootsWalked, 1);
    assert.equal(envelope.counts.elapsedMs, 42);
    assert.equal(typeof envelope.counts.candidatesRead, 'number');
    assert.deepEqual(envelope.severityCounts, { fail: 1, warn: 1, info: 1 });
    assert.deepEqual(envelope.degradations, [{ repoRoot: null, reason: 'no-git' }]);
    assert.equal(envelope.findings.length, 3);
    assert.deepEqual(envelope.findings[0], { id: 'file-marker', class: 'all-files', path: '/x/Math_Symbol.js', detail: 'ChainDrop marker', severity: 'fail' });
    assert.deepEqual(envelope.roots, ['/x']);
    for (const reason of SKIP_REASONS) {
      assert.ok(Object.prototype.hasOwnProperty.call(envelope.skips, reason), `skips.${reason} missing`);
    }
  });
});

// ---------------------------------------------------------------------------
describe('results.js — hostile filenames (T-17-10)', () => {
  it('a path containing a literal newline and a path containing a space+quote round-trip as exactly two entries when split on NUL, but the WRONG count when split on newline', () => {
    const dir = mkResultsDir();
    // Two embedded newlines in the first path -- splitting on newline must
    // produce 3 pieces (wrong), while splitting on NUL must produce the
    // correct 2 entries.
    const withNewline = '/roots/weird\nname\nfile.js';
    const withSpaceQuote = "/roots/has space and 'quote'.js";
    const result = buildResult();

    writeResults(dir, result, cloneSpec(), { byClass: { 'all-files': [withNewline, withSpaceQuote] } });

    const listPath = path.join(dir, 'lists', 'all-files.z');
    const nulEntries = readNulEntries(listPath);
    assert.deepEqual(nulEntries, [withNewline, withSpaceQuote]);
    assert.equal(nulEntries.length, 2);

    // Non-vacuity: splitting the SAME file on newline is provably wrong --
    // the two embedded newlines in the first path shred it into extra
    // pieces, so the newline-split count (3) does NOT equal the correct
    // NUL-split entry count (2).
    const raw = fs.readFileSync(listPath, 'utf8');
    const wrongSplit = raw.split('\n');
    assert.notEqual(wrongSplit.length, 2, 'newline-splitting must NOT produce the correct count -- proves NUL delimiting is load-bearing');
    assert.equal(wrongSplit.length, 3);
  });

  it('B5 — a finding whose path contains a TAB and a newline, and whose detail contains a TAB, round-trips as exactly four NUL-delimited fields with a byte-identical path; a TAB split of the SAME record desynchronises', () => {
    const dir = mkResultsDir();
    // Multiple TABs in both path and detail so a TAB split unambiguously
    // produces far more than four pieces (not a coincidental near-miss).
    const hostilePath = '/roots/weird\tna\tme\nwith-newline.js';
    const hostileDetail = 'detail\twith\ta\ttab\tinside';
    const result = buildResult({
      findings: [{ id: 'marker-string', class: 'bulk-content', absPath: hostilePath, detail: hostileDetail, severity: 'fail' }],
    });

    writeResults(dir, result, cloneSpec());

    const raw = fs.readFileSync(path.join(dir, 'lists', 'findings.z'), 'utf8');
    const nulFields = raw.split('\0');
    // Trailing NUL after the last field produces one trailing empty string.
    assert.equal(nulFields[nulFields.length - 1], '');
    nulFields.pop();
    assert.equal(nulFields.length, 4, 'exactly four NUL-delimited fields for one finding record');
    const [id, severity, recordPath, recordDetail] = nulFields;
    assert.equal(id, 'marker-string');
    assert.equal(severity, 'fail');
    assert.equal(recordPath, hostilePath, 'path must round-trip byte-identical');
    assert.equal(recordDetail, hostileDetail);

    // Non-vacuity: a TAB split of the SAME raw bytes desynchronises --
    // proves the TAB inside `path` really would have shifted a
    // TAB-delimited reader's field alignment.
    const tabFields = raw.split('\t');
    assert.ok(tabFields.length > 4, 'a TAB-separated layout would have produced MORE than four fields on this exact input');
  });

  it('scalars/finding-count equals the number of records actually written, including the hostile-filename record', () => {
    const dir = mkResultsDir();
    const result = buildResult({
      findings: [
        { id: 'file-marker', class: 'all-files', absPath: '/a.js', detail: 'd1', severity: 'fail' },
        { id: 'marker-string', class: 'bulk-content', absPath: '/b\twith\ttabs.js', detail: 'd2', severity: 'fail' },
        { id: 'setup-bare', class: 'all-files', absPath: '/c.js', detail: 'd3', severity: 'warn' },
      ],
    });

    writeResults(dir, result, cloneSpec());

    const findingCount = fs.readFileSync(path.join(dir, 'scalars', 'finding-count'), 'utf8').trim();
    assert.equal(Number(findingCount), 3);
    assert.equal(Number(findingCount), result.findings.length);
  });

  it('a NUL byte in a finding path makes writeResults throw before writing anything', () => {
    const dir = mkResultsDir();
    const result = buildResult({
      findings: [{ id: 'file-marker', class: 'all-files', absPath: '/a\0b.js', detail: 'd', severity: 'fail' }],
    });

    assert.throws(() => writeResults(dir, result, cloneSpec()));
    assert.deepEqual(fs.readdirSync(dir), [], 'nothing should have been written to resultsDir');
  });
});

// ---------------------------------------------------------------------------
describe('results.js — scalars', () => {
  it('every documented scalar exists, contains exactly one line, and parses as an integer; skip-<reason> is present and zero-filled when unused', () => {
    const dir = mkResultsDir();
    const result = buildResult({
      findings: [{ id: 'file-marker', class: 'all-files', absPath: '/a.js', detail: 'd', severity: 'fail' }],
      skipEntries: [['symlink', '/x/ignored.js']],
    });

    writeResults(dir, result, cloneSpec(), { elapsedMs: 123 });

    const documented = [
      'exit-code', 'incomplete', 'finding-count', 'fail-count', 'warn-count', 'info-count',
      'targeted-complete', 'bulk-complete', 'elapsed-ms', 'files-walked', 'dirs-walked', 'degradation-count',
    ];
    for (const name of documented) {
      const filePath = path.join(dir, 'scalars', name);
      assert.ok(fs.existsSync(filePath), `scalars/${name} missing`);
      const raw = fs.readFileSync(filePath, 'utf8');
      const lines = raw.split('\n').filter((l) => l !== '');
      assert.equal(lines.length, 1, `scalars/${name} must contain exactly one line`);
      assert.ok(Number.isInteger(Number(lines[0])), `scalars/${name} must parse as an integer`);
    }

    for (const reason of SKIP_REASONS) {
      const filePath = path.join(dir, 'scalars', `skip-${reason}`);
      assert.ok(fs.existsSync(filePath), `scalars/skip-${reason} missing`);
      const value = Number(fs.readFileSync(filePath, 'utf8').trim());
      if (reason === 'symlink') {
        assert.equal(value, 1);
      } else {
        assert.equal(value, 0, `scalars/skip-${reason} should be zero-filled when unused`);
      }
    }

    assert.equal(fs.readFileSync(path.join(dir, 'scalars', 'elapsed-ms'), 'utf8').trim(), '123');
    assert.equal(fs.readFileSync(path.join(dir, 'scalars', 'fail-count'), 'utf8').trim(), '1');
  });
});

// ---------------------------------------------------------------------------
describe('results.js — spec/*.txt lists', () => {
  it('poisoned-versions.txt has exactly one name@version per line, matching the spec exactly', () => {
    const dir = mkResultsDir();
    const spec = cloneSpec();
    writeResults(dir, buildResult(), spec);

    const lines = fs.readFileSync(path.join(dir, 'spec', 'poisoned-versions.txt'), 'utf8').split('\n').filter((l) => l !== '');
    const expected = [];
    for (const [pkg, versions] of Object.entries(spec.poisonedVersions)) {
      for (const v of versions) expected.push(`${pkg}@${v}`);
    }
    assert.deepEqual(lines, expected);
  });

  it('watcher-paths.txt and shell-history-paths.txt are present and non-empty', () => {
    const dir = mkResultsDir();
    writeResults(dir, buildResult(), cloneSpec());

    const watcher = fs.readFileSync(path.join(dir, 'spec', 'watcher-paths.txt'), 'utf8').split('\n').filter((l) => l !== '');
    const shellHistory = fs.readFileSync(path.join(dir, 'spec', 'shell-history-paths.txt'), 'utf8').split('\n').filter((l) => l !== '');
    assert.ok(watcher.length > 0);
    assert.ok(shellHistory.length > 0);
  });

  it('a spec mutated to contain a newline inside a scalar makes writeResults throw before writing anything', () => {
    const dir = mkResultsDir();
    const spec = cloneSpec();
    spec.markerStrings[0] = `evil\nmarker`;

    assert.throws(() => writeResults(dir, buildResult(), spec));
    assert.deepEqual(fs.readdirSync(dir), [], 'nothing should have been written to resultsDir');
  });
});

// ---------------------------------------------------------------------------
describe('results.js — permissions and symlink refusal', () => {
  it('lists/, skips/, scalars/, spec/ are mode 0700 and their files are mode 0600', { skip: process.platform === 'win32' }, () => {
    const dir = mkResultsDir();
    writeResults(dir, buildResult({ findings: [{ id: 'file-marker', class: 'all-files', absPath: '/a.js', detail: 'd', severity: 'fail' }] }), cloneSpec());

    for (const sub of ['lists', 'skips', 'scalars', 'spec']) {
      const subDir = path.join(dir, sub);
      const dirMode = fs.statSync(subDir).mode & 0o777;
      assert.equal(dirMode, 0o700, `${sub}/ must be mode 0700`);
      for (const name of fs.readdirSync(subDir)) {
        const fileMode = fs.statSync(path.join(subDir, name)).mode & 0o777;
        assert.equal(fileMode, 0o600, `${sub}/${name} must be mode 0600`);
      }
    }
  });

  it('refuses a resultsDir that does not exist', () => {
    const missing = path.join(os.tmpdir(), `results-protocol-missing-${Date.now()}`);
    assert.throws(() => writeResults(missing, buildResult(), cloneSpec()));
    assert.equal(fs.existsSync(missing), false);
  });

  it('refuses a resultsDir that is a regular file, not a directory', () => {
    const parent = mkResultsDir();
    const filePath = path.join(parent, 'not-a-dir');
    fs.writeFileSync(filePath, 'not a directory\n');
    assert.throws(() => writeResults(filePath, buildResult(), cloneSpec()));
  });

  it('refuses a symlinked resultsDir with a throw and writes nothing', () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'results-protocol-symlink-'));
    dirs.push(parent);
    const target = path.join(parent, 'target');
    const link = path.join(parent, 'link');
    fs.mkdirSync(target);
    fs.symlinkSync(target, link, 'dir');

    assert.throws(() => writeResults(link, buildResult(), cloneSpec()));
    assert.deepEqual(fs.readdirSync(target), [], 'nothing should have been written through the symlink');
  });
});

// ---------------------------------------------------------------------------
describe('results.js — FILE_CLASSES / SKIP_REASONS completeness', () => {
  it('every SKIP_REASONS key is present in findings.json.skips, zero-filled when unused', () => {
    const dir = mkResultsDir();
    writeResults(dir, buildResult(), cloneSpec());
    const envelope = JSON.parse(fs.readFileSync(path.join(dir, 'findings.json'), 'utf8'));
    for (const reason of SKIP_REASONS) {
      assert.equal(envelope.skips[reason], 0);
    }
  });

  it('writes a lists/<class>.z file for every FILE_CLASSES entry', () => {
    const dir = mkResultsDir();
    writeResults(dir, buildResult(), cloneSpec());
    for (const cls of FILE_CLASSES) {
      assert.ok(fs.existsSync(path.join(dir, 'lists', `${cls}.z`)), `lists/${cls}.z missing`);
    }
  });
});

// ---------------------------------------------------------------------------
// G-1502 / TRAV-10 -- with run.js no longer sourcing lists/<class>.z from a
// second, independently-budgeted enumeration pass (plan 17.1-04 Task 2),
// run()'s own byClass must (a) agree with enumerateSync()'s on a complete
// scan, and (b) provably diverge as a proper SUBSET, not a coincidental
// smaller set, when the single shared budget latches mid-walk (decision
// D-08). Guard 3 alone would only prove plumbing agreement on a fixture too
// small to latch; Guard 5 is the load-bearing proof the single-walk
// guarantee actually matters.
describe('engine.js — run().byClass and enumerateSync().byClass (G-1502, D-08)', () => {
  it('Guard 3: on a small, non-latching fixture spanning multiple classes, run().byClass and enumerateSync().byClass agree exactly, per class, across all 8 FILE_CLASSES', async () => {
    const root = mkFixtureRoot('results-protocol-crosscheck-');
    // Deliberately spans 7 of the 8 FILE_CLASSES (bulk-content can no longer
    // be assigned by classify() at all -- see classify.js's module header --
    // so an empty bulk-content bucket on both sides is the correct, non-
    // vacuous outcome for that one class, not a gap in this fixture).
    writeFixtureFile(path.join(root, 'Projects', 'a', 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));
    writeFixtureFile(path.join(root, 'node_modules', 'keyv', 'package.json'), JSON.stringify({ name: 'keyv', version: '1.0.0' }));
    writeFixtureFile(path.join(root, '.claude', 'settings.json'), '{}');
    writeFixtureFile(path.join(root, '.env'), 'BENIGN=1\n');
    writeFixtureFile(path.join(root, 'Math_Symbol.js'), '/* stub */\n');

    const spec = cloneSpec();
    const runResult = await new Traversal({ roots: [root], spec }).run();
    const enumResult = new Traversal({ roots: [root], classes: FILE_CLASSES, spec }).enumerateSync();

    let nonEmptyClasses = 0;
    for (const cls of FILE_CLASSES) {
      const runPaths = (runResult.byClass.get(cls) || []).slice().sort();
      const enumPaths = (enumResult.byClass.get(cls) || []).slice().sort();
      assert.deepEqual(runPaths, enumPaths, `class "${cls}" disagrees between run().byClass and enumerateSync().byClass`);
      if (runPaths.length > 0) nonEmptyClasses += 1;
    }
    assert.ok(
      nonEmptyClasses >= 5,
      `fixture must exercise multiple non-empty classes so this proves real agreement, not vacuous agreement on empties (saw ${nonEmptyClasses} non-empty classes)`
    );
    // Sanity: the bare package-lock.json needs zero read-pool work (it is
    // not a hash candidate and `lockfiles` is in neither
    // TARGETED_CONTENT_CLASSES nor bulk-content) yet still reached
    // run().byClass -- the exact class of file the naive fix would have
    // dropped (Task 3's Guard 1/break-proof 1 below reproduces this at the
    // process boundary).
    assert.ok(
      (runResult.byClass.get('lockfiles') || []).some((p) => p.endsWith(path.join('Projects', 'a', 'package-lock.json'))),
      'a bare, zero-read-pool-work package-lock.json must reach run().byClass.lockfiles'
    );
  });

  it('Guard 5 (D-08): under a maxFiles latch, run().byClass is a STRICT per-class SUBSET of the full enumerateSync().byClass, never equal', async () => {
    const root = mkFixtureRoot('results-protocol-latch-');
    const TOTAL_DIRS = 40; // 40 subdirectories x (1 dir-entry + 1 file-entry) = 80 walk entries total
    for (let i = 0; i < TOTAL_DIRS; i += 1) {
      writeFixtureFile(path.join(root, `d${i}`, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));
    }

    const spec = cloneSpec();
    const MAX_FILES = 20; // well below the fixture's 80-entry walk (noteFile() counts both directory AND file entries)

    const runResult = await new Traversal({ roots: [root], spec, maxFiles: MAX_FILES }).run();
    assert.equal(runResult.incomplete, true, 'the maxFiles bound must actually latch this run -- otherwise this case silently degrades into Guard 3 again (D-08)');
    assert.equal(runResult.tiers.targeted.complete, false, 'an enumeration-phase latch cuts the targeted tier too (D-20) -- confirms this is NOT a non-latching run');

    const enumResult = new Traversal({ roots: [root], classes: FILE_CLASSES, spec }).enumerateSync();

    let totalRun = 0;
    let totalEnum = 0;
    let sawStrictlyFewer = false;
    for (const cls of FILE_CLASSES) {
      const runPaths = new Set(runResult.byClass.get(cls) || []);
      const enumPaths = new Set(enumResult.byClass.get(cls) || []);
      for (const p of runPaths) {
        assert.ok(enumPaths.has(p), `class "${cls}": every path in run().byClass must also be in enumerateSync().byClass (subset relation) -- missing ${p}`);
      }
      totalRun += runPaths.size;
      totalEnum += enumPaths.size;
      if (runPaths.size < enumPaths.size) sawStrictlyFewer = true;
    }
    // A plain deep-equality assertion here would be WRONG (see the plan's
    // own action text) -- this must be a PROPER subset, strictly smaller.
    assert.ok(
      totalRun < totalEnum,
      `total run().byClass count (${totalRun}) must be STRICTLY LESS than the full enumeration's (${totalEnum}) -- a proper subset, not equality`
    );
    assert.ok(sawStrictlyFewer, 'at least one FILE_CLASSES member must have strictly fewer entries under run() than under the full enumeration');

    const runLockfiles = new Set(runResult.byClass.get('lockfiles') || []);
    const enumLockfiles = enumResult.byClass.get('lockfiles') || [];
    const missing = enumLockfiles.filter((p) => !runLockfiles.has(p));
    assert.ok(missing.length > 0, 'the missing set (full enumeration minus run()) must be non-empty for the lockfiles class');
    assert.ok(missing.every((p) => !runLockfiles.has(p)), 'the missing set must be disjoint from run()\'s own paths, by construction of a set difference');
    assert.equal(enumLockfiles.length, TOTAL_DIRS, `sanity: the full, unbudgeted enumeration must see all ${TOTAL_DIRS} lockfiles`);
    assert.ok(
      runLockfiles.size > 0 && runLockfiles.size < TOTAL_DIRS,
      `sanity: the latched run() must have captured SOME but not ALL lockfiles (captured ${runLockfiles.size} of ${TOTAL_DIRS}) -- proves the fixture is large enough to straddle the latch point`
    );

    // INTENDED post-G-1502 behaviour, not a defect: one budget now governs
    // both findings AND lists, so an incomplete scan yields shorter class
    // lists than the old two-budget arrangement would have produced (which
    // let the second, unbudgeted pass enumerate further than the findings
    // pass ever examined). Plan 17.1-06's release note must mention this.
  });
});
