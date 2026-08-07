'use strict';

// Argv entry point behavioural tests (G-1482, TRAV-04, D-04/D-05/D-18/D-19,
// plan 17-12 Task 3). Drives `lib/traverse/run.js` with real `spawnSync`
// process-boundary invocations -- this is the ONLY suite that proves the
// D-18 exit-precedence rule and the D-05 fail-closed spec gate hold at the
// actual process boundary, not just inside the unit-level `computeExit`
// table (tests/traverse/exit-precedence.test.js).
//
// DEVIATION FROM 17-VALIDATION.md's literal wording for the "findings +
// incomplete -> exit 1" case: the doc (and this plan's own Task 3 action
// text) describes using `LSH_BUDGET_SECONDS=0` for that scenario. Empirically
// proven false during this plan's execution (see the comment on the test
// below): `budget.js`'s zero-bound latches on the WALK's very first
// `noteDirectory()` call, which is made for the ROOT directory itself
// (lib/traverse/walk.js:188) -- BEFORE any of the root's own children are
// ever emitted. A `LSH_BUDGET_SECONDS=0` run can therefore NEVER discover a
// marker file, no matter how shallow, and can only ever produce
// `incomplete: true` with ZERO findings (exit 2) -- verified below in the
// "budget exhausted with no fail findings" case. `LSH_MAX_FILES=1` across
// TWO roots (array order is caller-controlled and fully deterministic --
// lib/roots.js never reorders) is the only deterministic way to let one
// finding survive while still forcing `incomplete: true`, so it is used for
// that one case instead.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RUN_JS = path.join(__dirname, '..', '..', 'lib', 'traverse', 'run.js');
const SPEC_PATH = path.join(__dirname, '..', '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
const REAL_SPEC = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));

const dirs = [];
function mkDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function writeFile(filePath, contents) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, contents);
}

function runCli(args, extraEnv = {}) {
  return spawnSync('node', [RUN_JS, ...args], {
    encoding: 'utf8',
    timeout: 30_000, // non-functional -- every case must terminate well within this
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...extraEnv },
  });
}

function readFindingsJson(resultsDir) {
  return JSON.parse(fs.readFileSync(path.join(resultsDir, 'findings.json'), 'utf8'));
}

function readScalar(resultsDir, name) {
  return Number(fs.readFileSync(path.join(resultsDir, 'scalars', name), 'utf8').trim());
}

// ---------------------------------------------------------------------------
describe('run.js — argv and gate refusals (all exit 2, all print nothing to stdout)', () => {
  it('no arguments -> exit 2, usage printed on stderr, stdout empty', () => {
    const res = runCli([]);
    assert.equal(res.status, 2);
    assert.match(res.stderr, /Usage:/);
    assert.equal(res.stdout, '');
  });

  it('an unknown flag -> exit 2, stdout empty', () => {
    const res = runCli(['--bogus']);
    assert.equal(res.status, 2);
    assert.equal(res.stdout, '');
  });

  it('an invalid spec (specVersion 2) -> exit 2, stderr names specVersion, stdout empty', () => {
    const specDir = mkDir('run-cli-badspec-');
    const badSpec = JSON.parse(JSON.stringify(REAL_SPEC));
    badSpec.specVersion = 2;
    const badSpecPath = path.join(specDir, 'bad-spec.json');
    writeFile(badSpecPath, JSON.stringify(badSpec));
    const resultsDir = mkDir('run-cli-results-');
    const emptyRoot = mkDir('run-cli-root-');

    const res = runCli(['--spec', badSpecPath, '--results-dir', resultsDir, '--roots', emptyRoot]);
    assert.equal(res.status, 2);
    assert.match(res.stderr, /specVersion/);
    assert.equal(res.stdout, '');
  });

  it('a missing --results-dir -> exit 2, writes nothing, stdout empty', () => {
    const missing = path.join(os.tmpdir(), `run-cli-does-not-exist-${Date.now()}`);
    const emptyRoot = mkDir('run-cli-root-');
    const res = runCli(['--spec', SPEC_PATH, '--results-dir', missing, '--roots', emptyRoot]);
    assert.equal(res.status, 2);
    assert.equal(fs.existsSync(missing), false);
    assert.equal(res.stdout, '');
  });

  it('a symlinked --results-dir -> exit 2, writes nothing, stdout empty', () => {
    const parent = mkDir('run-cli-symlink-parent-');
    const target = path.join(parent, 'target');
    const link = path.join(parent, 'link');
    fs.mkdirSync(target);
    fs.symlinkSync(target, link, 'dir');
    const emptyRoot = mkDir('run-cli-root-');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', link, '--roots', emptyRoot]);
    assert.equal(res.status, 2);
    assert.deepEqual(fs.readdirSync(target), []);
    assert.equal(res.stdout, '');
  });
});

// ---------------------------------------------------------------------------
describe('run.js — clean / findings / warn-only exit codes (D-18 at the process boundary)', () => {
  it('exit 0 on a clean empty root; findings.json and scalars/exit-code exist', () => {
    const resultsDir = mkDir('run-cli-results-');
    const emptyRoot = mkDir('run-cli-root-');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', emptyRoot]);
    assert.equal(res.status, 0);
    assert.equal(res.stdout, '');
    assert.ok(fs.existsSync(path.join(resultsDir, 'findings.json')));
    assert.ok(fs.existsSync(path.join(resultsDir, 'scalars', 'exit-code')));
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.exitCode, 0);
    assert.equal(envelope.incomplete, false);
  });

  it('exit 1 on a root containing a Math_Symbol.js marker, with incomplete: false', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    writeFile(path.join(root, 'node_modules', 'keyv', 'Math_Symbol.js'), '/* stub */\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root]);
    assert.equal(res.status, 1);
    assert.equal(res.stdout, '');
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, false);
    assert.equal(envelope.findings.length, 1);
    assert.equal(envelope.findings[0].id, 'file-marker');
  });

  it('exit 0 on a root containing only a small Math_Helper.js — a warn-severity finding exists, warn-count 1, fail-count 0', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    writeFile(path.join(root, 'Projects', 'a', 'Math_Helper.js'), 'export const add = (a, b) => a + b;\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root]);
    assert.equal(res.status, 0);
    assert.equal(res.stdout, '');
    assert.equal(readScalar(resultsDir, 'fail-count'), 0);
    assert.equal(readScalar(resultsDir, 'warn-count'), 1);
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.exitCode, 0);
    assert.ok(envelope.findings.some((f) => f.id === 'payload-variant-warn'));
  });
});

// ---------------------------------------------------------------------------
describe('run.js — budget exhaustion at the process boundary (D-18, D-20)', () => {
  it('LSH_BUDGET_SECONDS=0 on a root with a marker file two levels deep -> exit 2, clean AND incomplete (proves the zero bound cannot discover ANY root-level entry)', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    writeFile(path.join(root, 'node_modules', 'keyv', 'Math_Symbol.js'), '/* stub */\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root], { LSH_BUDGET_SECONDS: '0' });
    assert.equal(res.status, 2);
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true);
    assert.equal(envelope.findings.length, 0);
    assert.equal(readScalar(resultsDir, 'fail-count'), 0);
  });

  it('paired non-vacuity: the SAME fixture with no bound override exits 1 (the marker IS discovered without the zero budget)', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    writeFile(path.join(root, 'node_modules', 'keyv', 'Math_Symbol.js'), '/* stub */\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root]);
    assert.equal(res.status, 1);
    assert.equal(readFindingsJson(resultsDir).incomplete, false);
  });

  it('LSH_MAX_FILES=1 on a two-file, two-root fixture -> exit 2, clean AND incomplete', () => {
    const resultsDir = mkDir('run-cli-results-');
    const rootA = mkDir('run-cli-root-');
    const rootB = mkDir('run-cli-root-');
    writeFile(path.join(rootA, 'a.txt'), 'clean file A\n');
    writeFile(path.join(rootB, 'b.txt'), 'clean file B\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', `${rootA}:${rootB}`], { LSH_MAX_FILES: '1' });
    assert.equal(res.status, 2);
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true);
    assert.equal(envelope.findings.length, 0);
  });

  it('paired non-vacuity: the SAME two-file, two-root fixture with no bound override exits 0, incomplete: false', () => {
    const resultsDir = mkDir('run-cli-results-');
    const rootA = mkDir('run-cli-root-');
    const rootB = mkDir('run-cli-root-');
    writeFile(path.join(rootA, 'a.txt'), 'clean file A\n');
    writeFile(path.join(rootB, 'b.txt'), 'clean file B\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', `${rootA}:${rootB}`]);
    assert.equal(res.status, 0);
    assert.equal(readFindingsJson(resultsDir).incomplete, false);
  });

  it('LSH_MAX_FILES=1 across two DETERMINISTICALLY ORDERED roots (marker root first) -> exit 1 with incomplete: true (D-18 precedence: findings beat incompleteness)', () => {
    const resultsDir = mkDir('run-cli-results-');
    const rootA = mkDir('run-cli-root-a-'); // walked FIRST -- array order, never reordered
    const rootB = mkDir('run-cli-root-b-'); // walked SECOND, exhausts the LSH_MAX_FILES=1 bound
    writeFile(path.join(rootA, 'Math_Symbol.js'), '/* stub */\n');
    writeFile(path.join(rootB, 'other.js'), 'clean\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', `${rootA}:${rootB}`], { LSH_MAX_FILES: '1' });
    assert.equal(res.status, 1);
    assert.equal(res.stdout, '');
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true);
    assert.equal(envelope.findings.length, 1);
    assert.equal(envelope.findings[0].id, 'file-marker');
    assert.equal(readScalar(resultsDir, 'fail-count'), 1);
  });

  it('paired non-vacuity: the SAME two roots with no LSH_MAX_FILES override exit 1 with incomplete: false', () => {
    const resultsDir = mkDir('run-cli-results-');
    const rootA = mkDir('run-cli-root-a-');
    const rootB = mkDir('run-cli-root-b-');
    writeFile(path.join(rootA, 'Math_Symbol.js'), '/* stub */\n');
    writeFile(path.join(rootB, 'other.js'), 'clean\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', `${rootA}:${rootB}`]);
    assert.equal(res.status, 1);
    assert.equal(readFindingsJson(resultsDir).incomplete, false);
  });
});

// ---------------------------------------------------------------------------
describe('run.js — progress silence when piped (T-17-04b)', () => {
  it('stderr contains no carriage return and no ANSI escape sequence under spawnSync (never a TTY)', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    writeFile(path.join(root, 'a.txt'), 'clean\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root]);
    assert.equal(res.status, 0);
    assert.ok(!res.stderr.includes('\r'), 'stderr must not contain a carriage return when piped');
    assert.ok(!res.stderr.includes('\x1b'), 'stderr must not contain an ANSI escape sequence when piped');
  });
});
