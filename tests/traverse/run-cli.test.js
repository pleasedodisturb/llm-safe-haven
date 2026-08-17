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

// G-1621 (EXIT-04, D-20-13): `cwd` is an OPTIONAL third parameter, defaulting
// to `undefined` -- when omitted, `spawnSync`'s own `cwd` option is left
// unset entirely, which is Node's documented "inherit the parent process's
// cwd" behaviour, exactly matching every one of the ~20 pre-existing 2-arg
// call sites above (they all keep inheriting this repository as their
// working directory, byte-identical to before this change). Only the NEW
// zero-default-root cases below pass an explicit sandbox as the third
// argument.
function runCli(args, extraEnv = {}, cwd) {
  const spawnOpts = {
    encoding: 'utf8',
    timeout: 30_000, // non-functional -- every case must terminate well within this
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...extraEnv },
  };
  if (cwd !== undefined) spawnOpts.cwd = cwd;
  return spawnSync('node', [RUN_JS, ...args], spawnOpts);
}

function readFindingsJson(resultsDir) {
  return JSON.parse(fs.readFileSync(path.join(resultsDir, 'findings.json'), 'utf8'));
}

function readScalar(resultsDir, name) {
  return Number(fs.readFileSync(path.join(resultsDir, 'scalars', name), 'utf8').trim());
}

function readNulList(resultsDir, className) {
  const raw = fs.readFileSync(path.join(resultsDir, 'lists', `${className}.z`), 'utf8');
  if (raw === '') return [];
  const parts = raw.split('\0');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts;
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
describe('run.js — a configured-but-missing root is surfaced and makes the run incomplete (G-1504, D-03)', () => {
  it('--roots real:missing -> stderr names the missing path, stdout empty, the real root is still scanned, exit 2 on an otherwise-clean scan', () => {
    const resultsDir = mkDir('run-cli-results-');
    const realRoot = mkDir('run-cli-root-');
    writeFile(path.join(realRoot, 'clean.txt'), 'nothing interesting\n');
    const missing = path.join(os.tmpdir(), `run-cli-missing-root-${Date.now()}`);

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', `${realRoot}:${missing}`]);
    assert.equal(res.status, 2);
    assert.equal(res.stdout, '');
    assert.match(res.stderr, new RegExp(missing.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.ok(readScalar(resultsDir, 'files-walked') >= 1, 'the real root must still have been scanned, not skipped entirely');
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true);
    assert.equal(envelope.exitCode, 2);
  });

  it('the same missing root supplied via LSH_ROOTS in the environment (not --roots) produces the same warning and the same exit code', () => {
    const resultsDir = mkDir('run-cli-results-');
    const realRoot = mkDir('run-cli-root-');
    writeFile(path.join(realRoot, 'clean.txt'), 'nothing interesting\n');
    const missing = path.join(os.tmpdir(), `run-cli-missing-root-env-${Date.now()}`);

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir], { LSH_ROOTS: `${realRoot}:${missing}` });
    assert.equal(res.status, 2);
    assert.equal(res.stdout, '');
    assert.match(res.stderr, new RegExp(missing.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true);
    assert.equal(envelope.exitCode, 2);
  });

  it('LSH_ROOTS=/definitely/missing alone (every configured root missing) exits 2, never 0 -- the exact reproduction cross-AI review filed', () => {
    const resultsDir = mkDir('run-cli-results-');
    const missing = path.join(os.tmpdir(), `run-cli-all-missing-${Date.now()}`);

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir], { LSH_ROOTS: missing });
    assert.equal(res.status, 2);
    assert.equal(res.stdout, '');
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true);
    assert.equal(envelope.findings.length, 0);
    assert.equal(readScalar(resultsDir, 'incomplete'), 1);
    assert.equal(readScalar(resultsDir, 'exit-code'), 2);
  });

  it('negative control: the same invocation with every configured root real writes no missing-root line and exits 0 on a clean tree', () => {
    const resultsDir = mkDir('run-cli-results-');
    const realRoot = mkDir('run-cli-root-');
    writeFile(path.join(realRoot, 'clean.txt'), 'nothing interesting\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', realRoot]);
    assert.equal(res.status, 0);
    assert.equal(res.stdout, '');
    assert.equal(res.stderr.includes('configured scan root does not exist'), false);
    assert.equal(readFindingsJson(resultsDir).incomplete, false);
  });

  it('D-18 precedence survives: a missing configured root PLUS a real FAIL finding in a surviving root still exits 1, not 2', () => {
    const resultsDir = mkDir('run-cli-results-');
    const realRoot = mkDir('run-cli-root-');
    writeFile(path.join(realRoot, 'Math_Symbol.js'), '/* stub */\n');
    const missing = path.join(os.tmpdir(), `run-cli-missing-root-precedence-${Date.now()}`);

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', `${realRoot}:${missing}`]);
    assert.equal(res.status, 1);
    assert.equal(res.stdout, '');
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true, 'the missing root must still be recorded as incomplete even though findings won the exit code');
    assert.equal(envelope.findings.length, 1);
    assert.equal(readScalar(resultsDir, 'incomplete'), 1);
  });

  it('a duplicated missing root produces exactly ONE stderr line for that path', () => {
    const resultsDir = mkDir('run-cli-results-');
    const missing = path.join(os.tmpdir(), `run-cli-dup-missing-${Date.now()}`);

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', `${missing}:${missing}`]);
    assert.equal(res.status, 2);
    const occurrences = res.stderr.split('\n').filter((line) => line.includes(missing));
    assert.equal(occurrences.length, 1, `expected exactly one stderr line naming ${missing}, got: ${JSON.stringify(occurrences)}`);
  });
});

// ---------------------------------------------------------------------------
// EXIT-02 (G-1542, D-07b, plan 18-04 Task 3) — a configured root that EXISTS
// but could not be READ (parent lacking +x) is surfaced distinctly from an
// absent one, at the real process boundary.
// ---------------------------------------------------------------------------
describe('run.js — a configured-but-unreadable root is surfaced, distinctly from a missing one (EXIT-02, D-07b)', () => {
  const runningAsRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const skip = process.platform === 'win32' || runningAsRoot;

  it('--roots under a mode-000 parent -> exit 2, stderr names the path and EACCES, never "does not exist"', { skip }, () => {
    const resultsDir = mkDir('run-cli-results-');
    const parentDir = mkDir('run-cli-unreadable-parent-');
    const childDir = path.join(parentDir, 'child');
    fs.mkdirSync(childDir);
    fs.chmodSync(parentDir, 0o000);

    try {
      const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', childDir]);
      assert.equal(res.status, 2);
      assert.equal(res.stdout, '');
      assert.match(res.stderr, new RegExp(childDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.match(res.stderr, /EACCES/);
      assert.equal(
        res.stderr.includes(`${childDir}`) && res.stderr.includes('does not exist'),
        false,
        'the unreadable-root warning must never claim the root "does not exist"'
      );
      const envelope = readFindingsJson(resultsDir);
      assert.equal(envelope.incomplete, true);
      assert.equal(envelope.exitCode, 2);
    } finally {
      fs.chmodSync(parentDir, 0o755);
    }
  });

  it('negative control: the same construction with the parent readable writes no unreadable-root line and exits 0 on a clean tree', () => {
    const resultsDir = mkDir('run-cli-results-');
    const parentDir = mkDir('run-cli-readable-parent-');
    const childDir = path.join(parentDir, 'child');
    fs.mkdirSync(childDir);
    writeFile(path.join(childDir, 'clean.txt'), 'nothing interesting\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', childDir]);
    assert.equal(res.status, 0);
    assert.equal(res.stdout, '');
    assert.equal(res.stderr.includes('could not be read'), false);
    assert.equal(readFindingsJson(resultsDir).incomplete, false);
  });
});

// ---------------------------------------------------------------------------
// run.js — zero default roots (EXIT-04, G-1621, D-20-13). Research measured
// this defect live: `HOME=<empty> LSH_ROOTS= node lib/traverse/run.js --spec
// ... --results-dir ...` wrote `{ exitCode: 0, incomplete: false, roots: [] }`
// and exited 0 -- a green result after examining zero bytes. This mirrors
// 20-01's `scan() zero default roots` describe at the process boundary,
// reusing the SAME shared constants (`CWD_FALLBACK_NOTICE`,
// `NO_SCAN_ROOT_CAUSE`) from `lib/roots.js` rather than retyping their text.
//
// Every case below passes an explicit sandbox `cwd` (mkDir()) as runCli's
// new third argument. Without it, every case would inherit this repository
// as its cwd -- which has BOTH `.git` and `package.json` and would take the
// fallback branch unconditionally the moment Task 2 lands, making the
// non-project-cwd cases (exit 2) impossible to express at all.
//
// On macOS, `os.tmpdir()` returns a path under `/var/...`, which is itself a
// symlink to `/private/var/...`. `resolveZeroRootFallback({ cwd:
// process.cwd() })` inside the SPAWNED child reads `process.cwd()` AFTER an
// actual `chdir()` into that sandbox, and the kernel's `getcwd()` returns
// the SYMLINK-RESOLVED physical path -- so the fallback-root cases below
// compare against `fs.realpathSync(projectCwd)`, not the raw mkdtemp
// string. Every OTHER case in this describe compares against the raw
// string, because those paths are never chdir'd into (they reach
// `getRoots()` via `--roots`/`LSH_ROOTS`/`homedir()`, all of which use
// `path.resolve()`, which does not resolve symlinks).
describe('run.js — zero default roots (EXIT-04, G-1621, D-20-13)', () => {
  const { CWD_FALLBACK_NOTICE, NO_SCAN_ROOT_CAUSE } = require('../../lib/roots.js');

  function emptySandboxHome() {
    // A fresh mkdtemp'd directory contains none of DEFAULT_ROOT_NAMES
    // ('Projects','Developer','Code','src','repos','workspace'), so a
    // default-probe getRoots() call against it always resolves to zero.
    return mkDir('run-cli-empty-home-');
  }

  it('empty HOME, no --roots, no LSH_ROOTS, NON-project cwd: exit 2; findings.json incomplete:true, roots:[]; stderr names the cause once', () => {
    const resultsDir = mkDir('run-cli-results-');
    const home = emptySandboxHome();
    const nonProjectCwd = mkDir('run-cli-nonproject-cwd-');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir], { HOME: home }, nonProjectCwd);
    assert.equal(res.status, 2);
    const envelope = readFindingsJson(resultsDir);
    assert.equal(envelope.incomplete, true);
    assert.deepEqual(envelope.roots, []);
    const causeLines = res.stderr.split('\n').filter((line) => line.includes(NO_SCAN_ROOT_CAUSE));
    assert.equal(causeLines.length, 1, `expected the cause to be named exactly once on stderr, got: ${JSON.stringify(res.stderr)}`);
  });

  it('empty HOME, no --roots, no LSH_ROOTS, cwd contains package.json: exit 0; exactly one notice line prefixed "run.js: "; roots:[cwd], rootsWalked:1', () => {
    const resultsDir = mkDir('run-cli-results-');
    const home = emptySandboxHome();
    const projectCwd = mkDir('run-cli-project-cwd-pkg-');
    writeFile(path.join(projectCwd, 'package.json'), JSON.stringify({ name: 'fixture' }));

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir], { HOME: home }, projectCwd);
    assert.equal(res.status, 0);
    const noticeLine = `run.js: ${CWD_FALLBACK_NOTICE}`;
    const noticeLines = res.stderr.split('\n').filter((line) => line === noticeLine);
    assert.equal(noticeLines.length, 1, `expected exactly one line "${noticeLine}" on stderr, got: ${JSON.stringify(res.stderr)}`);
    const envelope = readFindingsJson(resultsDir);
    assert.deepEqual(envelope.roots, [fs.realpathSync(projectCwd)]);
    assert.equal(envelope.counts.rootsWalked, 1);
  });

  it('same, but cwd contains a .git DIRECTORY instead of package.json: identical outcome (the heuristic is the shared looksLikeProject, not a re-typed check)', () => {
    const resultsDir = mkDir('run-cli-results-');
    const home = emptySandboxHome();
    const projectCwd = mkDir('run-cli-project-cwd-git-');
    fs.mkdirSync(path.join(projectCwd, '.git'));

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir], { HOME: home }, projectCwd);
    assert.equal(res.status, 0);
    const noticeLine = `run.js: ${CWD_FALLBACK_NOTICE}`;
    const noticeLines = res.stderr.split('\n').filter((line) => line === noticeLine);
    assert.equal(noticeLines.length, 1, `expected exactly one line "${noticeLine}" on stderr, got: ${JSON.stringify(res.stderr)}`);
    const envelope = readFindingsJson(resultsDir);
    assert.deepEqual(envelope.roots, [fs.realpathSync(projectCwd)]);
    assert.equal(envelope.counts.rootsWalked, 1);
  });

  it('PAIRED CONTROL (D-20-02): HOME contains exactly one default root (Projects/), cwd is NOT a project: exit 0, roots is [HOME/Projects], no notice line', () => {
    const resultsDir = mkDir('run-cli-results-');
    const home = emptySandboxHome();
    fs.mkdirSync(path.join(home, 'Projects'));
    const nonProjectCwd = mkDir('run-cli-nonproject-cwd-');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir], { HOME: home }, nonProjectCwd);
    assert.equal(res.status, 0);
    assert.equal(res.stderr.includes(CWD_FALLBACK_NOTICE), false, 'no fallback notice line when a default root resolved');
    const envelope = readFindingsJson(resultsDir);
    assert.deepEqual(envelope.roots, [path.join(home, 'Projects')]);
  });

  it('explicit mode is unchanged: --roots <existing dir> from an empty HOME with a non-project cwd still walks that root, exits 0, no notice line', () => {
    const resultsDir = mkDir('run-cli-results-');
    const home = emptySandboxHome();
    const nonProjectCwd = mkDir('run-cli-nonproject-cwd-');
    const explicitRoot = mkDir('run-cli-root-');
    writeFile(path.join(explicitRoot, 'clean.txt'), 'nothing interesting\n');

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', explicitRoot], { HOME: home }, nonProjectCwd);
    assert.equal(res.status, 0);
    assert.equal(res.stderr.includes(CWD_FALLBACK_NOTICE), false);
    const envelope = readFindingsJson(resultsDir);
    assert.deepEqual(envelope.roots, [explicitRoot]);
  });

  it('explicit-and-missing is unchanged: --roots <missing> still exits 2 with the existing "does not exist" warning, and does NOT emit the new notice', () => {
    const resultsDir = mkDir('run-cli-results-');
    const home = emptySandboxHome();
    const nonProjectCwd = mkDir('run-cli-nonproject-cwd-');
    const missing = path.join(os.tmpdir(), `run-cli-missing-explicit-${Date.now()}`);

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', missing], { HOME: home }, nonProjectCwd);
    assert.equal(res.status, 2);
    assert.match(res.stderr, /does not exist or is not a directory/);
    assert.equal(res.stderr.includes(CWD_FALLBACK_NOTICE), false, 'explicit-mode misses must not trigger the default-probe fallback notice');
    assert.equal(res.stderr.includes(NO_SCAN_ROOT_CAUSE), false, 'explicit-mode misses render through the existing "root" cause, not the new "no-root" one');
  });
});

// ---------------------------------------------------------------------------
// G-1502 / TRAV-10 -- the reproduction on record: a bare, zero-read-pool-work
// classified file must reach lists/<class>.z from the SAME single walk that
// produces findings.json, at the real process boundary (not just inside
// Traversal.run() directly). This is what the old second, independently-
// budgeted enumerateSync() pass in run.js could silently disagree with
// (poisoned keyv@6.0.0 vanished from lists/lockfiles.z, 6/6 attempts), and
// what a naive "just delete the second walk" fix would ALSO have broken --
// package-lock.json needs zero read-pool work, so without Task 1's collector
// it would never have reached workMap and would never have been listed.
describe('run.js — a classified, read-free file reaches its class list from the single walk (G-1502, TRAV-10)', () => {
  it('Guard 1: a package-lock.json with a poisoned keyv@6.0.0 entry appears in lists/lockfiles.z', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    const lockfilePath = path.join(root, 'Projects', 'a', 'package-lock.json');
    writeFile(lockfilePath, JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '6.0.0' } } }));

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root]);
    assert.equal(res.stdout, '');
    const lockfiles = readNulList(resultsDir, 'lockfiles');
    assert.ok(lockfiles.includes(lockfilePath), `lists/lockfiles.z must contain ${lockfilePath}; got ${JSON.stringify(lockfiles)}`);
  });

  it('Guard 2: the same fixture with a SAFE keyv version is still listed -- list membership is classification, not detection', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    const lockfilePath = path.join(root, 'Projects', 'a', 'package-lock.json');
    writeFile(lockfilePath, JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '5.6.0' } } }));

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root]);
    assert.equal(res.status, 0, 'a safe version must produce no finding');
    const lockfiles = readNulList(resultsDir, 'lockfiles');
    assert.ok(lockfiles.includes(lockfilePath), `lists/lockfiles.z must contain ${lockfilePath} regardless of whether the version is poisoned; got ${JSON.stringify(lockfiles)}`);
  });

  it('Guard 4: an installed compromised-family package.json appears in lists/family-packages.z -- universal collector, universal proof', () => {
    const resultsDir = mkDir('run-cli-results-');
    const root = mkDir('run-cli-root-');
    const familyPkgPath = path.join(root, 'node_modules', 'keyv', 'package.json');
    writeFile(familyPkgPath, JSON.stringify({ name: 'keyv', version: '1.0.0' }));

    const res = runCli(['--spec', SPEC_PATH, '--results-dir', resultsDir, '--roots', root]);
    assert.equal(res.status, 0, 'a non-poisoned installed version must produce no finding');
    const familyPackages = readNulList(resultsDir, 'family-packages');
    assert.ok(
      familyPackages.includes(familyPkgPath),
      `lists/family-packages.z must contain ${familyPkgPath}; got ${JSON.stringify(familyPackages)}`
    );
  });
});

// ---------------------------------------------------------------------------
// G-1502 / TRAV-10 (D-20): run.js must construct exactly ONE Traversal per
// invocation. Comments are stripped BEFORE counting so a comment mentioning
// "new Traversal" (this repo's own module-header prose, and the doc comment
// this very plan added) cannot make the guard vacuous -- a raw grep on the
// source text would pass even if a second walk were reintroduced with the
// old justification comment still attached, which is exactly the failure
// mode a structural guard exists to catch.
function stripComments(source) {
  // Block comments first (non-greedy), then line comments. Good enough for
  // this file: no string literal in run.js contains "//" or "/*" sequences
  // that would be misread as a comment start.
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

describe('run.js — exactly one traversal per invocation (G-1502, D-20)', () => {
  it('after stripping comments, run.js contains exactly one "new Traversal(" and zero "enumerateSync(" occurrences', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', '..', 'lib', 'traverse', 'run.js'), 'utf8');
    const stripped = stripComments(source);

    const traversalCount = (stripped.match(/new Traversal\(/g) || []).length;
    const enumerateSyncCount = (stripped.match(/enumerateSync\(/g) || []).length;

    assert.equal(
      traversalCount,
      1,
      `G-1502/D-20: run.js must construct exactly ONE Traversal per invocation (found ${traversalCount} after comment-stripping). ` +
        'A second Traversal/enumerateSync() pass reintroduces two independently-budgeted walks observing two different filesystem ' +
        'snapshots -- the exact regression that made poisoned keyv@6.0.0 vanish from lists/lockfiles.z, 6/6 attempts. Do not ' +
        're-add a second walk; source lists/<class>.z from result.byClass instead.'
    );
    assert.equal(
      enumerateSyncCount,
      0,
      `G-1502/D-20: run.js must never call enumerateSync() (found ${enumerateSyncCount} after comment-stripping) -- ` +
        'lists/<class>.z is sourced from the single run() walk\'s result.byClass, not a second read-free pass.'
    );
  });

  it('non-vacuity: stripComments() actually removes a "new Traversal(" / "enumerateSync(" mention living inside a comment, proving a raw grep-the-file guard would be meaningless', () => {
    // A synthetic source snippet shaped like the exact regression this guard
    // exists to catch: a re-added second pass with its own justification
    // comment quoting both call shapes. A grep on the RAW text would count 2
    // "new Traversal(" occurrences (one real, one in the comment) and 1
    // "enumerateSync(" occurrence purely from the comment -- both wrong.
    const synthetic = [
      '// A second pass: new Traversal({ roots, classes: FILE_CLASSES, spec }).enumerateSync()',
      'const traversal = new Traversal({ roots, spec });',
      '/* block comment also mentioning new Traversal( and enumerateSync( */',
    ].join('\n');

    const rawTraversalCount = (synthetic.match(/new Traversal\(/g) || []).length;
    const rawEnumerateSyncCount = (synthetic.match(/enumerateSync\(/g) || []).length;
    assert.equal(rawTraversalCount, 3, 'sanity: the synthetic snippet must contain 3 raw "new Traversal(" occurrences (2 in comments, 1 real)');
    assert.equal(rawEnumerateSyncCount, 2, 'sanity: the synthetic snippet must contain 2 raw "enumerateSync(" occurrences, both in comments');

    const strippedSynthetic = stripComments(synthetic);
    const strippedTraversalCount = (strippedSynthetic.match(/new Traversal\(/g) || []).length;
    const strippedEnumerateSyncCount = (strippedSynthetic.match(/enumerateSync\(/g) || []).length;
    assert.equal(strippedTraversalCount, 1, 'after stripping, only the REAL construction remains');
    assert.equal(strippedEnumerateSyncCount, 0, 'after stripping, the comment-only enumerateSync( mentions are gone');
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
