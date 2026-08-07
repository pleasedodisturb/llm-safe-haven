'use strict';

// G-1482, TRAV-03 (17-08). Every git failure mode this module can hit is a
// named, tested degradation rather than an untested assumption -- and a
// failed listing can never be mistaken for "everything is ignored". The
// first block stubs `spawnSync` to simulate every verbatim shape from
// RESEARCH.md section B2; the second block exercises real git, including
// the nested-repo attribution case (D-26).

const assert = require('node:assert/strict');
const { test, describe } = require('node:test');
const path = require('path');
const os = require('os');
const fs = require('fs');

const { createIgnoreResolver, probeRepo } = require('../../lib/traverse/git-ignore.js');
const { hasGit, initRepo } = require('../helpers/git-fixture.js');

// ---------------------------------------------------------------------
// Stubbed spawnSync harness
// ---------------------------------------------------------------------

/**
 * Builds a stub `spawnSync(cmd, argv, opts)` that returns the scripted
 * results in order, recording every call (cmd, argv, opts) on `.calls` so
 * tests can inspect exactly what argv/options the module produced.
 */
function makeSpawnSyncStub(results) {
  const calls = [];
  let i = 0;
  function stub(cmd, argv, opts) {
    calls.push({ cmd, argv, opts });
    const r = results[i];
    i += 1;
    if (r === undefined) {
      throw new Error(`spawnSync stub exhausted at call ${i} (${argv.join(' ')})`);
    }
    return typeof r === 'function' ? r(argv, opts) : r;
  }
  stub.calls = calls;
  return stub;
}

function ok(stdout) {
  return { status: 0, stdout, stderr: '', error: null, signal: null };
}
function fail128(stderr) {
  return { status: 128, stdout: '', stderr, error: null, signal: null };
}
function enoent() {
  return {
    status: null,
    stdout: '',
    stderr: '',
    error: Object.assign(new Error('spawnSync git ENOENT'), { code: 'ENOENT' }),
    signal: null,
  };
}
function killed(signal) {
  return { status: null, stdout: '', stderr: '', error: null, signal };
}
function enobufs() {
  return {
    status: null,
    stdout: '',
    stderr: '',
    error: Object.assign(new Error('spawnSync ENOBUFS'), { code: 'ENOBUFS' }),
    signal: null,
  };
}

// ---------------------------------------------------------------------
// probeRepo() -- the six named degradation reasons, verbatim shapes
// ---------------------------------------------------------------------

test('probeRepo: ENOENT spawnSync error maps to no-git', () => {
  const spawnSync = makeSpawnSyncStub([enoent()]);
  const result = probeRepo('/some/dir', { spawnSync });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'no-git');
});

test('probeRepo: exit 128 "not a git repository" maps to not-a-repo', () => {
  const spawnSync = makeSpawnSyncStub([
    fail128('fatal: not a git repository (or any of the parent directories): .git\n'),
  ]);
  const result = probeRepo('/some/dir', { spawnSync });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'not-a-repo');
});

test('probeRepo: exit 128 "dubious ownership" maps to git-refused', () => {
  const spawnSync = makeSpawnSyncStub([
    fail128("fatal: detected dubious ownership in repository at '/x'\n"),
  ]);
  const result = probeRepo('/x', { spawnSync });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'git-refused');
});

test('probeRepo: status null + SIGTERM (the spawnSync timeout shape) maps to git-timeout', () => {
  const spawnSync = makeSpawnSyncStub([killed('SIGTERM')]);
  const result = probeRepo('/x', { spawnSync });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'git-timeout');
  assert.equal(result.detail.signal, 'SIGTERM');
});

test('probeRepo: ENOBUFS spawn error maps to git-timeout with the code in detail', () => {
  const spawnSync = makeSpawnSyncStub([enobufs()]);
  const result = probeRepo('/x', { spawnSync });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'git-timeout');
  assert.equal(result.detail.code, 'ENOBUFS');
});

test('probeRepo: exit 0 stdout "true" is healthy', () => {
  const spawnSync = makeSpawnSyncStub([ok('true\n')]);
  const result = probeRepo('/repo', { spawnSync });
  assert.equal(result.ok, true);
});

test('probeRepo: an unrecognised exit-0 stdout shape degrades to git-refused rather than assuming "true"', () => {
  const spawnSync = makeSpawnSyncStub([ok('unexpected-garbage\n')]);
  const result = probeRepo('/repo', { spawnSync });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'git-refused');
});

test('probeRepo: an unrecognised non-zero, non-128 status maps to git-refused with the status in detail', () => {
  const spawnSync = makeSpawnSyncStub([{ status: 1, stdout: '', stderr: 'weird\n', error: null, signal: null }]);
  const result = probeRepo('/repo', { spawnSync });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'git-refused');
  assert.equal(result.detail.status, 1);
});

// ---------------------------------------------------------------------
// createIgnoreResolver() -- bare-repo short-circuit
// ---------------------------------------------------------------------

test('createIgnoreResolver: bare-repo probe (exit 0, stdout "false") short-circuits before ls-files is ever invoked', () => {
  const spawnSync = makeSpawnSyncStub([ok('false\n')]);
  const resolver = createIgnoreResolver({ spawnSync });
  const index = resolver.indexFor('/bare.git');
  assert.equal(index.degraded, 'bare-repo');
  assert.equal(index.listed, null);
  // The case that would throw ("fatal: this operation must be run in a
  // work tree") if ls-files were called anyway -- assert it never was.
  assert.equal(spawnSync.calls.length, 1);
});

// ---------------------------------------------------------------------
// Healthy index vs. degraded-after-healthy-probe (the paired opposite that
// proves a failed listing can never be mistaken for "everything ignored")
// ---------------------------------------------------------------------

test('createIgnoreResolver: healthy probe + ls-files builds the exact Set', () => {
  const spawnSync = makeSpawnSyncStub([ok('true\n'), ok('a.js\0b/c.js\0')]);
  const resolver = createIgnoreResolver({ spawnSync });
  const index = resolver.indexFor('/repo');
  assert.equal(index.degraded, null);
  assert.deepEqual([...index.listed].sort(), ['a.js', 'b/c.js']);
});

test('createIgnoreResolver: a FAILED ls-files after a healthy probe degrades -- NOT an empty (prune-everything) Set', () => {
  const spawnSync = makeSpawnSyncStub([ok('true\n'), fail128('fatal: something bad\n')]);
  const resolver = createIgnoreResolver({ spawnSync });
  const index = resolver.indexFor('/repo');
  assert.notEqual(index.degraded, null);
  assert.equal(index.listed, null);

  const eligibility = resolver.isBulkEligible('/repo/src/app.js', '/repo');
  assert.equal(eligibility.eligible, true, 'a failed listing must fail OPEN, never prune the whole repo');
  assert.equal(eligibility.reason, index.degraded);
});

test('createIgnoreResolver: a SUCCESSFUL ls-files with EMPTY stdout is a healthy empty Set (paired opposite of the failed case)', () => {
  const spawnSync = makeSpawnSyncStub([ok('true\n'), ok('')]);
  const resolver = createIgnoreResolver({ spawnSync });
  const index = resolver.indexFor('/repo');
  assert.equal(index.degraded, null);
  assert.equal(index.listed.size, 0);

  const eligibility = resolver.isBulkEligible('/repo/src/app.js', '/repo');
  assert.equal(eligibility.eligible, false);
  assert.equal(eligibility.reason, 'gitignored');
});

// ---------------------------------------------------------------------
// Large output (>4 MiB) -- the maxBuffer regression guard
// ---------------------------------------------------------------------

test('createIgnoreResolver: a >4 MiB ls-files output parses to the exact expected entry count, with maxBuffer raised', () => {
  const PAD = 'x'.repeat(40);
  const entryCount = 120000;
  const paths = new Array(entryCount);
  for (let i = 0; i < entryCount; i += 1) {
    paths[i] = `f${i}-${PAD}`;
  }
  const stdout = paths.join('\0') + '\0';
  assert.ok(Buffer.byteLength(stdout) > 4 * 1024 * 1024, 'test fixture must exceed 4 MiB');

  const spawnSync = makeSpawnSyncStub([ok('true\n'), ok(stdout)]);
  const resolver = createIgnoreResolver({ spawnSync });
  const index = resolver.indexFor('/repo');
  assert.equal(index.listed.size, entryCount);

  const lsFilesCallOpts = spawnSync.calls[1].opts;
  assert.ok(lsFilesCallOpts.maxBuffer >= 256 * 1024 * 1024, 'default ~1 MiB buffer must not be in play');
});

// ---------------------------------------------------------------------
// Fail-open for EVERY degraded reason, paired against the healthy
// gitignored-false case above -- both branches in the same suite so
// neither can pass vacuously.
// ---------------------------------------------------------------------

const probeFailureCases = [
  { name: 'no-git', results: [enoent()] },
  { name: 'not-a-repo', results: [fail128('fatal: not a git repository (or any of the parent directories): .git\n')] },
  { name: 'git-refused (dubious ownership)', results: [fail128("fatal: detected dubious ownership in repository at '/x'\n")] },
  { name: 'bare-repo', results: [ok('false\n')] },
  { name: 'git-timeout (killed)', results: [killed('SIGTERM')] },
  { name: 'git-timeout (ENOBUFS)', results: [enobufs()] },
];

for (const { name, results } of probeFailureCases) {
  test(`createIgnoreResolver: isBulkEligible fails OPEN (eligible true) for degraded reason ${name}`, () => {
    const spawnSync = makeSpawnSyncStub(results);
    const resolver = createIgnoreResolver({ spawnSync });
    const eligibility = resolver.isBulkEligible('/repo/src/app.js', '/repo');
    assert.equal(eligibility.eligible, true);
    assert.ok(eligibility.reason, 'reason must be the degradation code, not empty');
  });
}

// ---------------------------------------------------------------------
// Hostile-filename / argv / option regression guards
// ---------------------------------------------------------------------

test('createIgnoreResolver: a filename containing a literal newline round-trips as ONE Set entry', () => {
  const weirdName = 'weird\nname.js';
  const spawnSync = makeSpawnSyncStub([ok('true\n'), ok(`a.js\0${weirdName}\0`)]);
  const resolver = createIgnoreResolver({ spawnSync });
  const index = resolver.indexFor('/repo');
  assert.equal(index.listed.size, 2);
  assert.ok(index.listed.has(weirdName));
});

test('createIgnoreResolver: the ls-files argv includes --full-name and -z (B1 regression guard, inspected not trusted)', () => {
  const spawnSync = makeSpawnSyncStub([ok('true\n'), ok('')]);
  const resolver = createIgnoreResolver({ spawnSync });
  resolver.indexFor('/repo');
  const lsFilesCall = spawnSync.calls[1];
  assert.ok(lsFilesCall.argv.includes('--full-name'));
  assert.ok(lsFilesCall.argv.includes('-z'));
});

test('createIgnoreResolver: recorded spawn options carry maxBuffer >= 256 MiB and env.GIT_PAGER === ""', () => {
  const spawnSync = makeSpawnSyncStub([ok('true\n'), ok('')]);
  const resolver = createIgnoreResolver({ spawnSync });
  resolver.indexFor('/repo');
  for (const call of spawnSync.calls) {
    assert.ok(call.opts.maxBuffer >= 256 * 1024 * 1024);
    assert.equal(call.opts.env.GIT_PAGER, '');
  }
});

// ---------------------------------------------------------------------
// Cache / cost model (D-14: one probe + one listing per repo, ever)
// ---------------------------------------------------------------------

test('createIgnoreResolver: stats().subprocesses is 2 per healthy repo and does not grow on repeated indexFor calls', () => {
  const spawnSync = makeSpawnSyncStub([ok('true\n'), ok('a.js\0')]);
  const resolver = createIgnoreResolver({ spawnSync });
  resolver.indexFor('/repo');
  assert.equal(resolver.stats().subprocesses, 2);
  resolver.indexFor('/repo');
  resolver.indexFor('/repo');
  assert.equal(resolver.stats().subprocesses, 2);
  assert.equal(resolver.stats().cacheHits, 2);
  assert.equal(resolver.stats().repos, 1);
});

test('createIgnoreResolver: degradations() reports the repo -> reason map', () => {
  const spawnSync = makeSpawnSyncStub([enoent()]);
  const resolver = createIgnoreResolver({ spawnSync });
  resolver.indexFor('/repo');
  assert.deepEqual(resolver.degradations(), { '/repo': 'no-git' });
});

// ---------------------------------------------------------------------
// Real-git integration (guarded: skipped when git is unavailable)
// ---------------------------------------------------------------------

function isolatedEnv(dir) {
  // Mirrors tests/helpers/git-fixture.js's gitEnv(): pins GIT_CONFIG_GLOBAL
  // / GIT_CONFIG_SYSTEM to /dev/null and HOME to the fixture dir so a
  // developer machine's real global gitignore or core.excludesFile can
  // never leak into a result and make a security test pass for the wrong
  // reason.
  return { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', HOME: dir };
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe('git-ignore.js real-git integration', () => {
  test(
    'gitignore semantics: build/ and secret.txt are pruned; tracked and untracked non-ignored source is not',
    { skip: !hasGit },
    () => {
      const dir = tmpDir('lsh-gi-basic-');
      initRepo(dir, {
        gitignore: 'build/\nsecret.txt\n',
        tracked: { 'src/app.js': 'console.log(1);' },
        untracked: {
          'src/util.js': 'console.log(2);',
          'build/out.js': 'ignored payload',
          'secret.txt': 'sekrit',
        },
      });

      // Prove ignore semantics, not absence -- the files physically exist.
      assert.ok(fs.existsSync(path.join(dir, 'build', 'out.js')));
      assert.ok(fs.existsSync(path.join(dir, 'secret.txt')));

      const resolver = createIgnoreResolver({ env: isolatedEnv(dir) });
      assert.equal(resolver.isBulkEligible(path.join(dir, 'build', 'out.js'), dir).eligible, false);
      assert.equal(resolver.isBulkEligible(path.join(dir, 'secret.txt'), dir).eligible, false);
      assert.equal(resolver.isBulkEligible(path.join(dir, 'src', 'app.js'), dir).eligible, true);
      assert.equal(resolver.isBulkEligible(path.join(dir, 'src', 'util.js'), dir).eligible, true);
    }
  );

  test(
    'path relativity: a repo root several directories below the process cwd resolves an absolute deep path correctly',
    { skip: !hasGit },
    () => {
      const base = tmpDir('lsh-gi-deep-');
      const repoDir = path.join(base, 'a', 'b', 'c', 'repo');
      initRepo(repoDir, { tracked: { 'sub1/sub2/file.js': 'x' } });

      const resolver = createIgnoreResolver({ env: isolatedEnv(repoDir) });
      const abs = path.join(repoDir, 'sub1', 'sub2', 'file.js');
      assert.equal(resolver.isBulkEligible(abs, repoDir).eligible, true);
    }
  );

  test(
    'nested repos (D-26): an inner file is NOT pruned by the outer .gitignore; an outer-only file IS pruned by the outer rule',
    { skip: !hasGit },
    () => {
      const outerDir = tmpDir('lsh-gi-nested-outer-');
      initRepo(outerDir, {
        gitignore: 'inner/\nouter-only/\n',
        tracked: { 'app.js': 'x' },
        untracked: { 'outer-only/x.js': 'y' },
      });

      const innerDir = path.join(outerDir, 'inner');
      initRepo(innerDir, { gitignore: '', untracked: { 'app.js': 'z' } });

      const resolver = createIgnoreResolver({ env: isolatedEnv(outerDir) });

      // The outer repo's rule for `inner/` must NOT prune a file evaluated
      // against the INNER repo's own (empty) ignore rules.
      const innerEligibility = resolver.isBulkEligible(path.join(innerDir, 'app.js'), innerDir);
      assert.equal(innerEligibility.eligible, true);

      // Mirror: a file matched by an outer rule, evaluated against the
      // OUTER repo, IS pruned -- proving this isn't just "everything is
      // eligible".
      const outerOnlyEligibility = resolver.isBulkEligible(path.join(outerDir, 'outer-only', 'x.js'), outerDir);
      assert.equal(outerOnlyEligibility.eligible, false);
      assert.equal(outerOnlyEligibility.reason, 'gitignored');
    }
  );

  test('bare repo on disk: probeRepo returns bare-repo against a real `git init --bare` fixture', { skip: !hasGit }, () => {
    const dir = tmpDir('lsh-gi-bare-');
    initRepo(dir, { bare: true });
    const result = probeRepo(dir, { env: isolatedEnv(dir) });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'bare-repo');
  });

  test(
    'global-config isolation: GIT_CONFIG_GLOBAL=/dev/null means a developer global gitignore cannot change the result',
    { skip: !hasGit },
    () => {
      const dir = tmpDir('lsh-gi-global-');
      initRepo(dir, {
        gitignore: 'build/\n',
        untracked: { '.DS_Store': 'binaryjunk' },
      });

      const resolver = createIgnoreResolver({ env: isolatedEnv(dir) });
      // .DS_Store is not excluded by THIS repo's own .gitignore. A common
      // developer global gitignore excludes it, but the isolated
      // GIT_CONFIG_GLOBAL=/dev/null (mirrored from HOME) means that cannot
      // leak into this result.
      assert.equal(resolver.isBulkEligible(path.join(dir, '.DS_Store'), dir).eligible, true);
    }
  );
});
