'use strict';

// Real-git-repo fixture builder (Phase 17 / TRAV-05, D-XX). Builds an actual
// git repository in a temp directory so gitignore-tiering tests (the FN
// probe: a targeted-tier IOC in a gitignored path must still fire) exercise
// real `git ls-files` / `.gitignore` semantics instead of a hand-rolled
// gitignore parser.
//
// Lives under tests/helpers/ (NOT matching the package.json test glob
// `tests/*.test.js`), so the test runner never picks it up as a test file.
//
// Every git invocation pins GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM to
// /dev/null and HOME to the fixture dir, so the developer's global gitignore
// or core.excludesFile can never leak into a fixture result and make a
// security test pass for the wrong reason (see 17-01-PLAN.md threat
// T-17-01-02).
//
// hasGit / initRepo never throw when the git binary is absent — hasGit is a
// boolean flag callers use to skip describe blocks (matching the
// `{ skip: !hasBash }` convention at tests/chaindrop-scanner.test.js:56);
// initRepo itself returns null if git is missing.

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const hasGit = spawnSync('git', ['--version']).status === 0;

function gitEnv(dir) {
  return {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    HOME: dir,
  };
}

function runGit(dir, args) {
  return spawnSync('git', args, { cwd: dir, encoding: 'utf8', env: gitEnv(dir) });
}

function writeFiles(dir, filesMap) {
  for (const [rel, contents] of Object.entries(filesMap)) {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
}

// initRepo(dir, { gitignore, tracked = {}, untracked = {}, bare = false })
//
// Initializes a git repo at `dir` (creating it if needed), optionally writes
// a `.gitignore`, writes the `tracked` and `untracked` path-to-contents maps
// to disk, and commits the tracked set. Returns `dir`, or `null` if git is
// unavailable.
function initRepo(dir, { gitignore, tracked = {}, untracked = {}, bare = false } = {}) {
  if (!hasGit) return null;

  fs.mkdirSync(dir, { recursive: true });
  runGit(dir, ['-c', 'init.defaultBranch=main', 'init', ...(bare ? ['--bare'] : [])]);

  if (bare) return dir;

  if (gitignore !== undefined) {
    writeFiles(dir, { '.gitignore': gitignore });
  }
  writeFiles(dir, tracked);
  writeFiles(dir, untracked);

  // git add + commit cover the tracked set only — untracked files (and the
  // .gitignore itself) are left on disk but not staged, matching a real
  // repo where .gitignore need not be tracked for --exclude-standard to
  // honor it.
  const trackedPaths = Object.keys(tracked);
  if (trackedPaths.length > 0) {
    runGit(dir, ['add', ...trackedPaths]);
    runGit(dir, [
      '-c', 'user.email=t@example.invalid',
      '-c', 'user.name=t',
      'commit', '-m', 'fixture',
    ]);
  }

  return dir;
}

module.exports = { hasGit, initRepo };
