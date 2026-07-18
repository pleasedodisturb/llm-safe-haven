'use strict';

// mkdtemp + git-init fixture helper (D-06). Lives under tests/helpers/, NOT
// matched by the tests/*.test.js glob, so the runner never treats it as a
// test file.
//
// Note (research correction, do not re-derive): lib/scan.js never shells out
// to git — findEnvFiles only checks SKIP_DIRS.has('.git') as a plain string
// against a directory name. This helper's real .git/ subdirectory shape is
// what exercises that branch; no git command output is ever consumed by
// scan.js. Deterministic author/committer env + gpgsign=false avoid any
// dependency on the host machine's real git config/signing setup.

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

function makeGitFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-git-fixture-'));
  const env = Object.assign({}, process.env, {
    GIT_AUTHOR_NAME: 'Test',
    GIT_AUTHOR_EMAIL: 'test@example.invalid',
    GIT_COMMITTER_NAME: 'Test',
    GIT_COMMITTER_EMAIL: 'test@example.invalid',
  });
  // git's `-c key=value` global-config overrides must precede the
  // subcommand (`git -c ... init`, not `git init -c ...` — the latter is
  // rejected as an unknown `init` switch on modern git).
  execFileSync('git', [
    '-c', 'commit.gpgsign=false',
    '-c', 'user.name=Test',
    '-c', 'user.email=test@example.invalid',
    'init', '-q',
  ], { cwd: dir, env });
  return dir; // real .git/ subdirectory — exercises SKIP_DIRS.has('.git')
}

module.exports = { makeGitFixture };
