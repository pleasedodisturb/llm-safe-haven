'use strict';

// Wave 0 test infrastructure (Phase 17 / TRAV-07, TRAV-05): the first real
// test file in tests/traverse/ — its existence makes the
// `tests/traverse/*.test.js` glob non-empty, and its assertions prove the
// promoted fixture helpers (tests/helpers/chaindrop-fixtures.js,
// tests/helpers/git-fixture.js) actually work rather than merely existing.
//
// Both describe blocks use paired opposite-outcome assertions (the house
// "prove-the-guard-bites" template, tests/tier3-agents.test.js:157-189) so
// this file cannot pass unless the helpers are non-vacuous.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { write, newHome, runScanner, hasBash } = require('../helpers/chaindrop-fixtures.js');
const { hasGit, initRepo } = require('../helpers/git-fixture.js');

describe('tests/helpers/chaindrop-fixtures.js — newHome/write/runScanner', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

  it('runScanner returns status 0 on an empty HOME (clean branch)', () => {
    const home = newHome(built, () => {});
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
  });

  it('runScanner returns status 1 on a HOME with a Math_Symbol.js marker (dirty branch)', () => {
    const home = newHome(built, (h, p) => write(p('Projects/x/node_modules/keyv/Math_Symbol.js'), '/* stub */\n'));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
  });
});

describe('tests/helpers/git-fixture.js — initRepo gitignore semantics', { skip: !hasGit ? 'git unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

  it('git ls-files lists the tracked file and omits the gitignored one, while the ignored file still physically exists', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-git-fixture-'));
    built.push(dir);

    initRepo(dir, {
      gitignore: 'ignored/\n',
      tracked: { 'tracked.txt': 'kept\n' },
      untracked: { 'ignored/secret.txt': 'hidden\n' },
    });

    const out = execFileSync(
      'git',
      ['-C', dir, 'ls-files', '--cached', '--others', '--exclude-standard', '--full-name'],
      {
        encoding: 'utf8',
        env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', HOME: dir },
      }
    );
    const listed = out.split('\n').filter(Boolean);

    assert.ok(listed.includes('tracked.txt'), `expected tracked.txt in listing: ${listed.join(',')}`);
    assert.ok(
      !listed.some((f) => f.startsWith('ignored/')),
      `expected no ignored/ entries in listing (proves ignore semantics, not just absence): ${listed.join(',')}`
    );

    // Non-vacuity: the ignored file must actually exist on disk — otherwise
    // "not listed" could vacuously pass because the file was never written.
    assert.ok(
      fs.existsSync(path.join(dir, 'ignored', 'secret.txt')),
      'ignored/secret.txt must physically exist — proves git is hiding it via .gitignore, not that the fixture never wrote it'
    );
  });
});
