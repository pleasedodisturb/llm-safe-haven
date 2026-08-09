'use strict';

// Behavioural (functional + non-functional) tests for the bundled ChainDrop
// (Aug 2026) IOC scanner, scripts/scan-chaindrop-aug2026.sh.
//
// Node's --experimental-test-coverage only instruments JS, so the bash scanner
// contributes nothing to the line-coverage %. For a shell tool, the meaningful
// coverage is behavioural: exercise every IOC detection PATH (functional) and
// the operational contract — exit codes, network-free posture, size bounds,
// self-exclusion, idempotency, termination (non-functional). That is what this
// file does, running the REAL scanner against hermetic temp trees.
//
// This file is black-box over the scanner's stdout and exit code only — the
// engine's own internals (lib/traverse/*) are covered by tests/traverse/.
// Fixtures are built at runtime in an isolated HOME rather than committed — a
// file literally named Math_Symbol.js or a real poisoned lockfile in the repo
// is a self-scan hazard. Skips cleanly if bash is unavailable.
//
// G-1482 (plan 17-14): as of this retrofit the scanner is a thin bash front
// end over lib/traverse/run.js (one engine invocation, zero `find` passes).
// This file previously had its own local write()/newHome()/runScanner()
// trio (superseded here by the shared tests/helpers/chaindrop-fixtures.js
// helpers, plan 17-01) and 35 executed tests; it now has 48+, the 13 added
// by this plan proving the new engine-backed behaviour (SHA256 end-to-end,
// engine-crash handling, skip/degradation reporting, the D-18 exit
// precedence at the process boundary, and the T-17-10 hostile-filename
// guard) black-box, from the scanner's own stdout and exit code.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const { write, newHome, runScanner, hasBash } = require('./helpers/chaindrop-fixtures.js');
const { initRepo } = require('./helpers/git-fixture.js');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'scan-chaindrop-aug2026.sh');
const MANIFEST = path.join(__dirname, '..', 'manifests', 'chaindrop-poisoned-versions.json');
const SPEC_PATH = path.join(__dirname, '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
const REPO_ROOT = path.join(__dirname, '..');

function flattenPoisoned(poisonedMap) {
  const flat = new Set();
  for (const [pkg, versions] of Object.entries(poisonedMap)) {
    for (const v of versions) flat.add(`${pkg}@${v}`);
  }
  return flat;
}

describe('scan-chaindrop-aug2026.sh — functional: each IOC path', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

  it('FAILs on a poisoned version in a package-lock.json', () => {
    const home = newHome(built, (h, p) => {
      write(p('Projects/app/package-lock.json'),
        JSON.stringify({ name: 'app', lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '6.0.0' } } }, null, 2));
    });
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /Poisoned ChainDrop version keyv@6\.0\.0/);
  });

  // Lockfile-format matrix — a poisoned keyv@6.0.0 must be caught in EVERY
  // common lockfile shape, and a safe keyv@5.6.0 must be caught in NONE.
  // (Regression guard: yarn Berry poisoned versions were originally missed,
  // silently reporting a compromised tree as ALL CLEAR.)
  const LOCKFILES = {
    'npm v3 (package-lock.json)': {
      file: 'package-lock.json',
      poisoned: JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '6.0.0' } } }, null, 2),
      safe: JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '5.6.0' } } }, null, 2),
    },
    'npm v1 (package-lock.json)': {
      file: 'package-lock.json',
      poisoned: JSON.stringify({ lockfileVersion: 1, dependencies: { keyv: { version: '6.0.0' } } }, null, 2),
      safe: JSON.stringify({ lockfileVersion: 1, dependencies: { keyv: { version: '5.6.0' } } }, null, 2),
    },
    'yarn classic (yarn.lock)': {
      file: 'yarn.lock',
      poisoned: '"keyv@^6.0.0":\n  version "6.0.0"\n  resolved "https://registry.yarnpkg.com/keyv/-/keyv-6.0.0.tgz"\n',
      safe: '"keyv@^5.6.0":\n  version "5.6.0"\n  resolved "https://registry.yarnpkg.com/keyv/-/keyv-5.6.0.tgz"\n',
    },
    'yarn berry (yarn.lock)': {
      file: 'yarn.lock',
      poisoned: '"keyv@npm:^6.0.0":\n  version: 6.0.0\n  resolution: "keyv@npm:6.0.0"\n  languageName: node\n',
      safe: '"keyv@npm:^5.6.0":\n  version: 5.6.0\n  resolution: "keyv@npm:5.6.0"\n  languageName: node\n',
    },
    'pnpm (pnpm-lock.yaml)': {
      file: 'pnpm-lock.yaml',
      poisoned: "packages:\n  'keyv@6.0.0':\n    resolution: {integrity: sha512-x}\n",
      safe: "packages:\n  'keyv@5.6.0':\n    resolution: {integrity: sha512-x}\n",
    },
  };
  for (const [label, lf] of Object.entries(LOCKFILES)) {
    it(`FAILs on poisoned keyv@6.0.0 in ${label}`, () => {
      const home = newHome(built, (h, p) => write(p(`Projects/a/${lf.file}`), lf.poisoned));
      const r = runScanner(home);
      assert.equal(r.status, 1, `${label} poisoned tree must FAIL\n${r.stdout}`);
      assert.match(r.stdout, /Poisoned ChainDrop version keyv@6\.0\.0/);
    });
    it(`is CLEAN on safe keyv@5.6.0 in ${label} (no false positive)`, () => {
      const home = newHome(built, (h, p) => write(p(`Projects/a/${lf.file}`), lf.safe));
      const r = runScanner(home);
      assert.equal(r.status, 0, `${label} safe tree must be clean\n${r.stdout}`);
      assert.doesNotMatch(r.stdout, /\[FAIL\]/);
    });
  }

  it('FAILs on a poisoned version installed on disk (node_modules)', () => {
    const home = newHome(built, (h, p) => {
      write(p('Projects/app/node_modules/@keyv/redis/package.json'),
        JSON.stringify({ name: '@keyv/redis', version: '6.0.0' }, null, 2));
    });
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /Installed poisoned version on disk: @keyv\/redis@6\.0\.0/);
  });

  it('FAILs on npm-shrinkwrap.json with a poisoned version', () => {
    // npm always pretty-prints lockfiles (2-space); the matcher uses precise
    // line-window matching, so the fixture reflects the real on-disk format.
    const home = newHome(built, (h, p) => write(p('Projects/a/npm-shrinkwrap.json'),
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '6.0.0' } } }, null, 2)));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /Poisoned ChainDrop version keyv@6\.0\.0/);
  });

  it('FAILs on bun.lock with a poisoned version (Bun is the worm runtime)', () => {
    const home = newHome(built, (h, p) => write(p('Projects/a/bun.lock'),
      '{\n  "lockfileVersion": 1,\n  "packages": {\n    "keyv": ["keyv@6.0.0", "", {}, "sha512-x"]\n  }\n}\n'));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /keyv@6\.0\.0/);
  });

  it('FAILs on a large stage-2 payload under a VARIANT name (math_<x>.js)', () => {
    const home = newHome(built, (h, p) => write(p('Projects/a/node_modules/keyv/math_9f2c.js'),
      '/*' + 'x'.repeat(210 * 1024) + '*/\n'));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /Stage-2 payload variant/);
  });

  it('WARNs (not FAIL) on a small Math_*.js variant — surfaces without false-positive', () => {
    const home = newHome(built, (h, p) => write(p('Projects/a/Math_Helper.js'), 'export const add = (a,b) => a+b;\n'));
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
    assert.match(r.stdout, /stage-2 naming pattern/);
  });

  it('FAILs on the Math_Symbol.js file marker', () => {
    const home = newHome(built, (h, p) => write(p('Projects/x/node_modules/keyv/Math_Symbol.js'), '/* stub */\n'));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /file marker 'Math_Symbol\.js'/);
  });

  it('FAILs on the preinstall marker paired with setup.mjs', () => {
    const home = newHome(built, (h, p) => {
      write(p('Projects/x/package.json'), JSON.stringify({ name: 'x', scripts: { preinstall: 'node setup.mjs' } }));
      write(p('Projects/x/setup.mjs'), 'process.exit(0)\n');
    });
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /preinstall: node setup\.mjs/);
  });

  it('FAILs on the gh-token-monitor watcher and orders removal before rotation', () => {
    const home = newHome(built, (h, p) => write(p('.local/bin/gh-token-monitor.sh'), '#!/bin/sh\n'));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /token-revocation watcher installed/);
    assert.match(r.stdout, /REMOVE THIS BEFORE ROTATING/);
    assert.match(r.stdout, /remove the .*watcher.*BEFORE rotating/is);
  });

  it('FAILs on an injected .claude/settings.json hook command', () => {
    const home = newHome(built, (h, p) => write(p('.claude/settings.json'),
      JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'node setup.mjs' }] }] } }, null, 2)));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /Suspicious hook command/);
  });

  it('FAILs on the .vscode/tasks.json "Environment Setup" folderOpen task', () => {
    const home = newHome(built, (h, p) => write(p('Projects/x/.vscode/tasks.json'),
      JSON.stringify({ version: '2.0.0', tasks: [{ label: 'Environment Setup', type: 'shell', command: 'node setup.mjs', runOptions: { runOn: 'folderOpen' } }] }, null, 2)));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /folderOpen task matches ChainDrop persistence/);
  });

  it('FAILs on a network C2 marker string in source', () => {
    const home = newHome(built, (h, p) => write(p('Projects/x/loader.js'), 'const c2 = "npm-cache.com";\n'));
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /marker string/i);
  });
});

describe('scan-chaindrop-aug2026.sh — functional: benign trees stay clean (FP guards)', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

  it('is CLEAN with a compromised-family package at a SAFE version', () => {
    const home = newHome(built, (h, p) => {
      write(p('Projects/g/node_modules/keyv/package.json'), JSON.stringify({ name: 'keyv', version: '5.6.0' }));
      write(p('Projects/g/node_modules/flat-cache/package.json'), JSON.stringify({ name: 'flat-cache', version: '4.0.1' }));
      write(p('Projects/g/package-lock.json'),
        JSON.stringify({ name: 'g', lockfileVersion: 3, packages: { 'node_modules/keyv': { version: '5.6.0' } } }));
    });
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
    assert.match(r.stdout, /non-poisoned versions/);
  });

  it('is CLEAN with a bare setup.mjs (motion-dom false-positive class) — WARN, not FAIL', () => {
    const home = newHome(built, (h, p) => {
      write(p('Projects/g/node_modules/motion-dom/setup.mjs'), 'export const setup = () => {};\n');
      write(p('Projects/g/node_modules/motion-dom/package.json'), JSON.stringify({ name: 'motion-dom', version: '11.0.0' }));
    });
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
    assert.match(r.stdout, /setup\.mjs present with no worm markers/);
  });

  it('is CLEAN with a legitimate folderOpen dev task (npm run dev) — INFO, not FAIL', () => {
    const home = newHome(built, (h, p) => write(p('Projects/g/.vscode/tasks.json'),
      JSON.stringify({ version: '2.0.0', tasks: [{ label: 'dev', type: 'shell', command: 'npm run dev', runOptions: { runOn: 'folderOpen' } }] })));
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
  });

  it('is CLEAN on an empty HOME with no code roots', () => {
    const home = newHome(built, () => {});
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
    assert.match(r.stdout, /ALL CLEAR/);
  });
});

describe('scan-chaindrop-aug2026.sh — non-functional contract', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

  it('exit code is deterministic and idempotent (same tree → same code twice)', () => {
    const home = newHome(built, (h, p) => write(p('Projects/x/node_modules/keyv/Math_Symbol.js'), '//\n'));
    const a = runScanner(home);
    const b = runScanner(home);
    assert.equal(a.status, 1);
    assert.equal(b.status, a.status, 'scanner must be idempotent — re-running an unchanged tree yields the same exit code');
  });

  it('honors LSH_NO_NETWORK by skipping the gh dead-drop audit', () => {
    const home = newHome(built, () => {});
    const r = runScanner(home);
    assert.match(r.stdout, /Network checks disabled/);
  });

  it('does NOT flag a marker hidden in a file over the 256k size cap (bounded read), but reports INCOMPLETE (G-1512/D-02) rather than falsely claiming ALL CLEAR', () => {
    // A marker inside a large data/blob file is intentionally skipped: the
    // whole-tree content read is size-capped so the scan cannot stall on big
    // files. This pins that bound so a regression that removes it is caught.
    // 17.1-01 (G-1512/TRAV-15, decision D-02, operator-approved): the
    // skipped-oversized file now folds into `incomplete`, so this exits 2,
    // not 0 -- the scan never examined this file and must not claim it did.
    const home = newHome(built, (h, p) => {
      const big = 'x'.repeat(300 * 1024) + '\nnpm-cache.com\n';
      write(p('Projects/x/huge.js'), big);
    });
    const r = runScanner(home);
    assert.equal(r.status, 2, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
    assert.match(r.stdout, /INCOMPLETE/);
    assert.match(r.stdout, /\[skip\] oversized: 1/);
  });

  it('excludes its own repo (SELF_ROOT) so bundled IOC data does not self-flag', () => {
    // Point the scanner at its own repo, which legitimately contains every IOC
    // string as detection data. It must come back clean.
    const home = newHome(built, () => {});
    const r = runScanner(home, { LSH_ROOTS: REPO_ROOT });
    assert.equal(r.status, 0, `scanner flagged its own detection data:\n${r.stdout}`);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
  });

  it('honors LSH_ROOTS override (scans the given root, finds the IOC there)', () => {
    const codeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-root-'));
    built.push(codeDir);
    write(path.join(codeDir, 'app', 'node_modules', 'keyv', 'math_init.js'), '//\n');
    const home = newHome(built, () => {});
    const r = runScanner(home, { LSH_ROOTS: codeDir });
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /math_init\.js/);
  });

  it('completes on a broad tree without hanging (termination budget)', () => {
    // ~600 files across nested dirs; the run must finish (status is a number,
    // not null-from-timeout) comfortably inside runScanner's 60s cap.
    const home = newHome(built, (h, p) => {
      for (let i = 0; i < 600; i++) write(p(`Projects/big/pkg${i % 30}/file${i}.js`), `// file ${i}\n`);
    });
    const r = runScanner(home);
    assert.notEqual(r.status, null, 'scanner timed out / was killed — traversal is not bounded');
    assert.equal(r.status, 0, r.stdout);
  });

  // --------------------------------------------------------------------
  // G-1482 (plan 17-14) — new engine-backed behaviour, black-box.
  // --------------------------------------------------------------------

  it('SHA256 end to end: a >256KiB setup.mjs matching a hash added to a TEMPORARY wave spec FAILs', () => {
    // The one hash gap the frozen parity corpus cannot close — forging a
    // sha256 PREIMAGE of a real IOC is impossible, so this is the only way
    // to prove the whole black-box hash path (engine hashing, lists/
    // findings.z, the message table, the exit code) on a file well past
    // the 256 KiB bulk-content cap (D-24 — the hash-candidate tier is
    // deliberately exempt from that cap). Only possible AFTER this
    // retrofit: the OLD scanner's digests were hardcoded bash literals and
    // could not be pointed at a fixture at all.
    const home = newHome(built, () => {});
    const dir = path.join(home, 'Projects', 'x');
    fs.mkdirSync(dir, { recursive: true });
    const content = crypto.randomBytes(400 * 1024); // well past the 256 KiB bulk cap
    fs.writeFileSync(path.join(dir, 'setup.mjs'), content);
    const digest = crypto.createHash('sha256').update(content).digest('hex');

    const spec = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));
    spec.knownBadHashes.push({ sha256: digest, description: 'test fixture (plan 17-14)', sizeBytes: content.length });
    const tmpSpecPath = path.join(home, 'temp-wave-spec.json');
    fs.writeFileSync(tmpSpecPath, JSON.stringify(spec));

    const r = runScanner(home, { LSH_WAVE_SPEC: tmpSpecPath });
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /setup\.mjs matches a known ChainDrop loader hash/);
  });

  it('paired negative: the SAME setup.mjs fixture with the UNMODIFIED bundled spec never FAILs (WARN only) -- but exits 2 (INCOMPLETE) because the same >256KiB size also trips the oversized bulk-content skip (G-1512/D-02)', () => {
    // Proves the FAIL above is not caused by some unrelated marker in the
    // fixture — only the temporary spec's added hash makes it FAIL.
    // 17.1-01 (G-1512/TRAV-15, decision D-02, operator-approved): setup.mjs
    // is BOTH a hash candidate (1 MiB cap, D-24 -- unaffected, still
    // produces the setup-bare WARN below) AND a marker-config bulk-content
    // candidate (256 KiB cap) -- this fixture is well past the smaller cap,
    // so it is also recorded as an `oversized` skip, which now folds into
    // `incomplete`. The scan is honestly reporting it could not examine
    // this file for marker strings, even though its hash-based check did
    // run and found nothing.
    const home = newHome(built, () => {});
    const dir = path.join(home, 'Projects', 'x');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'setup.mjs'), crypto.randomBytes(400 * 1024));

    const r = runScanner(home);
    assert.equal(r.status, 2, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
    assert.match(r.stdout, /setup\.mjs present with no worm markers/);
    assert.match(r.stdout, /INCOMPLETE/);
    assert.match(r.stdout, /\[skip\] oversized: 1/);
  });

  it('a marker string in a git-ignored path outside PRUNE_COMMON still FAILs — no gitignore tiering trade-off (2026-08-07 review)', () => {
    // A D-13 gitignore-tiering trade-off for this exact scenario was
    // proposed, reviewed, and REJECTED as a real detection regression (the
    // old bash scanner's section 6b never consulted gitignore for ANY of
    // its marker-string allowlist, not just credential files). The fix
    // (lib/traverse/classify.js's isMarkerConfigMember widened to cover
    // every spec.classes['bulk-content'].fileGlobs member, not just
    // .env/.env.*/.npmrc) restores bash parity exactly, so this case is
    // now an ordinary frozen CASES entry (id: marker-gitignored-source) in
    // tests/helpers/chaindrop-corpus.js, covered end to end by
    // tests/chaindrop-parity.test.js's main detection-parity loop. This
    // test pins the same property directly in this file too.
    const home = newHome(built, (h, p) => {
      initRepo(p('Projects/repo'), {
        gitignore: 'notes/\n',
        untracked: { 'notes/loader.js': 'const c2 = "npm-cache.com";\n' },
      });
    });
    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /marker string/i);
  });

  it('engine crash (non-writing, non-2 exit): a "node" shim exiting 7 without writing anything makes the scanner exit 2, never 0 or 1', () => {
    const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-shim-'));
    built.push(shimDir);
    fs.writeFileSync(path.join(shimDir, 'node'), '#!/bin/sh\nexit 7\n');
    fs.chmodSync(path.join(shimDir, 'node'), 0o755);

    const home = newHome(built, () => {});
    const r = runScanner(home, { PATH: `${shimDir}:${process.env.PATH}` });
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stdout, /did not finish, this is NOT a clean result/);
  });

  it('engine crash (exits 1 but writes nothing readable): the scanner still exits 2, never reads a crash as "findings exist"', () => {
    const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-shim-'));
    built.push(shimDir);
    // Exits 1 (the status the real engine uses for "findings written") but
    // writes NOTHING to the results dir — the readback-validation guard
    // (missing scalars/exit-code + lists/findings.z), not the status
    // mapping, is what must catch this.
    fs.writeFileSync(path.join(shimDir, 'node'), '#!/bin/sh\nexit 1\n');
    fs.chmodSync(path.join(shimDir, 'node'), 0o755);

    const home = newHome(built, () => {});
    const r = runScanner(home, { PATH: `${shimDir}:${process.env.PATH}` });
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stdout, /did not finish, this is NOT a clean result/);
  });

  it('skip counts appear in the report: a symlink and an oversized file produce non-zero named skip-reason lines -- exits 2 (INCOMPLETE) because the oversized skip folds into incomplete (G-1512/D-02); symlink deliberately does not (D-06/D-12 -- Guard 4 in tests/traverse/engine.test.js pins this directly)', () => {
    const home = newHome(built, (h, p) => {
      const dir = p('Projects/x');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'real.js'), 'clean\n');
      fs.symlinkSync(path.join(dir, 'real.js'), path.join(dir, 'link.js'));
      fs.writeFileSync(path.join(dir, 'huge.js'), 'x'.repeat(300 * 1024));
    });
    const r = runScanner(home);
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stdout, /\[skip\] symlink: \d+/);
    assert.match(r.stdout, /\[skip\] oversized: \d+/);
    assert.match(r.stdout, /INCOMPLETE/);
  });

  it('LSH_BUDGET_SECONDS=0 on a clean tree exits 2, prints the not-clean message, and the retained results dir exists', () => {
    // A custom spawnSync (not the shared runScanner helper) — runScanner
    // removes its own mkdtemp'd TMPDIR unconditionally right after the run,
    // which would collaterally delete the retained results dir (nested
    // inside that same TMPDIR) before this assertion could observe it.
    const home = newHome(built, (h, p) => write(p('Projects/x/clean.js'), 'clean\n'));
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-tmp-'));
    built.push(tmp);
    const r = spawnSync('bash', [SCRIPT], {
      encoding: 'utf8',
      timeout: 60_000,
      env: { HOME: home, TMPDIR: tmp, PATH: process.env.PATH, LSH_NO_NETWORK: '1', LSH_BUDGET_SECONDS: '0' },
    });
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stdout, /the scan did not finish, this is NOT a clean result/);
    const m = r.stdout.match(/Results retained at: (\S+)/);
    assert.ok(m, `expected a "Results retained at" line\n${r.stdout}`);
    assert.ok(fs.existsSync(m[1]), `retained results dir does not exist: ${m[1]}`);
  });

  it('a finding AND an incomplete scan (LSH_MAX_FILES=1, marker root walked first) exits 1 and prints an INCOMPLETE line — D-18 precedence', () => {
    // LSH_BUDGET_SECONDS=0 can NEVER produce this combination: budget.js's
    // zero bound latches on the walk's very first noteDirectory() call (the
    // ROOT directory itself), before any child of that root is ever
    // emitted, so a zero-second budget can only ever yield ZERO findings
    // (verified empirically in tests/traverse/run-cli.test.js, which hit
    // this exact issue in plan 17-12 and documents it at the top of that
    // file). LSH_MAX_FILES=1 across two roots, with the marker as a DIRECT
    // child of the first-walked root, is the deterministic way to let one
    // finding survive while a later root still exhausts the bound.
    const home = newHome(built, (h, p) => {
      write(p('Projects/Math_Symbol.js'), '/* stub */\n'); // root's DIRECT child — survives before the bound trips
      write(p('Developer/other.js'), 'clean\n');
    });
    const r = runScanner(home, { LSH_MAX_FILES: '1' });
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /INCOMPLETE — results retained at/);
  });

  it('LSH_MAX_FILES=1 on a clean, multi-root tree bounds the run and reports incompleteness rather than hanging or silently truncating', () => {
    const home = newHome(built, (h, p) => {
      write(p('Projects/a.js'), 'clean a\n');
      write(p('Developer/b.js'), 'clean b\n');
    });
    const r = runScanner(home, { LSH_MAX_FILES: '1' });
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stdout, /the scan did not finish, this is NOT a clean result/);
  });

  it('a warn-only tree (a small Math_Helper.js and nothing else) exits 0 and prints the WARN line — severity-aware exit at the scanner level', () => {
    const home = newHome(built, (h, p) => write(p('Projects/a/Math_Helper.js'), 'export const add = (a,b) => a+b;\n'));
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
    assert.match(r.stdout, /\[WARN\]/);
  });

  it('a clean run leaves no lsh_chaindrop.* directory behind in its own TMPDIR', () => {
    const home = newHome(built, () => {});
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-tmp-'));
    built.push(tmp);
    const res = spawnSync('bash', [SCRIPT], {
      encoding: 'utf8',
      timeout: 60_000,
      env: { HOME: home, TMPDIR: tmp, PATH: process.env.PATH, LSH_NO_NETWORK: '1' },
    });
    assert.equal(res.status, 0, res.stdout);
    const leftover = fs.readdirSync(tmp).filter((n) => n.startsWith('lsh_chaindrop.'));
    assert.deepEqual(leftover, [], `orphan results dir(s) left in TMPDIR: ${leftover.join(', ')}`);
  });

  it('invokes the traversal engine exactly once per scan', () => {
    const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-shim-'));
    built.push(shimDir);
    const counterFile = path.join(shimDir, 'invocations.count');
    const realNode = process.execPath;
    fs.writeFileSync(
      path.join(shimDir, 'node'),
      `#!/bin/sh\nprintf 'x' >> "${counterFile}"\nexec "${realNode}" "$@"\n`
    );
    fs.chmodSync(path.join(shimDir, 'node'), 0o755);

    const home = newHome(built, (h, p) => write(p('Projects/x/node_modules/keyv/Math_Symbol.js'), '/* stub */\n'));
    const r = runScanner(home, { PATH: `${shimDir}:${process.env.PATH}` });
    assert.equal(r.status, 1, r.stdout);
    const invocationCount = fs.existsSync(counterFile) ? fs.readFileSync(counterFile, 'utf8').length : 0;
    assert.equal(invocationCount, 1, 'expected the traversal engine to be invoked exactly once');
  });

  it('a finding whose path contains a literal TAB and newline is reported byte-identically (scanner-level T-17-10/B5 guard)', () => {
    const home = newHome(built, () => {});
    const dir = path.join(home, 'Projects', 'x');
    fs.mkdirSync(dir, { recursive: true });
    const weirdName = 'loader\tweird\nname.js';
    fs.writeFileSync(path.join(dir, weirdName), 'const c2 = "npm-cache.com";\n');

    const r = runScanner(home);
    assert.equal(r.status, 1, r.stdout);
    assert.ok(r.stdout.includes(weirdName), `expected the hostile filename to appear byte-identically in stdout\n${JSON.stringify(r.stdout)}`);
  });
});

describe('ChainDrop manifest integrity + scanner parity (drift guards)', () => {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const spec = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));

  it('manifest is structurally complete (poisoned/lastKnownGood/coreFamily/hashes)', () => {
    for (const key of ['poisoned', 'lastKnownGood', 'coreFamily', 'fileHashes', 'network', 'publishWindowStart']) {
      assert.ok(manifest[key], `manifest missing "${key}"`);
    }
    assert.ok(Array.isArray(manifest.coreFamily) && manifest.coreFamily.length >= 11);
    // Every poisoned package must be listed in coreFamily.
    for (const pkg of Object.keys(manifest.poisoned)) {
      assert.ok(manifest.coreFamily.includes(pkg), `poisoned "${pkg}" absent from coreFamily`);
    }
    // The primary (non-scoped) family must have a last-known-good pin — that is
    // the vendor-confirmed downgrade target. Some @keyv/* scoped packages have
    // no published prior-version pin; we don't fabricate one, so they're exempt.
    const primaryFamily = manifest.coreFamily.filter((p) => !p.startsWith('@keyv/'));
    for (const pkg of primaryFamily) {
      if (manifest.poisoned[pkg]) {
        assert.ok(manifest.lastKnownGood[pkg], `no lastKnownGood pin for primary-family "${pkg}"`);
      }
    }
    // No orphan pins: every lastKnownGood entry must name a poisoned package.
    for (const pkg of Object.keys(manifest.lastKnownGood)) {
      assert.ok(manifest.poisoned[pkg], `lastKnownGood names "${pkg}" which is not in the poisoned map`);
    }
  });

  // G-1482 (plan 17-14): these two tests used to regex-parse
  // POISONED_PKG_VERSIONS=(...) / COMPROMISED_FAMILY=(...) directly out of
  // scripts/scan-chaindrop-aug2026.sh — the scanner no longer hardcodes
  // either array (it reads its IOC data from the wave spec via the
  // traversal engine's results directory), so both are rewritten to read
  // manifests/waves/chaindrop-aug2026.json instead, keeping the same
  // assertions. tests/chaindrop-spec-parity.test.js's spec-vs-manifest
  // parity block is the PERMANENT guard this pair now duplicates at the
  // manifest level (kept here too so a manifest/spec drift is caught from
  // this file's own describe block, matching its historical name).
  it('wave spec poisonedVersions matches the manifest `poisoned` map exactly', () => {
    const specFlat = flattenPoisoned(spec.poisonedVersions);
    const manifestFlat = flattenPoisoned(manifest.poisoned);
    assert.deepEqual([...specFlat].sort(), [...manifestFlat].sort(),
      'wave spec and manifest poisoned-version lists have drifted — update both');
  });

  it('every compromised-family name in the wave spec is present in manifest coreFamily', () => {
    const specFam = new Set(spec.compromisedFamily);
    const coreFamily = new Set(manifest.coreFamily);
    for (const fam of specFam) assert.ok(coreFamily.has(fam), `family "${fam}" not in manifest coreFamily`);
  });
});
