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
// Fixtures are built at runtime in an isolated HOME rather than committed — a
// file literally named Math_Symbol.js or a real poisoned lockfile in the repo
// is a self-scan hazard. Skips cleanly if bash is unavailable.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'scan-chaindrop-aug2026.sh');
const MANIFEST = path.join(__dirname, '..', 'manifests', 'chaindrop-poisoned-versions.json');
const REPO_ROOT = path.join(__dirname, '..');
const hasBash = spawnSync('bash', ['-c', 'true']).status === 0;

function write(file, contents) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

// Run the scanner against an isolated HOME (+ clean TMPDIR), network disabled.
// extraEnv lets a test flip LSH_NO_NETWORK off or set LSH_ROOTS.
function runScanner(home, extraEnv = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-tmp-'));
  const res = spawnSync('bash', [SCRIPT], {
    encoding: 'utf8',
    timeout: 60_000, // non-functional: a run must terminate well within this
    env: { HOME: home, TMPDIR: tmp, PATH: process.env.PATH, LSH_NO_NETWORK: '1', ...extraEnv },
  });
  fs.rmSync(tmp, { recursive: true, force: true });
  return res;
}

// Build a throwaway HOME, hand it to `build`, return its path. Registered for
// cleanup by the caller's `after`.
function newHome(built, build) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-'));
  built.push(home);
  build(home, (rel) => path.join(home, rel));
  return home;
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

  it('does NOT flag a marker hidden in a file over the 256k size cap (bounded read)', () => {
    // A marker inside a large data/blob file is intentionally skipped: the
    // whole-tree content read is size-capped so the scan cannot stall on big
    // files. This pins that bound so a regression that removes it is caught.
    const home = newHome(built, (h, p) => {
      const big = 'x'.repeat(300 * 1024) + '\nnpm-cache.com\n';
      write(p('Projects/x/huge.js'), big);
    });
    const r = runScanner(home);
    assert.equal(r.status, 0, r.stdout);
    assert.doesNotMatch(r.stdout, /\[FAIL\]/);
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
});

describe('ChainDrop manifest integrity + scanner parity (drift guards)', () => {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));

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

  it('scanner POISONED_PKG_VERSIONS matches the manifest `poisoned` map exactly', () => {
    const script = fs.readFileSync(SCRIPT, 'utf8');
    const block = script.match(/POISONED_PKG_VERSIONS=\(([\s\S]*?)\n\)/);
    assert.ok(block, 'could not locate POISONED_PKG_VERSIONS array');
    const scriptSet = new Set([...block[1].matchAll(/"([^"]+@[^"]+)"/g)].map((m) => m[1]));
    const manifestSet = new Set();
    for (const [pkg, versions] of Object.entries(manifest.poisoned)) {
      for (const v of versions) manifestSet.add(`${pkg}@${v}`);
    }
    assert.deepEqual([...scriptSet].sort(), [...manifestSet].sort(),
      'scanner and manifest poisoned-version lists have drifted — update both');
  });

  it('every compromised-family name in the scanner is present in manifest coreFamily', () => {
    const script = fs.readFileSync(SCRIPT, 'utf8');
    const block = script.match(/COMPROMISED_FAMILY=\(([\s\S]*?)\)/);
    assert.ok(block, 'could not locate COMPROMISED_FAMILY array');
    const scriptFam = new Set([...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]));
    const coreFamily = new Set(manifest.coreFamily);
    for (const fam of scriptFam) assert.ok(coreFamily.has(fam), `family "${fam}" not in manifest coreFamily`);
  });
});
