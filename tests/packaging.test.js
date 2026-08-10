'use strict';

// Product-gate packaging tests (G-1482, TRAV-07). Everything can be green in
// the repo and still broken for the user if `lib/traverse/` or
// `manifests/waves/` never made it into the published tarball -- these tests
// prove the SHIPPED artifact, not the repo checkout, contains the engine and
// runs cold, offline, with zero runtime dependencies.
//
// Uses `npm pack --dry-run --json` (contents assertion, no tarball written)
// and a real `npm pack` + `tar` extract (cold-run smoke) rather than
// asserting on package.json's `files` array directly -- npm's own glob
// resolution is the ground truth users actually receive, and asserting the
// declared config could pass while a real npm/gitignore interaction still
// dropped a file.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO_ROOT = path.join(__dirname, '..');
const NPM_TIMEOUT_MS = 60000;
const MAX_BUFFER = 64 * 1024 * 1024;

function npmAvailable() {
  const r = spawnSync('npm', ['--version'], { timeout: 10000 });
  return !r.error && r.status === 0;
}

// Computed once at module load -- every npm-dependent test shares this,
// rather than re-probing per test, and the whole suite degrades gracefully
// (skipped, not failed) when npm genuinely is not on PATH.
const NPM_OK = npmAvailable();
const NPM_SKIP_REASON = 'npm is not available on PATH';

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** `npm pack --dry-run --json` -- writes no tarball, reports the file set npm would ship. */
function packDryRunFiles() {
  const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: REPO_ROOT,
    timeout: NPM_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });
  assert.equal(result.status, 0, `npm pack --dry-run --json failed: ${result.stderr ? result.stderr.toString() : ''}`);
  const parsed = JSON.parse(result.stdout.toString('utf8'));
  return parsed[0].files.map((f) => f.path);
}

// ---------------------------------------------------------------------------
// Tarball contents
// ---------------------------------------------------------------------------

describe('packaging: npm pack tarball contents', () => {
  it(
    'ships the traversal engine, lib/roots.js, and the wave spec',
    { skip: !NPM_OK && NPM_SKIP_REASON },
    () => {
      const files = packDryRunFiles();
      const fileSet = new Set(files);

      // Derived from disk, not hardcoded (T-17-07-01) -- a future module
      // added to lib/traverse/ is covered automatically by this assertion.
      const traverseDirFiles = fs
        .readdirSync(path.join(REPO_ROOT, 'lib', 'traverse'))
        .filter((f) => f.endsWith('.js'))
        .map((f) => `lib/traverse/${f}`);
      assert.ok(traverseDirFiles.length > 0, 'lib/traverse/ should contain at least one module to assert against');

      const expected = [
        'lib/roots.js',
        ...traverseDirFiles,
        'manifests/waves/chaindrop-aug2026.json',
        'scripts/scan-chaindrop-aug2026.sh',
        'scripts/validate-wave-spec.js',
      ];

      for (const expectedPath of expected) {
        assert.ok(fileSet.has(expectedPath), `expected "${expectedPath}" in the published tarball, not found. Shipped files: ${files.join(', ')}`);
      }
    }
  );

  it('ships no path under tests/ or .planning/', { skip: !NPM_OK && NPM_SKIP_REASON }, () => {
    const files = packDryRunFiles();
    const leaked = files.filter((p) => p.startsWith('tests/') || p.startsWith('.planning/'));
    assert.deepEqual(leaked, [], `tarball must not contain tests/ or .planning/ paths, found: ${JSON.stringify(leaked)}`);
  });

  it('package.json declares zero runtime dependencies', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    assert.equal(
      Object.keys(pkg.dependencies || {}).length,
      0,
      'package.json must declare zero runtime dependencies (repo constraint, see CLAUDE.md)'
    );
  });
});

// ---------------------------------------------------------------------------
// Cold-run smoke -- proves the zero-runtime-dependency claim end to end from
// the EXTRACTED tarball, never the repo checkout.
// ---------------------------------------------------------------------------

describe('packaging: cold-run smoke from an extracted tarball', () => {
  it(
    'runs --version and the bundled ChainDrop scanner from a cold extract, offline, with zero node_modules',
    { skip: !NPM_OK && NPM_SKIP_REASON },
    () => {
      const packDest = mkTmp('lsh-pack-dest-');
      const extractDir = mkTmp('lsh-pack-extract-');
      const fixtureHome = mkTmp('lsh-pack-home-');

      try {
        const packResult = spawnSync('npm', ['pack', '--json', '--pack-destination', packDest], {
          cwd: REPO_ROOT,
          timeout: NPM_TIMEOUT_MS,
          maxBuffer: MAX_BUFFER,
        });
        assert.equal(packResult.status, 0, `npm pack failed: ${packResult.stderr ? packResult.stderr.toString() : ''}`);
        const packed = JSON.parse(packResult.stdout.toString('utf8'));
        const tarballPath = path.join(packDest, packed[0].filename);
        assert.ok(fs.existsSync(tarballPath), `expected tarball at ${tarballPath}`);

        const untar = spawnSync('tar', ['xzf', tarballPath, '-C', extractDir], { timeout: 30000 });
        assert.equal(untar.status, 0, `tar extraction failed: ${untar.stderr ? untar.stderr.toString() : ''}`);

        const packageDir = path.join(extractDir, 'package');
        assert.ok(fs.existsSync(packageDir), 'extracted tarball should contain a package/ directory');
        assert.ok(
          !fs.existsSync(path.join(packageDir, 'node_modules')),
          'extracted tarball must not contain node_modules -- zero runtime deps'
        );

        // --version, run FROM the extracted directory -- never the repo.
        const versionResult = spawnSync('node', [path.join(packageDir, 'bin', 'llm-safe-haven.js'), '--version'], {
          cwd: packageDir,
          timeout: 15000,
        });
        assert.equal(
          versionResult.status,
          0,
          `--version should exit 0 from the cold extract: ${versionResult.stderr ? versionResult.stderr.toString() : ''}`
        );

        // Cold, offline scanner run against an empty fixture HOME -- no
        // Projects/Developer/etc. root exists under it, so the default root
        // list resolves to nothing and the static persistence-path checks
        // find nothing either; the run should be fast and ALL CLEAR.
        const scanResult = spawnSync('bash', [path.join(packageDir, 'scripts', 'scan-chaindrop-aug2026.sh')], {
          cwd: packageDir,
          env: { ...process.env, HOME: fixtureHome, LSH_NO_NETWORK: '1' },
          timeout: 30000,
          maxBuffer: MAX_BUFFER,
        });
        const stdout = scanResult.stdout ? scanResult.stdout.toString() : '';
        const stderr = scanResult.stderr ? scanResult.stderr.toString() : '';
        assert.equal(scanResult.status, 0, `cold scanner run should exit 0 (ALL CLEAR), got ${scanResult.status}. stderr: ${stderr}`);
        assert.ok(stdout.includes('ALL CLEAR'), `expected "ALL CLEAR" in cold scanner stdout, got: ${stdout}`);
      } finally {
        fs.rmSync(packDest, { recursive: true, force: true });
        fs.rmSync(extractDir, { recursive: true, force: true });
        fs.rmSync(fixtureHome, { recursive: true, force: true });
      }
    }
  );
});
