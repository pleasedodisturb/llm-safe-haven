'use strict';

// Tests for lib/docs-verify/helpers/discover-md.js (G-1570).
//
// PRODUCTION CONTRACT, stated honestly (see the header comment in
// discover-md.js): discoverMarkdown() returns every on-disk *.md under
// root, MINUS the root .gitignore's directory entries, MINUS
// STATIC_SKIP_DIRS. It is NOT "every tracked markdown file" -- it
// consults no VCS index. The parity assertion below is a TRIPWIRE on a
// coincidence that holds on this checkout today, not the definition: it
// fires the moment an untracked *.md appears outside an ignored
// directory, or a nested .gitignore (today only .serena/.gitignore,
// which covers no markdown) starts covering markdown.
//
// The independent oracle (git ls-files) is invoked from THIS TEST FILE
// ONLY, decoded via -z (NUL-delimited) and split on the NUL character --
// never piped through a text-search tool, whose `-I` shim silently skips
// NUL-bearing files and exits 1 identically to "no match" (project
// convention, feedback_grep_nul_silent_skip).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const {
  discoverMarkdown,
  STATIC_SKIP_DIRS,
  gitignoreDirEntries,
} = require('../../lib/docs-verify/helpers/discover-md.js');

const REPO_ROOT = path.join(__dirname, '..', '..');

/**
 * Returns every VCS-tracked *.md path (repo-relative POSIX), or THROWS
 * with a message naming the cause -- never a test-runner skip. A skipped
 * parity test is indistinguishable from a passing one in CI output.
 */
function trackedMarkdownFiles(root) {
  if (!fs.existsSync(path.join(root, '.git'))) {
    throw new Error(
      'docs-verify discovery parity oracle requires a .git directory at the repo root -- none found'
    );
  }
  let res;
  try {
    res = spawnSync('git', ['ls-files', '-z', '--', '*.md'], { cwd: root, encoding: 'buffer', timeout: 30_000 });
  } catch (err) {
    throw new Error(`docs-verify discovery parity oracle requires a working git binary on PATH: ${err.message}`);
  }
  if (res.error) {
    throw new Error(`docs-verify discovery parity oracle requires a working git binary on PATH: ${res.error.message}`);
  }
  if (res.status !== 0) {
    throw new Error(`git ls-files exited ${res.status}: ${res.stderr ? res.stderr.toString('utf8') : ''}`);
  }
  return res.stdout
    .toString('utf8')
    .split('\0')
    .filter((p) => p !== '');
}

function isUnderSkip(p, skipDirs) {
  for (const skip of skipDirs) {
    if (p === skip || p.startsWith(`${skip}/`)) return true;
  }
  return false;
}

function filterExcluded(paths, skipDirs) {
  return paths.filter((p) => !isUnderSkip(p, skipDirs));
}

describe('discover-md.js -- non-vacuity guards (run first, per project convention)', () => {
  it('the raw oracle, the filtered oracle, and the discovered set are all non-empty and contain README.md + docs/mcp-security.md', () => {
    const raw = trackedMarkdownFiles(REPO_ROOT);
    assert.ok(raw.length > 0, 'raw VCS oracle must be non-empty');

    const skipDirs = new Set([...STATIC_SKIP_DIRS, ...gitignoreDirEntries(REPO_ROOT)]);
    const filtered = filterExcluded(raw, skipDirs);
    assert.ok(filtered.length > 0, 'filtered oracle must be non-empty');

    const discovered = discoverMarkdown(REPO_ROOT).files;
    assert.ok(discovered.length > 0, 'empty discovery');

    assert.ok(raw.includes('README.md'));
    assert.ok(filtered.includes('README.md'));
    assert.ok(discovered.includes('README.md'), 'README.md missing');

    assert.ok(raw.includes('docs/mcp-security.md'));
    assert.ok(filtered.includes('docs/mcp-security.md'));
    assert.ok(discovered.includes('docs/mcp-security.md'));

    // Only NOW, with every non-vacuity guard cleared, is the set
    // comparison below meaningful -- an oracle that returned nothing and
    // a walk that returned nothing would otherwise trivially "agree".
  });
});

describe('discover-md.js -- parity with the VCS-tracked set, filtered through the SAME exclusions', () => {
  it('discoverMarkdown(repoRoot).files equals the tracked *.md set minus STATIC_SKIP_DIRS minus gitignore dir entries', () => {
    const raw = trackedMarkdownFiles(REPO_ROOT);
    const skipDirs = new Set([...STATIC_SKIP_DIRS, ...gitignoreDirEntries(REPO_ROOT)]);
    const filtered = filterExcluded(raw, skipDirs).slice().sort();
    const discovered = discoverMarkdown(REPO_ROOT).files.slice().sort();
    assert.deepEqual(discovered, filtered);
  });

  it('fixture-corpus tripwire: tracked *.md under tests/fixtures/docs-verify/ is non-empty AND excluded from discovery (single case, both halves)', () => {
    const raw = trackedMarkdownFiles(REPO_ROOT);
    const fixtureTracked = raw.filter((p) => p.startsWith('tests/fixtures/docs-verify/'));
    assert.ok(
      fixtureTracked.length > 0,
      "the guard's own planted-defect corpus must be committed -- an empty corpus would satisfy the exclusion half vacuously"
    );
    const discovered = discoverMarkdown(REPO_ROOT).files;
    for (const p of fixtureTracked) {
      assert.ok(!discovered.includes(p), `${p} must be excluded from discovery`);
    }
  });
});

describe('discover-md.js -- exclusion coverage', () => {
  it('no discovered path starts with tests/fixtures/', () => {
    const discovered = discoverMarkdown(REPO_ROOT).files;
    const leaked = discovered.filter((f) => f.startsWith('tests/fixtures/'));
    assert.deepEqual(leaked, []);
  });

  it('no discovered path starts with docs/sessions/, .planning/, or graphify-out/ (gitignore-derived exclusions)', () => {
    const discovered = discoverMarkdown(REPO_ROOT).files;
    const leaked = discovered.filter(
      (f) => f.startsWith('docs/sessions/') || f.startsWith('.planning/') || f.startsWith('graphify-out/')
    );
    assert.deepEqual(leaked, []);
  });

  it('STATIC_SKIP_DIRS contains the multi-segment tests/fixtures entry (non-vacuity: at least one multi-segment entry exists)', () => {
    const entries = [...STATIC_SKIP_DIRS];
    assert.ok(entries.includes('tests/fixtures'), 'tests/fixtures missing from STATIC_SKIP_DIRS');
    assert.ok(
      entries.some((e) => e.includes('/')),
      'non-vacuity: no multi-segment entry present to exercise path matching'
    );
  });

  it('multi-segment exclusion is matched on the normalized path, never a bare basename (paired control)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-discover-md-'));
    try {
      fs.mkdirSync(path.join(tmp, 'fixtures'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'fixtures', 'a.md'), '# a\n');
      fs.mkdirSync(path.join(tmp, 'tests', 'fixtures'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'tests', 'fixtures', 'b.md'), '# b\n');

      const { files } = discoverMarkdown(tmp);
      assert.ok(files.includes('fixtures/a.md'), 'a basename-matching implementation would wrongly exclude this');
      assert.ok(
        !files.includes('tests/fixtures/b.md'),
        'a no-multi-segment-support implementation would wrongly include this'
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('discover-md.js -- single-segment .gitignore entries match at ANY depth; multi-segment entries stay prefix-only (F4, Codex review PR #105)', () => {
  it('a single-segment .gitignore entry (node_modules/) excludes a NESTED directory of that name, not just a root-level one', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-discover-md-nested-single-'));
    try {
      fs.writeFileSync(path.join(tmp, '.gitignore'), 'node_modules/\n');
      fs.mkdirSync(path.join(tmp, 'a', 'b', 'node_modules'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'a', 'b', 'node_modules', 'x.md'), '# x\n');
      fs.writeFileSync(path.join(tmp, 'visible.md'), '# visible\n');

      const { files } = discoverMarkdown(tmp);
      assert.ok(
        !files.includes('a/b/node_modules/x.md'),
        `nested node_modules markdown was swept despite a single-segment .gitignore entry: ${JSON.stringify(files)}`
      );
      assert.ok(files.includes('visible.md'), 'non-vacuity: an ordinary root-level file must still be discovered');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('must-still-pass twin: a multi-segment skip entry (tests/fixtures) stays prefix-only -- a nested dir merely NAMED "fixtures" deeper in the tree is still discovered', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-discover-md-nested-multi-'));
    try {
      fs.mkdirSync(path.join(tmp, 'a', 'b', 'fixtures'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'a', 'b', 'fixtures', 'y.md'), '# y\n');

      const { files } = discoverMarkdown(tmp);
      assert.ok(
        files.includes('a/b/fixtures/y.md'),
        `a/b/fixtures/y.md was wrongly excluded -- STATIC_SKIP_DIRS' "tests/fixtures" entry is multi-segment and must stay prefix-only, never a basename match: ${JSON.stringify(files)}`
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('must-still-pass twin: a single-segment entry still excludes at the ROOT level too (depth 0), not only nested', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-discover-md-root-single-'));
    try {
      fs.writeFileSync(path.join(tmp, '.gitignore'), 'node_modules/\n');
      fs.mkdirSync(path.join(tmp, 'node_modules'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'node_modules', 'z.md'), '# z\n');
      fs.writeFileSync(path.join(tmp, 'visible.md'), '# visible\n');

      const { files } = discoverMarkdown(tmp);
      assert.ok(!files.includes('node_modules/z.md'), `root-level node_modules markdown was swept: ${JSON.stringify(files)}`);
      assert.ok(files.includes('visible.md'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('discover-md.js -- error surfacing', () => {
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

  it(
    'an unreadable subdirectory produces a non-empty errors array, not a silently shrunk files array',
    { skip: isRoot ? 'running as root bypasses permission bits -- this case cannot be exercised' : false },
    () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-discover-md-unreadable-'));
      const blocked = path.join(tmp, 'blocked');
      fs.mkdirSync(blocked);
      fs.writeFileSync(path.join(blocked, 'inner.md'), '# inner\n');
      fs.writeFileSync(path.join(tmp, 'visible.md'), '# visible\n');
      fs.chmodSync(blocked, 0o000);
      try {
        const { files, errors } = discoverMarkdown(tmp);
        assert.ok(errors.length > 0, 'an unreadable directory must surface in errors, not vanish silently');
        assert.ok(files.includes('visible.md'));
      } finally {
        fs.chmodSync(blocked, 0o755);
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    }
  );
});

describe('discover-md.js -- determinism and honesty', () => {
  it('two calls return identical, byte-sorted output', () => {
    const a = discoverMarkdown(REPO_ROOT).files;
    const b = discoverMarkdown(REPO_ROOT).files;
    assert.deepEqual(a, b, 'discovery order is not stable');
    const sorted = a.slice().sort();
    assert.deepEqual(a, sorted, 'discovery is not byte-sorted');
  });

  it('the helper never spawns a subprocess (VCS/text-search or otherwise)', () => {
    const source = fs.readFileSync(
      path.join(__dirname, '..', '..', 'lib', 'docs-verify', 'helpers', 'discover-md.js'),
      'utf8'
    );
    assert.ok(!/child_process|spawnSync|execSync|execFileSync/.test(source));
  });
});
