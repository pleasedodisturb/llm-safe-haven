'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  commandBasename,
  extractSpec,
  packageNameFromSpec,
  versionFromSpec,
  classifySpecSuffix,
  EXACT_SEMVER_RE,
  derivePackageName,
  isSafePackageName,
} = require('../../lib/mcp/npx-args.js');

describe('npx-args shared helpers (Phase 6, D-15)', () => {
  it('exports exactly the eight documented helpers', () => {
    const mod = require('../../lib/mcp/npx-args.js');
    assert.deepStrictEqual(
      Object.keys(mod).sort(),
      ['EXACT_SEMVER_RE', 'classifySpecSuffix', 'commandBasename', 'derivePackageName', 'extractSpec', 'isSafePackageName', 'packageNameFromSpec', 'versionFromSpec']
    );
  });

  describe('extractSpec (WR-06: the single shared flag-scan loop)', () => {
    it('returns the first positional token raw, version suffix intact', () => {
      assert.strictEqual(extractSpec(['@scope/pkg@1.2.3']), '@scope/pkg@1.2.3');
    });

    it('returns the -p value, not the trailing command token', () => {
      assert.strictEqual(extractSpec(['-p', 'pkg@1.0.0', 'serve']), 'pkg@1.0.0');
    });

    it('returns the --package value and handles the joined --package=<spec> form', () => {
      assert.strictEqual(extractSpec(['--package', 'pkg@1.0.0', 'serve']), 'pkg@1.0.0');
      assert.strictEqual(extractSpec(['--package=pkg@1.0.0', 'serve']), 'pkg@1.0.0');
    });

    it('skips leading flag tokens before the positional spec', () => {
      assert.strictEqual(extractSpec(['--yes', 'pkg']), 'pkg');
    });

    it('WR-06 divergence case: a NON-STRING -p value refuses (null) — never falls back to the trailing command token', () => {
      // Pre-consolidation, the three local copies disagreed here:
      // unpinned-execution's returned 'cmd' (the wrong token) while
      // derivePackageName returned null. The shared semantics refuse.
      assert.strictEqual(extractSpec(['-p', 123, 'cmd']), null);
    });

    it('returns null for a dangling trailing -p, empty args, and non-array args', () => {
      assert.strictEqual(extractSpec(['-p']), null);
      assert.strictEqual(extractSpec([]), null);
      assert.strictEqual(extractSpec(undefined), null);
    });
  });

  describe('versionFromSpec', () => {
    it('extracts an exact version from unscoped and scoped specs', () => {
      assert.strictEqual(versionFromSpec('pkg@1.2.3'), '1.2.3');
      assert.strictEqual(versionFromSpec('@scope/pkg@1.2.3'), '1.2.3');
    });

    it('extracts range and dist-tag suffixes raw (classification is the caller\'s job)', () => {
      assert.strictEqual(versionFromSpec('pkg@^1.0.0'), '^1.0.0');
      assert.strictEqual(versionFromSpec('@scope/pkg@next'), 'next');
    });

    it('returns null for a bare name (no suffix), a malformed spec, or a non-string', () => {
      assert.strictEqual(versionFromSpec('pkg'), null);
      assert.strictEqual(versionFromSpec('@scope/pkg'), null);
      assert.strictEqual(versionFromSpec('../../evil'), null);
      assert.strictEqual(versionFromSpec(null), null);
    });

    it('F2: extracts PyPI/PEP 508 operator suffixes WITH the operator', () => {
      assert.strictEqual(versionFromSpec('pkg==1.0.0'), '==1.0.0');
      assert.strictEqual(versionFromSpec('pkg>=0.1'), '>=0.1');
      assert.strictEqual(versionFromSpec('pkg~=1.4'), '~=1.4');
      assert.strictEqual(versionFromSpec('pkg!=2.0'), '!=2.0');
      assert.strictEqual(versionFromSpec('pkg<=3'), '<=3');
    });
  });

  describe('classifySpecSuffix (F8: the single shared pin classification)', () => {
    it('classifies exact npm semvers as "exact"', () => {
      assert.strictEqual(classifySpecSuffix('1.2.3'), 'exact');
      assert.strictEqual(classifySpecSuffix('v1.2.3'), 'exact');
      assert.strictEqual(classifySpecSuffix('1.2.3-beta.1'), 'exact');
      assert.strictEqual(classifySpecSuffix('1.2.3+build.5'), 'exact');
    });

    it('F2: classifies an exact PyPI == pin as "exact", but a ==-prefix wildcard as "range"', () => {
      assert.strictEqual(classifySpecSuffix('==1.0.0'), 'exact');
      assert.strictEqual(classifySpecSuffix('==1.0.0rc1'), 'exact');
      assert.strictEqual(classifySpecSuffix('==1.*'), 'range');
    });

    it('classifies ranges, wildcards, and partial versions as "range"', () => {
      for (const s of ['^1.0.0', '~2.3.4', '>=0.1', '~=1.4', '!=2.0', '<3', '1', '1.2', '1.x', '*']) {
        assert.strictEqual(classifySpecSuffix(s), 'range', `expected range for ${s}`);
      }
    });

    it('classifies dist-tags as "tag"', () => {
      assert.strictEqual(classifySpecSuffix('latest'), 'tag');
      assert.strictEqual(classifySpecSuffix('next'), 'tag');
      assert.strictEqual(classifySpecSuffix('canary'), 'tag');
    });

    it('returns null for a missing suffix (bare name) or non-string', () => {
      assert.strictEqual(classifySpecSuffix(null), null);
      assert.strictEqual(classifySpecSuffix(''), null);
      assert.strictEqual(classifySpecSuffix(undefined), null);
    });

    it('EXACT_SEMVER_RE capture group normalizes the v prefix away', () => {
      assert.strictEqual(EXACT_SEMVER_RE.exec('v1.2.3')[1], '1.2.3');
    });
  });

  describe('commandBasename', () => {
    it('returns the basename for a bare "npx" command', () => {
      assert.strictEqual(commandBasename('npx'), 'npx');
    });

    it('returns the basename for an absolute /usr/bin/npx path', () => {
      assert.strictEqual(commandBasename('/usr/bin/npx'), 'npx');
    });

    it('returns null for a non-string command', () => {
      assert.strictEqual(commandBasename(null), null);
      assert.strictEqual(commandBasename(undefined), null);
      assert.strictEqual(commandBasename(42), null);
    });

    it('returns null for an empty-string command', () => {
      assert.strictEqual(commandBasename(''), null);
    });
  });

  describe('packageNameFromSpec', () => {
    it('returns a bare package name unchanged', () => {
      assert.strictEqual(packageNameFromSpec('pkg'), 'pkg');
    });

    it('preserves a leading @scope/name', () => {
      assert.strictEqual(packageNameFromSpec('@scope/name'), '@scope/name');
    });

    it('strips a trailing @version from a scoped spec', () => {
      assert.strictEqual(packageNameFromSpec('@scope/name@1.2.3'), '@scope/name');
    });

    it('strips a trailing @version from an unscoped spec', () => {
      assert.strictEqual(packageNameFromSpec('pkg@1.2.3'), 'pkg');
    });

    it('F2: strips PyPI/PEP 508 operator suffixes (== >= ~= !=) from a uvx-style spec', () => {
      assert.strictEqual(packageNameFromSpec('mcp-server-fetch==1.0.0'), 'mcp-server-fetch');
      assert.strictEqual(packageNameFromSpec('pkg>=0.1'), 'pkg');
      assert.strictEqual(packageNameFromSpec('pkg~=1.4'), 'pkg');
      assert.strictEqual(packageNameFromSpec('pkg!=2.0'), 'pkg');
    });

    it('returns null for a path-traversal spec (CR-02)', () => {
      assert.strictEqual(packageNameFromSpec('../../evil'), null);
    });

    it('returns null for other path-separator-bearing specs', () => {
      assert.strictEqual(packageNameFromSpec('./local/pkg'), null);
      assert.strictEqual(packageNameFromSpec('/abs/pkg'), null);
    });

    it('returns null for a non-string spec', () => {
      assert.strictEqual(packageNameFromSpec(null), null);
      assert.strictEqual(packageNameFromSpec(undefined), null);
    });
  });

  describe('derivePackageName', () => {
    it('derives from a bare positional arg', () => {
      assert.strictEqual(derivePackageName(['pkg']), 'pkg');
    });

    it('returns the -p value, not the trailing command token (WR-03)', () => {
      assert.strictEqual(derivePackageName(['-p', '@scope/pkg', 'run-bin']), '@scope/pkg');
    });

    it('returns the --package value, not the trailing command token (WR-03)', () => {
      assert.strictEqual(derivePackageName(['--package', '@scope/pkg', 'run-bin']), '@scope/pkg');
    });

    it('handles the joined --package=<spec> form', () => {
      assert.strictEqual(derivePackageName(['--package=@scope/pkg', 'run-bin']), '@scope/pkg');
    });

    it('skips leading flag tokens before the positional spec', () => {
      assert.strictEqual(derivePackageName(['--yes', 'pkg']), 'pkg');
    });

    it('returns null for empty args', () => {
      assert.strictEqual(derivePackageName([]), null);
    });

    it('returns null when args is not an array', () => {
      assert.strictEqual(derivePackageName(undefined), null);
    });

    it('returns null for a dangling trailing -p with no value', () => {
      assert.strictEqual(derivePackageName(['-p']), null);
    });
  });

  describe('isSafePackageName', () => {
    it('accepts a bare package name', () => {
      assert.strictEqual(isSafePackageName('pkg'), true);
    });

    it('accepts a scoped @scope/name', () => {
      assert.strictEqual(isSafePackageName('@scope/name'), true);
    });

    it('rejects an absolute path', () => {
      assert.strictEqual(isSafePackageName('/etc/passwd'), false);
    });

    it('rejects a dot-dot traversal segment', () => {
      assert.strictEqual(isSafePackageName('..'), false);
      assert.strictEqual(isSafePackageName('../evil'), false);
    });

    it('rejects a three-segment path', () => {
      assert.strictEqual(isSafePackageName('a/b/c'), false);
    });

    it('rejects a name containing a backslash', () => {
      assert.strictEqual(isSafePackageName('pkg\\evil'), false);
    });

    it('rejects a non-string or empty-string input', () => {
      assert.strictEqual(isSafePackageName(''), false);
      assert.strictEqual(isSafePackageName(null), false);
      assert.strictEqual(isSafePackageName(undefined), false);
    });
  });
});
