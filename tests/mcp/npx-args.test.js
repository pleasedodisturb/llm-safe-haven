'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  commandBasename,
  packageNameFromSpec,
  derivePackageName,
  isSafePackageName,
} = require('../../lib/mcp/npx-args.js');

describe('npx-args shared helpers (Phase 6, D-15)', () => {
  it('exports exactly the four documented helpers', () => {
    const mod = require('../../lib/mcp/npx-args.js');
    assert.deepStrictEqual(
      Object.keys(mod).sort(),
      ['commandBasename', 'derivePackageName', 'isSafePackageName', 'packageNameFromSpec']
    );
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
