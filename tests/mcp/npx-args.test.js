'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  commandBasename,
  extractSpec,
  packageNameFromSpec,
  versionFromSpec,
  classifySpecSuffix,
  gitSpecPin,
  EXACT_SEMVER_RE,
  derivePackageName,
  isSafePackageName,
} = require('../../lib/mcp/npx-args.js');

describe('npx-args shared helpers (Phase 6, D-15)', () => {
  it('exports exactly the nine documented helpers', () => {
    const mod = require('../../lib/mcp/npx-args.js');
    assert.deepStrictEqual(
      Object.keys(mod).sort(),
      ['EXACT_SEMVER_RE', 'classifySpecSuffix', 'commandBasename', 'derivePackageName', 'extractSpec', 'gitSpecPin', 'isSafePackageName', 'packageNameFromSpec', 'versionFromSpec']
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

    describe('F1: per-runner value-taking flag grammar', () => {
      it('npx: skips a known value-taking flag WITH its value (--loglevel warn)', () => {
        assert.strictEqual(extractSpec(['--loglevel', 'warn', 'pkg@1.2.3'], 'npx'), 'pkg@1.2.3');
      });

      it('npx: skips -c/--call and --node-arg values', () => {
        assert.strictEqual(extractSpec(['-c', 'echo hi', 'pkg'], 'npx'), 'pkg');
        assert.strictEqual(extractSpec(['--node-arg', '--max-old-space-size=512', 'pkg'], 'npx'), 'pkg');
        assert.strictEqual(extractSpec(['--registry', 'https://registry.example.com', 'pkg'], 'npx'), 'pkg');
      });

      it('uvx: -p is --python, NOT --package — its value is skipped, the positional is the spec', () => {
        assert.strictEqual(extractSpec(['-p', '3.12', 'real-pkg'], 'uvx'), 'real-pkg');
        assert.strictEqual(extractSpec(['--python', '3.12', 'real-pkg'], 'uvx'), 'real-pkg');
      });

      it('uvx: --from value IS the spec (split and joined forms), not the trailing command token', () => {
        assert.strictEqual(extractSpec(['--from', 'pkg==1.0.0', 'cmd'], 'uvx'), 'pkg==1.0.0');
        assert.strictEqual(extractSpec(['--from=pkg==1.0.0', 'cmd'], 'uvx'), 'pkg==1.0.0');
      });

      it('uvx: skips --with/--index-url/--constraint values before the positional spec', () => {
        assert.strictEqual(extractSpec(['--with', 'extra-pkg', 'real-pkg'], 'uvx'), 'real-pkg');
        assert.strictEqual(extractSpec(['--index-url', 'https://pypi.example.com', 'real-pkg'], 'uvx'), 'real-pkg');
        assert.strictEqual(extractSpec(['--constraint', 'constraints.txt', 'real-pkg'], 'uvx'), 'real-pkg');
      });

      it('an omitted/unknown runner uses the npx grammar (historical default)', () => {
        assert.strictEqual(extractSpec(['--loglevel', 'warn', 'pkg']), 'pkg');
        assert.strictEqual(extractSpec(['-p', 'pkg@1.0.0', 'serve'], 'node'), 'pkg@1.0.0');
      });

      it('documented limitation: an UNKNOWN value-taking flag still leaks its value as the positional', () => {
        // Arity of unknown flags is unknowable — this locks the
        // deliberate conservative fallback so a change to it is loud.
        assert.strictEqual(extractSpec(['--some-future-flag', 'value', 'pkg'], 'npx'), 'value');
      });
    });

    describe('F5: a flag-shaped spec-flag value refuses (null)', () => {
      it('npx -p followed by another flag never treats the flag as the spec', () => {
        assert.strictEqual(extractSpec(['-p', '--yes', 'cowsay@1.0.0'], 'npx'), null);
        assert.strictEqual(extractSpec(['--package', '--yes', 'cowsay@1.0.0'], 'npx'), null);
      });

      it('joined forms refuse flag-shaped and empty values too', () => {
        assert.strictEqual(extractSpec(['--package=-evil', 'cmd'], 'npx'), null);
        assert.strictEqual(extractSpec(['--package=', 'cmd'], 'npx'), null);
        assert.strictEqual(extractSpec(['--from=-evil', 'cmd'], 'uvx'), null);
      });

      it('uvx --from with a missing, non-string, or flag-shaped value refuses', () => {
        assert.strictEqual(extractSpec(['--from'], 'uvx'), null);
        assert.strictEqual(extractSpec(['--from', 123, 'cmd'], 'uvx'), null);
        assert.strictEqual(extractSpec(['--from', '--offline', 'cmd'], 'uvx'), null);
      });
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

  describe('gitSpecPin (G-1368: git direct-reference pin classification)', () => {
    const FULL_SHA = 'd2f6f8b0c3a94ef7f4b8c19aa2f0e3d4c5b6a798';

    it('returns null for non-git specs (caller falls through to SPEC_RE classification)', () => {
      assert.strictEqual(gitSpecPin('pkg'), null);
      assert.strictEqual(gitSpecPin('pkg@1.2.3'), null);
      assert.strictEqual(gitSpecPin('@scope/pkg@1.2.3'), null);
      assert.strictEqual(gitSpecPin('mcp-server-fetch==1.0.0'), null);
      assert.strictEqual(gitSpecPin('https://github.com/org/repo'), null);
      assert.strictEqual(gitSpecPin('git-extras'), null);
      assert.strictEqual(gitSpecPin(null), null);
      assert.strictEqual(gitSpecPin(undefined), null);
      assert.strictEqual(gitSpecPin(42), null);
    });

    it('classifies a git+https spec with NO ref as unpinned', () => {
      assert.strictEqual(gitSpecPin('git+https://github.com/oraios/serena'), 'unpinned');
    });

    it('classifies branch and tag refs as unpinned (mutable)', () => {
      assert.strictEqual(gitSpecPin('git+https://github.com/oraios/serena@main'), 'unpinned');
      assert.strictEqual(gitSpecPin('git+https://github.com/oraios/serena@v1.2.3'), 'unpinned');
    });

    it('classifies a full 40-hex commit SHA ref as exact (the immutable pin)', () => {
      assert.strictEqual(gitSpecPin(`git+https://github.com/oraios/serena@${FULL_SHA}`), 'exact');
    });

    it('accepts an UPPERCASE full SHA (lowercased before the hex check)', () => {
      assert.strictEqual(gitSpecPin(`git+https://github.com/oraios/serena@${FULL_SHA.toUpperCase()}`), 'exact');
    });

    it('classifies a short SHA (7-39 hex) as unpinned (prefix-ambiguous)', () => {
      assert.strictEqual(gitSpecPin(`git+https://github.com/oraios/serena@${FULL_SHA.slice(0, 12)}`), 'unpinned');
      assert.strictEqual(gitSpecPin(`git+https://github.com/oraios/serena@${FULL_SHA.slice(0, 39)}`), 'unpinned');
    });

    it('a 41-hex ref and a 40-char non-hex ref are unpinned (not a SHA)', () => {
      assert.strictEqual(gitSpecPin(`git+https://github.com/oraios/serena@${FULL_SHA}0`), 'unpinned');
      assert.strictEqual(gitSpecPin(`git+https://github.com/oraios/serena@${'g'.repeat(40)}`), 'unpinned');
    });

    it('git+ssh authority disambiguation: the user@host @ is never the ref separator', () => {
      assert.strictEqual(gitSpecPin(`git+ssh://git@github.com/org/repo@${FULL_SHA}`), 'exact');
      assert.strictEqual(gitSpecPin('git+ssh://git@github.com/org/repo'), 'unpinned');
      assert.strictEqual(gitSpecPin('git+ssh://git@github.com/org/repo@main'), 'unpinned');
    });

    it('handles the bare git:// scheme', () => {
      assert.strictEqual(gitSpecPin(`git://github.com/org/repo@${FULL_SHA}`), 'exact');
      assert.strictEqual(gitSpecPin('git://github.com/org/repo'), 'unpinned');
    });

    it('a pip-style #fragment is not part of the ref', () => {
      assert.strictEqual(gitSpecPin(`git+https://github.com/org/repo@${FULL_SHA}#egg=pkg`), 'exact');
      assert.strictEqual(gitSpecPin(`git+https://github.com/org/repo@${FULL_SHA}#subdirectory=sub`), 'exact');
      assert.strictEqual(gitSpecPin('git+https://github.com/org/repo@main#egg=pkg'), 'unpinned');
    });

    it('a trailing @ with an empty ref is unpinned', () => {
      assert.strictEqual(gitSpecPin('git+https://github.com/org/repo@'), 'unpinned');
    });

    it('consumer refusal pin: name/version derivation on git specs stays null (typosquat/provenance/tool-poisoning behavior unchanged)', () => {
      const spec = `git+https://github.com/oraios/serena@${FULL_SHA}`;
      assert.strictEqual(packageNameFromSpec(spec), null);
      assert.strictEqual(versionFromSpec(spec), null);
      assert.strictEqual(derivePackageName(['--from', spec, 'serena'], 'uvx'), null);
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

    it('F1: uvx runner derives from --from, and skips the --python value', () => {
      assert.strictEqual(derivePackageName(['--from', 'mcp-server-fetch==1.0.0', 'mcp-server-fetch'], 'uvx'), 'mcp-server-fetch');
      assert.strictEqual(derivePackageName(['--python', '3.12', 'mcp-server-fetc'], 'uvx'), 'mcp-server-fetc');
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
