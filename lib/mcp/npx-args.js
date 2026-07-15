'use strict';

/**
 * Shared package-spec derivation helpers for MCP detectors (Phase 6, D-15).
 *
 * Extracted from lib/mcp/detectors/tool-poisoning.js (the canonical,
 * WR-03-fixed copy) after the same `-p`/`--package` false-negative class
 * was independently fixed twice (unpinned-execution.js, then
 * tool-poisoning.js). provenance.js is the THIRD consumer that would have
 * reimplemented — and risked reintroducing — the same bug; this module is
 * the single source of truth going forward.
 *
 * extractSpec() is the ONE flag-scan loop (WR-06): every consumer —
 * unpinned-execution.js (version pinning), tool-poisoning.js (Tier-2
 * description lookup via derivePackageName), provenance.js (name +
 * version selection) — derives from its result instead of carrying a
 * local copy of the `-p`/`--package`-aware scan. The pre-consolidation
 * copies had already diverged on a reachable edge (a non-string `-p`
 * value: one copy fell back to the trailing command token, another
 * refused) — this module pins the refusing semantics: if `-p`/`--package`
 * explicitly designates the package but its value is unusable, return
 * null rather than guessing from the trailing token (which is a binary
 * name, not the installed package).
 */

const path = require('path');

function commandBasename(command) {
  if (typeof command !== 'string' || command === '') return null;
  return path.basename(command);
}

/**
 * Extracts the raw package-spec token from an npx/uvx-style args array —
 * the single flag-scan loop every detector shares (WR-06). When
 * `-p`/`--package` (split or `--package=<spec>` joined) is present, ITS
 * VALUE is the spec (a non-string value returns null — refuse, never
 * fall back to the trailing command token). Otherwise skips flag tokens
 * and returns the first positional token, or null if none is found.
 * Returns the spec RAW (version/tag suffix intact) — use
 * packageNameFromSpec()/versionFromSpec() to split it.
 */
function extractSpec(args) {
  const list = Array.isArray(args) ? args : [];
  for (let i = 0; i < list.length; i++) {
    const arg = list[i];
    if (typeof arg !== 'string') continue;
    if (arg === '--package' || arg === '-p') {
      const value = list[i + 1];
      return typeof value === 'string' ? value : null;
    }
    if (arg.startsWith('--package=')) {
      return arg.slice('--package='.length);
    }
    if (arg.startsWith('-')) continue;
    return arg;
  }
  return null;
}

/**
 * The ONE spec-splitting regex (F8 consolidation: packageNameFromSpec and
 * versionFromSpec previously carried twin regex literals that could drift
 * apart). Splits a single package spec into:
 *   group 1: optional @scope/ prefix
 *   group 2: the package name segment (lazy, so an operator suffix wins
 *            over the name swallowing it)
 *   group 3: an npm-style @version/@tag/@range suffix (after the @)
 *   group 4: a PyPI/PEP 508-style operator suffix, OPERATOR INCLUDED
 *            (==1.0.0, >=0.1, ~=1.4, !=2.0, <3, >1) — uvx specs pin with
 *            ==, not @ (F2: 'pkg==1.0.0' previously parsed as a bare
 *            NAME 'pkg==1.0.0', so a pinned uvx typosquat was never
 *            name-compared and a pinned uvx spec was flagged unpinned)
 */
const SPEC_RE = /^(@[^/@\s]+\/)?([^@/\s]+?)(?:@([^\s]+)|((?:===?|!=|<=?|>=?|~=)\S*))?$/;

/**
 * Shared spec splitter over SPEC_RE. Returns { name, suffix } or null for
 * a non-string, whitespace-bearing, or malformed spec (e.g. a path
 * separator like ../../evil — refusing to derive rather than falling back
 * to the raw arg, which would later be path-joined; CR-02 traversal).
 * The explicit whitespace pre-check keeps SPEC_RE's backtracking linear
 * on hostile input — no spec legitimately contains whitespace.
 */
function splitSpec(spec) {
  if (typeof spec !== 'string' || spec === '' || /\s/.test(spec)) return null;
  const m = SPEC_RE.exec(spec);
  if (!m) return null;
  return {
    name: `${m[1] || ''}${m[2]}`,
    suffix: m[3] !== undefined ? m[3] : (m[4] !== undefined ? m[4] : null),
  };
}

/**
 * Strips a trailing version suffix (@version/@tag for npm, ==version and
 * PEP 508 operator suffixes for PyPI/uvx) from a single package spec,
 * preserving a leading @scope/. Returns null for a non-string or
 * malformed spec.
 */
function packageNameFromSpec(spec) {
  const parts = splitSpec(spec);
  return parts === null ? null : parts.name;
}

/**
 * Extracts the raw version suffix from a single package spec — an npm
 * @-suffix is returned WITHOUT the @ ('1.2.3', 'next', '^1.0.0'); a PyPI
 * operator suffix is returned WITH its operator ('==1.0.0', '>=0.1'),
 * since the operator carries the pin-vs-range meaning. Returns null when
 * the spec has no suffix (bare name) or is malformed. Callers classify
 * via classifySpecSuffix().
 */
function versionFromSpec(spec) {
  const parts = splitSpec(spec);
  return parts === null ? null : parts.suffix;
}

// An exact npm semver — optionally v-prefixed (the registry rejects the
// v, so consumers normalize it away via the capture group), optionally
// with a -prerelease/+build suffix. The ONLY npm suffix shape that counts
// as pinned (WR-02). Exported so provenance.js can normalize the fetch
// ref without carrying its own copy (F8).
const EXACT_SEMVER_RE = /^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)$/;
// A PEP 440 exact pin: == (or === arbitrary equality) followed by a
// version with NO wildcard — ==1.0.* is a floating prefix match, not a
// pin. Character class covers epochs (1!2.0), pre/post/dev/local
// segments (1.0.0rc1, 1.0+local, 1.0.post1).
const PYPI_EXACT_RE = /^===?\d[0-9A-Za-z.!+-]*$/;
// Range/wildcard/partial shapes: leading range operator, wildcard chars,
// or a bare/partial numeric (1, 1.2, 1.x) — checked AFTER the exact
// patterns, so an exact semver never reaches this.
const RANGEISH_RE = /^[\^~><=!]|[*\s|]|^v?\d/;

/**
 * F8: the single pin-classification shared by unpinned-execution.js
 * (pinned = 'exact') and provenance.js (ref selection). Classifies a raw
 * suffix from versionFromSpec():
 *   'exact' — an exact npm semver (1.2.3, v1.2.3, 1.2.3-beta.1) or an
 *             exact PyPI == pin (==1.0.0); the only pinned shapes
 *   'range' — floating range/wildcard/partial (^1.0.0, ~=1.4, >=0.1,
 *             1.x, *, 1.2, ==1.*): resolvable to different versions over
 *             time, and not a registry-fetchable path segment
 *   'tag'   — anything else: a dist-tag (latest, next, beta) — directly
 *             fetchable, but still a floating ref
 *   null    — no suffix (null/empty input): a bare, unpinned name
 */
function classifySpecSuffix(suffix) {
  if (typeof suffix !== 'string' || suffix === '') return null;
  if (EXACT_SEMVER_RE.test(suffix) || PYPI_EXACT_RE.test(suffix)) return 'exact';
  if (RANGEISH_RE.test(suffix)) return 'range';
  return 'tag';
}

/**
 * Derives the npm package name from an npx/uvx-style args array. When
 * `-p`/`--package` (split or `--package=<spec>` joined) is present, ITS
 * VALUE is the package whose code actually runs and whose description
 * Tier 2 must scan — NOT the trailing command token. Scanning the wrong
 * token let a package selected via `-p @evil/pkg run` evade the Tier-2
 * injection-phrase scan entirely (WR-03 class, previously fixed only in
 * unpinned-execution). Thin composition over extractSpec() — the shared
 * flag-scan loop lives there (WR-06).
 */
function derivePackageName(args) {
  return packageNameFromSpec(extractSpec(args));
}

/**
 * CR-02 defense-in-depth: a derived package name is only ever path-joined
 * when it is a plausible npm name — exactly one segment (name) or two
 * segments where the first is an @scope. Every segment must be non-empty
 * and must not be a dot/dot-dot traversal token, contain a backslash, or
 * be absolute. derivePackageName() already refuses malformed specs, but
 * this guard keeps a future caller change from reintroducing traversal.
 */
function isSafePackageName(pkgName) {
  if (typeof pkgName !== 'string' || pkgName === '') return false;
  if (path.isAbsolute(pkgName)) return false;
  const segments = pkgName.split('/');
  if (segments.length > 2) return false;
  if (segments.length === 2 && !segments[0].startsWith('@')) return false;
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..') return false;
    if (segment.includes('\\')) return false;
  }
  return true;
}

module.exports = {
  commandBasename,
  extractSpec,
  packageNameFromSpec,
  versionFromSpec,
  classifySpecSuffix,
  EXACT_SEMVER_RE,
  derivePackageName,
  isSafePackageName,
};
