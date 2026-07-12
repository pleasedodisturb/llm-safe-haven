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
 * Strips a trailing @version/@tag suffix from a single package spec,
 * preserving a leading @scope/. Returns null for a non-string or a spec
 * that is not a well-formed npm name (e.g. contains a path separator,
 * like ../../evil) — refusing to derive rather than falling back to the
 * raw arg, which would later be path-joined (CR-02 traversal).
 */
function packageNameFromSpec(spec) {
  if (typeof spec !== 'string') return null;
  const m = spec.match(/^(@[^/@\s]+\/)?([^@/\s]+)(@[^\s]+)?$/);
  if (!m) return null;
  return `${m[1] || ''}${m[2]}`;
}

/**
 * Extracts the raw @version/@tag suffix from a single package spec, or
 * null when the spec has no suffix (bare name) or is not a well-formed
 * npm spec. The complement of packageNameFromSpec() — same regex, other
 * capture group. Callers own classifying the suffix (exact semver vs
 * range vs dist-tag); this only splits it out.
 */
function versionFromSpec(spec) {
  if (typeof spec !== 'string') return null;
  const m = spec.match(/^(@[^/@\s]+\/)?([^@/\s]+)(@([^\s]+))?$/);
  if (!m || !m[4]) return null;
  return m[4];
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
  derivePackageName,
  isSafePackageName,
};
