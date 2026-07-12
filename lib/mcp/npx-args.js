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
 * unpinned-execution.js and tool-poisoning.js import from here instead of
 * carrying local copies. Behavior-identical refactor — the existing
 * 409-test baseline plus this module's own dedicated tests guard it.
 */

const path = require('path');

function commandBasename(command) {
  if (typeof command !== 'string' || command === '') return null;
  return path.basename(command);
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
 * Derives the npm package name from an npx/uvx-style args array. When
 * `-p`/`--package` (split or `--package=<spec>` joined) is present, ITS
 * VALUE is the package whose code actually runs and whose description
 * Tier 2 must scan — NOT the trailing command token. Scanning the wrong
 * token let a package selected via `-p @evil/pkg run` evade the Tier-2
 * injection-phrase scan entirely (WR-03 class, previously fixed only in
 * unpinned-execution). Otherwise skips flag tokens and derives from the
 * first positional token. Returns null if no candidate spec is found.
 */
function derivePackageName(args) {
  const list = Array.isArray(args) ? args : [];
  for (let i = 0; i < list.length; i++) {
    const arg = list[i];
    if (typeof arg !== 'string') continue;
    if (arg === '--package' || arg === '-p') {
      return packageNameFromSpec(list[i + 1]);
    }
    if (arg.startsWith('--package=')) {
      return packageNameFromSpec(arg.slice('--package='.length));
    }
    if (arg.startsWith('-')) continue;
    return packageNameFromSpec(arg);
  }
  return null;
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
  packageNameFromSpec,
  derivePackageName,
  isSafePackageName,
};
