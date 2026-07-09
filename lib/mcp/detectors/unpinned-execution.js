'use strict';

/**
 * Unpinned execution detector (Phase 5, MCPD-01).
 *
 * Flags npx/uvx server commands invoked without a pinned package version
 * (bare name, or an explicit @latest/@next/@canary/trailing-@ spec), and
 * remote server URLs with no version/integrity binding.
 *
 * D-07 dedup boundary: this detector owns version/integrity binding on
 * remote URLs. Transport security (http://, 0.0.0.0, missing auth
 * header) belongs exclusively to insecure-endpoint (MCPD-06) — the same
 * URL attribute is never double-reported by both detectors.
 */

const path = require('path');
const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');

const id = 'unpinned-execution';
const requirement = 'MCPD-01';

// Static, hand-authored regex literals only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-01). Both
// patterns are linear with no nested unbounded quantifiers.
const PIN_RE = /^(@[^/@\s]+\/)?([^@/\s]+)@([^\s]+)$/;
// A version suffix only counts as PINNED when it is an exact semver
// (optionally v-prefixed, optionally with a -prerelease/+build suffix).
// Everything else floats and can silently pull a compromised update:
// dist-tags (latest/next/canary), wildcards (*, x, 1.x, 1.2.x), range
// operators (^ ~ >= <= > <), and partial versions (1, 1.2) — WR-02.
const EXACT_SEMVER_RE = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const URL_VERSION_RE = /(@sha256[:-]|\bsha256\b|\bdigest\b|\/v?\d+\.\d+|[?&](version|ref|tag|sha)=)/i;

/**
 * Returns false when `arg` has no @version suffix at all (bare package
 * name — treated as unpinned), otherwise returns whether the version
 * suffix is an exact semver pin. Any floating spec (dist-tag, wildcard,
 * range, partial version) is unpinned.
 */
function isPinnedPackageArg(arg) {
  const m = PIN_RE.exec(arg);
  if (!m) return false;
  return EXACT_SEMVER_RE.test(m[3]);
}

/**
 * Extracts the package spec token from an npx/uvx args array. When
 * '--package'/'-p' (or '--package=<spec>') is present, its VALUE is the
 * package that gets installed — the trailing positional token is just
 * the binary name to execute, which never carries a version, so
 * version-checking it instead produced false 'unpinned' findings on
 * correctly-pinned `npx -p pkg@1.0.0 serve` invocations (WR-03).
 * Otherwise skips flag tokens and returns the first positional token,
 * or null if none found.
 */
function extractPackageSpec(args) {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (typeof arg !== 'string') continue;
    if (arg === '--package' || arg === '-p') {
      const value = args[i + 1];
      if (typeof value === 'string') return value;
      i++; // dangling flag with a non-string follower — skip both
      continue;
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
 * uvx supports `--from <spec>` to pin/select a source distribution
 * separately from the positional command name. If present, its value is
 * checked for a version operator instead of the positional spec.
 */
function extractFromValue(args) {
  const idx = args.indexOf('--from');
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}

function isPinnedUvxFrom(fromValue) {
  if (typeof fromValue !== 'string') return false;
  // Only the exact-pin operator (==) counts. Range operators (>=, <=,
  // ~=, <, >, !=) select a floating version and are UNPINNED — none of
  // them contains the '==' substring, so this single check suffices
  // (WR-02).
  return fromValue.includes('==');
}

function commandBasename(command) {
  if (typeof command !== 'string' || command === '') return null;
  return path.basename(command);
}

function hasUrlVersionBinding(url) {
  return URL_VERSION_RE.test(url);
}

/**
 * Renders a URL for inclusion in a finding message WITHOUT leaking
 * secrets: remote MCP URLs routinely carry credentials in the userinfo
 * component (the user-colon-password prefix before the host) or in a
 * query-string parameter. Only protocol + host(:port) + path survive —
 * userinfo, query, and fragment are stripped. Never interpolate the raw
 * server.url into a message (project invariant: secret values must
 * NEVER appear in finding text).
 */
function safeUrlLabel(parsed) {
  return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
}

function run(servers, context = {}) {
  const findings = [];

  for (const server of Array.isArray(servers) ? servers : []) {
    const bin = commandBasename(server.command);

    if (bin === 'npx' || bin === 'uvx') {
      const args = Array.isArray(server.args) ? server.args : [];
      let unpinned = false;

      if (bin === 'uvx' && args.includes('--from')) {
        const fromValue = extractFromValue(args);
        unpinned = fromValue !== null && !isPinnedUvxFrom(fromValue);
      } else {
        const spec = extractPackageSpec(args);
        if (spec !== null) {
          unpinned = !isPinnedPackageArg(spec);
        }
      }

      if (unpinned) {
        findings.push(Finding({
          id: `${id}/${bin}-no-version`,
          detector: id,
          severity: SEVERITY.MEDIUM,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}" runs ${bin} without a pinned package version — an unpinned spec can silently pull a compromised update.`,
        }));
      }
    }

    if (server.url) {
      let parsed;
      try {
        parsed = new URL(server.url);
      } catch {
        continue;
      }
      if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && !hasUrlVersionBinding(server.url)) {
        findings.push(Finding({
          id: `${id}/url-no-version-binding`,
          detector: id,
          severity: SEVERITY.MEDIUM,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}" points at a remote URL with no version/integrity binding (${safeUrlLabel(parsed)}) — the endpoint can change contents without notice.`,
        }));
      }
    }
  }

  return findings;
}

module.exports = { id, requirement, run };
