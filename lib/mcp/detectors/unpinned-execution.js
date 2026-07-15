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

const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');
const { commandBasename, extractSpec, versionFromSpec, classifySpecSuffix } = require('../npx-args.js');

const id = 'unpinned-execution';
const requirement = 'MCPD-01';

// Static, hand-authored regex literal only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-01). The pattern
// is linear with no nested unbounded quantifiers.
const URL_VERSION_RE = /(@sha256[:-]|\bsha256\b|\bdigest\b|\/v?\d+\.\d+|[?&](version|ref|tag|sha)=)/i;

/**
 * Returns whether the spec carries an EXACT version pin — the shared
 * versionFromSpec()/classifySpecSuffix() pipeline in npx-args.js (F8:
 * this detector's local PIN_RE/EXACT_SEMVER_RE duplicated provenance.js's
 * classification and the two had already begun to drift). A bare name
 * (no suffix), a malformed spec, and every floating shape — dist-tags
 * (latest/next/canary), wildcards (*, x, 1.x), range operators
 * (^ ~ >= <= > < and PEP 508 ~= != — WR-02), and partial versions
 * (1, 1.2) — are all unpinned. Exact pins: npm 1.2.3/v1.2.3 and PyPI
 * ==1.0.0 (F2: uvx pins with ==, which previously parsed as part of the
 * NAME, so a correctly ==-pinned uvx spec was a false 'unpinned').
 */
function isPinnedPackageArg(arg) {
  return classifySpecSuffix(versionFromSpec(arg)) === 'exact';
}

// Package-spec extraction is the shared extractSpec() in npx-args.js
// (WR-06 consolidation) — the '--package'/'-p' value is the package that
// gets installed; the trailing positional token is just the binary name
// to execute, which never carries a version, so version-checking it
// produced false 'unpinned' findings on correctly-pinned
// `npx -p pkg@1.0.0 serve` invocations (WR-03). One deliberate semantic
// unification: a `-p` with a NON-STRING value now refuses to derive
// (null → no spec → no finding) instead of the old local copy's
// fall-through to the trailing command token — the shared refusing
// semantics are documented in npx-args.js.

/**
 * uvx supports `--from <spec>` to pin/select a source distribution
 * separately from the positional command name. If present, its value is
 * checked for a version pin instead of the positional spec — through the
 * SAME classifySpecSuffix pipeline as every other spec (F2/F8: the old
 * substring check `fromValue.includes('==')` counted a floating prefix
 * match like pkg==1.* as pinned).
 */
function extractFromValue(args) {
  const idx = args.indexOf('--from');
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
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
        unpinned = fromValue !== null && !isPinnedPackageArg(fromValue);
      } else {
        const spec = extractSpec(args);
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
