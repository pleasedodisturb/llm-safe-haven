'use strict';

/**
 * Scope breadth detector (Phase 5, MCPD-07).
 *
 * ADVISORY detector (SEVERITY.INFO) — must never read as alarming (D-05).
 * It flags servers that both (a) look filesystem/shell/terminal capable
 * per a narrow, hand-authored identifier allowlist, AND (b) declare no
 * explicit absolute or ~/-prefixed path argument bounding that capability.
 *
 * This detector starts DELIBERATELY NARROW per CONTEXT.md discretion and
 * D-10: false negatives are acceptable (a broad-capability server this
 * detector doesn't recognize simply isn't flagged), but false positives
 * are launch-blocking (D-10/D-12) — a false positive on a genuinely
 * bounded, well-configured server trains users to ignore the tool
 * (T-05-07). The allowlist and path-scope check are pinned exactly as
 * specified; do not widen them without re-running the D-12 dogfood gate.
 */

const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');

const id = 'scope-breadth';
const requirement = 'MCPD-07';

// Static, hand-authored regex literals only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-06).
const BROAD_CAPABILITY_IDENTIFIERS = [
  /server-filesystem/i,
  /desktop-commander/i,
  /mcp-shell/i,
  /\bshell\b/i,
  /\bterminal\b/i,
  /\bexec\b/i,
];
const PATH_ARG_RE = /^(~\/|\/)/;

function isBroadCapabilityServer(server) {
  const args = Array.isArray(server.args) ? server.args : [];
  const haystack = [server.command, server.name, ...args].filter(Boolean).join(' ');
  return BROAD_CAPABILITY_IDENTIFIERS.some(re => re.test(haystack));
}

function hasExplicitScopeArg(args) {
  return (Array.isArray(args) ? args : []).some(a => typeof a === 'string' && PATH_ARG_RE.test(a));
}

function run(servers, context = {}) {
  const findings = [];

  for (const server of Array.isArray(servers) ? servers : []) {
    if (isBroadCapabilityServer(server) && !hasExplicitScopeArg(server.args)) {
      findings.push(Finding({
        id: `${id}/unscoped-broad-capability`,
        detector: id,
        severity: SEVERITY.INFO,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}" appears filesystem/shell-capable and declares no explicit directory scope — `
          + `consider adding a bounded path argument (e.g. an absolute path or ~/-prefixed directory).`,
      }));
    }
  }

  return findings;
}

module.exports = { id, requirement, run };
