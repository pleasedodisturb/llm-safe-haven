'use strict';

/**
 * Insecure endpoint detector (Phase 5, MCPD-06).
 *
 * Flags mutable/insecure remote MCP server endpoints: plain http://
 * transport, a wildcard/any-interface endpoint host (0.0.0.0, [::]),
 * and a remote endpoint with no recognized authentication header
 * configured.
 *
 * D-07 dedup boundary: this detector owns transport security ONLY
 * (http://, wildcard hosts, missing auth). Version/integrity binding on
 * remote URLs is unpinned-execution's (MCPD-01) — never emitted here.
 */

const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');

const id = 'insecure-endpoint';
const requirement = 'MCPD-06';

// Static, hand-authored regex literal only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-01).
const AUTH_HEADER_NAMES = /^(authorization|x-api-key|api-key|x-auth-token|cookie)$/i;

// Wildcard/any-interface hosts (WR-06). The WHATWG URL parser already
// normalizes IPv4 shorthand and hex/octal forms ('0', '0x0', '000') to
// '0.0.0.0', and long-form IPv6 ('[0:0:0:0:0:0:0:0]') to '[::]', so
// these three literals cover every spelling. Bare '::' cannot survive
// URL parsing but is kept defensively for future non-URL callers.
const WILDCARD_HOSTS = new Set(['0.0.0.0', '[::]', '::']);

function hasAuthHeader(headers) {
  return Object.keys(headers || {}).some(key => AUTH_HEADER_NAMES.test(key));
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
    if (!server.url) continue;

    let parsed;
    try {
      parsed = new URL(server.url);
    } catch {
      continue;
    }

    if (parsed.protocol === 'http:') {
      findings.push(Finding({
        id: `${id}/plain-http`,
        detector: id,
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}" uses non-TLS http:// (${safeUrlLabel(parsed)}) — traffic is unencrypted.`,
      }));
    }

    if (WILDCARD_HOSTS.has(parsed.hostname)) {
      findings.push(Finding({
        id: `${id}/wildcard-bind`,
        detector: id,
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}"'s configured endpoint is a wildcard/any-interface address (${safeUrlLabel(parsed)}) — not a routable connect target; it typically resolves to localhost. Verify the intended endpoint host.`,
      }));
    }

    if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && !hasAuthHeader(server.headers)) {
      findings.push(Finding({
        id: `${id}/unauthenticated-transport`,
        detector: id,
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}" has no recognized authentication header configured (${safeUrlLabel(parsed)}) — the endpoint accepts unauthenticated requests.`,
      }));
    }
  }

  return findings;
}

module.exports = { id, requirement, run };
