'use strict';

/**
 * Insecure endpoint detector (Phase 5, MCPD-06).
 *
 * Flags mutable/insecure remote MCP server endpoints: plain http://
 * transport, a 0.0.0.0 wildcard bind, and a remote endpoint with no
 * recognized authentication header configured.
 *
 * D-07 dedup boundary: this detector owns transport security ONLY
 * (http://, 0.0.0.0, missing auth). Version/integrity binding on
 * remote URLs is unpinned-execution's (MCPD-01) — never emitted here.
 */

const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');

const id = 'insecure-endpoint';
const requirement = 'MCPD-06';

// Static, hand-authored regex literal only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-01).
const AUTH_HEADER_NAMES = /^(authorization|x-api-key|api-key|x-auth-token|cookie)$/i;

function hasAuthHeader(headers) {
  return Object.keys(headers || {}).some(key => AUTH_HEADER_NAMES.test(key));
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
        message: `Server "${server.name}" uses non-TLS http:// (${server.url}) — traffic is unencrypted.`,
      }));
    }

    if (parsed.hostname === '0.0.0.0') {
      findings.push(Finding({
        id: `${id}/wildcard-bind`,
        detector: id,
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}" is bound to 0.0.0.0 (${server.url}) — reachable from any network interface.`,
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
        message: `Server "${server.name}" has no recognized authentication header configured (${server.url}) — the endpoint accepts unauthenticated requests.`,
      }));
    }
  }

  return findings;
}

module.exports = { id, requirement, run };
