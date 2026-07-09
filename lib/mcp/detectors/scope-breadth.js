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
 *
 * D-12 dogfood hardening: capability identifiers are tested ONLY against
 * command/package IDENTIFIER tokens — the command basename, the server
 * name, and the package spec of an npx/uvx invocation — never the full
 * joined args string. The first dogfood run against real configs false-
 * positived on `/bin/sh -c 'KEY="$(rbw get ...)" exec npx -y @vendor/x'`
 * credential-injection wrappers, where the shell builtin `exec` (pure
 * shell syntax, not a capability) matched a bare \bexec\b identifier.
 * That identifier is dropped entirely and args text is no longer part of
 * the capability haystack.
 */

const path = require('path');
const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');

const id = 'scope-breadth';
const requirement = 'MCPD-07';

// Static, hand-authored regex literals only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-06). Bare
// \bexec\b was removed after the D-12 dogfood run: it matched the shell
// builtin `exec` inside credential-injection wrapper args, which says
// nothing about the server's actual capability.
const BROAD_CAPABILITY_IDENTIFIERS = [
  /server-filesystem/i,
  /desktop-commander/i,
  /mcp-shell/i,
  /\bshell\b/i,
  /\bterminal\b/i,
];
const PATH_ARG_RE = /^(~\/|\/)/;

// Flags of npx/uvx that consume the NEXT token as their value — that
// value is skipped when hunting for the positional package spec
// (mirrors unpinned-execution's extractPackageSpec discipline).
const VALUE_FLAGS = new Set(['--package', '-p', '--from']);

function commandBasename(command) {
  if (typeof command !== 'string' || command === '') return null;
  return path.basename(command);
}

/**
 * Extracts package identifier tokens from an npx/uvx args array: skips
 * flag tokens (anything starting with '-') and the value following a
 * value-taking flag, returning the first remaining positional token (the
 * package spec). For uvx, a `--from <spec>` value is itself a package
 * identifier and is included as an additional token.
 */
function extractPackageTokens(args) {
  const tokens = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (typeof arg !== 'string') continue;
    if (VALUE_FLAGS.has(arg)) {
      const value = args[i + 1];
      if (arg === '--from' && typeof value === 'string') tokens.push(value);
      i++; // skip the flag's value
      continue;
    }
    if (arg.startsWith('-')) continue;
    tokens.push(arg);
    break; // only the first positional token is the package spec
  }
  return tokens;
}

/**
 * Capability matching runs ONLY over identifier tokens — command
 * basename, server name, and (for npx/uvx) the package spec — never the
 * full args string, so shell syntax inside a `/bin/sh -c "..."` wrapper
 * can never trigger a match (D-12 dogfood fix).
 */
function capabilityTokens(server) {
  const tokens = [];
  const bin = commandBasename(server.command);
  if (bin) tokens.push(bin);
  if (server.name) tokens.push(server.name);
  if (bin === 'npx' || bin === 'uvx') {
    tokens.push(...extractPackageTokens(Array.isArray(server.args) ? server.args : []));
  }
  return tokens;
}

function isBroadCapabilityServer(server) {
  const tokens = capabilityTokens(server);
  return tokens.some(token => BROAD_CAPABILITY_IDENTIFIERS.some(re => re.test(token)));
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
