'use strict';

/**
 * Gemini CLI MCP config parser (Phase 12, AGENT-02). Gemini CLI stores its
 * config as plain JSON (lib/mcp/config-sources.js owns the exact paths —
 * this module only reads whatever source.path it's given) at:
 *   - user scope:    ~/.gemini/settings.json
 *   - project scope: <project>/.gemini/settings.json
 * Verified against official docs (google-gemini.github.io/gemini-cli/docs/
 * tools/mcp-server.html) — RESEARCH.md verified table row 2.
 *
 * Flow: readConfigSafe -> stripJsonc (no-op-safe over plain JSON) ->
 * JSON.parse -> stripProtoPollution -> extract flat `mcpServers` object ->
 * normalizeServer per entry. Never throws past this module boundary —
 * every failure path returns { ok:false, reason, code:2 } per base.js's
 * contract. Structurally identical to windsurf.js; the ONLY difference is
 * the remote-URL field: Gemini's documented shape is `url` (SSE) or
 * `httpUrl` (streaming HTTP) — first non-empty wins.
 *
 * Read-and-ignore keys (documented, NOT part of normalizeServer's frozen
 * shape): cwd, trust, includeTools, excludeTools.
 */

const {
  readConfigSafe,
  stripJsonc,
  stripProtoPollution,
  extractServerEntries,
  normalizeServer,
} = require('../base.js');

const agentId = 'gemini-cli';

function parse(source, opts = {}) {
  const read = readConfigSafe(source.path, opts);
  if (!read.ok) {
    return read;
  }

  let parsed;
  try {
    parsed = JSON.parse(stripJsonc(read.raw));
  } catch (err) {
    return { ok: false, reason: 'malformed', code: 2, detail: err.message };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, reason: 'malformed', code: 2, detail: 'top-level config is not an object' };
  }

  const hadTopLevelKeys = Object.keys(parsed).length > 0;
  parsed = stripProtoPollution(parsed);
  if (hadTopLevelKeys && Object.keys(parsed).length === 0) {
    return { ok: false, reason: 'polluted', code: 2, detail: 'config contains only prototype-pollution keys' };
  }

  // Shared container policy (base.js extractServerEntries, WR-01):
  // absent -> empty; non-object -> malformed code 2; pollution-key server
  // name -> polluted code 2 — identical across all JSON-family parsers.
  const container = extractServerEntries(parsed.mcpServers);
  if (!container.ok) {
    return container;
  }
  const entries = container.entries;

  const servers = [];
  for (const [name, serverConfig] of Object.entries(entries)) {
    if (!serverConfig || typeof serverConfig !== 'object') continue;
    const clean = stripProtoPollution(serverConfig);
    // Gemini CLI: `url` (SSE) or `httpUrl` (streaming HTTP) — first
    // non-empty wins. cwd/trust/includeTools/excludeTools are documented
    // fields read-and-ignored here, never passed into normalizeServer.
    const url = clean.url || clean.httpUrl || null;
    servers.push(normalizeServer({
      agentId,
      scope: source.scope,
      configPath: source.path,
      name,
      command: clean.command,
      args: clean.args,
      env: clean.env,
      url,
      headers: clean.headers,
    }));
  }

  return { ok: true, servers };
}

module.exports = { parse, agentId };
