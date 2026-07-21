'use strict';

/**
 * Google Antigravity MCP config parser (Phase 12, AGENT-04). This agent
 * was the ticket's hard research gate (D-06) — the path was verified
 * against official docs and an independent GitHub issue rather than
 * assumed from a sibling product's layout. The resolved path is:
 *   - global:    ~/.gemini/config/mcp_config.json
 *   - workspace: <project>/.agents/mcp_config.json (best-effort — see
 *                RESEARCH.md Open Question 2: a different, buggy
 *                project-local path exists in some Antigravity versions
 *                that reads but silently ignores mcpServers; this is NOT
 *                that path)
 * Despite sharing the `mcp_config.json` filename with another IDE-adjacent
 * agent already supported by this scanner, Antigravity's actual directory
 * layout under the homedir is unrelated to that other agent's — the path
 * above was independently verified against official docs rather than
 * assumed by filename similarity (RESEARCH.md Pitfall 1).
 *
 * Flow: readConfigSafe -> stripJsonc (no-op-safe over plain JSON) ->
 * JSON.parse -> stripProtoPollution -> extract flat `mcpServers` object ->
 * normalizeServer per entry. Never throws past this module boundary —
 * every failure path returns { ok:false, reason, code:2 } per base.js's
 * contract. Structurally identical to the other thin JSON-family parsers
 * in this directory (see gemini-cli.js); the ONLY difference is the
 * remote-URL field: Antigravity's documented shape uses `serverUrl`.
 *
 * Read-and-ignore keys (documented, NOT part of normalizeServer's frozen
 * shape): authProviderType, oauth.
 */

const {
  readConfigSafe,
  stripJsonc,
  stripProtoPollution,
  extractServerEntries,
  normalizeServer,
} = require('../base.js');

const agentId = 'antigravity';

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
    // Antigravity's documented remote-server shape uses `serverUrl`; map
    // it into the normalized `url` slot when `url` itself is absent.
    // authProviderType/oauth are documented fields read-and-ignored here,
    // never passed into normalizeServer.
    const url = clean.url || clean.serverUrl || null;
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
