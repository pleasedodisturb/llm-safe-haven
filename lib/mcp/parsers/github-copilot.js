'use strict';

/**
 * GitHub Copilot (VS Code) MCP config parser (Phase 12, AGENT-05). Copilot
 * stores its config as JSONC (comments + trailing commas tolerated) at:
 *   - project scope: <project>/.vscode/mcp.json
 *   - user scope:    the platform-specific VS Code User directory's
 *                     mcp.json (darwin ~/Library/Application Support/Code/
 *                     User/, linux ~/.config/Code/User/, win32
 *                     %APPDATA%/Code/User/) — lib/mcp/config-sources.js
 *                     owns the exact path resolution; this module only
 *                     reads whatever source.path it's given.
 * Verified against official docs (code.visualstudio.com/docs/agents/
 * reference/mcp-configuration) — RESEARCH.md verified table row 5.
 *
 * Critical difference from every other JSON-family parser (D-07): the
 * top-level key is `servers`, NOT `mcpServers`. This is the ONE line that
 * changes from windsurf.js's structure.
 *
 * Read-and-ignore top-level keys (documented, NOT part of normalizeServer's
 * frozen shape, NEVER passed into normalizeServer): `inputs` (secret
 * placeholders) and `sandbox` (macOS/Linux-only object).
 * Read-and-ignore per-server keys: type, cwd, envFile, oauth.
 *
 * Flow: readConfigSafe -> stripJsonc -> JSON.parse -> stripProtoPollution
 * -> extract flat `servers` object -> normalizeServer per entry. Never
 * throws past this module boundary — every failure path returns
 * { ok:false, reason, code:2 } per base.js's contract.
 */

const {
  readConfigSafe,
  stripJsonc,
  stripProtoPollution,
  extractServerEntries,
  normalizeServer,
} = require('../base.js');

const agentId = 'github-copilot';

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
  // D-07: Copilot keys on `servers`, NOT `mcpServers` — the single
  // critical difference from every other JSON-family parser in this repo.
  // Top-level `inputs`/`sandbox` are never read here (read-and-ignore).
  const container = extractServerEntries(parsed.servers);
  if (!container.ok) {
    return container;
  }
  const entries = container.entries;

  const servers = [];
  for (const [name, serverConfig] of Object.entries(entries)) {
    if (!serverConfig || typeof serverConfig !== 'object') continue;
    const clean = stripProtoPollution(serverConfig);
    // type/cwd/envFile/oauth are documented fields read-and-ignored here,
    // never passed into normalizeServer.
    servers.push(normalizeServer({
      agentId,
      scope: source.scope,
      configPath: source.path,
      name,
      command: clean.command,
      args: clean.args,
      env: clean.env,
      url: clean.url,
      headers: clean.headers,
    }));
  }

  return { ok: true, servers };
}

module.exports = { parse, agentId };
