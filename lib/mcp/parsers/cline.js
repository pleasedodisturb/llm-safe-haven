'use strict';

/**
 * Cline MCP config parser. Cline stores its config as JSONC (comments +
 * trailing commas tolerated) at the VS Code globalStorage settings file
 * cline_mcp_settings.json (lib/mcp/config-sources.js owns the exact
 * OS-specific path — this module only reads whatever source.path it's
 * given).
 *
 * Flow: readConfigSafe -> stripJsonc -> JSON.parse -> stripProtoPollution
 * -> extract flat `mcpServers` object -> normalizeServer per entry.
 * Never throws past this module boundary — every failure path returns
 * { ok:false, reason, code:2 } per lib/mcp/base.js's contract.
 */

const {
  readConfigSafe,
  stripJsonc,
  stripProtoPollution,
  extractServerEntries,
  normalizeServer,
} = require('../base.js');

const agentId = 'cline';

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
  // absent → empty; non-object → malformed code 2; pollution-key server
  // name → polluted code 2 — identical across all four JSON parsers.
  const container = extractServerEntries(parsed.mcpServers);
  if (!container.ok) {
    return container;
  }
  const entries = container.entries;

  const servers = [];
  for (const [name, serverConfig] of Object.entries(entries)) {
    if (!serverConfig || typeof serverConfig !== 'object') continue;
    const clean = stripProtoPollution(serverConfig);
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
