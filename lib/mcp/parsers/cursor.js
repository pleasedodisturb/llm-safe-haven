'use strict';

/**
 * Cursor MCP config parser (Phase 4, Task 2).
 *
 * Cursor's config shape is the simple case: a flat `mcpServers` object
 * keyed by server name, in a single JSONC file (comments + trailing
 * commas tolerated). This is the REFERENCE JSONC parser implementation —
 * windsurf.js and cline.js (Plan 04-04) mirror this file's structure.
 *
 * The one hard requirement is URL-survival (RESEARCH.md Pitfall 5): a
 * naive regex comment-stripper truncates `"url": "https://..."` because
 * it treats the `//` as a line-comment start. `stripJsonc` (base.js) is
 * string-literal-aware and must run BEFORE JSON.parse.
 */

const {
  readConfigSafe,
  stripJsonc,
  stripProtoPollution,
  extractServerEntries,
  normalizeServer,
} = require('../base.js');

/**
 * Extracts normalized servers from a flat `mcpServers` object.
 *
 * Container validation (absent → empty; non-object → malformed code 2;
 * pollution-key server name → polluted code 2) is the SHARED
 * extractServerEntries policy in base.js — identical across all four
 * JSON/JSONC parsers, so the same hostile input resolves the same way
 * regardless of which agent's config it lands in (WR-01).
 */
function extractServers(mcpServersRaw, agentId, scope, configPath) {
  const container = extractServerEntries(mcpServersRaw);
  if (!container.ok) {
    return container;
  }
  const cleaned = container.entries;

  const servers = Object.keys(cleaned).map(name => {
    const def = cleaned[name];
    const safeDef = (def && typeof def === 'object' && !Array.isArray(def)) ? def : {};
    return normalizeServer({
      agentId,
      scope,
      configPath,
      name,
      command: safeDef.command,
      args: safeDef.args,
      env: safeDef.env,
      url: safeDef.url,
      headers: safeDef.headers,
    });
  });

  return { ok: true, servers };
}

/**
 * @param {{ agentId: string, scope: string, path: string, format: string }} source
 * @param {object} opts - { fs } (opts-injection, forwarded to readConfigSafe)
 */
function parse(source, opts = {}) {
  const res = readConfigSafe(source.path, opts);
  if (!res.ok) {
    return res;
  }

  // stripJsonc BEFORE JSON.parse — string-literal-aware, so a `//` inside
  // a "url" value is never mistaken for a comment (Pitfall 5).
  const stripped = stripJsonc(res.raw);

  let parsed;
  try {
    parsed = JSON.parse(stripped);
  } catch (err) {
    return { ok: false, reason: 'malformed', code: 2, detail: err.message };
  }

  const top = stripProtoPollution(parsed);
  return extractServers(top.mcpServers, 'cursor', source.scope, source.path);
}

module.exports = {
  parse,
  agentId: 'cursor',
  // Exposed for testing
  _extractServers: extractServers,
};
