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
  normalizeServer,
} = require('../base.js');

/**
 * Extracts normalized servers from a flat `mcpServers` object.
 *
 * Fails closed with `{ ok:false, reason:'polluted', code:2 }` when the
 * raw object had own keys but every one of them was a prototype-
 * pollution key — i.e. its ONLY content was hostile. A missing/absent
 * `mcpServers` is not pollution, just an empty config.
 */
function extractServers(mcpServersRaw, agentId, scope, configPath) {
  if (mcpServersRaw === undefined || mcpServersRaw === null) {
    return { ok: true, servers: [] };
  }
  if (typeof mcpServersRaw !== 'object' || Array.isArray(mcpServersRaw)) {
    return { ok: true, servers: [] };
  }

  const rawKeyCount = Object.keys(mcpServersRaw).length;
  const cleaned = stripProtoPollution(mcpServersRaw);
  const keys = Object.keys(cleaned);

  if (rawKeyCount > 0 && keys.length === 0) {
    return { ok: false, reason: 'polluted', code: 2 };
  }

  const servers = keys.map(name => {
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
