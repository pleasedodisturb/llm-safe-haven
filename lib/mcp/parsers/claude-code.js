'use strict';

/**
 * Claude Code MCP config parser (Phase 4, Task 1).
 *
 * Claude Code is the one asymmetric case among the 5 supported agents:
 * user scope (top-level `mcpServers`) and local scope (nested
 * `projects[<cwd>].mcpServers`) both live in the SAME `~/.claude.json`
 * file at different key depths (RESEARCH.md Pitfall 3). Project scope is
 * a third, separate file (`<project>/.mcp.json`).
 *
 * `parse(source, opts)` dispatches on `source.scope` — the caller
 * (config-sources.js's discover()) already produces one source
 * descriptor per scope, so this parser reads the same file up to twice
 * (once per scope) rather than trying to extract all three scopes in a
 * single call.
 */

const {
  readConfigSafe,
  stripProtoPollution,
  normalizeServer,
} = require('../base.js');

/**
 * Extracts normalized servers from a single scope's `mcpServers` object.
 *
 * Fails closed with `{ ok:false, reason:'polluted', code:2 }` when ANY
 * server NAME is a prototype-pollution key (`__proto__`/`constructor`/
 * `prototype`) — even alongside legit servers. Server names are data,
 * not structure: silently dropping a hostile-named server would let it
 * evade the scan entirely with exit 0 (detection evasion), which would
 * misrepresent an attack as "nothing configured".
 *
 * A missing/absent `mcpServers` (undefined, non-object, or genuinely
 * empty) is NOT pollution — it just means this scope has no servers.
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

  if (keys.length < rawKeyCount) {
    // One or more server names were prototype-pollution tokens — never
    // silently drop a server; a dropped name must bump exit to 2.
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
 * @param {{ agentId: string, scope: 'user'|'local'|'project', path: string, format: string }} source
 * @param {object} opts - { cwd, fs } — opts.cwd resolves the local-scope
 *   `projects[<cwd>]` key; defaults to process.cwd().
 */
function parse(source, opts = {}) {
  const res = readConfigSafe(source.path, opts);
  if (!res.ok) {
    return res;
  }

  let parsed;
  try {
    parsed = JSON.parse(res.raw);
  } catch (err) {
    return { ok: false, reason: 'malformed', code: 2, detail: err.message };
  }

  const top = stripProtoPollution(parsed);

  if (source.scope === 'project') {
    return extractServers(top.mcpServers, 'claude-code', 'project', source.path);
  }

  if (source.scope === 'user') {
    return extractServers(top.mcpServers, 'claude-code', 'user', source.path);
  }

  if (source.scope === 'local') {
    const cwd = opts.cwd || process.cwd();
    const projects = stripProtoPollution(top.projects || {});
    const projectEntryRaw = projects[cwd];

    if (!projectEntryRaw || typeof projectEntryRaw !== 'object' || Array.isArray(projectEntryRaw)) {
      return { ok: true, servers: [] };
    }

    const projectEntry = stripProtoPollution(projectEntryRaw);
    return extractServers(projectEntry.mcpServers, 'claude-code', 'local', source.path);
  }

  // Unknown scope — fail closed rather than silently returning an empty list.
  return { ok: false, reason: 'unsupported-scope', code: 2, detail: `unknown scope: ${source.scope}` };
}

module.exports = {
  parse,
  agentId: 'claude-code',
  // Exposed for testing
  _extractServers: extractServers,
};
