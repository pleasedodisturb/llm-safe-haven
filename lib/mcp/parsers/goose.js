'use strict';

/**
 * Goose (Block) MCP config parser — a RESTRICTED, fail-closed YAML reader
 * over Goose's documented `extensions:` shape (AGENT-03, Phase 12).
 *
 * Goose's config.yaml is an OBJECT-KEYED MAPPING under `extensions:` (one
 * key per extension name), NOT a block sequence like continue-dev.js's
 * `mcpServers:` — this is the D-04 distinction driving this module's
 * design. Verbatim shape (goose-docs.ai/docs/guides/config-files/):
 *
 *   extensions:
 *     developer:
 *       type: builtin
 *       enabled: true
 *     filesystem:
 *       type: stdio
 *       cmd: npx
 *       args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
 *       env_keys: []
 *       envs: {}
 *     remote-tools:
 *       type: streamable_http
 *       uri: "https://example.com/mcp"
 *       headers: {}
 *
 * D-03 (Phase 12): this reader consumes the SHARED restricted-YAML
 * primitives extracted into lib/mcp/restricted-yaml.js (indentOf,
 * isBlankOrComment, parseMappingBlock, checkUnsupportedShape) — the
 * SAME fail-closed grammar continue-dev.js uses, so an identical
 * hostile construct (anchors, flow-style, quoted/pollution keys, block
 * scalars) is rejected identically regardless of which agent's config
 * it lands in. checkUnsupportedShape is called with topLevelKey
 * 'extensions' so its flow-style check targets Goose's own top-level
 * key rather than continue-dev's `mcpServers`.
 *
 * D-04 semantic mapping (Pitfall 2 decision log):
 *   - type: builtin | platform  -> SKIP (no external server; not a
 *     supply-chain surface)
 *   - type: stdio               -> command: cmd, args, env: envs ONLY.
 *     `env_keys` names keys resolved from the OS keyring/secrets.yaml at
 *     RUNTIME — they are never literal values and MUST NEVER be
 *     fabricated into env. A config with only env_keys (no envs) yields
 *     an EMPTY env object, never a fake one built from the key names.
 *   - type: sse | streamable_http -> url: uri, headers
 *   - Extensions are scanned regardless of `enabled: false` — a
 *     configured-but-disabled server is still a supply-chain surface
 *     (D-04 explicit).
 *   - Any other/unrecognized `type` value is outside the documented
 *     enum (builtin/platform/stdio/sse/streamable_http) — rather than
 *     silently skip (which could hide a real surface) or silently
 *     guess a shape, this fails CLOSED with
 *     { ok:false, reason:'unsupported-yaml', code:2 }, same MCPC-03
 *     "never silently mis-parse" policy as continue-dev.js.
 *
 * Anything outside the documented object-keyed mapping shape — a
 * block-sequence `extensions:` (continue-dev's shape, not Goose's),
 * YAML anchors/aliases, flow-style mappings, prototype-pollution keys —
 * is REJECTED fail-closed, never silently mis-parsed. Zero npm YAML
 * dependency: only lib/mcp/base.js, lib/mcp/restricted-yaml.js, and
 * Node built-ins.
 */

const {
  readConfigSafe,
  stripProtoPollution,
  normalizeServer,
} = require('../base.js');

const {
  isBlankOrComment,
  checkUnsupportedShape,
  parseMappingBlock,
  indentOf,
} = require('../restricted-yaml.js');

const agentId = 'goose';

function parse(source, opts = {}) {
  const read = readConfigSafe(source.path, opts);
  if (!read.ok) {
    return read;
  }

  const text = read.raw;
  const reject = checkUnsupportedShape(text, 'extensions');
  if (reject) {
    return { ok: false, reason: reject.reason, code: 2, detail: reject.detail };
  }

  const lines = text.split('\n');
  const keyLineIndex = lines.findIndex(l => /^extensions:\s*(#.*)?$/.test(l));
  if (keyLineIndex === -1) {
    // No extensions key present — a valid config with no MCP extensions
    // is genuinely clean, distinct from a parse failure.
    return { ok: true, servers: [] };
  }

  let firstIdx = keyLineIndex + 1;
  while (firstIdx < lines.length && isBlankOrComment(lines[firstIdx])) firstIdx++;
  if (firstIdx >= lines.length || indentOf(lines[firstIdx]) === 0) {
    // extensions: present but the block is empty.
    return { ok: true, servers: [] };
  }

  const blockIndent = indentOf(lines[firstIdx]);
  if (lines[firstIdx].trim().startsWith('-')) {
    // Goose's extensions: is documented as an OBJECT-KEYED MAPPING
    // (D-04), not a block sequence — a block-sequence extensions: is
    // outside the documented shape. Fail closed.
    return { ok: false, reason: 'unparseable', code: 2, detail: 'extensions is not an object-keyed mapping (found a block sequence)' };
  }

  let extensionsObj;
  try {
    extensionsObj = parseMappingBlock(lines, firstIdx, blockIndent).obj;
  } catch (err) {
    return { ok: false, reason: 'unparseable', code: 2, detail: err.message };
  }

  const servers = [];
  for (const [extName, rawExt] of Object.entries(extensionsObj)) {
    if (!rawExt || typeof rawExt !== 'object' || Array.isArray(rawExt)) {
      return { ok: false, reason: 'unparseable', code: 2, detail: `extension "${extName}" is not a mapping` };
    }
    const ext = stripProtoPollution(rawExt);
    const type = ext.type;

    if (type === 'builtin' || type === 'platform') {
      // No external server to scan — D-04.
      continue;
    }

    let mapped;
    if (type === 'stdio') {
      mapped = {
        name: ext.name || extName,
        command: ext.cmd,
        args: Array.isArray(ext.args) ? ext.args : (ext.args ? [ext.args] : []),
        // Pitfall 2: only `envs` (the direct map) feeds env — `env_keys`
        // names are keyring-resolved secrets at runtime and are NEVER
        // resolved or fabricated into a value here.
        env: ext.envs && typeof ext.envs === 'object' && !Array.isArray(ext.envs) ? ext.envs : {},
        url: null,
        headers: {},
      };
    } else if (type === 'sse' || type === 'streamable_http') {
      mapped = {
        name: ext.name || extName,
        command: null,
        args: [],
        env: {},
        url: ext.uri,
        headers: ext.headers && typeof ext.headers === 'object' && !Array.isArray(ext.headers) ? ext.headers : {},
      };
    } else {
      // Undocumented extension type — reject rather than silently skip
      // (could hide a real surface) or silently guess a shape.
      return { ok: false, reason: 'unsupported-yaml', code: 2, detail: `extension "${extName}" has an unrecognized type "${type}"` };
    }

    const clean = stripProtoPollution(mapped);
    servers.push(normalizeServer({
      agentId,
      scope: source.scope,
      configPath: source.path,
      name: clean.name,
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
