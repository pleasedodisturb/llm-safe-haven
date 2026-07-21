'use strict';

/**
 * Continue.dev MCP config parser — a RESTRICTED, fail-closed YAML reader.
 *
 * Continue.dev's config.yaml is the only YAML-format target among the 5
 * Wave A agents this scanner supports. Per RESEARCH.md's "Don't Hand-Roll"
 * guidance, this module does NOT implement a general-purpose YAML
 * grammar — it is scoped exclusively to Continue.dev's documented,
 * narrow `mcpServers:` flat block-sequence-of-mappings shape:
 *
 *   mcpServers:
 *     - name: my-server
 *       command: node
 *       args: [server.js, --flag]
 *       env:
 *         API_KEY: ${env:API_KEY}
 *       url: https://mcp.example.com
 *
 * Anything outside that documented shape — YAML anchors (&) / aliases
 * (*), flow-style mappings/sequences (`{...}` / `[...]` for mcpServers
 * itself), multi-document separators (`---` beyond a single leading
 * marker), tab indentation, or an object-keyed `mcpServers` — is REJECTED
 * with { ok:false, reason:'unparseable', code:2 }. Constructs the reader
 * cannot faithfully parse — block scalars (`|` / `>`) and trailing
 * inline `# comments` on value lines — are REJECTED with
 * { ok:false, reason:'unsupported-yaml', code:2 }: silently mis-parsing
 * them would drop the real command/env body or append comment text to a
 * security-inspected value. All of this fails CLOSED (reports
 * incomplete) rather than risking a silent mis-parse of a form this
 * restricted reader was never designed to understand — the SAFE failure
 * direction per MCPC-03. Zero npm YAML dependency: only lib/mcp/base.js,
 * the shared lib/mcp/restricted-yaml.js primitives, and Node built-ins.
 *
 * D-03 (Phase 12): the restricted-YAML primitives previously defined
 * inline in this file (indentOf, isBlankOrComment, stripQuotes,
 * parseInlineList, checkUnsupportedShape, parseListBlock,
 * parseMappingBlock) were extracted VERBATIM into
 * lib/mcp/restricted-yaml.js so goose.js's object-keyed-mapping reader
 * can share the exact same fail-closed grammar rather than duplicating a
 * second hand-rolled parser. Extraction was NOT fragile — the module
 * boundary was used (not the duplication fallback). This file's own
 * behavior, and every existing fixture/assertion in
 * tests/mcp/parsers/continue-dev.test.js, is UNCHANGED: parse() still
 * calls checkUnsupportedShape(text, 'mcpServers') (the explicit
 * topLevelKey argument matches the shared module's default, so behavior
 * is byte-identical either way) and dispatches on the `mcpServers:`
 * block-sequence shape exactly as before.
 */

const {
  readConfigSafe,
  stripProtoPollution,
  normalizeServer,
} = require('../base.js');

const {
  isBlankOrComment,
  checkUnsupportedShape,
  parseListBlock,
  indentOf,
} = require('../restricted-yaml.js');

const agentId = 'continue-dev';

function parse(source, opts = {}) {
  const read = readConfigSafe(source.path, opts);
  if (!read.ok) {
    return read;
  }

  const text = read.raw;
  const reject = checkUnsupportedShape(text, 'mcpServers');
  if (reject) {
    return { ok: false, reason: reject.reason, code: 2, detail: reject.detail };
  }

  const lines = text.split('\n');
  const keyLineIndex = lines.findIndex(l => /^mcpServers:\s*(#.*)?$/.test(l));
  if (keyLineIndex === -1) {
    // No mcpServers key present — a valid config with no MCP servers is
    // genuinely clean, distinct from a parse failure.
    return { ok: true, servers: [] };
  }

  let firstIdx = keyLineIndex + 1;
  while (firstIdx < lines.length && isBlankOrComment(lines[firstIdx])) firstIdx++;
  if (firstIdx >= lines.length || indentOf(lines[firstIdx]) === 0) {
    // mcpServers: present but the block is empty.
    return { ok: true, servers: [] };
  }

  const blockIndent = indentOf(lines[firstIdx]);
  if (!lines[firstIdx].trim().startsWith('- ') && lines[firstIdx].trim() !== '-') {
    // Not a block sequence — e.g. an object-keyed mcpServers
    // ("mcpServers:\n  serverName:\n    command: ...") is outside the
    // documented flat-array shape. Fail closed.
    return { ok: false, reason: 'unparseable', code: 2, detail: 'mcpServers is not a block sequence (array)' };
  }

  let items;
  try {
    items = parseListBlock(lines, firstIdx, blockIndent).items;
  } catch (err) {
    return { ok: false, reason: 'unparseable', code: 2, detail: err.message };
  }

  const servers = [];
  for (const item of items) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return { ok: false, reason: 'unparseable', code: 2, detail: 'mcpServers item is not a mapping' };
    }
    const clean = stripProtoPollution(item);
    servers.push(normalizeServer({
      agentId,
      scope: source.scope,
      configPath: source.path,
      name: clean.name,
      command: clean.command,
      args: Array.isArray(clean.args) ? clean.args : (clean.args ? [clean.args] : []),
      env: clean.env && typeof clean.env === 'object' && !Array.isArray(clean.env) ? clean.env : {},
      url: clean.url,
      headers: clean.headers && typeof clean.headers === 'object' && !Array.isArray(clean.headers) ? clean.headers : {},
    }));
  }

  return { ok: true, servers };
}

module.exports = { parse, agentId };
