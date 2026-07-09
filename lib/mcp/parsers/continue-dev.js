'use strict';

/**
 * Continue.dev MCP config parser — a RESTRICTED, fail-closed YAML reader.
 *
 * Continue.dev's config.yaml is the only YAML-format target among the 5
 * agents this scanner supports. Per RESEARCH.md's "Don't Hand-Roll"
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
 * direction per MCPC-03. Zero npm YAML dependency: only lib/mcp/base.js
 * and Node built-ins.
 */

const {
  readConfigSafe,
  stripProtoPollution,
  normalizeServer,
} = require('../base.js');

const agentId = 'continue-dev';

function indentOf(line) {
  const match = line.match(/^( *)/);
  return match ? match[1].length : 0;
}

function isBlankOrComment(line) {
  const trimmed = line.trim();
  return trimmed === '' || trimmed.startsWith('#');
}

function stripQuotes(value) {
  const v = value.trim();
  if (v.length >= 2) {
    const first = v[0];
    const last = v[v.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return v.slice(1, -1);
    }
  }
  return v;
}

function parseInlineList(value) {
  const inner = value.trim().replace(/^\[/, '').replace(/\]$/, '');
  if (inner.trim() === '') return [];
  return inner.split(',').map(s => stripQuotes(s.trim())).filter(s => s !== '');
}

/**
 * Detects any YAML construct outside the restricted reader's documented
 * narrow shape. Returns a { reason, detail } rejection object, or null if
 * the text contains none of the unsupported constructs.
 *
 * Two rejection classes:
 *   - reason 'unparseable':      structural constructs outside the
 *     documented shape (tabs, multi-doc, anchors/aliases, flow style)
 *   - reason 'unsupported-yaml': constructs the reader CANNOT faithfully
 *     parse and would otherwise silently corrupt — block scalars
 *     (`command: |` parses to the literal string '|', dropping the real
 *     command body and the following env block) and trailing inline
 *     `# comments` on content lines (the comment text would be appended
 *     verbatim to the scanned value). Fail closed, never ok:true with
 *     corrupted values.
 */
function checkUnsupportedShape(text) {
  if (/\t/.test(text)) {
    return { reason: 'unparseable', detail: 'tab indentation is not supported by the restricted reader' };
  }

  const lines = text.split('\n');

  const separatorLines = lines
    .map((line, idx) => ({ trimmed: line.trim(), idx }))
    .filter(entry => entry.trimmed === '---');
  const onlyLeadingSeparator = separatorLines.length === 1 && separatorLines[0].idx === 0;
  if (separatorLines.length > 0 && !onlyLeadingSeparator) {
    return { reason: 'unparseable', detail: 'multi-document YAML (--- separators) is not supported by the restricted reader' };
  }

  // Anchor (&name) / alias (*name) tokens — only flagged when they appear
  // in a structural position (right after "- " or ": ", or as the entire
  // trimmed line), so a "&"/"*" inside a URL query string or scalar value
  // is never mistaken for an anchor/alias.
  const anchorAliasPattern = /(^|[:-]\s)[&*][A-Za-z_][\w-]*/;
  // Block/folded scalar indicator as a key's value: "key: |", "key: >",
  // "key: |-", "key: >2", … (optionally followed only by a comment). The
  // reader would parse the indicator character as the literal value and
  // silently drop the scalar body below it.
  const blockScalarPattern = /^\s*(?:- )?[A-Za-z_][\w-]*:\s*[|>]/;
  for (const line of lines) {
    if (isBlankOrComment(line)) continue;
    if (anchorAliasPattern.test(line)) {
      return { reason: 'unparseable', detail: 'YAML anchors (&) / aliases (*) are not supported by the restricted reader' };
    }
    if (blockScalarPattern.test(line)) {
      return { reason: 'unsupported-yaml', detail: 'YAML block scalars (| / >) are not supported by the restricted reader' };
    }
    // A "#" preceded by whitespace on a content line is a trailing inline
    // comment — the reader cannot faithfully strip it (a quoted value
    // containing " # " is indistinguishable without full YAML quoting
    // rules), so it must be rejected, never appended to a scanned value.
    // A "#" with no preceding whitespace (e.g. a URL fragment) is part of
    // the scalar per YAML rules and stays allowed.
    if (/\s#/.test(line)) {
      return { reason: 'unsupported-yaml', detail: 'trailing inline comments are not supported by the restricted reader' };
    }
  }

  if (/mcpServers:\s*[{[]/.test(text)) {
    return { reason: 'unparseable', detail: 'flow-style mcpServers ({...} / [...]) is not supported by the restricted reader' };
  }

  return null;
}

/**
 * Parses a block sequence ("- " items) at a fixed indentation level.
 * Each item is either a scalar (pushed as a string) or, when the item
 * begins "- key: ..." (or "- key:" with a nested block), a mapping —
 * parsed by delegating sibling keys to parseMappingBlock at the item's
 * property indent (list indent + 2).
 */
function parseListBlock(lines, start, indent) {
  const items = [];
  let i = start;

  while (i < lines.length) {
    const line = lines[i];
    if (isBlankOrComment(line)) { i++; continue; }
    const lineIndent = indentOf(line);
    if (lineIndent < indent) break;
    if (lineIndent > indent) { i++; continue; }

    const trimmed = line.trim();
    if (trimmed !== '-' && !trimmed.startsWith('- ')) break;

    const rest = trimmed === '-' ? '' : trimmed.slice(2);
    const colonIdx = rest.indexOf(':');
    const isMapping = colonIdx !== -1 && /^[A-Za-z_][\w-]*:/.test(rest);

    if (!isMapping) {
      items.push(stripQuotes(rest));
      i++;
      continue;
    }

    const itemIndent = indent + 2;
    const key = rest.slice(0, colonIdx).trim();
    const value = rest.slice(colonIdx + 1).trim();
    const itemObj = {};
    i++;

    if (value !== '') {
      itemObj[key] = value.startsWith('[') ? parseInlineList(value) : stripQuotes(value);
    } else {
      let j = i;
      while (j < lines.length && isBlankOrComment(lines[j])) j++;
      if (j < lines.length && indentOf(lines[j]) > indent) {
        const childIndent = indentOf(lines[j]);
        if (lines[j].trim().startsWith('-')) {
          const sub = parseListBlock(lines, j, childIndent);
          itemObj[key] = sub.items;
          i = sub.nextIndex;
        } else {
          const sub = parseMappingBlock(lines, j, childIndent);
          itemObj[key] = sub.obj;
          i = sub.nextIndex;
        }
      } else {
        itemObj[key] = null;
      }
    }

    const restParsed = parseMappingBlock(lines, i, itemIndent);
    Object.assign(itemObj, restParsed.obj);
    items.push(itemObj);
    i = restParsed.nextIndex;
  }

  return { items, nextIndex: i };
}

/**
 * Parses "key: value" lines at a fixed indentation level into a plain
 * object, recursing into nested block sequences or mappings when a key's
 * value is empty (the value lives on subsequent, deeper-indented lines).
 */
function parseMappingBlock(lines, start, indent) {
  const obj = {};
  let i = start;

  while (i < lines.length) {
    const line = lines[i];
    if (isBlankOrComment(line)) { i++; continue; }
    const lineIndent = indentOf(line);
    if (lineIndent !== indent) break;

    const trimmed = line.trim();
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1 || !/^[A-Za-z_][\w-]*:/.test(trimmed)) break;

    const key = trimmed.slice(0, colonIdx).trim();
    const value = trimmed.slice(colonIdx + 1).trim();
    i++;

    if (value !== '') {
      obj[key] = value.startsWith('[') ? parseInlineList(value) : stripQuotes(value);
      continue;
    }

    let j = i;
    while (j < lines.length && isBlankOrComment(lines[j])) j++;
    if (j < lines.length && indentOf(lines[j]) > indent) {
      const childIndent = indentOf(lines[j]);
      if (lines[j].trim().startsWith('-')) {
        const sub = parseListBlock(lines, j, childIndent);
        obj[key] = sub.items;
        i = sub.nextIndex;
      } else {
        const sub = parseMappingBlock(lines, j, childIndent);
        obj[key] = sub.obj;
        i = sub.nextIndex;
      }
    } else {
      obj[key] = null;
    }
  }

  return { obj, nextIndex: i };
}

function parse(source, opts = {}) {
  const read = readConfigSafe(source.path, opts);
  if (!read.ok) {
    return read;
  }

  const text = read.raw;
  const reject = checkUnsupportedShape(text);
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
