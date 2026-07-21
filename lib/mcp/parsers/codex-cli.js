'use strict';

/**
 * Codex CLI MCP config parser — a NET-NEW restricted, fail-closed TOML
 * reader (Phase 12, AGENT-01). No general TOML grammar exists or is
 * introduced by this file — per CLAUDE.md's zero-runtime-dependency rule
 * and the continue-dev.js restricted-reader philosophy it clones, this
 * module is scoped EXCLUSIVELY to Codex CLI's documented
 * `[mcp_servers.<name>]` table-per-name shape:
 *
 *   [mcp_servers.fs]
 *   command = "node"
 *   args = ["server.js", "--flag"]
 *   env = { API_KEY = "secret" }        # inline table form
 *   enabled = true
 *   required = false
 *   startup_timeout_sec = 15
 *
 *   [mcp_servers.fs.env]                 # OR sub-table form (mutually
 *   API_KEY = "secret"                   # exclusive with inline `env =
 *                                         # {...}` on the SAME server —
 *                                         # rejected if both appear, D-01)
 *
 *   [mcp_servers.api]
 *   url = "https://api.example.com/mcp"  # remote transport
 *
 * D-01: everything outside that documented shape — multiline basic
 * strings (`"""..."""`), literal strings (`'...'`) / literal multiline
 * (`'''...'''`), TOML array-of-tables (`[[mcp_servers]]`), dotted keys
 * outside the two documented table-header forms, and nested inline
 * tables inside env's inline table — is REJECTED fail-closed with
 * `{ ok:false, reason, code:2, detail }`, never a best-effort guess or a
 * silent mis-parse (MCPC-03/MCPC-04, same contract as continue-dev.js).
 *
 * Pitfall 3 (RESEARCH.md): `[[mcp_servers]]` (TOML array-of-tables) is
 * Mistral Vibe CLI's shape, a DIFFERENT product's config.toml — this
 * parser must never "helpfully" accept it too. Doing so would conflate
 * two products' formats and bypass scan-mcp.js's parser-mismatch guard
 * entirely, since a single parser accepting two shapes never trips that
 * guard. Anti-pattern explicitly rejected: do not support array-of-
 * tables "for compatibility".
 *
 * D-02: prototype-pollution tokens (`__proto__`/`constructor`/
 * `prototype`) as a table name OR a key are rejected with reason
 * 'polluted' BEFORE assignment (mirrors continue-dev's
 * pollutionKeyPattern policy), and every extracted server object still
 * passes through `stripProtoPollution()` before `normalizeServer()` as
 * defense in depth.
 *
 * Zero npm TOML dependency: only lib/mcp/base.js and Node built-ins.
 */

const {
  readConfigSafe,
  stripProtoPollution,
  normalizeServer,
} = require('../base.js');

const agentId = 'codex-cli';

const POLLUTION_KEY_PATTERN = /^(__proto__|constructor|prototype)$/;

// Bare TOML key: word chars, digits, underscore, dash. Quoted table names
// (double-quoted only — single-quoted/literal names fall under the
// rejected "literal strings" class below) are also accepted for header
// lines, mirroring the documented shape's own basic-string convention.
const NAME_PATTERN = '(?:[A-Za-z0-9_-]+|"[^"]*")';
const HEADER_RE = new RegExp(`^\\[mcp_servers\\.(${NAME_PATTERN})(\\.env)?\\]$`);
const OTHER_HEADER_RE = /^\[[^\]]+\]$/;
const KV_RE = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/;

// Keys read-and-ignored for scanning purposes (per the documented shape) —
// never passed to normalizeServer().
const IGNORED_KEYS = new Set(['enabled', 'required', 'startup_timeout_sec', 'tool_timeout_sec']);

/**
 * Pre-pass rejection scanner, run BEFORE any table extraction — mirrors
 * continue-dev.js's checkUnsupportedShape philosophy for TOML's own
 * hostile-construct surface. Returns { reason, detail } or null.
 */
function checkUnsupportedShape(text) {
  if (text.includes('"""')) {
    return { reason: 'unsupported-toml', detail: 'multiline basic strings ("""..."""") are not supported' };
  }
  if (text.includes("'''")) {
    return { reason: 'unsupported-toml', detail: "multiline literal strings ('''...''') are not supported" };
  }
  // Pitfall 3: [[mcp_servers]] is Mistral Vibe CLI's array-of-tables
  // shape, never Codex's table-per-name shape.
  if (/^\s*\[\[mcp_servers\b/m.test(text)) {
    return { reason: 'unsupported-toml', detail: 'array-of-tables ([[mcp_servers]]) is not the documented Codex shape' };
  }

  const lines = text.split('\n');
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;

    // A bare dotted-key assignment targeting mcp_servers (e.g.
    // `mcp_servers.foo.command = "x"`) is an alternate TOML syntax for
    // the same structure the two documented table-header forms cover —
    // outside those two forms, reject rather than silently accept a
    // second way to spell the same thing.
    if (/^mcp_servers\.[^\s=[\]]+\s*=/.test(line)) {
      return { reason: 'unsupported-toml', detail: `dotted key '${line}' is outside the documented [mcp_servers.<name>] table-header forms` };
    }

    // Literal strings (single-quoted values) are not part of the
    // documented shape (only single-line basic/double-quoted strings
    // are) — reject rather than mis-parse.
    if (!line.startsWith('[') && /=\s*'/.test(line)) {
      return { reason: 'unsupported-toml', detail: 'literal strings (single-quoted) are not supported' };
    }
  }

  return null;
}

/**
 * Splits `text` on top-level occurrences of `sep`, respecting double-
 * quoted string boundaries (so a comma inside a quoted string is never
 * treated as a separator).
 */
function splitTopLevel(text, sep) {
  const parts = [];
  let current = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      current += c;
      if (c === '\\' && i + 1 < text.length) {
        current += text[i + 1];
        i++;
        continue;
      }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      current += c;
      continue;
    }
    if (c === sep) {
      parts.push(current);
      current = '';
      continue;
    }
    current += c;
  }
  parts.push(current);
  return parts;
}

function unescapeBasicString(inner) {
  return inner.replace(/\\(.)/g, (_match, c) => {
    switch (c) {
      case 'n': return '\n';
      case 't': return '\t';
      case 'r': return '\r';
      case '"': return '"';
      case '\\': return '\\';
      default: return c;
    }
  });
}

/**
 * Parses a single-line TOML basic string ("...") — the ONLY string form
 * this restricted reader accepts as a value. Returns null (never throws)
 * for anything else (booleans, numbers, arrays, tables, unterminated or
 * multiline strings), signaling "not a supported value" to the caller.
 */
function parseBasicString(raw) {
  const m = raw.match(/^"([^"\\]*(?:\\.[^"\\]*)*)"$/);
  if (!m) return null;
  return unescapeBasicString(m[1]);
}

/**
 * Parses a TOML array-of-strings literal (`["a", "b"]`). Returns null on
 * anything that is not a bracketed list of single-line basic strings.
 */
function parseStringArray(raw) {
  const m = raw.match(/^\[([\s\S]*)\]$/);
  if (!m) return null;
  const inner = m[1].trim();
  if (inner === '') return [];

  const items = splitTopLevel(inner, ',');
  const result = [];
  for (const item of items) {
    const trimmed = item.trim();
    if (trimmed === '') continue;
    const value = parseBasicString(trimmed);
    if (value === null) return null;
    result.push(value);
  }
  return result;
}

/**
 * Parses a TOML inline table (`{ KEY = "v", KEY2 = "v2" }`) whose values
 * are single-line basic strings only. A nested inline table as a value
 * (`{ FOO = { bar = "x" } }`) naturally fails the inner key=value match
 * below and returns null — never silently flattened or dropped.
 *
 * Returns { value, polluted:false } on success, { polluted:true } if a
 * key is a prototype-pollution token, or null if the table cannot be
 * parsed as the documented flat string-valued shape.
 */
function parseInlineTable(raw) {
  const m = raw.match(/^\{([\s\S]*)\}$/);
  if (!m) return null;
  const inner = m[1].trim();
  const value = {};
  if (inner === '') return { value, polluted: false };

  const items = splitTopLevel(inner, ',');
  for (const item of items) {
    const trimmed = item.trim();
    if (trimmed === '') continue;
    const kv = trimmed.match(KV_RE);
    if (!kv) return null;
    const key = kv[1];
    if (POLLUTION_KEY_PATTERN.test(key)) {
      return { polluted: true };
    }
    const val = parseBasicString(kv[2].trim());
    if (val === null) return null;
    value[key] = val;
  }
  return { value, polluted: false };
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
  const servers = new Map();
  const order = [];
  let current = null; // { name, section: 'server' | 'env' }

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;

    const headerMatch = line.match(HEADER_RE);
    if (headerMatch) {
      let name = headerMatch[1];
      if (name.startsWith('"')) name = name.slice(1, -1);
      if (POLLUTION_KEY_PATTERN.test(name)) {
        return { ok: false, reason: 'polluted', code: 2, detail: `table name '${name}' is a prototype-pollution token` };
      }
      if (!servers.has(name)) {
        servers.set(name, { command: undefined, args: undefined, url: undefined, envInline: undefined, envSub: undefined });
        order.push(name);
      }
      current = { name, section: headerMatch[2] ? 'env' : 'server' };
      continue;
    }

    if (OTHER_HEADER_RE.test(line)) {
      // A table header unrelated to mcp_servers (e.g. Codex's own
      // [model]/[sandbox] sections) — outside this parser's documented
      // scope; skip its contents rather than reject the whole file.
      current = null;
      continue;
    }

    if (!current) {
      // A bare key outside any table and outside mcp_servers (already
      // covered by the dotted-key pre-pass check above) — not this
      // parser's concern.
      continue;
    }

    const kvMatch = line.match(KV_RE);
    if (!kvMatch) {
      return { ok: false, reason: 'unparseable', code: 2, detail: `could not parse line: ${rawLine}` };
    }
    const key = kvMatch[1];
    const rawValue = kvMatch[2].trim();

    if (POLLUTION_KEY_PATTERN.test(key)) {
      return { ok: false, reason: 'polluted', code: 2, detail: `key '${key}' is a prototype-pollution token` };
    }

    const server = servers.get(current.name);

    if (current.section === 'env') {
      const value = parseBasicString(rawValue);
      if (value === null) {
        return { ok: false, reason: 'unparseable', code: 2, detail: `env value for '${key}' is not a single-line basic string` };
      }
      if (!server.envSub) server.envSub = {};
      server.envSub[key] = value;
      continue;
    }

    if (key === 'command') {
      const value = parseBasicString(rawValue);
      if (value === null) {
        return { ok: false, reason: 'unparseable', code: 2, detail: 'command must be a single-line basic string' };
      }
      server.command = value;
    } else if (key === 'url') {
      const value = parseBasicString(rawValue);
      if (value === null) {
        return { ok: false, reason: 'unparseable', code: 2, detail: 'url must be a single-line basic string' };
      }
      server.url = value;
    } else if (key === 'args') {
      const arr = parseStringArray(rawValue);
      if (arr === null) {
        return { ok: false, reason: 'unparseable', code: 2, detail: 'args must be an array of single-line basic strings' };
      }
      server.args = arr;
    } else if (key === 'env') {
      const inlineResult = parseInlineTable(rawValue);
      if (inlineResult === null) {
        return { ok: false, reason: 'unparseable', code: 2, detail: 'env inline table could not be parsed as a flat string-valued table' };
      }
      if (inlineResult.polluted) {
        return { ok: false, reason: 'polluted', code: 2, detail: 'env inline table contains a prototype-pollution key' };
      }
      server.envInline = inlineResult.value;
    } else if (IGNORED_KEYS.has(key)) {
      // Read-and-ignore: not part of the normalized server shape.
    } else {
      return { ok: false, reason: 'unsupported-toml', code: 2, detail: `unsupported key '${key}' in [mcp_servers.${current.name}]` };
    }
  }

  const result = [];
  for (const name of order) {
    const server = servers.get(name);
    if (server.envInline !== undefined && server.envSub !== undefined) {
      // D-01: a server declaring BOTH env forms is ambiguous — never
      // silently pick one.
      return { ok: false, reason: 'unsupported-toml', code: 2, detail: `server '${name}' declares both inline env and an env sub-table` };
    }
    const env = server.envInline !== undefined ? server.envInline : (server.envSub !== undefined ? server.envSub : {});
    const clean = stripProtoPollution({ name, command: server.command, args: server.args, env, url: server.url });
    result.push(normalizeServer({
      agentId,
      scope: source.scope,
      configPath: source.path,
      name: clean.name,
      command: clean.command,
      args: clean.args,
      env: clean.env,
      url: clean.url,
      headers: {},
    }));
  }

  return { ok: true, servers: result };
}

module.exports = { parse, agentId };
