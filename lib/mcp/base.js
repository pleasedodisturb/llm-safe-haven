'use strict';

/**
 * Shared foundation module for the MCP config scanner (Phase 4). Every
 * parser under lib/mcp/parsers/*.js and the lib/scan-mcp.js orchestrator
 * import from here. This file freezes two things:
 *
 *   1. Hostile-input-safe read helpers — size cap, symlink rejection,
 *      prototype-pollution stripping, never-throw structured failure —
 *      plus a string-literal-aware JSONC stripper.
 *   2. The frozen schema/exit-code contract that Phases 5-8 build on:
 *      schema version, confidence/severity enums, Finding() shape,
 *      exit-code constants, normalizeServer() shape.
 *
 * Exit-code convention (mirrors lib/scan.js): 0 = clean, 1 = findings,
 * 2 = error/could-not-complete. A malformed/oversized/symlinked/
 * prototype-polluted config is NEVER reported as 0 ("clean") — a security
 * gate must distinguish "no findings" from "the scan did not finish".
 */

// 5MB — no legitimate MCP config is this large. Single named constant so
// this is a one-line change later if real-world fixtures demand it.
const MAX_CONFIG_SIZE = 5 * 1024 * 1024;

/**
 * Safely reads a config file, failing closed on every hostile-input class:
 *   - symlink (checked via lstatSync BEFORE any read, so the link itself is
 *     inspected, never its target)
 *   - non-regular file (FIFO/device/socket — a FIFO passes the symlink and
 *     size guards but blocks readFileSync forever waiting for a writer, a
 *     hard DoS; rejected via isFile() BEFORE any read)
 *   - oversized (statSync size check BEFORE readFileSync, so the cap is
 *     enforced before the file is loaded into memory)
 *   - unreadable/nonexistent (readFileSync failure)
 *
 * Never throws — every failure path returns a structured
 * { ok:false, reason, code:2, detail } object.
 *
 * opts (for testing): { fs } — defaults to the real Node fs module.
 */
function readConfigSafe(filePath, opts = {}) {
  const fs = opts.fs || require('fs');

  try {
    const lstat = fs.lstatSync(filePath);
    if (lstat.isSymbolicLink()) {
      return {
        ok: false,
        reason: 'symlink',
        code: 2,
        detail: `${filePath} is a symlink — refusing to follow`,
      };
    }

    const stat = fs.statSync(filePath);
    if (!stat.isFile()) {
      return {
        ok: false,
        reason: 'not-regular-file',
        code: 2,
        detail: `${filePath} is not a regular file`,
      };
    }
    if (stat.size > MAX_CONFIG_SIZE) {
      return {
        ok: false,
        reason: 'oversized',
        code: 2,
        detail: `${filePath} is ${stat.size} bytes, exceeds ${MAX_CONFIG_SIZE}`,
      };
    }
  } catch (err) {
    return { ok: false, reason: 'unreadable', code: 2, detail: err.message };
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return { ok: true, raw };
  } catch (err) {
    return { ok: false, reason: 'unreadable', code: 2, detail: err.message };
  }
}

/**
 * Strips __proto__, constructor, and prototype own-keys from a parsed
 * config object. Reuse (near-verbatim) of the proven guard in
 * lib/agents/claude-code.js:141-146.
 *
 * A non-plain-object input (array, null, primitive) returns {} — this is
 * the fail-closed behavior for a config whose top level is not a JSON
 * object at all.
 */
function stripProtoPollution(value) {
  if (typeof value !== 'object' || Array.isArray(value) || value === null) {
    return {};
  }
  delete value.__proto__;
  delete value.constructor;
  delete value.prototype;
  return value;
}

/**
 * Validates and cleans an `mcpServers` container object — the SINGLE
 * policy every JSON/JSONC parser applies, so an identical hostile input
 * resolves identically regardless of which agent's config file it lands
 * in (a payload's detectability must never depend on the target agent):
 *
 *   - absent (undefined/null)            → { ok:true, entries:{} } —
 *     a config with no mcpServers key is genuinely clean
 *   - non-object (array/string/number)   → { ok:false, reason:'malformed',
 *     code:2 } — a structurally wrong mcpServers is hostile/malformed
 *     input and must surface as exit 2, never silently pass as clean
 *   - ANY server NAME that is a prototype-pollution token
 *     (__proto__/constructor/prototype)  → { ok:false, reason:'polluted',
 *     code:2 } — server names are data, not structure; silently dropping
 *     one lets a hostile server evade the scan (CR-01), and keeping it
 *     poisons downstream consumers. Fail closed.
 */
function extractServerEntries(mcpServersRaw) {
  if (mcpServersRaw === undefined || mcpServersRaw === null) {
    return { ok: true, entries: {} };
  }
  if (typeof mcpServersRaw !== 'object' || Array.isArray(mcpServersRaw)) {
    return { ok: false, reason: 'malformed', code: 2, detail: 'mcpServers is not an object' };
  }

  const rawKeyCount = Object.keys(mcpServersRaw).length;
  const entries = stripProtoPollution(mcpServersRaw);
  if (Object.keys(entries).length < rawKeyCount) {
    return {
      ok: false,
      reason: 'polluted',
      code: 2,
      detail: 'a server name is a prototype-pollution key (__proto__/constructor/prototype)',
    };
  }

  return { ok: true, entries };
}

/**
 * Strips // line comments, /* block *\/ comments, and trailing commas
 * (before } or ]) from a JSONC text, WITHOUT mangling string literals — a
 * naive regex-only stripper (e.g. `text.replace(/\/\/.*$/gm, '')`) treats
 * the // inside `"url": "https://..."` as a comment start, truncating the
 * value mid-string (RESEARCH.md Pitfall 5). This is a character-by-
 * character, string-literal-aware scanner: it tracks inString state so a
 * // or /* inside a quoted string is never treated as a comment, and an
 * escaped quote (\") never ends the string early.
 *
 * The output is a JSON string suitable for JSON.parse — this does not
 * parse JSONC itself, only strips the JSONC-only syntax down to valid
 * JSON.
 */
function stripJsonc(text) {
  let result = '';
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;

  // Trailing-comma handling lives INSIDE the scanner, where inString
  // state is known — a post-hoc regex over the assembled output would
  // also run over preserved string literals ("end, }" would silently
  // lose its comma). A structural comma is buffered (pendingComma +
  // any whitespace/comments after it in pendingWs) and dropped only
  // when the next significant char is } or ]; otherwise it is flushed
  // verbatim.
  let pendingComma = false;
  let pendingWs = '';

  const flushPending = () => {
    if (pendingComma) {
      result += ',' + pendingWs;
      pendingComma = false;
      pendingWs = '';
    }
  };

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];

    if (inLineComment) {
      if (c === '\n') {
        inLineComment = false;
        if (pendingComma) pendingWs += c;
        else result += c;
      }
      continue;
    }

    if (inBlockComment) {
      if (c === '*' && next === '/') {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (inString) {
      result += c;
      if (c === '\\') {
        // Preserve the escaped char (including \") without ending the
        // string on it.
        result += next;
        i++;
        continue;
      }
      if (c === '"') inString = false;
      continue;
    }

    if (c === '/' && next === '/') {
      inLineComment = true;
      i++;
      continue;
    }
    if (c === '/' && next === '*') {
      inBlockComment = true;
      i++;
      continue;
    }

    if (c === ',') {
      // A second structural comma while one is pending (invalid JSON
      // like ", ,") flushes the first — never silently merge them.
      flushPending();
      pendingComma = true;
      continue;
    }

    if (pendingComma) {
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        pendingWs += c;
        continue;
      }
      if (c === '}' || c === ']') {
        // Trailing comma before a closer — drop the comma, keep the
        // whitespace and the closer.
        result += pendingWs + c;
        pendingComma = false;
        pendingWs = '';
        continue;
      }
      flushPending();
      // fall through to normal handling of c
    }

    if (c === '"') {
      inString = true;
      result += c;
      continue;
    }

    result += c;
  }

  // A comma pending at EOF belongs to malformed input — emit it verbatim
  // so JSON.parse reports the true failure.
  flushPending();

  return result;
}

// ---------------------------------------------------------------------
// Frozen schema/exit-code contract. Phases 5-8 import these rather than
// redefining them — a field renamed here after Phase 5 starts breaks
// every detector fixture. Concrete values ARE the contract; do not
// rename after this phase.
// ---------------------------------------------------------------------

const SCHEMA_VERSION = '1';

const CONFIDENCE = Object.freeze({
  VERIFIED: 'verified',
  UNVERIFIED: 'unverified',
});

const SEVERITY = Object.freeze({
  INFO: 'info',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

// Exit-code convention: 0 = clean, 1 = findings, 2 = error/could-not-
// complete. A could-not-run, malformed-config, oversized-config,
// symlinked-config, or prototype-polluted-config scan is NEVER reported
// as 0 ("clean") — a security gate must distinguish "no findings" from
// "the scan did not finish".
const EXIT = Object.freeze({
  CLEAN: 0,
  FINDINGS: 1,
  INCOMPLETE: 2,
});

/**
 * Constructs a Finding with the frozen shape every detector (Phase 5+)
 * must produce. Unused by Phase 4 itself (the findings array is always
 * empty here), but the SHAPE is frozen now so Phase 5's first detector
 * does not have to invent it.
 *
 * Throw-free: an invalid confidence value is coerced to 'unverified'
 * rather than throwing or silently accepting a bogus enum value.
 */
function Finding({ id, detector, severity, confidence = CONFIDENCE.UNVERIFIED, agentId, scope, serverName, message }) {
  const validConfidence = confidence === CONFIDENCE.VERIFIED || confidence === CONFIDENCE.UNVERIFIED
    ? confidence
    : CONFIDENCE.UNVERIFIED;

  return {
    id,
    detector,
    severity,
    confidence: validConfidence,
    agentId,
    scope,
    serverName,
    message,
  };
}

/**
 * Normalizes a per-agent-shaped server descriptor into the frozen shape
 * every parser (lib/mcp/parsers/*.js) produces and every Phase 5+
 * detector consumes — never raw per-agent JSON/YAML. Missing OR
 * wrong-typed inputs default to null/[]/{} rather than being passed
 * through, so downstream code can rely on every key always being
 * present AND correctly typed: a hostile config setting
 * "args": "rm -rf /" (a string) or "env": ["A=1"] (an array) must
 * never reach a detector that assumes server.args is an array or
 * iterates Object.entries(server.env) — it would mis-scan or throw.
 *
 * ${...} / ${env:...} interpolation tokens are treated as opaque
 * strings — this is a static-config parser, not a shell-expansion
 * engine, so values are never resolved or evaluated.
 */
function normalizeServer({ agentId, scope, configPath, name, command, args, env, url, headers }) {
  return {
    agentId,
    scope,
    configPath,
    name: typeof name === 'string' && name !== '' ? name : null,
    command: typeof command === 'string' && command !== '' ? command : null,
    args: Array.isArray(args) ? args : [],
    env: (env && typeof env === 'object' && !Array.isArray(env)) ? env : {},
    url: typeof url === 'string' && url !== '' ? url : null,
    headers: (headers && typeof headers === 'object' && !Array.isArray(headers)) ? headers : {},
  };
}

module.exports = {
  MAX_CONFIG_SIZE,
  readConfigSafe,
  stripProtoPollution,
  extractServerEntries,
  stripJsonc,
  SCHEMA_VERSION,
  CONFIDENCE,
  SEVERITY,
  EXIT,
  Finding,
  normalizeServer,
};
