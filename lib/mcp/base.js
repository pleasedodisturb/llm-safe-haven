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

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];

    if (inLineComment) {
      if (c === '\n') {
        inLineComment = false;
        result += c;
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

    if (c === '"') {
      inString = true;
      result += c;
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

    result += c;
  }

  // Trailing comma before } or ] — safe now that comments/strings are
  // already stripped, so this cannot match inside a string value.
  return result.replace(/,(\s*[}\]])/g, '$1');
}

module.exports = {
  MAX_CONFIG_SIZE,
  readConfigSafe,
  stripProtoPollution,
  stripJsonc,
};
