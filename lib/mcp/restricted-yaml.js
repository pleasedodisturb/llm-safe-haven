'use strict';

/**
 * Shared restricted-YAML primitives (D-03, Phase 12).
 *
 * Extracted VERBATIM from lib/mcp/parsers/continue-dev.js (the original,
 * proven restricted-reader implementation) so that every restricted YAML
 * consumer in this scanner — continue-dev.js's block-SEQUENCE `mcpServers:`
 * shape and goose.js's block-MAPPING `extensions:` shape — shares one
 * fail-closed grammar rather than risking a second hand-rolled reader
 * drifting from the proven contract.
 *
 * Extraction choice (D-03): module-boundary extraction was NOT fragile —
 * every function below is topLevel-key-agnostic EXCEPT `checkUnsupportedShape`,
 * which historically hardcoded continue-dev's `mcpServers:` flow-style
 * regex. That one check is now parameterized as
 * `checkUnsupportedShape(text, topLevelKey = 'mcpServers')` so each caller
 * passes its own top-level key (`'mcpServers'` for continue-dev,
 * `'extensions'` for goose) while continue-dev's call site keeps its
 * exact prior behavior via the default parameter. No fallback duplication
 * was needed.
 *
 * Same restricted-reader philosophy as before: this is NOT a general-
 * purpose YAML grammar. Anything outside the documented narrow shapes —
 * YAML anchors (&) / aliases (*), flow-style mappings/sequences, multi-
 * document separators, tab indentation, quoted mapping keys, block
 * scalars, trailing inline comments, or a prototype-pollution mapping key
 * — is REJECTED fail-closed (MCPC-03). Zero npm YAML dependency: only
 * Node built-ins are used by consumers of this module.
 */

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
 * `topLevelKey` (default 'mcpServers') parameterizes ONLY the flow-style
 * top-level-key check (e.g. `mcpServers: {...}` vs `extensions: {...}`) —
 * every other check below is already shape-agnostic and applies
 * identically regardless of which restricted parser calls this function.
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
function checkUnsupportedShape(text, topLevelKey = 'mcpServers') {
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
  // Prototype-pollution key in mapping position ("__proto__:", "- constructor:",
  // …). The line parsers assign obj[key] = value — with key '__proto__' and an
  // OBJECT value that assignment silently sets the item's PROTOTYPE instead of
  // an own key, so stripProtoPollution cannot see it and command/env could be
  // INHERITED from attacker-controlled YAML. Same fail-closed policy as
  // extractServerEntries in base.js: reject, never mis-parse.
  const pollutionKeyPattern = /^\s*(?:- )?(?:__proto__|constructor|prototype)\s*:/;
  // A QUOTED mapping key ("command": …, - 'url': …) is valid YAML that
  // a real parser loads, but parseMappingBlock's bare-identifier
  // guard (/^[A-Za-z_][\w-]*:/) does not match it and `break`s — silently
  // dropping command/args/url and returning ok:true, letting a hostile server
  // evade the scan while the agent still runs it. Reject, never mis-parse.
  // (A quoted SCALAR list item `- "foo"` has no colon after the closing quote
  // and is NOT matched.)
  const quotedKeyPattern = /^\s*(?:- )?(["'])(?:(?!\1).)*\1\s*:/;
  const anchorAliasPattern = /(^|[:-]\s)[&*][A-Za-z_][\w-]*/;
  // Block/folded scalar indicator as a key's value: "key: |", "key: >",
  // "key: |-", "key: >2", … (optionally followed only by a comment). The
  // reader would parse the indicator character as the literal value and
  // silently drop the scalar body below it.
  const blockScalarPattern = /^\s*(?:- )?[A-Za-z_][\w-]*:\s*[|>]/;
  for (const line of lines) {
    if (isBlankOrComment(line)) continue;
    if (pollutionKeyPattern.test(line)) {
      return { reason: 'polluted', detail: 'a mapping key is a prototype-pollution token (__proto__/constructor/prototype)' };
    }
    if (quotedKeyPattern.test(line)) {
      return { reason: 'unsupported-yaml', detail: 'quoted mapping keys are not supported by the restricted reader' };
    }
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

  const flowStylePattern = new RegExp(`${topLevelKey}:\\s*[{[]`);
  if (flowStylePattern.test(text)) {
    return { reason: 'unparseable', detail: `flow-style ${topLevelKey} ({...} / [...]) is not supported by the restricted reader` };
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

module.exports = {
  indentOf,
  isBlankOrComment,
  stripQuotes,
  parseInlineList,
  checkUnsupportedShape,
  parseListBlock,
  parseMappingBlock,
};
