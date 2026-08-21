'use strict';

/**
 * Check 2 -- MCP rule-ID coverage (G-1570, GUARD-01).
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-01-PLAN.md "Check 2 grammar".
 * Read that section before editing this file.
 *
 * EMITTED side: every lib/mcp/detectors/*.js module (except index.js)
 * declares a module-level `const id = '...'` and emits rule IDs in the
 * single shape `` id: `${id}/<suffix>` ``. 19 of 20 real emission sites
 * use a literal suffix; ONE (lib/mcp/detectors/unpinned-execution.js:96)
 * interpolates a variable (`${bin}`) whose finite alternative set is
 * fixed by strict-equality comparisons elsewhere in the same module
 * (unpinned-execution.js:80: `bin === 'npx' || bin === 'uvx'`).
 *
 * DOCUMENTED side: the detector table in docs/mcp-security.md. Column 1
 * is the backticked detector id; column 2 is a comma-separated list of
 * backticked rule suffixes, which may use brace-alternation
 * (`{npx|uvx}-no-version`) and MAY carry a backslash-escaped pipe inside
 * that brace group (docs/mcp-security.md's own unpinned-execution row
 * does exactly this) -- a naive `line.split('|')` mis-aligns that row's
 * cells and silently empties its documented set.
 *
 * COMPARISON: per detector, every emitted suffix must be a member of
 * that SAME detector's own documented suffix set -- never a
 * whole-document substring test. The composed `<detector-id>/<suffix>`
 * form never appears verbatim anywhere in docs/mcp-security.md; a
 * whole-document test would produce ~20 false findings on this
 * checkout's real corpus.
 *
 * All regexes below are static hand-authored literals -- never built from
 * markdown- or module-controlled text (ReDoS/injection defense,
 * T-21-01-04), matching the comment convention already in
 * lib/mcp/detectors/credential-passthrough.js. The one dynamic piece
 * (the `${var}` alternative-set resolution) builds its comparison regex
 * from a source-scraped IDENTIFIER, which is escaped before use.
 */

const path = require('path');

const id = 'mcp-rule-ids';

// Matches `const id = '<literal>';` at any indentation, optionally
// missing the trailing semicolon -- the exact module-level declaration
// shape every lib/mcp/detectors/*.js file uses.
const ID_CONST_RE = /^\s*const\s+id\s*=\s*'([^']+)'\s*;?\s*$/m;

// Matches one `id: `${id}/<suffix>`` emission site per line. <suffix> may
// itself contain a `${var}` interpolation (the dynamic case).
const RULE_LINE_RE = /id:\s*`\$\{id\}\/([^`]*)`/;

// Matches a `${identifier}` interpolation inside an already-extracted
// suffix capture.
const VAR_INTERPOLATION_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/;

function escapeRegExp(literal) {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Splits a markdown table row on `|`, EXCEPT when the pipe is preceded by
 * a backslash -- in which case the backslash is dropped and a literal `|`
 * is appended to the current cell instead of starting a new one. Cells
 * are trimmed. Not a nicety: docs/mcp-security.md's unpinned-execution
 * row writes its rule cell as `` `{npx\|uvx}-no-version` `` and a naive
 * split mis-aligns every cell after it.
 */
function splitTableRow(line) {
  const cells = [];
  let current = '';
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '\\' && line[i + 1] === '|') {
      current += '|';
      i += 1;
      continue;
    }
    if (ch === '|') {
      cells.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  cells.push(current.trim());
  return cells;
}

/**
 * Expands a single brace-alternation group into one token per
 * alternative. A token with no brace group is returned unchanged inside
 * a one-element array.
 */
function expandBraceAlternation(token) {
  const match = token.match(/^(.*)\{([^}]+)\}(.*)$/);
  if (!match) return [token];
  const [, prefix, group, suffix] = match;
  return group.split('|').map((alt) => `${prefix}${alt}${suffix}`);
}

/**
 * Scans a markdown document line by line for table rows whose first cell
 * is a single backticked lowercase-hyphen detector id, and returns
 * Map<detectorId, Set<suffix>> built from the rule-ID column. Suffixes
 * only -- the composed `<detector-id>/<suffix>` form does not occur in
 * docs/mcp-security.md at all.
 */
function documentedRuleSuffixes(docText) {
  const map = new Map();
  const lines = docText.split('\n');
  const detectorIdRe = /^`([a-z][a-z0-9-]*)`$/;
  const tokenRe = /`([^`]+)`/g;

  for (const line of lines) {
    if (!line.trim().startsWith('|')) continue;
    const cells = splitTableRow(line);
    const firstCell = (cells[1] || '').trim();
    const detectorMatch = firstCell.match(detectorIdRe);
    if (!detectorMatch) continue;
    const detectorId = detectorMatch[1];
    const ruleCell = cells[2] || '';
    const suffixes = new Set();
    let m = tokenRe.exec(ruleCell);
    while (m !== null) {
      for (const expanded of expandBraceAlternation(m[1])) {
        suffixes.add(expanded);
      }
      m = tokenRe.exec(ruleCell);
    }
    if (suffixes.size > 0) {
      map.set(detectorId, suffixes);
    }
  }
  return map;
}

/**
 * Extracts, from one detector module's raw source text: the module-level
 * id constant, and every rule suffix emitted in the
 * `` id: `${id}/<suffix>` `` shape, each with its one-based source line.
 * A suffix containing a `${var}` interpolation has `var`'s finite
 * alternative set resolved by collecting the string literals it is
 * compared against with strict equality anywhere in the module's source
 * (`var === 'literal'` or `'literal' === var`). An interpolation whose
 * alternative set cannot be resolved this way is NOT skipped and NOT
 * guessed -- it lands in `unresolved` instead.
 *
 * Returns { detectorId, suffixes: [{ suffix, line }], unresolved: [{ line, raw }] }.
 */
function emittedRuleSuffixes(source) {
  const idMatch = source.match(ID_CONST_RE);
  const detectorId = idMatch ? idMatch[1] : null;
  const lines = source.split('\n');
  const suffixes = [];
  const unresolved = [];

  lines.forEach((lineText, idx) => {
    const ruleMatch = lineText.match(RULE_LINE_RE);
    if (!ruleMatch) return;
    const raw = ruleMatch[1];
    const lineNo = idx + 1;
    const varMatch = raw.match(VAR_INTERPOLATION_RE);
    if (!varMatch) {
      suffixes.push({ suffix: raw, line: lineNo });
      return;
    }
    const varName = varMatch[1];
    const escaped = escapeRegExp(varName);
    const alternatives = new Set();
    const cmpForward = new RegExp(`\\b${escaped}\\s*===\\s*'([^']*)'`, 'g');
    const cmpReverse = new RegExp(`'([^']*)'\\s*===\\s*${escaped}\\b`, 'g');
    let cm = cmpForward.exec(source);
    while (cm !== null) {
      alternatives.add(cm[1]);
      cm = cmpForward.exec(source);
    }
    cm = cmpReverse.exec(source);
    while (cm !== null) {
      alternatives.add(cm[1]);
      cm = cmpReverse.exec(source);
    }
    if (alternatives.size === 0) {
      unresolved.push({ line: lineNo, raw });
      return;
    }
    for (const alt of alternatives) {
      suffixes.push({ suffix: raw.replace(`\${${varName}}`, alt), line: lineNo });
    }
  });

  return { detectorId, suffixes, unresolved };
}

/**
 * Compares every lib/mcp/detectors/*.js module's emitted rule suffixes
 * against its own row in docs/mcp-security.md. THROWS (never returns a
 * silent "clean") on: a listFiles/readText error; any unresolved dynamic
 * interpolation; and any detector module from which zero suffixes were
 * extracted (the per-detector non-vacuity guard -- a change to the
 * emission shape would otherwise silently turn every detector into
 * "no rules found, nothing missing, clean").
 */
function run(context) {
  const detectorsDir = 'lib/mcp/detectors';
  const listing = context.listFiles(detectorsDir, { ext: '.js' });
  if (listing.error) {
    throw new Error(`mcp-rule-ids: could not list ${detectorsDir}: ${listing.error}`);
  }

  const docResult = context.readText('docs/mcp-security.md');
  if (docResult.error) {
    throw new Error(`mcp-rule-ids: could not read docs/mcp-security.md: ${docResult.error}`);
  }
  const documented = documentedRuleSuffixes(docResult.text);

  const findings = [];
  for (const file of listing.files) {
    if (path.posix.basename(file) === 'index.js') continue;

    const textResult = context.readText(file);
    if (textResult.error) {
      throw new Error(`mcp-rule-ids: could not read ${file}: ${textResult.error}`);
    }

    const { detectorId, suffixes, unresolved } = emittedRuleSuffixes(textResult.text);

    if (detectorId === null) {
      // 21-REVIEW.md WR-01: ID_CONST_RE (single-quote only) did not match
      // this module's `const id` declaration. Without this guard,
      // documented.get(null) silently falls back to an empty Set and
      // every one of this detector's genuinely-documented suffixes gets
      // reported as a fabricated "null/<suffix>" finding -- a real
      // incompleteness disguised as a correctness finding. Fail loudly
      // instead, the same as the adjacent unresolved/zero-suffix guards.
      throw new Error(
        `mcp-rule-ids: could not determine the detector id in ${file} -- ` +
          "no \"const id = '...'\" declaration matched ID_CONST_RE"
      );
    }

    if (unresolved.length > 0) {
      throw new Error(
        `mcp-rule-ids: unresolved dynamic rule id in ${file}:${unresolved[0].line} (\`${unresolved[0].raw}\`) -- ` +
          'the finite alternative set could not be resolved from strict-equality comparisons in this module'
      );
    }
    if (suffixes.length === 0) {
      throw new Error(
        `mcp-rule-ids: zero rule ids extracted from ${file} -- the non-vacuity guard forbids treating this as clean`
      );
    }

    const docSet = documented.get(detectorId) || new Set();
    for (const entry of suffixes) {
      if (!docSet.has(entry.suffix)) {
        findings.push({
          check: id,
          file,
          line: entry.line,
          severity: 'fail',
          message: `${detectorId}/${entry.suffix} is emitted by ${file}:${entry.line} but not documented in docs/mcp-security.md`,
        });
      }
    }
  }

  return findings;
}

module.exports = { id, run, splitTableRow, expandBraceAlternation, documentedRuleSuffixes, emittedRuleSuffixes };
