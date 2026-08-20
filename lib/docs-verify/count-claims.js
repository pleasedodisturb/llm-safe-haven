'use strict';

/**
 * Check 7 -- count-claim consistency against canonical repository counts
 * (G-1570, GUARD-01, D-05).
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-04-PLAN.md Task 2. Read that
 * section before editing this file.
 *
 * D-05: the 7th check, added so DOC-06 becomes mechanically graded. Grades
 * prose count claims ("(5 agents)", "seven agents", "Eight detectors")
 * against canonical repository counts (agent modules, MCP parsers, MCP
 * detectors, hardening-guide files).
 *
 * CLAIM_REGISTRY is a FROZEN ALLOWLIST of bindable claim shapes -- never a
 * blocklist of phrasings to ignore. This project already paid five
 * iterations for the blocklist anti-pattern on the POSIX-class validator
 * (feedback_validators_as_grammars); an allowlist is honest about the
 * boundary of what this check can grade. A count claim in a SCOPED_DOCS
 * document that no registry entry binds is a `warn` (an unbindable
 * claim, surfaced rather than guessed at), never a `fail` -- warn severity
 * does not drive a nonzero exit (lib/docs-verify/index.js's
 * tallySeverities only counts `fail`).
 *
 * SCOPED_DOCS is a frozen file-role allowlist mirroring identifiers.js's
 * own convention: third-party catalogue docs (docs/references.md) and
 * per-agent hardening guides state OTHER projects' or OTHER agents'
 * counts and must never be graded against this repo's own canonical
 * sources.
 */

const path = require('path');

const id = 'count-claims';

// ---------------------------------------------------------------------------
// wordToNumber
// ---------------------------------------------------------------------------

const NUMBER_WORDS = Object.freeze({
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  eleven: 11,
  twelve: 12,
  thirteen: 13,
  fourteen: 14,
  fifteen: 15,
  sixteen: 16,
  seventeen: 17,
  eighteen: 18,
  nineteen: 19,
  twenty: 20,
});

/**
 * wordToNumber(token) -- a digit string or an English number word one
 * through twenty (case-insensitive), mapped to an integer. Returns null
 * for anything else (an unknown token, or ordinary prose).
 */
function wordToNumber(token) {
  const t = String(token);
  if (/^\d+$/.test(t)) return parseInt(t, 10);
  const lower = t.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(NUMBER_WORDS, lower)) return NUMBER_WORDS[lower];
  return null;
}

// ---------------------------------------------------------------------------
// SCOPED_DOCS -- file-role allowlist
// ---------------------------------------------------------------------------

const SCOPED_DOCS = Object.freeze(['README.md', 'CLAUDE.md', 'docs/mcp-security.md', 'hooks/README.md', 'docs/wave-spec.md']);

function isScopedDoc(relPath) {
  return SCOPED_DOCS.includes(relPath);
}

// ---------------------------------------------------------------------------
// CANONICAL_SOURCES -- id -> counting function, resolved relative to the
// inspected root so fixtures work identically to the real repo.
// ---------------------------------------------------------------------------

function countFiles(context, dir, ext, excludeBasenames) {
  const listing = context.listFiles(dir, { ext, recursive: false });
  if (listing.error) {
    throw new Error(`count-claims: could not list ${dir}: ${listing.error}`);
  }
  return listing.files.filter((f) => !excludeBasenames.has(path.posix.basename(f))).length;
}

const CANONICAL_SOURCES = Object.freeze({
  'agent-modules': (context) => countFiles(context, 'lib/agents', '.js', new Set(['index.js', 'base.js'])),
  'mcp-parsers': (context) => countFiles(context, 'lib/mcp/parsers', '.js', new Set(['index.js'])),
  'mcp-detectors': (context) => countFiles(context, 'lib/mcp/detectors', '.js', new Set(['index.js'])),
  'hardening-guides': (context) => countFiles(context, 'docs/hardening', '.md', new Set()),
});

// ---------------------------------------------------------------------------
// CLAIM_REGISTRY -- the frozen allowlist of bindable claim shapes this
// repository actually uses today. Each pattern has exactly one capture
// group (the claimed number/word). Patterns are deliberately SPECIFIC to
// the surrounding phrase, never a bare "(N agents)" -- a bare parenthesised
// count also appears in unrelated, already-correct sentences elsewhere
// (e.g. a hardening-guide count phrased differently), and binding those to
// the wrong canonical source would be a false positive of this check's own
// making.
// ---------------------------------------------------------------------------

const CLAIM_REGISTRY = Object.freeze([
  {
    name: 'mcp-scan-parenthesized-agents',
    pattern: /Scan MCP server configs \((\d+|[A-Za-z]+) agents\)/i,
    source: 'mcp-parsers',
  },
  {
    name: 'mcp-discovers-parses-agents',
    pattern: /discovers and parses MCP server configs across \*{0,2}(\d+|[A-Za-z]+) agents\*{0,2}/i,
    source: 'mcp-parsers',
  },
  {
    name: 'hardening-guides-for-agents',
    pattern: /hardening guides for (\d+|[A-Za-z]+) agents/i,
    source: 'hardening-guides',
  },
  {
    name: 'detects-and-hardens-agents',
    pattern: /detects and hardens (\d+|[A-Za-z]+) agents/i,
    source: 'agent-modules',
  },
  {
    name: 'detectors-run-on-every-scan',
    pattern: /(\d+|[A-Za-z]+) detectors run on every scan/i,
    source: 'mcp-detectors',
  },
]);

// ---------------------------------------------------------------------------
// Unbindable-claim fallback -- the subject nouns the registry above
// covers, built from a STATIC module-level list (never from doc-
// controlled text) so the fallback regex is not "built from markdown".
// ---------------------------------------------------------------------------

const SUBJECT_NOUNS = Object.freeze(['agents', 'detectors']);
const UNBOUND_CLAIM_RE = new RegExp(`\\b(\\d+|[A-Za-z]+)\\s+(${SUBJECT_NOUNS.join('|')})\\b`, 'gi');

// ---------------------------------------------------------------------------
// run(context)
// ---------------------------------------------------------------------------

/**
 * run(context) -- walks only the SCOPED_DOCS subset of context.mdFiles.
 * For each line: try every CLAIM_REGISTRY entry in order; the first match
 * resolves the canonical count (via CANONICAL_SOURCES, cached per run) and
 * emits a `fail` finding when the claimed and actual counts differ. If no
 * registry entry matched but the line contains a bindable-noun count
 * claim (a number or number-word immediately followed by "agents" or
 * "detectors"), emit a `warn` unbound-claim finding instead -- never a
 * fail, and never silently dropped. A canonical source whose directory
 * cannot be listed THROWS (never a guessed zero) -- the sweep is
 * incomplete, not clean.
 */
function run(context) {
  const findings = [];
  const canonicalCache = {};

  function getCanonicalCount(sourceId) {
    if (!(sourceId in canonicalCache)) {
      const fn = CANONICAL_SOURCES[sourceId];
      if (typeof fn !== 'function') {
        throw new Error(`count-claims: unknown canonical source '${sourceId}'`);
      }
      canonicalCache[sourceId] = fn(context);
    }
    return canonicalCache[sourceId];
  }

  for (const doc of context.mdFiles) {
    if (!isScopedDoc(doc.path)) continue;

    const lines = String(doc.text).split('\n');
    lines.forEach((lineText, idx) => {
      const lineNo = idx + 1;
      let matched = false;

      for (const entry of CLAIM_REGISTRY) {
        const m = entry.pattern.exec(lineText);
        if (m) {
          matched = true;
          const claimedRaw = m[1];
          const claimed = wordToNumber(claimedRaw);
          if (claimed === null) break; // not a well-formed number/word -- nothing to grade
          const actual = getCanonicalCount(entry.source);
          if (claimed !== actual) {
            findings.push({
              check: id,
              file: doc.path,
              line: lineNo,
              severity: 'fail',
              message: `count claim '${claimedRaw}' (${entry.name}) at ${doc.path}:${lineNo} claims ${claimed} but canonical source '${entry.source}' counts ${actual}`,
            });
          }
          break;
        }
      }

      if (matched) return;

      UNBOUND_CLAIM_RE.lastIndex = 0;
      let gm = UNBOUND_CLAIM_RE.exec(lineText);
      while (gm !== null) {
        const num = wordToNumber(gm[1]);
        if (num !== null) {
          findings.push({
            check: id,
            file: doc.path,
            line: lineNo,
            severity: 'warn',
            message: `unbound count claim '${gm[1]} ${gm[2]}' at ${doc.path}:${lineNo} does not match any known claim shape in CLAIM_REGISTRY`,
          });
        }
        gm = UNBOUND_CLAIM_RE.exec(lineText);
      }
    });
  }

  return findings;
}

module.exports = { id, run, CLAIM_REGISTRY, SCOPED_DOCS, CANONICAL_SOURCES, wordToNumber };
