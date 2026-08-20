'use strict';

/**
 * Check 1 -- identifier existence, scoped by file role (G-1570, GUARD-01).
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-02-PLAN.md Task 1. Read that
 * section before editing this file.
 *
 * SCOPING (21-RESEARCH.md Pitfall 1): applied ONLY to docs whose stated
 * purpose is describing this tool's own API/config/hook surface --
 * SCOPED_DOCS below. A naive backtick-and-shape scan across every tracked
 * doc produces a false-positive flood of legitimate third-party
 * environment-variable names (ANTHROPIC_API_KEY, DATABASE_URL, ...) that
 * are not claims about this repo's own source at all. Scoping is a frozen
 * file-role list, deliberately never a hand-maintained token blocklist --
 * this project already paid five iterations for that anti-pattern on the
 * POSIX-class validator (feedback_validators_as_grammars).
 *
 * "EXISTS" MEANS RAW SOURCE-TEXT PRESENCE (21-RESEARCH.md Pitfall 2),
 * never require()-and-inspect-exports. REQUIRED_SECTIONS in
 * lib/traverse/wave-spec.js is a real declared const, deliberately not
 * exported -- an export-inspecting implementation would incorrectly flag
 * docs/wave-spec.md's claim about it as broken.
 *
 * CLAIM GRAMMAR: a single-backtick span whose entire content is either an
 * UPPER_SNAKE_CASE token of at least 3 characters, or an identifier
 * (starting with a letter or underscore -- never a bare `$`, which would
 * false-positive on bash's `$(cmd)` command-substitution syntax
 * highlighted inside backticks, e.g. docs/hardening/github-copilot.md)
 * immediately followed by a parenthesised argument list of ANY shape,
 * including empty. The argument text is discarded and never matched
 * against source. Deliberately OUT of grammar, so no corrupt claim is
 * ever produced: a nested parenthesis in the argument list (`f(g(x))`), a
 * call spanning a line break (spans are matched per-line only), and a
 * bare parenthesis with no leading identifier (`(argv)`).
 *
 * All regexes below are static hand-authored literals over doc- or
 * module-controlled text -- the ONE dynamically composed pattern
 * (identifierExistsInSource's whole-word matcher) escapes every regex
 * metacharacter in the scraped identifier before composition (ReDoS /
 * injection defense, matching the credential-passthrough.js convention).
 */

const id = 'identifiers';

// Frozen file-role allowlist, never a token blocklist. A trailing slash
// means "this directory and everything under it"; anything else is an
// exact repo-relative path match.
const SCOPED_DOCS = Object.freeze(['docs/hardening/', 'hooks/README.md', 'docs/mcp-security.md', 'docs/wave-spec.md']);

function isScopedDoc(relPath) {
  return SCOPED_DOCS.some((entry) => (entry.endsWith('/') ? relPath.startsWith(entry) : relPath === entry));
}

// Entire backtick content must be uppercase letters/digits/underscores,
// starting with a letter, at least 3 characters total.
const UPPER_SNAKE_RE = /^[A-Z][A-Z0-9_]{2,}$/;

// Entire backtick content must be `<identifier>(<args>)` with no nested
// parenthesis and no backtick inside the argument list. <args> may be
// empty. The identifier may not start with `$` (see module comment).
const FUNCTION_CALL_RE = /^([A-Za-z_][A-Za-z0-9_$]*)\(([^()`]*)\)$/;

/**
 * Scans `text` line by line (a claim never spans a line break -- the
 * closing backtick must be on the same line as the opening one) for
 * single-backtick spans matching CLAIM GRAMMAR above. Returns
 * `{ identifier, line }` records, one-based line numbers, in the order
 * encountered.
 */
function extractClaims(text) {
  const claims = [];
  const lines = String(text).split('\n');
  lines.forEach((lineText, idx) => {
    const lineNo = idx + 1;
    const spanRe = /`([^`]+)`/g;
    let m = spanRe.exec(lineText);
    while (m !== null) {
      const content = m[1];
      if (UPPER_SNAKE_RE.test(content)) {
        claims.push({ identifier: content, line: lineNo });
      } else {
        const callMatch = content.match(FUNCTION_CALL_RE);
        if (callMatch) {
          claims.push({ identifier: callMatch[1], line: lineNo });
        }
      }
      m = spanRe.exec(lineText);
    }
  });
  return claims;
}

function escapeRegExp(literal) {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Whole-word raw-source-text occurrence test. Every regex metacharacter
 * in `identifier` is escaped before the pattern is built, so a hostile or
 * merely unusual scraped identifier can never corrupt the generated
 * pattern or throw.
 */
function identifierExistsInSource(identifier, sources) {
  const pattern = new RegExp(`\\b${escapeRegExp(String(identifier))}\\b`);
  return (Array.isArray(sources) ? sources : []).some((contents) => pattern.test(contents));
}

/**
 * Compares every backticked identifier/function-call claim in the
 * SCOPED_DOCS subset of context.mdFiles against the raw source text of
 * every hooks/**\/*.js and lib/**\/*.js file. THROWS (never returns a
 * silent "clean") on a listFiles/readText error, so a broken sweep is
 * never mistaken for a clean one.
 */
function run(context) {
  const hooksListing = context.listFiles('hooks', { ext: '.js', recursive: true });
  if (hooksListing.error) {
    throw new Error(`identifiers: could not list hooks: ${hooksListing.error}`);
  }
  const libListing = context.listFiles('lib', { ext: '.js', recursive: true });
  if (libListing.error) {
    throw new Error(`identifiers: could not list lib: ${libListing.error}`);
  }

  const sources = [];
  for (const file of [...hooksListing.files, ...libListing.files]) {
    const result = context.readText(file);
    if (result.error) {
      throw new Error(`identifiers: could not read ${file}: ${result.error}`);
    }
    sources.push(result.text);
  }

  const findings = [];
  for (const doc of context.mdFiles) {
    if (!isScopedDoc(doc.path)) continue;
    const claims = extractClaims(doc.text);
    for (const claim of claims) {
      if (!identifierExistsInSource(claim.identifier, sources)) {
        findings.push({
          check: id,
          file: doc.path,
          line: claim.line,
          severity: 'fail',
          message: `identifier '${claim.identifier}' claimed at ${doc.path}:${claim.line} does not appear in hooks/**/*.js or lib/**/*.js (searched ${hooksListing.files.length + libListing.files.length} files under hooks/ and lib/)`,
        });
      }
    }
  }
  return findings;
}

module.exports = { id, run, SCOPED_DOCS, extractClaims, identifierExistsInSource };
