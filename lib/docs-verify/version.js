'use strict';

/**
 * Check 5 -- self-referential version-string consistency (G-1570, GUARD-01).
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-02-PLAN.md Task 2. Read that
 * section before editing this file.
 *
 * SCOPE (21-RESEARCH.md Pitfall 4): only claims that are UNAMBIGUOUSLY
 * self-referential -- the package name immediately followed by `@version`
 * or by whitespace and `vversion`, or an `npx <pkg>@version` invocation.
 * A bare `vX.Y.Z` token anywhere else in prose is explicitly NOT a claim
 * about this package (this repo's own docs cite several third-party
 * tools' semver strings in narrative security prose) and must never be
 * compared. SELF_VERSION_PATTERNS below is a frozen array of pattern-
 * builder functions -- each wraps a STATIC regex-literal template with
 * exactly one substitution point (the package name, escaped, derived
 * ONLY from context.pkg.name -- never from markdown text).
 *
 * COMPARISON is exact string equality against context.pkg.version. A
 * caret, tilde, or any range operator is a mismatch: this check has no
 * semver-range semantics and must not acquire any, because the guarantee
 * being enforced is that a pinned install instruction a reader copies and
 * pastes names the version that actually shipped.
 *
 * HONEST SCOPE (21-02-PLAN.md "Honest scope" + 21-02-SUMMARY.md
 * Deviations): the plan's own research (21-RESEARCH.md:544) claimed no
 * tracked document states a self-referential llm-safe-haven version. That
 * claim is INCORRECT -- research/top100-mcp/DRAFT.md:179 pins
 * `npx llm-safe-haven@0.4.0` inside a fenced install-instruction code
 * block, stale against the current package.json (0.7.0). This check
 * deliberately does NOT exclude fenced code blocks: a fenced bash block
 * is the canonical real-world shape for a pinned install instruction (far
 * more common than an inline backtick), and excluding it would suppress
 * exactly the drift class this check exists to catch.
 */

const id = 'version';

// Each entry is `(escapedName) => RegExp`. The template string itself is
// a static literal; only the already-escaped package name is
// interpolated -- never doc-controlled text (ReDoS/injection defense).
// The captured group requires an optional leading `^`/`~` followed
// immediately by a DIGIT, which is what excludes a non-numeric
// placeholder like `llm-safe-haven@x.y.z` (CLAUDE.md's own literal
// recommendation text) from ever being extracted as a claim.
const SELF_VERSION_PATTERNS = Object.freeze([
  // `<pkg>@<version>` -- npm package-manager pin shape.
  (escapedName) => new RegExp(`\\b${escapedName}@([\\^~]?\\d[\\w.+-]*)`, 'g'),
  // `<pkg> v<version>` -- prose pin shape. The captured group excludes
  // the leading `v` so comparison is apples-to-apples against
  // context.pkg.version, which never carries a `v` prefix.
  (escapedName) => new RegExp(`\\b${escapedName}\\s+v([\\^~]?\\d[\\w.+-]*)`, 'g'),
  // `npx <pkg>@<version>` -- the canonical pinned-install-instruction
  // shape this check exists to guard (CLAUDE.md: "Recommend pinned
  // versions").
  (escapedName) => new RegExp(`\\bnpx\\s+${escapedName}@([\\^~]?\\d[\\w.+-]*)`, 'g'),
]);

function escapeRegExp(literal) {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Scans `text` line by line for SELF_VERSION_PATTERNS matches against
 * `packageName`. Returns `{ value, line }` records (one-based line
 * numbers). The `@`-form and the `npx`-form both match an
 * `npx <pkg>@<version>` occurrence at the same text position; matches
 * whose captured value starts at the same (line, offset) are deduplicated
 * to one claim rather than double-counted.
 */
function extractVersionClaims(text, packageName) {
  const escapedName = escapeRegExp(String(packageName));
  const claims = [];
  const seen = new Set();
  const lines = String(text).split('\n');
  lines.forEach((lineText, idx) => {
    const lineNo = idx + 1;
    for (const buildPattern of SELF_VERSION_PATTERNS) {
      const re = buildPattern(escapedName);
      let m = re.exec(lineText);
      while (m !== null) {
        const value = m[1];
        const valueStart = m.index + m[0].length - value.length;
        const dedupeKey = `${lineNo}:${valueStart}`;
        if (!seen.has(dedupeKey)) {
          seen.add(dedupeKey);
          claims.push({ value, line: lineNo });
        }
        m = re.exec(lineText);
      }
    }
  });
  return claims;
}

/**
 * Compares every self-referential version claim across context.mdFiles
 * against context.pkg.version by exact string equality. THROWS when the
 * canonical version cannot be read (context.pkg is null/undefined, or its
 * name/version fields are not strings) -- a version check that cannot
 * read the canonical value must never report clean.
 */
function run(context) {
  if (
    !context ||
    !context.pkg ||
    typeof context.pkg.name !== 'string' ||
    typeof context.pkg.version !== 'string'
  ) {
    throw new Error('version: context.pkg is missing a usable name/version -- the canonical version could not be read');
  }
  const { name, version: canonicalVersion } = context.pkg;

  const findings = [];
  for (const doc of context.mdFiles) {
    const claims = extractVersionClaims(doc.text, name);
    for (const claim of claims) {
      if (claim.value !== canonicalVersion) {
        findings.push({
          check: id,
          file: doc.path,
          line: claim.line,
          severity: 'fail',
          message: `self-referential version claim '${claim.value}' at ${doc.path}:${claim.line} does not match package.json version '${canonicalVersion}'`,
        });
      }
    }
  }
  return findings;
}

module.exports = { id, run, SELF_VERSION_PATTERNS, extractVersionClaims };
