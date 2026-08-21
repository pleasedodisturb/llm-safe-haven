'use strict';

/**
 * GitHub-slug helper for docs:verify (G-1570) -- Check 4's dependency.
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-03-PLAN.md Task 1. Read that
 * section before editing this file.
 *
 * GitHub has never published an official anchor-slug specification; every
 * implementation is reverse-engineered. This module pins two behaviors
 * against `github-slugger`'s own source (checked during cross-AI review,
 * 21-REVIEWS.md): repeated hyphens are NOT collapsed, and leading/
 * trailing hyphens are NOT trimmed. A cross-AI reviewer claimed GitHub
 * trims leading/trailing hyphens; that claim was checked against
 * github-slugger's source and REFUTED -- it does `replace(regex, '')`
 * then `replace(/ /g, '-')` with no trim step. Do NOT "fix" this by
 * adding a collapse or trim step; both are pinned by named cases in
 * tests/docs-verify/slug.test.js so a future change fails loudly.
 *
 * Lives under helpers/ (never the top level of lib/docs-verify/) so
 * loadChecks() never mistakes this for a check module -- it has no `id`
 * or `run` export.
 */

// Every character that is NOT a Unicode letter, a Unicode digit, a literal
// space, a hyphen, or an underscore. Unicode-aware via \p{L}/\p{N} so a
// non-ASCII heading (e.g. "Café Notes") survives slugging instead of being
// stripped to nothing.
const DISALLOWED_CHAR_RE = /[^\p{L}\p{N}_ -]/gu;

// A leading run of 1-6 ATX hash marks followed by whitespace, at the very
// start of the string -- stripped before slugging so a raw "## Heading"
// and its already-stripped "Heading" text produce the same slug.
const LEADING_HASH_RE = /^#{1,6}\s+/;

/**
 * slugify(headingText) -- one heading text -> one slug, no dedupe. Applies,
 * in this FIXED order (order matters -- see the plan's Task 1 <action>):
 *
 *   1. NFC-normalize (a decomposed and a precomposed spelling of the same
 *      heading must produce the same slug).
 *   2. Strip a leading run of hash marks and the whitespace after it.
 *   3. Trim surrounding whitespace.
 *   4. Lowercase (locale-independent -- String#toLowerCase, never
 *      toLocaleLowerCase, whose result is ICU-build-dependent).
 *   5. Remove every character that is not a letter, digit, space, hyphen
 *      or underscore. Backticks and parens fall out here too, with no
 *      special case needed: inline code inside a heading (e.g.
 *      "The `computeExit()` contract") contributes its bare identifier
 *      text because the backticks and parens are simply punctuation like
 *      any other and are stripped by this same step.
 *   6. Replace each remaining space with a single hyphen. Runs of hyphens
 *      produced this way are NOT collapsed, and a leading/trailing hyphen
 *      produced this way is NOT trimmed -- both pinned, see module header.
 */
function slugify(headingText) {
  let text = String(headingText).normalize('NFC');
  text = text.replace(LEADING_HASH_RE, '');
  text = text.trim();
  text = text.toLowerCase();
  text = text.replace(DISALLOWED_CHAR_RE, '');
  text = text.replace(/ /g, '-');
  return text;
}

// A fence-open or fence-close line: up to 3 leading spaces, then a run of
// 3+ backticks or 3+ tildes. The captured run is compared on close (same
// character, length >= opening length, and the rest of the line is only
// whitespace) so an info string after an opening fence (```bash) does not
// stop fence tracking, matching CommonMark's fenced-code-block rule.
const FENCE_RE = /^ {0,3}(`{3,}|~{3,})/;

// An ATX heading only: up to 3 leading spaces, then 1-6 hash marks,
// followed by whitespace and the heading text (or end of line for a bare
// "#"). Setext headings (a text line underlined with = or -) are
// deliberately NOT matched by this regex -- see the module header and the
// named "Setext headings are out of grammar" test case.
const ATX_HEADING_RE = /^ {0,3}(#{1,6})(?:\s+(.*))?$/;

/**
 * headingSlugs(markdownText) -- scans line by line, tracks fenced-code-
 * block state (both backtick and tilde fences, including a trailing info
 * string on the opener) so a hash line inside a fence is never counted as
 * a heading, slugs every real ATX heading with slugify(), and assigns
 * duplicate suffixes in document order: the first occurrence of a slug
 * keeps it bare, the second gains "-1", the third "-2", and so on.
 *
 * Returns an ordered array of { slug, line, text } records (one-based
 * line numbers).
 */
function headingSlugs(markdownText) {
  const lines = String(markdownText).split('\n');
  const records = [];
  const seenCounts = new Map();

  let inFence = false;
  let fenceChar = null;
  let fenceLen = 0;

  lines.forEach((lineText, idx) => {
    const lineNo = idx + 1;
    const fenceMatch = lineText.match(FENCE_RE);

    if (inFence) {
      const closesFence =
        fenceMatch &&
        fenceMatch[1][0] === fenceChar &&
        fenceMatch[1].length >= fenceLen &&
        lineText.trim() === fenceMatch[1];
      if (closesFence) {
        inFence = false;
        fenceChar = null;
        fenceLen = 0;
      }
      return; // a line inside a fence is never a heading, opener/closer included
    }

    if (fenceMatch) {
      inFence = true;
      fenceChar = fenceMatch[1][0];
      fenceLen = fenceMatch[1].length;
      return;
    }

    const headingMatch = lineText.match(ATX_HEADING_RE);
    if (!headingMatch) return;

    const rawText = (headingMatch[2] || '').trim();
    const slugBase = slugify(rawText);
    const count = seenCounts.get(slugBase) || 0;
    const slug = count > 0 ? `${slugBase}-${count}` : slugBase;
    seenCounts.set(slugBase, count + 1);

    records.push({ slug, line: lineNo, text: rawText });
  });

  return records;
}

module.exports = { slugify, headingSlugs };
