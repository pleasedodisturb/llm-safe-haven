'use strict';

/**
 * Check 3 -- relative link resolution, bounded to the repository root
 * (G-1570, GUARD-01).
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-03-PLAN.md "Pinned link grammar
 * (Check 3 / Check 4)". Read that section before editing this file.
 *
 * GRADED shapes: `[t](target)`, `[t](target#fragment)`,
 * `[t](target "title")`, `[t](<target with space>)`, `<scheme:...>` and
 * `<./relative.md>` autolinks, and `![alt](image.png)` (an image is a
 * link for existence purposes -- the leading `!` does not exempt it).
 *
 * OUT OF SCOPE, each producing ZERO claims (never a corrupt one):
 * reference-style `[t][ref]` + `[ref]: target` definitions, a
 * nested-parenthesis target `[t](a(b).md)`, and any link inside a fenced
 * code block (a documented example is not a live link).
 *
 * The containment boundary is `resolveInRoot` from ./helpers/context.js
 * -- a parent-directory-hop target that escapes the root is reported as
 * out-of-tree and is NEVER opened (T-21-03-01). A percent-decode failure
 * (`decodeTargetOrNull` returning null) is likewise a finding with no
 * filesystem access. `isExternal` short-circuits before any filesystem or
 * network path -- external targets are skipped entirely, never fetched
 * (T-21-03-02); this module makes no network call of any kind.
 *
 * `decodeTargetOrNull` is shared with Check 4 (anchors.js) so the two
 * checks cannot disagree about what a decodable path/fragment is.
 */

const fs = require('fs');
const path = require('path');

const { resolveInRoot } = require('./helpers/context.js');

const id = 'links';

// A URI-scheme prefix (RFC 3986: a letter, then letters/digits/+/-/., then
// a colon) or a protocol-relative `//` prefix. Covers http:, https:,
// mailto:, ftp:, etc. A bare relative path such as `d.md` has no colon at
// all and never matches.
const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

function isExternal(target) {
  const t = String(target);
  if (t.startsWith('//')) return true;
  return SCHEME_RE.test(t);
}

/**
 * decodeTargetOrNull(raw) -- wraps decodeURIComponent in a try/catch and
 * returns null on a URIError (a stray `%` not followed by two hex
 * digits). This is the malformed-escape guard, shared with Check 4
 * (anchors.js) via this module's export -- one shared decoder is why the
 * two checks cannot disagree about what a decodable fragment is.
 */
function decodeTargetOrNull(raw) {
  try {
    return decodeURIComponent(raw);
  } catch (err) {
    if (err instanceof URIError) return null;
    throw err;
  }
}

/**
 * Splits a raw target on the first `#` into { target, anchor }. `anchor`
 * is `null` when no fragment is present. Splitting happens on the RAW
 * (not yet decoded) target, before any filesystem work, per the plan's
 * "Split target and fragment before any filesystem work" instruction.
 */
function splitTargetFragment(raw) {
  const hashIdx = raw.indexOf('#');
  if (hashIdx === -1) return { target: raw, anchor: null };
  return { target: raw.slice(0, hashIdx), anchor: raw.slice(hashIdx + 1) };
}

// A fence-open or fence-close line: up to 3 leading spaces, then a run of
// 3+ backticks or 3+ tildes. Mirrors the fence tracker in
// helpers/slug.js -- duplicated locally rather than shared, since links.js
// has no dependency on slug.js (only anchors.js, built in Task 3, depends
// on both).
const FENCE_RE = /^ {0,3}(`{3,}|~{3,})/;

// One graded shape per alternative, tried in order at each scan position:
//   1. `(!?)\[[^\]]*\]\(([^()]*)\)` -- an inline or image link. The paren
//      content excludes '(' and ')' entirely, which is exactly what makes
//      a nested-parenthesis target `[t](a(b).md)` fail to match this
//      alternative at all (zero claims, never a truncated one) rather
//      than requiring a separate exclusion rule.
//   2. `<([^<>\s]+)>` -- an autolink. Only reached when alternative 1 does
//      not match at this position, so a `<target with space>` INSIDE a
//      link's parens is always consumed by alternative 1 first and is
//      never double-counted as a bare autolink.
const LINK_LINE_RE = /(!?)\[[^\]]*\]\(([^()]*)\)|<([^<>\s]+)>/g;

// The paren-content inner shapes: angle-bracket-delimited (title optional
// after it) or plain-whitespace-terminated (title optional after it). A
// target followed by whitespace ends the target -- this is what strips a
// trailing ` "title"` from the plain form.
const INNER_ANGLE_RE = /^<([^<>]*)>(?:\s+"[^"]*")?$/;
const INNER_PLAIN_RE = /^(\S+)(?:\s+"[^"]*")?$/;

// A dot-relative path prefix ("./" or "../"), the second graded bare-
// autolink shape alongside a URI scheme. Guards the bare `<...>`
// alternative of LINK_LINE_RE against prose placeholder tokens.
const AUTOLINK_RELATIVE_PREFIX_RE = /^\.{1,2}\//;

// An inline single-backtick code span. Masked (replaced with same-length
// spaces) before link matching on a non-fenced line -- a link-syntax
// example shown as inline code (e.g. "`- **[Name](path)** - description`",
// prose describing HOW to write a bullet-list link) is a documented
// example, not a live link, extending the SAME rationale already applied
// to fenced code blocks (verified against the real corpus: without this,
// a markdown-syntax tutorial describing link/anchor syntax inside inline
// code produces a spurious "broken link" finding on its own example).
const INLINE_CODE_RE = /`[^`]*`/g;

function maskInlineCode(lineText) {
  return lineText.replace(INLINE_CODE_RE, (m) => ' '.repeat(m.length));
}

/**
 * extractLinks(text) -- a line-oriented, fence-aware scan implementing
 * exactly the grammar pinned above. Returns `[{ target, anchor, line }]`
 * (one-based line numbers). A line inside a fenced code block never
 * contributes a link -- a documented example link is not a live link.
 */
function extractLinks(text) {
  const lines = String(text).split('\n');
  const found = [];

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
      return;
    }

    if (fenceMatch) {
      inFence = true;
      fenceChar = fenceMatch[1][0];
      fenceLen = fenceMatch[1].length;
      return;
    }

    const maskedLine = maskInlineCode(lineText);
    LINK_LINE_RE.lastIndex = 0;
    let m = LINK_LINE_RE.exec(maskedLine);
    while (m !== null) {
      if (m[2] !== undefined) {
        const inner = m[2].trim();
        const angleMatch = inner.match(INNER_ANGLE_RE);
        const plainMatch = angleMatch ? null : inner.match(INNER_PLAIN_RE);
        const rawTarget = angleMatch ? angleMatch[1] : plainMatch ? plainMatch[1] : null;
        if (rawTarget !== null) {
          const { target, anchor } = splitTargetFragment(rawTarget);
          found.push({ target, anchor, line: lineNo });
        }
      } else if (m[3] !== undefined) {
        const raw = m[3];
        // Only the two autolink shapes the pinned grammar grades: a
        // URI-scheme target (classified external downstream) or a
        // dot-relative path (`./x` or `../x`). A bare word like `<cwd>`,
        // `<pkg>`, or `<darwin|linux|win32|android>` is prose placeholder
        // syntax, not an autolink -- verified against the real corpus,
        // where treating every `<...>` span as an autolink produced
        // dozens of false "broken link" findings on placeholder tokens.
        if (isExternal(raw) || AUTOLINK_RELATIVE_PREFIX_RE.test(raw)) {
          const { target, anchor } = splitTargetFragment(raw);
          found.push({ target, anchor, line: lineNo });
        }
      }
      m = LINK_LINE_RE.exec(maskedLine);
    }
  });

  return found;
}

/**
 * statPath(absPath) -- the check's filesystem-existence probe, referenced
 * indirectly via `linksModule.statPath` inside run() (not a captured
 * local closure) so a test can monkey-patch `require(...).statPath` for
 * the duration of one case to record every path the check asks about --
 * this is how the out-of-tree "never opened" guarantee is proven rather
 * than merely asserted from the finding text alone.
 */
function statPath(absPath) {
  try {
    const st = fs.statSync(absPath);
    return { exists: true, isDirectory: st.isDirectory() };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { exists: false, isDirectory: false };
    throw err;
  }
}

/**
 * run(context) -- walks every entry in context.mdFiles, extracts links,
 * skips external and anchor-only targets, decodes the path portion
 * through decodeTargetOrNull, resolves it relative to the linking
 * document's directory, and passes the result through resolveInRoot.
 *
 *   - A null from decodeTargetOrNull is a `severity: 'fail'` finding
 *     naming the malformed target, and NO filesystem access -- a
 *     malformed escape is a defect in the document, not an incompleteness
 *     of the sweep.
 *   - An out-of-tree result is a finding with an explicit out-of-tree
 *     reason and NO filesystem access.
 *   - An in-tree result is checked with statPath: a missing target is a
 *     finding; an existing DIRECTORY target produces NOTHING (GitHub
 *     renders a relative directory link as a tree view, and as that
 *     directory's README when one exists -- it is a working link, not a
 *     finding); an existing file target produces nothing either. Do not
 *     "fix" the directory rule back to a finding -- Agreed Concern 5 /
 *     Amendment 5(a) in 21-REVIEWS.md is why it is this way.
 */
function run(context) {
  const findings = [];

  for (const doc of context.mdFiles) {
    const docLinks = extractLinks(doc.text);
    for (const link of docLinks) {
      if (link.target === '') continue; // anchor-only target -- Check 4's concern, not this one
      if (isExternal(link.target)) continue; // never fetched, never resolved

      const decoded = linksModule.decodeTargetOrNull(link.target);
      if (decoded === null) {
        findings.push({
          check: id,
          file: doc.path,
          line: link.line,
          severity: 'fail',
          message: `malformed percent-encoding in link target '${link.target}' at ${doc.path}:${link.line}`,
        });
        continue;
      }

      const docDir = path.posix.dirname(doc.path);
      const relFromRoot = docDir === '.' ? decoded : path.posix.join(docDir, decoded);
      const resolved = resolveInRoot(context.root, relFromRoot);
      if (!resolved.ok) {
        findings.push({
          check: id,
          file: doc.path,
          line: link.line,
          severity: 'fail',
          message: `link target '${link.target}' at ${doc.path}:${link.line} resolves out-of-tree (${resolved.reason})`,
        });
        continue; // NO filesystem access on an out-of-tree target
      }

      const stat = linksModule.statPath(resolved.abs);
      if (!stat.exists) {
        findings.push({
          check: id,
          file: doc.path,
          line: link.line,
          severity: 'fail',
          message: `link target '${link.target}' at ${doc.path}:${link.line} does not exist (resolved to ${relFromRoot})`,
        });
      }
      // An existing file OR an existing directory produces no finding.
    }
  }

  return findings;
}

const linksModule = { id, run, extractLinks, isExternal, decodeTargetOrNull, statPath };

module.exports = linksModule;
