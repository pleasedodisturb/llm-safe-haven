'use strict';

/**
 * Check 4 -- anchor resolution against target-document heading slugs
 * (G-1570, GUARD-01).
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-03-PLAN.md "Pinned link grammar
 * (Check 3 / Check 4)" and Task 3's <action>. Read those before editing
 * this file.
 *
 * Check 4 is the check that names DOC-03b: docs/credential-management.md
 * links to a supply-chain-defense.md fragment describing a Bitwarden CLI
 * case study, and the only Shai-Hulud heading in that file is the
 * "Sustained npm Supply Chain Campaign" one -- the linked text describes a
 * different heading entirely, so it fails under any reasonable slug
 * implementation, making it a slug-algorithm-independent smoke test.
 *
 * This module reuses extractLinks/isExternal/decodeTargetOrNull from
 * links.js and headingSlugs from helpers/slug.js -- it reimplements none
 * of them. It contains NO percent-decoding primitive of its own; every
 * decode goes through decodeTargetOrNull, so the two checks (links and
 * anchors) cannot disagree about what a decodable path/fragment is (a
 * negative source scan in tests/docs-verify/anchors.test.js enforces
 * this).
 */

const path = require('path');

const { extractLinks, isExternal, decodeTargetOrNull } = require('./links.js');
const { headingSlugs } = require('./helpers/slug.js');

const id = 'anchors';

/**
 * run(context) -- builds a map from every discovered markdown path to
 * that document's slug set (computed once), then walks every document's
 * links:
 *
 *   - an external target is skipped;
 *   - a link with no fragment is skipped;
 *   - an anchor-only target (target === '') resolves against the LINKING
 *     document itself;
 *   - a file-plus-fragment target resolves the file the same way Check 3
 *     does (decode the path portion, join against the linking document's
 *     directory, normalize). If the resolved path is not a key in the
 *     slug map -- the file does not exist, or was never discovered as
 *     markdown, or the path decode itself was malformed -- this produces
 *     NOTHING. That is Check 3's finding; duplicating it here would
 *     double-report one defect as two.
 *
 * When the target document IS present, the fragment is normalized in
 * this FIXED order: percent-decode through decodeTargetOrNull, then
 * NFC-normalize, then lowercase, then compare against the slug set.
 * Decoding must come first -- a percent-encoded multi-byte character
 * cannot be NFC-normalized while it is still three ASCII escape
 * sequences, so normalizing first would silently fail every non-ASCII
 * anchor a renderer wrote in encoded form.
 *
 * A null from decodeTargetOrNull (malformed fragment escape) is a
 * `severity: 'fail'` finding naming the malformed fragment, the linking
 * doc and line -- and the walk CONTINUES to the next link. It is a
 * finding, not an incompleteness: an unguarded decode would turn one
 * malformed anchor into an exit-2 sweep that reports nothing else.
 *
 * A slug-set miss is a `severity: 'fail'` finding naming the anchor, the
 * linking doc and line, and the target document.
 */
function run(context) {
  const slugMap = new Map();
  for (const doc of context.mdFiles) {
    slugMap.set(doc.path, new Set(headingSlugs(doc.text).map((h) => h.slug)));
  }

  const findings = [];

  for (const doc of context.mdFiles) {
    const docLinks = extractLinks(doc.text);
    for (const link of docLinks) {
      if (isExternal(link.target)) continue;
      if (link.anchor === null) continue; // no fragment -- not this check's concern

      let targetPath;
      if (link.target === '') {
        targetPath = doc.path; // anchor-only -- resolves against the linking document itself
      } else {
        const decodedFilePath = decodeTargetOrNull(link.target);
        if (decodedFilePath === null) continue; // a malformed target PATH is Check 3's finding, not this one's
        const docDir = path.posix.dirname(doc.path);
        targetPath = path.posix.normalize(docDir === '.' ? decodedFilePath : path.posix.join(docDir, decodedFilePath));
      }

      const slugSet = slugMap.get(targetPath);
      if (!slugSet) continue; // missing/undiscovered target file -- Check 3's finding, never double-reported here

      const decodedAnchor = decodeTargetOrNull(link.anchor);
      if (decodedAnchor === null) {
        findings.push({
          check: id,
          file: doc.path,
          line: link.line,
          severity: 'fail',
          message: `malformed percent-encoding in anchor fragment '#${link.anchor}' at ${doc.path}:${link.line}`,
        });
        continue;
      }

      const normalizedAnchor = decodedAnchor.normalize('NFC').toLowerCase();
      if (!slugSet.has(normalizedAnchor)) {
        findings.push({
          check: id,
          file: doc.path,
          line: link.line,
          severity: 'fail',
          message: `anchor '#${link.anchor}' at ${doc.path}:${link.line} does not match any heading in ${targetPath}`,
        });
      }
    }
  }

  return findings;
}

module.exports = { id, run };
