'use strict';

/**
 * Terminal sanitization for docs:verify (G-1570, Codex review F1, PR #105).
 *
 * `sanitizeForTerminal(s)` strips every C0 control byte (0x00-0x1f,
 * including ESC/CSI-introducer 0x1b and CR 0x0d), DEL (0x7f), the C1
 * control range (0x80-0x9f, where OSC/CSI/DCS also live in their 8-bit
 * form), and Unicode format/bidi controls (`\p{Cf}`: zero-widths,
 * bidi embeddings/overrides/isolates, BOM, ...) before a string reaches
 * stdout, replacing each stripped byte with U+FFFD so the reader SEES
 * that something was removed rather than it silently vanishing.
 *
 * Mirrors lib/scorecard.js's `sanitizeForTerminal` (CR-01) byte-for-byte
 * in behaviour, but is implemented locally rather than required from
 * that module: lib/scorecard.js's top level reads `process.stdout.isTTY`
 * at require() time to decide whether to emit ANSI color codes -- a
 * load-time environment read this always-plain-text subsystem has no
 * reason to inherit, and lib/docs-verify/ stays self-contained per its
 * own "shared helpers live under lib/docs-verify/helpers/" convention
 * (see lib/docs-verify/index.js's header comment).
 *
 * THREAT (finding F1): every field formatReport() interpolates into a
 * report line -- f.severity, f.check, f.file, f.message, inc.check,
 * inc.reason -- is ultimately derived from on-disk filenames or
 * doc-authored text, both attacker-controlled by this project's threat
 * model. A filename or link target carrying `\x1b[2K\r` (CSI erase-line
 * + carriage return) followed by a fabricated report line can visually
 * overwrite a genuine finding on a real terminal; an OSC 8 hyperlink
 * escape can render an invisible clickable link. This is the exact
 * defect class already fixed in lib/scorecard.js and scripts/scan-*.sh.
 */
function sanitizeForTerminal(s) {
  return String(s == null ? '' : s).replace(/[\x00-\x1f\x7f-\x9f]|\p{Cf}/gu, '�');
}

module.exports = { sanitizeForTerminal };
