'use strict';

// Runtime fragment assembly for bash-firewall attack-class test inputs.
//
// Why fragments: (1) repo docs and test sources never carry a complete
// destructive or exfiltration command as one literal, and (2) the operator's
// own installed bash-firewall scans shell commands, so a literal payload in a
// command line would be blocked. Every attack input is built here at runtime
// from pieces. Assertion messages print the row LABEL (cls/form) only — never
// the built string — so RED output pasted into commit messages carries labels,
// not payloads.
//
// Lives under tests/helpers/ (outside the `tests/*.test.js` glob).

const j = (...parts) => parts.join('');

// --- program / file-name fragments -------------------------------------------
const RM = j('r', 'm');
const CURL = j('cu', 'rl');
const WGET = j('wg', 'et');
const DOTENV = j('.', 'e', 'nv');
const SECURITY = j('secu', 'rity');
const KC_FIND_GENERIC = j('find-', 'generic-', 'password');
const KC_FIND_INTERNET = j('find-', 'internet-', 'password');
const KC_DUMP = j('dump-', 'keychain');
const BASE64 = j('base', '64');
const DECODE_FLAG = j('-', 'd');
const SH = j('s', 'h');
const BASH = j('ba', 'sh');
const ZSH = j('z', 'sh');
const DASH = j('da', 'sh');
const KSH = j('k', 'sh');
const EVAL = j('ev', 'al');
const RF = j('-', 'r', 'f');
const R_ONLY = j('-', 'r');
const EXAMPLE_URL = j('https', '://', 'example.com');

// --- builders ------------------------------------------------------------------
/** ROOTDEL: recursive+force delete of the filesystem root (legacy-blocked control). */
const ROOTDEL = () => [RM, RF, '/'].join(' ');
/** DEL(t): recursive+force delete of target word t (t is inserted verbatim). */
const DEL = (t) => [RM, RF, t].join(' ');
/** DELR(t): recursive-only delete (no force flag). */
const DELR = (t) => [RM, R_ONLY, t].join(' ');
/** UP(p): curl upload of local file p. form 'd' => -d @p, form 'F' => -F f=@p. */
const UP = (p, form = 'd') => (form === 'F'
  ? [CURL, '-F', j('f=@', p), EXAMPLE_URL].join(' ')
  : [CURL, '-d', j('@', p), EXAMPLE_URL].join(' '));
/** DEC: base64 with a decode flag. */
const DEC = () => [BASE64, DECODE_FLAG].join(' ');
/** FETCH: a fetch of a remote script to stdout. */
const FETCH = () => [CURL, '-fsSL', j(EXAMPLE_URL, '/i.', 'sh')].join(' ');

// --- case rows -------------------------------------------------------------------
/**
 * @param {string} cls   class name (e.g. 'shell-c-wrapper')
 * @param {string} form  row form label
 * @param {() => string} build  builds the command at runtime
 * @param {'block'|'allow'} expect
 */
function row(cls, form, build, expect) {
  if (expect !== 'block' && expect !== 'allow') throw new Error(`bad expect for ${cls}/${form}`);
  if (typeof build !== 'function') throw new Error(`build must be a function for ${cls}/${form}`);
  return { cls, form, build, expect };
}
const block = (cls, form, build) => row(cls, form, build, 'block');
const allow = (cls, form, build) => row(cls, form, build, 'allow');

function label(r) {
  return `${r.cls}/${r.form}`;
}

/** Group rows by class; returns Map<cls, rows[]>. */
function groupByClass(rows) {
  const m = new Map();
  for (const r of rows) {
    if (!m.has(r.cls)) m.set(r.cls, []);
    m.get(r.cls).push(r);
  }
  return m;
}

module.exports = {
  j,
  RM, CURL, WGET, DOTENV, SECURITY, KC_FIND_GENERIC, KC_FIND_INTERNET, KC_DUMP,
  BASE64, DECODE_FLAG, SH, BASH, ZSH, DASH, KSH, EVAL, RF, R_ONLY, EXAMPLE_URL,
  ROOTDEL, DEL, DELR, UP, DEC, FETCH,
  row, block, allow, label, groupByClass,
};
