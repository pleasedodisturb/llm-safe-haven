'use strict';

/**
 * Wave-spec loader + validator (G-1482, TRAV-02, D-03/D-05).
 *
 * This is the fail-closed gate for D-05: `loadWaveSpec` / `validateWaveSpec`
 * NEVER throw and NEVER return a partially valid spec. A caller that
 * receives `{ valid: false }` MUST exit 2 (incomplete), never continue with
 * a fallback/default IOC set — a scanner running against a half-loaded
 * spec reports clean while blind, which is the one unacceptable outcome
 * this module exists to prevent (see lib/mcp/base.js EXIT.INCOMPLETE for
 * the same fail-closed exit-code convention already established in this
 * codebase).
 *
 * Modeled on the codebase's existing hand-rolled, dependency-free,
 * fail-closed shape-validator idiom (checkUnsupportedShape in
 * lib/mcp/restricted-yaml.js and lib/mcp/parsers/codex-cli.js) rather than
 * a JSON Schema library — zero runtime dependencies (CLAUDE.md).
 *
 * Check order in validateWaveSpec (deliberate, do not reorder):
 *   1. spec is a non-null, non-array object
 *   2. specVersion is a known, supported number
 *   3. every required section is present with the right JS type
 *   4. every bounds.* value is a positive safe integer
 *   5. string hygiene — no spec string (value OR key) may contain a
 *      newline, carriage return, or NUL byte, because spec scalars are
 *      later written into results-dir list files and interpolated into
 *      bash arrays; injecting one of these bytes there is a cross-
 *      boundary injection primitive (T-17-10)
 *   6. no `__proto__` / `constructor` / `prototype` key anywhere in the
 *      parsed object (mirrors the Phase 12 prototype-pollution defence in
 *      lib/mcp/restricted-yaml.js's pollutionKeyPattern)
 */

const fs = require('fs');

const SUPPORTED_SPEC_VERSIONS = Object.freeze([1]);

// The full set of top-level sections a valid wave spec must carry. Mirrors
// the field list authored into manifests/waves/chaindrop-aug2026.json.
const REQUIRED_SECTIONS = Object.freeze([
  'fileMarkers',
  'knownBadHashes',
  'poisonedVersions',
  'compromisedFamily',
  'markerStrings',
  'installMarker',
  'persistence',
  'lockfiles',
  'staticPaths',
  'classes',
  'bounds',
]);

const POLLUTED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;
const HYGIENE_RE = /[\n\r\0]/;

// A POSIX bracket-class TOKEN -- `[:space:]`, `[:alpha:]`, ... -- matched
// wherever it appears, not only at the start of a bracket expression.
//
// This deliberately keys on the token itself rather than on the opening
// `[[:` sequence. An earlier form, `/\[\[:/`, matched only the leading case
// and was bypassed by the two shapes an operator is most likely to write:
//
//     [^[:space:]]      negated  -- NOT caught by /\[\[:/
//     [a-z[:digit:]]    mixed    -- NOT caught by /\[\[:/
//
// Both compile in JS as literal character classes and never do what the
// author meant, which is the exact silently-non-firing detector this ban
// exists to prevent. Measured: `/[^[:space:]]/.test('s')` is `false`, so a
// pattern meaning "not whitespace" fails to match a non-whitespace
// character. Found by adversarial code review of PR #96 (2026-08-12) after
// both plan review and a hand check of the leading form had passed it.
//
// THIRD iteration. Each previous form was bypassable, and the bypasses were
// found one layer at a time — record them so the next reader does not
// re-narrow it:
//
//   /\[\[:/          leading only. Missed `[^[:space:]]` and `[a-z[:digit:]]`.
//   /\[:[a-z]+:\]/   token, lowercase only. Missed `[[:SPACE:]]`,
//                    `[[:Alpha:]]`, `[[: space :]]`, and both of POSIX's
//                    OTHER bracket constructs below.
//
// POSIX defines three bracket constructs, not one, and JavaScript
// mis-compiles all three into literal character classes:
//
//   [:class:]     character class      [[:space:]]
//   [.symbol.]    collating symbol     [[.hyphen.]]
//   [=char=]      equivalence class    [[=a=]]
//
// So this matches the CONSTRUCT shape — an opening `[` followed by one of
// `: . =`, arbitrary inner text, then the SAME delimiter and a closing `]`
// (backreference `\1`). Case and internal spacing are irrelevant because the
// class name is never inspected.
//
// The backreference is what keeps it precise. Detecting only the opening
// `\[[:.=]` would false-positive on `[.]`, `[=]` and `[:]`, which are
// ordinary JS character classes matching a literal dot, equals or colon.
// Measured against a legit-pattern corpus, this form has ZERO false
// positives — including on `[.]`, `[\[:]`, `[.,;:]`, `[a.b]` and
// `\[\[:not-a-class` — and flags none of the four shipped JS-regex fields.
//
// A ban that starts rejecting valid detectors would be its own outage, which
// is why paired control 4 in the test file pins the legitimate look-alikes.
//
// Deliberately the SAME expression as the test-side drift guard in
// tests/traverse/wave-spec.test.js, so the validator and the test cannot
// disagree about what counts as a POSIX construct (G-1552).
const POSIX_CLASS_RE = /\[([:.=])[^\]]*\1\]/;

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringArrayReason(value, name) {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    return `section "${name}" must be an array of strings`;
  }
  return null;
}

/**
 * Every dotted-path field the engine feeds straight into JS `new RegExp()`
 * (lib/traverse/engine.js's `generateContentFindings`). A field missing or
 * empty here must FAIL validation rather than silently reach
 * `new RegExp(undefined)` (which is `/(?:)/` and matches every string) or
 * `new RegExp('')` (same effect) -- either would make the corresponding
 * detector pass over every file without ever reporting a miss (G-1482
 * merge-blocking fix, 2026-08-10: this is the exact defect class the
 * `jsCommandPattern`/`jsFailPattern` fields exist to close -- a POSIX ERE
 * string like `[[:space:]]` handed to `new RegExp()` does not throw, it
 * silently compiles to a literal-character-class match that never fires,
 * which is why "non-empty, RegExp-constructible" alone is necessary but not
 * sufficient). Since G-1552 the POSIX-bracket-class ban is ENFORCED in
 * regexFieldReason() itself — see its comment — and no longer only in the
 * test suite, which could not see an operator-supplied `--spec` /
 * `LSH_WAVE_SPEC` file. The drift guard in tests/traverse/wave-spec.test.js
 * is retained as the guard for the SHIPPED manifest specifically.
 *
 * D-06: this array is the ban's entire scope. The sibling POSIX-ERE fields
 * (installMarker.pattern, persistence.claudeSettings.commandPattern,
 * persistence.vscodeTasks.failPattern) are deliberately absent because they
 * are not fed to `new RegExp()`; adding one here would reject the shipped
 * manifest.
 */
const JS_REGEX_FIELD_PATHS = Object.freeze([
  ['installMarker', 'jsPattern'],
  ['persistence', 'claudeSettings', 'jsCommandPattern'],
  ['persistence', 'vscodeTasks', 'triggerPattern'],
  ['persistence', 'vscodeTasks', 'jsFailPattern'],
]);

function getAtPath(obj, segments) {
  let node = obj;
  for (const seg of segments) {
    if (!isPlainObject(node)) return undefined;
    node = node[seg];
  }
  return node;
}

/**
 * Validates that `value` is a non-empty string `new RegExp()` accepts.
 * Returns a rejection reason string, or null if the field is valid.
 */
function regexFieldReason(value, dottedPath) {
  if (typeof value !== 'string' || value.length === 0) {
    return `field "${dottedPath}" must be a non-empty string (regex source consumed by JS new RegExp()), got ${JSON.stringify(value)}`;
  }
  try {
    // eslint-disable-next-line no-new
    new RegExp(value);
  } catch (err) {
    return `field "${dottedPath}" is not a valid JS regular expression: ${(err && err.message) || 'unknown RegExp error'}`;
  }

  // ORDER IS LOAD-BEARING (do not move this above the try/catch): the
  // constructibility check runs FIRST, so a genuinely malformed pattern
  // still reports that it is malformed. Reversing the two would tell an
  // operator with a broken group that their problem is a POSIX class,
  // sending them the wrong way.
  //
  // A POSIX bracket class is ERE syntax JS does not implement:
  // `new RegExp('[[:space:]]')` does NOT throw — it compiles to a literal
  // character class matching one of `[`, `:`, `s`, `p`, `a`, `c`, `e`. The
  // detector then runs, matches nothing it was meant to match, and the scan
  // reports clean. "Non-empty and RegExp-constructible" is therefore
  // necessary but not sufficient (G-1482 found this defect in the shipped
  // spec; G-1552 moves the ban out of the test suite and into this
  // fail-closed validator, so an operator-supplied `--spec` /
  // `LSH_WAVE_SPEC` file cannot install a silently non-firing detector).
  //
  // Three facts a future reader must not get wrong:
  //
  //   1. The scoping is AUTOMATIC and must stay that way. regexFieldReason()
  //      has exactly one caller — the JS_REGEX_FIELD_PATHS loop in
  //      validateWaveSpec (step 4b) — so this ban is confined to those four
  //      fields with no scoping condition anyone can get wrong later. Do NOT
  //      add a second caller without re-reading decision D-06.
  //
  //   2. Why the sibling fields are exempt, stated correctly:
  //      `installMarker.pattern`, `persistence.claudeSettings.commandPattern`
  //      and `persistence.vscodeTasks.failPattern` are NOT fed to
  //      `new RegExp()`. That — not "they are bash-consumed" — is the whole
  //      justification. failPattern's own note in
  //      manifests/waves/chaindrop-aug2026.json records that it has NO bash
  //      consumer today, so a future reader must not restate the stronger
  //      claim. Banning POSIX spec-wide would reject the shipped manifest.
  //
  //   3. The shipped manifests/waves/chaindrop-aug2026.json passes this ban
  //      unchanged — measured, not assumed: all four JS-consumed fields are
  //      POSIX-free. This branch carries zero risk to the real manifest.
  if (POSIX_CLASS_RE.test(value)) {
    return `field "${dottedPath}" contains a POSIX bracket class ([[:...:]]), which JS new RegExp() does not implement: it compiles as a literal character class that never matches what the class describes, giving a detector that runs, matches nothing, and reports clean. Rewrite it using the JS equivalent (\\s / \\d / \\w), as the js* fields in the bundled wave spec already do (G-1482, G-1552)`;
  }

  return null;
}

/**
 * Describes which forbidden byte a hygiene-violating string contains, for
 * an actionable rejection reason (never a generic "invalid string").
 */
function describeHygieneChar(str) {
  const match = HYGIENE_RE.exec(str);
  if (!match) return null;
  const code = match[0].charCodeAt(0);
  if (code === 0) return 'a NUL byte (0x00)';
  if (code === 13) return 'a carriage return (\\r)';
  return 'a newline (\\n)';
}

/**
 * Walks the full parsed spec (values AND keys) looking for the first
 * string containing a newline, carriage return, or NUL byte. Returns
 * `{ path, char }` naming the offending location, or null if the spec is
 * clean. Operates on the whole object rather than only the sections named
 * in E3, because any string reachable from the spec could in principle be
 * written into a results-dir list file or a bash array.
 */
function findHygieneViolation(node, path) {
  if (typeof node === 'string') {
    const char = describeHygieneChar(node);
    return char ? { path: path || '(root)', char } : null;
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      const found = findHygieneViolation(node[i], `${path}[${i}]`);
      if (found) return found;
    }
    return null;
  }
  if (isPlainObject(node)) {
    for (const key of Object.keys(node)) {
      const keyChar = describeHygieneChar(key);
      if (keyChar) {
        return { path: path ? `${path}.<key:${key}>` : `<key:${key}>`, char: keyChar };
      }
      const childPath = path ? `${path}.${key}` : key;
      const found = findHygieneViolation(node[key], childPath);
      if (found) return found;
    }
    return null;
  }
  return null;
}

/**
 * Walks the full parsed spec looking for a `__proto__` / `constructor` /
 * `prototype` mapping key anywhere. Returns the offending dotted path, or
 * null if none is present. Note: JSON.parse assigns object keys via
 * CreateDataProperty, so a `"__proto__"` key in JSON text becomes an OWN
 * enumerable property (visible to Object.keys), never the object's actual
 * prototype — the walk below correctly sees it via ordinary key iteration.
 */
function findPollutedKey(node, path) {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      const found = findPollutedKey(node[i], `${path}[${i}]`);
      if (found) return found;
    }
    return null;
  }
  if (isPlainObject(node)) {
    for (const key of Object.keys(node)) {
      if (POLLUTED_KEYS.has(key)) {
        return path ? `${path}.${key}` : key;
      }
      const childPath = path ? `${path}.${key}` : key;
      const found = findPollutedKey(node[key], childPath);
      if (found) return found;
    }
    return null;
  }
  return null;
}

/**
 * Validates a parsed wave-spec object. Never throws. Returns
 * `{ valid: true, spec }` or `{ valid: false, reason }` — the reason
 * string always names the offending field so an operator mid-live-wave
 * knows what to fix, never a generic failure message.
 */
function validateWaveSpec(spec) {
  // 1. non-null, non-array object.
  if (!isPlainObject(spec)) {
    return { valid: false, reason: 'spec is not a non-null, non-array object' };
  }

  // 2. specVersion is a known, supported number.
  if (typeof spec.specVersion !== 'number' || !SUPPORTED_SPEC_VERSIONS.includes(spec.specVersion)) {
    return {
      valid: false,
      reason: `unsupported specVersion: ${JSON.stringify(spec.specVersion)} (supported: ${SUPPORTED_SPEC_VERSIONS.join(', ')})`,
    };
  }

  // 3. required sections present, with the right JS type.
  for (const key of REQUIRED_SECTIONS) {
    if (!(key in spec)) {
      return { valid: false, reason: `missing required section: ${key}` };
    }
  }

  let reason;
  if ((reason = stringArrayReason(spec.fileMarkers && spec.fileMarkers.fail, 'fileMarkers.fail'))) {
    return { valid: false, reason };
  }
  if ((reason = stringArrayReason(spec.compromisedFamily, 'compromisedFamily'))) {
    return { valid: false, reason };
  }
  if ((reason = stringArrayReason(spec.markerStrings, 'markerStrings'))) {
    return { valid: false, reason };
  }
  if ((reason = stringArrayReason(spec.lockfiles, 'lockfiles'))) {
    return { valid: false, reason };
  }
  if ((reason = stringArrayReason(spec.staticPaths, 'staticPaths'))) {
    return { valid: false, reason };
  }

  if (!isPlainObject(spec.poisonedVersions)) {
    return { valid: false, reason: 'section "poisonedVersions" must be an object mapping package name to an array of version strings' };
  }
  for (const [pkg, versions] of Object.entries(spec.poisonedVersions)) {
    if ((reason = stringArrayReason(versions, `poisonedVersions.${pkg}`))) {
      return { valid: false, reason };
    }
  }

  if (!Array.isArray(spec.knownBadHashes)) {
    return { valid: false, reason: 'section "knownBadHashes" must be an array' };
  }
  for (let i = 0; i < spec.knownBadHashes.length; i += 1) {
    const entry = spec.knownBadHashes[i];
    if (!isPlainObject(entry)) {
      return { valid: false, reason: `knownBadHashes[${i}] must be an object` };
    }
    if (typeof entry.sha256 !== 'string' || !SHA256_HEX_RE.test(entry.sha256)) {
      return { valid: false, reason: `knownBadHashes[${i}].sha256 must be a 64-character hex string` };
    }
  }

  for (const key of ['classes', 'bounds', 'persistence', 'installMarker']) {
    if (!isPlainObject(spec[key])) {
      return { valid: false, reason: `section "${key}" must be an object` };
    }
  }

  // 4. every bounds.* value is a positive safe integer (the "note" field,
  //    if present, is free-text documentation and exempt).
  for (const [key, value] of Object.entries(spec.bounds)) {
    if (key === 'note') continue;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
      return { valid: false, reason: `bounds.${key} must be a positive safe integer, got ${JSON.stringify(value)}` };
    }
  }

  // 4b. every JS-consumed regex-source field is a non-empty, RegExp-
  //     constructible string that carries no POSIX bracket class (see
  //     regexFieldReason's own comment for why "does not throw" alone is
  //     necessary but not sufficient, and D-06 for why the POSIX ban is
  //     scoped to JS_REGEX_FIELD_PATHS rather than applied spec-wide).
  //     This loop is regexFieldReason's ONLY call site, which is what makes
  //     that scoping automatic.
  for (const segments of JS_REGEX_FIELD_PATHS) {
    const dottedPath = segments.join('.');
    const value = getAtPath(spec, segments);
    if ((reason = regexFieldReason(value, dottedPath))) {
      return { valid: false, reason };
    }
  }

  // 5. string hygiene — no newline / CR / NUL anywhere in the spec.
  const hygieneViolation = findHygieneViolation(spec, '');
  if (hygieneViolation) {
    return { valid: false, reason: `string hygiene violation at ${hygieneViolation.path}: contains ${hygieneViolation.char}` };
  }

  // 6. no prototype-pollution key anywhere in the spec.
  const pollutedKey = findPollutedKey(spec, '');
  if (pollutedKey) {
    return { valid: false, reason: `prototype-pollution key "${pollutedKey}" present in spec` };
  }

  return { valid: true, spec };
}

const MAX_SPEC_BYTES = 1_048_576;

/**
 * Loads and validates a wave spec from disk. Never throws — every failure
 * mode (missing file, oversized file, unparseable JSON, or a spec that
 * fails validateWaveSpec) returns the same `{ valid: false, reason }`
 * shape as validateWaveSpec itself.
 *
 * opts.fs (for testing): an object providing statSync/readFileSync,
 * defaults to the real `fs` module.
 */
function loadWaveSpec(specPath, opts = {}) {
  const fsImpl = opts.fs || fs;

  let stat;
  try {
    stat = fsImpl.statSync(specPath);
  } catch (err) {
    return { valid: false, reason: `could not stat spec file: ${(err && err.code) || (err && err.message) || 'unknown error'}` };
  }

  if (!stat.isFile()) {
    return { valid: false, reason: 'spec path is not a regular file' };
  }

  if (stat.size > MAX_SPEC_BYTES) {
    return { valid: false, reason: 'spec-too-large' };
  }

  let raw;
  try {
    raw = fsImpl.readFileSync(specPath, 'utf8');
  } catch (err) {
    return { valid: false, reason: `could not read spec file: ${(err && err.code) || (err && err.message) || 'unknown error'}` };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { valid: false, reason: 'unparseable' };
  }

  return validateWaveSpec(parsed);
}

// POSIX_CLASS_RE is exported for ONE reason: so the test-side drift guard can
// assert against this exact object instead of re-declaring a copy. Two
// independent reviewers pointed out that the previous "deliberately the same
// expression" comment was socially enforced and technically vacant — fix the
// validator, forget the test, and the guard keeps passing against the old
// shape. It is not part of the module's behavioural API and nothing in lib/
// reads it from here.
module.exports = { SUPPORTED_SPEC_VERSIONS, loadWaveSpec, validateWaveSpec, JS_REGEX_FIELD_PATHS, getAtPath, POSIX_CLASS_RE };
