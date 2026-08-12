'use strict';

// Non-vacuous validator tests for lib/traverse/wave-spec.js (TRAV-02,
// T-17-01). Every guard is proven with a case built by mutating a deep
// clone of the REAL bundled manifests/waves/chaindrop-aug2026.json spec,
// paired against a case asserting the unmutated clone still validates
// (house "prove-the-guard-bites" template, tests/tier3-agents.test.js:
// 157-189) -- a passing suite proves the validator actually inspects that
// spec's shape, not merely that some arbitrary object fails some check.
//
// Every negative case asserts BOTH `valid === false` AND that `reason`
// names the offending field -- a generic failure is not acceptable, since
// the operator must be told what to fix during a live wave (D-05).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { loadWaveSpec, validateWaveSpec, SUPPORTED_SPEC_VERSIONS, JS_REGEX_FIELD_PATHS, getAtPath } = require('../../lib/traverse/wave-spec.js');

const SPEC_PATH = path.join(__dirname, '..', '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
const REAL_SPEC = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));

// Mirrors REQUIRED_SECTIONS in lib/traverse/wave-spec.js and the acceptance
// criteria key list for manifests/waves/chaindrop-aug2026.json (17-04 Task 1).
const REQUIRED_SECTIONS = [
  'fileMarkers', 'knownBadHashes', 'poisonedVersions', 'compromisedFamily',
  'markerStrings', 'installMarker', 'persistence', 'lockfiles', 'staticPaths',
  'classes', 'bounds',
];

function clone(spec) {
  return JSON.parse(JSON.stringify(spec));
}

describe('wave-spec.js — SUPPORTED_SPEC_VERSIONS + the bundled spec is valid', () => {
  it('SUPPORTED_SPEC_VERSIONS is frozen and contains exactly [1]', () => {
    assert.deepEqual(SUPPORTED_SPEC_VERSIONS, [1]);
    assert.ok(Object.isFrozen(SUPPORTED_SPEC_VERSIONS));
  });

  it('the bundled wave spec validates via validateWaveSpec', () => {
    const result = validateWaveSpec(clone(REAL_SPEC));
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.spec.specVersion, 1);
  });

  it('loadWaveSpec loads and validates the bundled spec from disk', () => {
    const result = loadWaveSpec(SPEC_PATH);
    assert.equal(result.valid, true, result.reason);
  });
});

describe('wave-spec.js — specVersion guard', () => {
  it('rejects an unknown numeric specVersion (2), naming the observed value', () => {
    const bad = clone(REAL_SPEC);
    bad.specVersion = 2;
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /specVersion/);
    assert.match(result.reason, /\b2\b/);
  });

  it('rejects a string specVersion ("1"), never coercing string-to-number', () => {
    const bad = clone(REAL_SPEC);
    bad.specVersion = '1';
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /specVersion/);
  });

  it('rejects a spec with specVersion deleted entirely', () => {
    const bad = clone(REAL_SPEC);
    delete bad.specVersion;
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /specVersion/);
  });
});

describe('wave-spec.js — required-section presence guard (each of the 11 sections, in turn)', () => {
  for (const section of REQUIRED_SECTIONS) {
    it(`rejects a spec with "${section}" deleted, naming that section`, () => {
      const bad = clone(REAL_SPEC);
      delete bad[section];
      const result = validateWaveSpec(bad);
      assert.equal(result.valid, false, `expected deleting "${section}" to fail validation`);
      assert.match(result.reason, new RegExp(section), `reason should name "${section}": ${result.reason}`);
    });
  }

  it('accepts the real spec with every required section present (paired valid case)', () => {
    const result = validateWaveSpec(clone(REAL_SPEC));
    assert.equal(result.valid, true, result.reason);
  });
});

describe('wave-spec.js — section shape guards', () => {
  it('rejects poisonedVersions as an array instead of an object', () => {
    const bad = clone(REAL_SPEC);
    bad.poisonedVersions = ['keyv@6.0.0'];
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /poisonedVersions/);
  });

  it('accepts poisonedVersions in its real object-of-string-arrays shape (paired valid case)', () => {
    const good = clone(REAL_SPEC);
    assert.ok(!Array.isArray(good.poisonedVersions));
    const result = validateWaveSpec(good);
    assert.equal(result.valid, true, result.reason);
  });

  it('rejects a knownBadHashes entry with a 63-character sha256', () => {
    const bad = clone(REAL_SPEC);
    bad.knownBadHashes[0].sha256 = bad.knownBadHashes[0].sha256.slice(0, 63);
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /knownBadHashes\[0\]/);
    assert.match(result.reason, /sha256/);
  });

  it('accepts the real 64-character-hex knownBadHashes entries (paired valid case)', () => {
    const good = clone(REAL_SPEC);
    for (const entry of good.knownBadHashes) {
      assert.equal(entry.sha256.length, 64);
    }
    const result = validateWaveSpec(good);
    assert.equal(result.valid, true, result.reason);
  });
});

describe('wave-spec.js — bounds guard', () => {
  it('rejects a negative bounds.bulkReadCapBytes', () => {
    const bad = clone(REAL_SPEC);
    bad.bounds.bulkReadCapBytes = -1;
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /bounds\.bulkReadCapBytes/);
  });

  it('accepts the real positive bounds values (paired valid case)', () => {
    const good = clone(REAL_SPEC);
    const result = validateWaveSpec(good);
    assert.equal(result.valid, true, result.reason);
  });
});

describe('wave-spec.js — string hygiene guard (T-17-10, cross-boundary injection)', () => {
  it('rejects a markerStrings entry containing a newline', () => {
    const bad = clone(REAL_SPEC);
    bad.markerStrings[0] = 'evil\ninjected';
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /markerStrings/);
    assert.match(result.reason, /newline/);
  });

  it('rejects a markerStrings entry containing a NUL byte', () => {
    const bad = clone(REAL_SPEC);
    // Built via String.fromCharCode(0) rather than a source-level escape,
    // to avoid any risk of the literal escape sequence surviving into the
    // file as a raw control byte.
    bad.markerStrings[0] = 'evil' + String.fromCharCode(0) + 'byte';
    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(result.reason, /markerStrings/);
    assert.match(result.reason, /NUL/);
  });

  it('accepts the real markerStrings entries, none of which contain injection bytes (paired valid case)', () => {
    const good = clone(REAL_SPEC);
    for (const s of good.markerStrings) {
      assert.ok(!/[\n\r\0]/.test(s), `expected no hygiene violation in fixture data: ${JSON.stringify(s)}`);
    }
    const result = validateWaveSpec(good);
    assert.equal(result.valid, true, result.reason);
  });
});

describe('wave-spec.js — prototype-pollution guard', () => {
  it('rejects a spec parsed from JSON text containing a __proto__ key', () => {
    // JSON.parse assigns object keys via CreateDataProperty, so a
    // "__proto__" key in JSON text becomes an OWN enumerable property --
    // never the object's actual prototype (verified: Object.keys includes
    // it, {}.polluted stays undefined). This is exactly the real attack
    // surface (a hostile spec FILE read with JSON.parse), unlike
    // `obj.__proto__ = {...}` dot-assignment in JS source, which would hit
    // the real Object.prototype accessor instead.
    const text = JSON.stringify(REAL_SPEC).replace(/^\{/, '{"__proto__":{"polluted":true},');
    const parsed = JSON.parse(text);
    assert.ok(Object.prototype.hasOwnProperty.call(parsed, '__proto__'), 'JSON.parse should create __proto__ as an own property');
    assert.equal(({}).polluted, undefined, 'sanity: the real Object.prototype must stay unpolluted');

    const result = validateWaveSpec(parsed);
    assert.equal(result.valid, false);
    assert.match(result.reason, /prototype-pollution/);
    assert.match(result.reason, /__proto__/);
  });

  it('accepts the real spec, which has no polluted keys (paired valid case)', () => {
    const good = clone(REAL_SPEC);
    const result = validateWaveSpec(good);
    assert.equal(result.valid, true, result.reason);
  });
});

describe('wave-spec.js — JS-consumed regex-field guard (G-1482 merge-blocking fix)', () => {
  // A JS `new RegExp()` does not understand POSIX bracket classes --
  // `[[:space:]]` compiles to a literal 8-character class, not whitespace --
  // so every field the engine feeds into `new RegExp()`
  // (JS_REGEX_FIELD_PATHS) must be present, non-empty, and RegExp-
  // constructible, and must never itself contain a `[[:` POSIX class (the
  // second check is the permanent drift guard: it is what would have caught
  // commandPattern/failPattern being handed to `new RegExp()` in the first
  // place, before any corpus fixture had to prove the miss at runtime).
  // Must stay byte-identical to the validator's POSIX_CLASS_RE
  // (lib/traverse/wave-spec.js) — the two are deliberately the same
  // expression so they cannot disagree about what counts as a POSIX class.
  // Token form, not the leading-`[[:` form: the latter was bypassed by
  // `[^[:space:]]` (negated) and `[a-z[:digit:]]` (mixed), found by
  // adversarial code review of PR #96.
  const POSIX_CLASS_RE = /\[:[a-z]+:\]/;

  it('the real spec has no `[[:` POSIX bracket class in any JS-consumed regex field', () => {
    for (const segments of JS_REGEX_FIELD_PATHS) {
      const value = getAtPath(REAL_SPEC, segments);
      assert.equal(typeof value, 'string', `${segments.join('.')} must be a string in the real spec`);
      assert.doesNotMatch(
        value,
        POSIX_CLASS_RE,
        `${segments.join('.')} contains a POSIX bracket class ([[:...:]]) — a JS new RegExp() does not understand POSIX classes and will silently fail to match what the class describes (G-1482)`
      );
    }
  });

  it('non-vacuity: a POSIX-class value DOES trip the guard above (verified by local mutation, not asserted against the real spec)', () => {
    // Proves the assertion in the previous test is not vacuously true for
    // every string (e.g. via a mistyped regex) -- mutate a local copy to
    // reintroduce the exact defect and confirm the guard's own regex fires.
    assert.match('node[[:space:]]+-e', POSIX_CLASS_RE);
  });

  for (const segments of JS_REGEX_FIELD_PATHS) {
    const dottedPath = segments.join('.');

    it(`rejects a spec with "${dottedPath}" deleted (no fallthrough to new RegExp(undefined))`, () => {
      const bad = clone(REAL_SPEC);
      let node = bad;
      for (let i = 0; i < segments.length - 1; i += 1) node = node[segments[i]];
      delete node[segments[segments.length - 1]];

      const result = validateWaveSpec(bad);
      assert.equal(result.valid, false, `a spec missing ${dottedPath} must fail validation, not silently pass through to new RegExp(undefined) (which matches every string)`);
      assert.match(result.reason, new RegExp(dottedPath.replace(/\./g, '\\.')));
    });

    it(`rejects a spec with "${dottedPath}" set to an empty string`, () => {
      const bad = clone(REAL_SPEC);
      let node = bad;
      for (let i = 0; i < segments.length - 1; i += 1) node = node[segments[i]];
      node[segments[segments.length - 1]] = '';

      const result = validateWaveSpec(bad);
      assert.equal(result.valid, false, `${dottedPath} = "" must fail validation (new RegExp('') matches every string)`);
    });

    it(`rejects a spec with "${dottedPath}" set to an invalid regex source`, () => {
      const bad = clone(REAL_SPEC);
      let node = bad;
      for (let i = 0; i < segments.length - 1; i += 1) node = node[segments[i]];
      node[segments[segments.length - 1]] = '(unterminated group';

      const result = validateWaveSpec(bad);
      assert.equal(result.valid, false, `${dottedPath} must be constructible by new RegExp(); an unterminated group must be rejected`);
    });
  }

  it('accepts the real spec (paired valid case for every JS_REGEX_FIELD_PATHS entry)', () => {
    const good = clone(REAL_SPEC);
    const result = validateWaveSpec(good);
    assert.equal(result.valid, true, result.reason);
  });

  // ---- G-1552 (SCAN-03): the ban is now ENFORCED in validateWaveSpec() ----
  //
  // The two tests at the top of this block are drift guards for the SHIPPED
  // manifests/waves/chaindrop-aug2026.json. They cannot see an
  // operator-supplied spec, and `--spec` / LSH_WAVE_SPEC accept any path
  // (lib/traverse/run.js:52,90). The cases below prove validateWaveSpec()
  // itself REJECTS a POSIX bracket class in the four JS-consumed fields, so
  // such a spec cannot install a silently non-firing detector.
  //
  // Those two existing tests are deliberately RETAINED, not replaced. They
  // now overlap with the validator, which is correct: they remain the guard
  // for the shipped FILE specifically (a drift there fails both, as it
  // should). Deleting them would be a regression, not a cleanup.

  for (const segments of JS_REGEX_FIELD_PATHS) {
    const dottedPath = segments.join('.');

    it(`rejects a spec with "${dottedPath}" containing a POSIX bracket class (G-1552)`, () => {
      const bad = clone(REAL_SPEC);
      let node = bad;
      for (let i = 0; i < segments.length - 1; i += 1) node = node[segments[i]];
      // The realistic operator error: copying the bash sibling's POSIX ERE
      // into the JS-consumed field. It compiles without throwing, and then
      // never matches whitespace.
      node[segments[segments.length - 1]] = 'setup\\.mjs|node[[:space:]]+-e';

      const result = validateWaveSpec(bad);
      assert.equal(
        result.valid,
        false,
        `${dottedPath} carrying a POSIX bracket class must be REJECTED by validateWaveSpec(), not merely flagged by a test — new RegExp() accepts it and the detector then silently never fires (G-1552)`
      );
      assert.match(
        result.reason,
        new RegExp(dottedPath.replace(/\./g, '\\.')),
        `reason must name the offending field "${dottedPath}": ${result.reason}`
      );
      // Assert on reason CONTENT, not merely on `valid` — a rejection for the
      // wrong reason (hygiene, say) would otherwise pass this test and send
      // the operator to fix the wrong thing.
      assert.match(
        result.reason,
        /POSIX/,
        `reason must identify the problem as a POSIX bracket class: ${result.reason}`
      );
    });
  }

  // ---- PR #96 code-review finding: the leading-`[[:` form was bypassable ----
  //
  // The original ban was `/\[\[:/`, which matches only a POSIX class at the
  // START of a bracket expression. Adversarial code review found two shapes
  // that slipped through — and they are the two an operator is MOST likely to
  // write, because they are what you reach for when the simple form is not
  // enough:
  //
  //     [^[:space:]]      negated
  //     [a-z[:digit:]]    mixed with an ordinary range
  //
  // Both compile in JS as literal character classes. Measured:
  // `/[^[:space:]]/.test('s')` is FALSE — a pattern meaning "not whitespace"
  // fails to match a non-whitespace character. That is a silently non-firing
  // detector reaching production through the exact validator built to stop it.
  //
  // Neither plan review nor a hand check of the leading form caught this;
  // only reviewing the shipped diff did. These cases exist so the narrower
  // form cannot come back.
  const POSIX_BYPASS_SHAPES = [
    ['negated', '[^[:space:]]'],
    ['mixed with a range', '[a-z[:digit:]]'],
    ['two classes in one expression', '[[:alpha:][:digit:]]'],
    ['embedded mid-pattern', 'node[[:upper:]]+-e'],
  ];

  for (const [label, source] of POSIX_BYPASS_SHAPES) {
    it(`rejects a ${label} POSIX class — "${source}" (PR #96 review; bypassed the leading-[[: form)`, () => {
      const bad = clone(REAL_SPEC);
      const segments = JS_REGEX_FIELD_PATHS[0];
      let node = bad;
      for (let i = 0; i < segments.length - 1; i += 1) node = node[segments[i]];
      node[segments[segments.length - 1]] = source;

      const result = validateWaveSpec(bad);
      assert.equal(
        result.valid,
        false,
        `"${source}" must be rejected. It compiles without throwing and then never matches what its author meant, which is the silently-non-firing detector this ban exists to prevent.`
      );
      assert.match(result.reason, /POSIX/, `reason must identify it as a POSIX class: ${result.reason}`);
    });
  }

  it('paired control 4 — legitimate patterns that merely LOOK POSIX-adjacent are still accepted', () => {
    // Guards the opposite failure: a ban broad enough to catch the negated
    // and mixed shapes must not start rejecting valid regexes. The rejected
    // alternative `/\[\^?[^\]]*\[:/` false-positives on both of these.
    for (const source of ['[\\[:]', '\\[\\[:not-a-class', '[a-z]', '^\\s*$', '[A-Za-z0-9_-]+']) {
      const good = clone(REAL_SPEC);
      const segments = JS_REGEX_FIELD_PATHS[0];
      let node = good;
      for (let i = 0; i < segments.length - 1; i += 1) node = node[segments[i]];
      node[segments[segments.length - 1]] = source;

      const result = validateWaveSpec(good);
      assert.equal(
        result.valid,
        true,
        `"${source}" is a legitimate JS regex and must still validate — the POSIX ban must not over-reach: ${result.reason}`
      );
    }
  });

  it('paired control 1 — the shipped spec still validates unchanged (D-06 zero-risk claim under test)', () => {
    const result = validateWaveSpec(clone(REAL_SPEC));
    assert.equal(
      result.valid,
      true,
      `D-06 claims the shipped manifest passes the POSIX ban with ZERO manifest edits. It does not: ${result.reason}`
    );
  });

  it('paired control 2 — a POSIX class in the bash-consumed sibling installMarker.pattern still validates (D-06 scoping)', () => {
    const good = clone(REAL_SPEC);
    good.installMarker.pattern = '"preinstall"[[:space:]]*:[[:space:]]*"node[[:space:]]+loader\\.mjs"';
    assert.match(good.installMarker.pattern, POSIX_CLASS_RE, 'sanity: this control only means something if the value really carries a POSIX class');

    const result = validateWaveSpec(good);
    assert.equal(
      result.valid,
      true,
      `The single most important assertion in G-1552: the ban is scoped to JS_REGEX_FIELD_PATHS, NOT repo-wide. installMarker.pattern (like claudeSettings.commandPattern and vscodeTasks.failPattern) is never fed to new RegExp(), and the shipped manifest legitimately holds POSIX ERE there. If this fails, someone widened the ban and broke the shipped manifest — re-read 18-CONTEXT.md D-06 before changing anything: ${result.reason}`
    );
  });

  it('paired control 3 — a malformed regex still reports as malformed, not as a POSIX class (precedence)', () => {
    const bad = clone(REAL_SPEC);
    bad.installMarker.jsPattern = '(unterminated group';

    const result = validateWaveSpec(bad);
    assert.equal(result.valid, false);
    assert.match(
      result.reason,
      /not a valid JS regular expression/,
      `the new RegExp() constructibility check must stay AHEAD of the POSIX check: ${result.reason}`
    );
    assert.doesNotMatch(
      result.reason,
      /POSIX/,
      `a genuinely broken pattern must not be mis-reported as a POSIX class — that sends the operator the wrong way: ${result.reason}`
    );
  });

  it('paired control 4 — an ordinary legal JS character class ([a-z]) is unaffected by the ban', () => {
    const good = clone(REAL_SPEC);
    good.installMarker.jsPattern = '"preinstall"\\s*:\\s*"node\\s+[a-z]+\\.mjs"';

    const result = validateWaveSpec(good);
    assert.equal(
      result.valid,
      true,
      `the ban must match the POSIX opening sequence "[[:", not any bracket: ${result.reason}`
    );
  });
});

describe('wave-spec.js — loadWaveSpec file-level guards', () => {
  it('rejects an oversized spec file (reason: spec-too-large)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-wave-spec-'));
    const big = path.join(tmp, 'big.json');
    const padding = 'x'.repeat(1_048_576 + 1);
    fs.writeFileSync(big, JSON.stringify({ specVersion: 1, padding }));
    try {
      const result = loadWaveSpec(big);
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'spec-too-large');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('accepts the real spec file, which is well under the size cap (paired valid case)', () => {
    const result = loadWaveSpec(SPEC_PATH);
    assert.equal(result.valid, true, result.reason);
  });

  it('rejects unparseable JSON (reason: unparseable)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-wave-spec-'));
    const bad = path.join(tmp, 'bad.json');
    fs.writeFileSync(bad, '{ this is not json');
    try {
      const result = loadWaveSpec(bad);
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'unparseable');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('rejects a missing spec file without throwing', () => {
    const result = loadWaveSpec('/nonexistent/path/does-not-exist.json');
    assert.equal(result.valid, false);
    assert.match(result.reason, /could not stat spec file/);
  });
});

describe('wave-spec.js — never throws on malformed top-level input', () => {
  it('validateWaveSpec(null) fails closed instead of throwing', () => {
    const result = validateWaveSpec(null);
    assert.equal(result.valid, false);
    assert.match(result.reason, /non-null/);
  });

  it('validateWaveSpec([]) (an array) fails closed instead of throwing', () => {
    const result = validateWaveSpec([]);
    assert.equal(result.valid, false);
    assert.match(result.reason, /non-array/);
  });

  it('validateWaveSpec("a string") fails closed instead of throwing', () => {
    const result = validateWaveSpec('a string');
    assert.equal(result.valid, false);
  });
});
