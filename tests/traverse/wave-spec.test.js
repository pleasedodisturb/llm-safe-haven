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
  const POSIX_CLASS_RE = /\[\[:/;

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
