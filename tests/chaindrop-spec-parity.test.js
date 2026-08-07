'use strict';

// Three-way drift guard (TRAV-02, D-03/D-05/D-10): manifests/waves/
// chaindrop-aug2026.json (the new wave spec) vs manifests/
// chaindrop-poisoned-versions.json (the existing, doc-referenced manifest,
// which D-10 keeps in place and parity-tests rather than generating-from)
// vs scripts/scan-chaindrop-aug2026.sh's own bash arrays (still the live
// scanner's data source until plan 17-14 retrofits it onto the spec).
//
// Modeled on the existing bash-array-parity block this extends
// (tests/chaindrop-scanner.test.js:343-363) — those two tests regex-parse
// the bash source directly and will be REMOVED by plan 17-14 once the
// scanner is retrofitted onto the spec; this file's spec-vs-manifest
// assertions are what survives as the PERMANENT guard.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const SPEC_PATH = path.join(__dirname, '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
const MANIFEST_PATH = path.join(__dirname, '..', 'manifests', 'chaindrop-poisoned-versions.json');

const spec = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));
const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));

function flattenPoisoned(poisonedMap) {
  const flat = new Set();
  for (const [pkg, versions] of Object.entries(poisonedMap)) {
    for (const v of versions) flat.add(`${pkg}@${v}`);
  }
  return flat;
}

describe('wave spec <-> manifests/chaindrop-poisoned-versions.json drift guard (permanent)', () => {
  it('specVersion 1 is present and the spec is well-formed JSON', () => {
    assert.equal(spec.specVersion, 1);
  });

  it('spec poisonedVersions matches manifest.poisoned exactly (flattened name@version sets)', () => {
    const specFlat = [...flattenPoisoned(spec.poisonedVersions)].sort();
    const manifestFlat = [...flattenPoisoned(manifest.poisoned)].sort();
    assert.deepEqual(specFlat, manifestFlat, 'wave spec and manifest poisoned-version lists have drifted — update both');
  });

  it('spec compromisedFamily matches manifest.coreFamily exactly (as a set)', () => {
    const specFam = [...spec.compromisedFamily].sort();
    const manifestFam = [...manifest.coreFamily].sort();
    assert.deepEqual(specFam, manifestFam, 'wave spec compromisedFamily and manifest coreFamily have drifted — update both');
  });

  it('spec knownBadHashes[].sha256 matches manifest.fileHashes keys exactly (as a set)', () => {
    const specHashes = [...new Set(spec.knownBadHashes.map((h) => h.sha256.toLowerCase()))].sort();
    const manifestHashes = [...new Set(Object.keys(manifest.fileHashes).map((h) => h.toLowerCase()))].sort();
    assert.deepEqual(specHashes, manifestHashes, 'wave spec knownBadHashes and manifest fileHashes have drifted — update both');
  });

  it('spec markerStrings covers every manifest network entry (domains, ips, and the dead-drop description)', () => {
    const networkValues = [
      ...manifest.network.domains,
      ...manifest.network.ips,
      manifest.network.exfilRepoDescription,
    ];
    for (const value of networkValues) {
      assert.ok(
        spec.markerStrings.includes(value),
        `manifest network entry "${value}" is not covered by spec markerStrings`
      );
    }
  });

  // Non-vacuity (verified once by hand while writing this test, then
  // restored — feedback_vacuous_guard_tests): mutating one poisoned
  // version in manifests/waves/chaindrop-aug2026.json (e.g. changing
  // "keyv": ["6.0.0"] to ["6.0.1"]) makes the "spec poisonedVersions
  // matches manifest.poisoned" assertion above fail with a clear
  // left/right diff — the guard is not a vacuous deepEqual([], []).
});

// The "wave spec <-> scripts/scan-chaindrop-aug2026.sh bash-array drift
// guard" describe block that used to live here is REMOVED by plan 17-14:
// the scanner no longer hardcodes POISONED_PKG_VERSIONS / COMPROMISED_FAMILY
// bash arrays at all (scripts/scan-chaindrop-aug2026.sh now reads its IOC
// data from the wave spec via the traversal engine's results directory —
// see tests/chaindrop-scanner.test.js's rewritten manifest-parity block).
// The spec-vs-manifest parity asserted above is the PERMANENT guard.
