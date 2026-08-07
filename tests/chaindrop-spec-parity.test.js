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
const SCRIPT_PATH = path.join(__dirname, '..', 'scripts', 'scan-chaindrop-aug2026.sh');

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

describe('wave spec <-> scripts/scan-chaindrop-aug2026.sh bash-array drift guard (temporary — removed by plan 17-14)', () => {
  const script = fs.readFileSync(SCRIPT_PATH, 'utf8');
  const poisonedBlock = script.match(/POISONED_PKG_VERSIONS=\(([\s\S]*?)\n\)/);
  const familyBlock = script.match(/COMPROMISED_FAMILY=\(([\s\S]*?)\)/);
  const arraysStillPresent = Boolean(poisonedBlock && familyBlock);

  it('POISONED_PKG_VERSIONS / COMPROMISED_FAMILY bash arrays are still present in the script (guard precondition)', () => {
    // Plan 17-14 removes both bash arrays (the scanner is retrofitted onto
    // the wave spec) AND this entire describe block — spec-vs-manifest
    // parity above is the permanent guard once that lands. Until then,
    // this precondition keeps the sub-assertions below meaningful: if the
    // arrays are ever removed without this test file being updated in the
    // same change, this assertion fails loudly instead of the two checks
    // below silently vacuously passing on empty regex matches.
    assert.ok(arraysStillPresent, 'POISONED_PKG_VERSIONS/COMPROMISED_FAMILY arrays not found — this describe block is now obsolete and plan 17-14 should have removed it');
  });

  it('spec poisonedVersions matches the live POISONED_PKG_VERSIONS bash array exactly', { skip: !arraysStillPresent }, () => {
    const scriptSet = new Set([...poisonedBlock[1].matchAll(/"([^"]+@[^"]+)"/g)].map((m) => m[1]));
    const specFlat = flattenPoisoned(spec.poisonedVersions);
    assert.deepEqual([...scriptSet].sort(), [...specFlat].sort(), 'bash POISONED_PKG_VERSIONS and wave spec poisonedVersions have drifted — update both');
  });

  it('spec compromisedFamily matches the live COMPROMISED_FAMILY bash array exactly', { skip: !arraysStillPresent }, () => {
    const scriptFam = new Set([...familyBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]));
    const specFam = new Set(spec.compromisedFamily);
    assert.deepEqual([...scriptFam].sort(), [...specFam].sort(), 'bash COMPROMISED_FAMILY and wave spec compromisedFamily have drifted — update both');
  });
});
