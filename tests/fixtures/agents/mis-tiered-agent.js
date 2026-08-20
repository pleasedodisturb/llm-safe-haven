'use strict';

// Test fixture ONLY (G-1661, plan 21-06) — deliberately mis-tiered to prove
// computeExpectedTier() can detect a mismatch.
//
// This file MUST NOT be moved into lib/agents/. lib/agents/index.js's
// loadAgents() SKIP set is only { index.js, base.js } — any other .js file
// dropped into that directory is auto-discovered, graded by the meta-test,
// and shipped in the published npm tarball. It lives here, outside the
// registry directory, precisely so that can never happen.
//
// Declared capabilities: writes an ignore file the vendor's own documentation
// does NOT confirm is honored (ignoreFileHonored: false) -> computeExpectedTier
// resolves this to tier 3. The stated `tier` below is 2 -- a claim the
// declared capabilities do not support. The predicate must report the
// mismatch (computeExpectedTier(fixture) !== fixture.tier).

function detect() {
  return { found: false, version: null, path: null };
}

function harden() {
  return { actions: [], warnings: [] };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'Mis-Tiered Fixture Agent',
  id: 'mis-tiered-fixture',
  tier: 2,
  installsEnforcedHooks: false,
  writesIgnoreFile: true,
  ignoreFileHonored: false,
  detect,
  harden,
  audit,
};
