'use strict';

// Test fixture ONLY (G-1661, plan 21-06) — the well-tiered control paired
// with mis-tiered-agent.js. Without this twin, deleting computeExpectedTier()
// entirely (or making it reject every input) would still satisfy the
// mis-tier fixture's "does not match" assertion — this fixture proves the
// guard distinguishes a correctly-tiered module rather than merely rejecting
// everything.
//
// This file MUST NOT be moved into lib/agents/. lib/agents/index.js's
// loadAgents() SKIP set is only { index.js, base.js } — any other .js file
// dropped into that directory is auto-discovered, graded by the meta-test,
// and shipped in the published npm tarball. It lives here, outside the
// registry directory, precisely so that can never happen.
//
// Declared capabilities: identical to mis-tiered-agent.js except
// ignoreFileHonored is true -> computeExpectedTier resolves this to tier 2,
// which matches the stated `tier` below. The predicate must report NO
// mismatch (computeExpectedTier(fixture) === fixture.tier).

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
  name: 'Well-Tiered Control Fixture Agent',
  id: 'well-tiered-fixture',
  tier: 2,
  installsEnforcedHooks: false,
  writesIgnoreFile: true,
  ignoreFileHonored: true,
  detect,
  harden,
  audit,
};
