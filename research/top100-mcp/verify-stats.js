'use strict';

/**
 * Phase 13 (G-1409) — D-01: mechanical re-derivation of every headline
 * number DRAFT.md claims, computed directly against dataset.json (never
 * against stats.json, never hand-transcribed). Mirrors 04-aggregate.js's
 * derivation shape (per-server/per-finding loop, Set-dedupe by detector
 * before incrementing server-level counts) so the two never drift apart.
 *
 * Exits non-zero and prints every mismatch if any of the 9 expected
 * values (frozen at the 2026-07-19 dataset snapshot, Phase 10 D-10 keeps
 * the dataset historical — it is NOT regenerated) fails to reproduce.
 * Re-runnable any time DRAFT.md's headline numbers need re-checking.
 */

const fs = require('fs');
const path = require('path');

const DATASET_PATH = path.join(__dirname, 'dataset.json');

const EXPECTED = {
  unpinnedExecutionServers: 90,
  lacksAttestation: 38,
  credentialPassthroughServers: 22,
  synthesized: 32,
  typosquatServers: 5,
  scopeBreadthServers: 1,
  insecureEndpointServers: 1,
  provenanceNotApplicable: 11,
  scanIncomplete: 0,
};

function main() {
  if (!fs.existsSync(DATASET_PATH)) {
    console.error('verify-stats.js: dataset.json not found.');
    process.exitCode = 2;
    return;
  }

  const dataset = JSON.parse(fs.readFileSync(DATASET_PATH, 'utf8'));
  const servers = dataset.servers || [];

  const byDetectorFindingCount = {};
  const byDetectorServerCount = {}; // servers with >=1 VERIFIED finding of that detector
  let synthesizedCount = 0;
  let scanIncompleteCount = 0;

  for (const s of servers) {
    if (s.synthesized) synthesizedCount++;
    if (s.scanIncomplete) scanIncompleteCount++;
    const detectorsSeenVerified = new Set();
    for (const f of s.findings || []) {
      byDetectorFindingCount[f.detector] = (byDetectorFindingCount[f.detector] || 0) + 1;
      if (f.confidence === 'verified') detectorsSeenVerified.add(f.detector);
    }
    for (const det of detectorsSeenVerified) {
      byDetectorServerCount[det] = (byDetectorServerCount[det] || 0) + 1;
    }
  }

  const provenanceCounts = {};
  for (const s of servers) {
    provenanceCounts[s.provenance] = (provenanceCounts[s.provenance] || 0) + 1;
  }

  const actual = {
    unpinnedExecutionServers: byDetectorServerCount['unpinned-execution'] || 0,
    lacksAttestation: provenanceCounts['lacks-attestation'] || 0,
    credentialPassthroughServers: byDetectorServerCount['credential-passthrough'] || 0,
    synthesized: synthesizedCount,
    typosquatServers: byDetectorServerCount['typosquat'] || 0,
    scopeBreadthServers: byDetectorServerCount['scope-breadth'] || 0,
    insecureEndpointServers: byDetectorServerCount['insecure-endpoint'] || 0,
    provenanceNotApplicable: provenanceCounts['not-applicable'] || 0,
    scanIncomplete: scanIncompleteCount,
  };

  console.log('byDetectorServerCount', byDetectorServerCount);
  console.log('byDetectorFindingCount', byDetectorFindingCount);
  console.log('provenance', provenanceCounts);
  console.log('synthesized', synthesizedCount);
  console.log('scanIncomplete', scanIncompleteCount);
  console.log('');
  console.log('--- verified against expected headline numbers ---');

  let mismatches = 0;
  for (const key of Object.keys(EXPECTED)) {
    const exp = EXPECTED[key];
    const got = actual[key];
    const ok = exp === got;
    if (!ok) mismatches++;
    console.log(`${ok ? 'OK  ' : 'FAIL'} ${key}: expected ${exp}, got ${got}`);
  }

  if (mismatches > 0) {
    console.error(`\nverify-stats.js: ${mismatches} headline number(s) mismatched dataset.json.`);
    process.exitCode = 1;
    return;
  }

  console.log('\nverify-stats.js: all 9 headline numbers reproduced exactly.');
}

main();
