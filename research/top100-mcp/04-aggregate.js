'use strict';

/**
 * G-1372 — Task 2: aggregation — dataset.json -> stats.json.
 *
 * Computes headline stats, per-detector counts, synthesized/real split,
 * a best-effort cross-set tool-name collision analysis (statically from
 * README tool tables — NO code execution, no live tools/list), and a
 * disclosureCandidates list for the Task 3 disclosure self-review
 * (Methodology §5 / ticket AC-6): single-server findings that look more
 * like an exploitable defect than a generic public-install-snippet fact.
 */

const fs = require('fs');
const path = require('path');

const DATASET_PATH = path.join(__dirname, 'dataset.json');
const STATS_PATH = path.join(__dirname, 'stats.json');

// Findings whose message is purely a fact about the PUBLIC recommended
// install snippet (unpinned version, missing attestation, plain-http/
// wildcard endpoint) are safe to name per the disclosure policy.
// Everything else — inlined literal secrets, scope-breadth, tool-
// poisoning phrasing, typosquat/scope-confusion — reads more like a
// claim about a specific server's behavior/defect and is a private-
// appendix candidate by default (Methodology §5: "when unsure, aggregate").
const PUBLIC_FACT_DETECTORS = new Set(['unpinned-execution', 'provenance', 'insecure-endpoint']);

function main() {
  if (!fs.existsSync(DATASET_PATH)) {
    console.error('04-aggregate.js: dataset.json not found — run 03-scan-runner.js first.');
    process.exitCode = 1;
    return;
  }
  const dataset = JSON.parse(fs.readFileSync(DATASET_PATH, 'utf8'));
  const servers = dataset.servers || [];

  const total = servers.length;
  const byDetector = {};
  const detectorServerCounts = {}; // servers with >=1 VERIFIED finding of that detector
  let synthesizedCount = 0;
  let scanIncompleteCount = 0;

  for (const s of servers) {
    if (s.synthesized) synthesizedCount++;
    if (s.scanIncomplete) scanIncompleteCount++;
    const detectorsSeenVerified = new Set();
    for (const f of s.findings || []) {
      byDetector[f.detector] = (byDetector[f.detector] || 0) + 1;
      if (f.confidence === 'verified') detectorsSeenVerified.add(f.detector);
    }
    for (const det of detectorsSeenVerified) {
      detectorServerCounts[det] = (detectorServerCounts[det] || 0) + 1;
    }
  }

  const provenanceCounts = { 'has-attestation': 0, 'lacks-attestation': 0, 'unverified-fetch-failed': 0, 'unverified-offline': 0, 'not-applicable': 0, 'scan-incomplete': 0 };
  for (const s of servers) {
    provenanceCounts[s.provenance] = (provenanceCounts[s.provenance] || 0) + 1;
  }

  const unpinnedCount = detectorServerCounts['unpinned-execution'] || 0;
  const lacksAttestationCount = provenanceCounts['lacks-attestation'] || 0;
  const insecureEndpointCount = detectorServerCounts['insecure-endpoint'] || 0;
  const credentialPassthroughCount = detectorServerCounts['credential-passthrough'] || 0;
  const scopeBreadthCount = detectorServerCounts['scope-breadth'] || 0;
  const toolPoisoningCount = detectorServerCounts['tool-poisoning'] || 0;
  const typosquatCount = detectorServerCounts['typosquat'] || 0;
  const toolShadowingCount = detectorServerCounts['tool-shadowing'] || 0;

  // --- Cross-set tool-name collision analysis (best-effort, static) ---
  // Tool names are not present anywhere in our collected data (README
  // "tool tables" require per-server semantic table parsing well beyond
  // what a recommended-install-snippet scrape captures, and NO code
  // execution / tools/list introspection is permitted). Every server is
  // therefore counted as skipped, honestly, rather than fabricating a
  // collision count from data we don't actually have.
  const toolCollisionAnalysis = {
    method: 'static README tool-table scrape (no code execution, no live tools/list)',
    serversWithStaticallyVisibleToolNames: 0,
    serversSkipped: total,
    collisionsFound: 0,
    note:
      'Tool names were not statically recoverable from the recommended-install-snippet ' +
      'collection performed in Task 1 (README tool tables require dedicated per-server ' +
      'table parsing beyond the mcpServers-snippet scrape this pipeline does). Every one ' +
      'of the 100 servers is counted as skipped rather than fabricating a collision figure ' +
      '— this mirrors the scanner\'s own honesty-first framing (docs/mcp-security.md §5): ' +
      'tool-shadowing here is the static server-NAME collision proxy only (already reflected ' +
      'in tool-shadowing findings above), never verified tool-level shadowing.',
  };

  // --- Disclosure self-review candidates (AC-6) ---
  const disclosureCandidates = [];
  for (const s of servers) {
    for (const f of s.findings || []) {
      if (!PUBLIC_FACT_DETECTORS.has(f.detector)) {
        disclosureCandidates.push({
          server: s.name,
          rank: s.rank,
          detector: f.detector,
          id: f.id,
          severity: f.severity,
          confidence: f.confidence,
          message: f.message,
        });
      }
    }
  }

  const stats = {
    generatedAt: new Date().toISOString(),
    snapshotDate: dataset.snapshotDate,
    pinnedCommit: dataset.pinnedCommit,
    scannerVersion: dataset.scannerVersion,
    total,
    synthesizedCount,
    realSnippetCount: total - synthesizedCount,
    scanIncompleteCount,
    headline: {
      unpinnedCount,
      lacksAttestationCount,
      insecureEndpointCount,
      credentialPassthroughCount,
      scopeBreadthCount,
      toolPoisoningCount,
      typosquatCount,
      toolShadowingCount,
    },
    byDetectorFindingCount: byDetector,
    byDetectorServerCount: detectorServerCounts,
    provenanceCounts,
    toolCollisionAnalysis,
    disclosureCandidates,
  };

  fs.writeFileSync(STATS_PATH, JSON.stringify(stats, null, 2));
  console.log(
    `Wrote stats.json: total=${total}, unpinned=${unpinnedCount}, ` +
    `lacksAttestation=${lacksAttestationCount}, disclosureCandidates=${disclosureCandidates.length}.`,
  );
}

main();
