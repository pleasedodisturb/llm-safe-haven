'use strict';

/**
 * Auto-discovery registry for MCP static/heuristic detector modules
 * (Phase 5). Mirrors lib/agents/index.js's structural pattern: every
 * .js file in this directory (except index.js itself) is require()d and
 * validated for the { id, run } shape; a broken module is skipped
 * silently, never crashing the scan (D-01, D-02).
 *
 * NOT wired into buildEnvelope() — Phase 7's orchestrator owns invoking
 * runAll() against real parsed servers (D-03). This registry only ships
 * the plugin infrastructure.
 */

const fs = require('fs');
const path = require('path');

const SKIP = new Set(['index.js']);

/**
 * Loads every valid detector module in this directory, sorted
 * alphabetically by `id` for deterministic Finding[] ordering across
 * calls (order-sensitive test assertions and reproducible scan output
 * both depend on this).
 *
 * `requirement` is NOT required for registration — only `id` (string)
 * and `run` (function) are load-bearing per D-02.
 */
function loadDetectors() {
  const detectors = [];
  const dir = __dirname;

  const files = fs.readdirSync(dir).filter(f => f.endsWith('.js') && !SKIP.has(f));

  for (const file of files) {
    try {
      const mod = require(path.join(dir, file));
      // id MUST be a non-empty string: a non-string id (e.g. a number)
      // would pass a truthiness-only check and later crash the
      // localeCompare sort below — the exact scan-wide crash the D-01/
      // D-02 guarantee forbids (WR-01).
      if (typeof mod.id === 'string' && mod.id !== '' && typeof mod.run === 'function') {
        detectors.push(mod);
      }
    } catch {
      // Broken detector module — skip silently, never crash the scan (D-01).
    }
  }

  // The gate above guarantees string ids, and String() makes the
  // comparator itself throw-proof even if that invariant is ever relaxed.
  detectors.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  return detectors;
}

/**
 * Fans run(servers, context) out across every loaded detector and
 * aggregates the combined Finding[]. A throwing detector never aborts
 * the batch — its (partial or absent) contribution is simply dropped
 * and every other detector still runs (D-01).
 */
function runAll(servers, context = {}) {
  const detectors = loadDetectors();
  const findings = [];
  for (const detector of detectors) {
    try {
      const result = detector.run(servers, context);
      if (Array.isArray(result)) findings.push(...result);
    } catch {
      // A throwing detector must never crash the whole scan (D-01).
    }
  }
  return findings;
}

module.exports = { loadDetectors, runAll };
