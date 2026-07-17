'use strict';

/**
 * MCP config scanner orchestrator (Phase 4 deliverable; detector wiring
 * added in Phase 7).
 *
 * This is the deliverable that wires lib/mcp/config-sources.js (discovery),
 * lib/mcp/parsers/*.js (per-agent parsing), and lib/mcp/detectors/index.js
 * (runAll(), Phases 5-6) into the frozen `--json` envelope. `findings` and
 * `summary` are populated from the full detector pass every scan
 * (Phase 7, MCPO-05/MCPO-06).
 *
 * Exit-code convention: 0 = clean, 1 = findings, 2 = error/could-not-complete.
 * A could-not-run, malformed-config, oversized-config, symlinked-config, or
 * prototype-polluted-config scan is NEVER reported as 0 ("clean") — a
 * security gate must distinguish "no findings" from "the scan did not finish".
 */

const { SCHEMA_VERSION, EXIT } = require('./mcp/base.js');

const DEFAULT_PARSERS = {
  'claude-code': require('./mcp/parsers/claude-code.js'),
  cursor: require('./mcp/parsers/cursor.js'),
  windsurf: require('./mcp/parsers/windsurf.js'),
  cline: require('./mcp/parsers/cline.js'),
  'continue-dev': require('./mcp/parsers/continue-dev.js'),
};

/**
 * Builds the frozen `--json` envelope as PURE data — no printing here.
 *
 * Iterates every discovered source; sources with status 'found' are handed
 * to the matching agent's parser. A parse failure bumps exitCode to
 * EXIT.INCOMPLETE (2) and records the failure reason on that source's
 * status, but does NOT drop servers successfully parsed from OTHER
 * sources — partial data + exit 2 (RESEARCH.md Open Question 2 resolution).
 *
 * After discovery/parsing, the detector registry (lib/mcp/detectors/
 * index.js runAll()) is awaited unconditionally — even when zero servers
 * were discovered, since some findings are data-independent (e.g.
 * typosquat/allowlist-unavailable) — and its Finding[] populates
 * `findings`/`summary`. The exit code is an UPGRADE-ONLY check (D-08):
 * an EXIT.INCOMPLETE set by the discovery/parse layer above is NEVER
 * downgraded by the findings check; a security gate must never report an
 * unfinished scan as clean.
 *
 * opts (for testing): { discoverAll, parsers, now, fetchImpl } — never
 * touches the real filesystem or clock when injected.
 */
async function buildEnvelope(flags, opts = {}) {
  const discoverAll = opts.discoverAll || require('./mcp/config-sources.js').discoverAll;
  const parsers = opts.parsers || DEFAULT_PARSERS;
  const now = opts.now || (() => new Date().toISOString());

  let exitCode = EXIT.CLEAN;
  const sources = [];
  const servers = [];

  const discovered = discoverAll(opts);

  for (const source of discovered) {
    if (source.status !== 'found') {
      sources.push({ ...source });
      continue;
    }

    const parser = parsers[source.agentId];
    if (!parser || typeof parser.parse !== 'function') {
      // No parser registered for this agent id — treat as incomplete
      // rather than silently reporting a "found" source as clean.
      exitCode = EXIT.INCOMPLETE;
      sources.push({ ...source, status: 'no-parser' });
      continue;
    }

    // Dispatch is keyed on the caller-supplied source.agentId; each
    // parser also hardcodes its own agent identity. If they disagree
    // (e.g. a YAML source routed to a JSON parser via a bad parsers
    // map), the wrong grammar would run over the file — fail closed
    // with a clear mismatch status instead of a misleading 'malformed'.
    if (parser.agentId !== source.agentId) {
      exitCode = EXIT.INCOMPLETE;
      sources.push({ ...source, status: 'parser-mismatch' });
      continue;
    }

    let result;
    try {
      result = parser.parse(source, opts);
    } catch (err) {
      exitCode = EXIT.INCOMPLETE;
      sources.push({ ...source, status: 'parse-error' });
      continue;
    }

    if (result && result.ok) {
      servers.push(...(result.servers || []));
      sources.push({ ...source, status: 'parsed' });
    } else {
      exitCode = EXIT.INCOMPLETE;
      sources.push({ ...source, status: (result && result.reason) || 'unreadable' });
    }
  }

  // D-02: detector context — online only when explicitly requested;
  // fetchImpl is injectable for tests (provenance.js defaults to the
  // real global fetch per Phase 6 D-11). The detector loop runs
  // unconditionally, even with zero discovered servers.
  const context = { online: flags.online === true, fetchImpl: opts.fetchImpl };
  const findings = await require('./mcp/detectors/index.js').runAll(servers, context);

  // D-09: summary counts ALL findings (verified + unverified) — the
  // JSON consumer sees per-finding confidence and can filter.
  const summary = { bySeverity: {}, byDetector: {} };
  for (const f of findings) {
    summary.bySeverity[f.severity] = (summary.bySeverity[f.severity] || 0) + 1;
    summary.byDetector[f.detector] = (summary.byDetector[f.detector] || 0) + 1;
  }

  // D-08: INCOMPLETE from the discovery/parse layer always wins — never
  // downgrade an already-set EXIT.INCOMPLETE (Pitfall 5). Otherwise exit
  // 1 iff at least one finding is confidence:verified; unverified-only
  // findings stay exit 0.
  if (exitCode !== EXIT.INCOMPLETE) {
    exitCode = findings.some(f => f.confidence === 'verified') ? EXIT.FINDINGS : EXIT.CLEAN;
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    exitCode,
    generatedAt: now(),
    offline: !(flags.online === true),
    sources,
    servers,
    findings,
    summary,
  };
}

/**
 * scanMcp(flags, opts) — the scan.js dispatch target for `scan --mcp`.
 * Builds the envelope, prints it (JSON or human), and returns
 * { ran:true, code, findingsCount } for lib/cli.js's exit-code
 * propagation. Never throws.
 */
async function scanMcp(flags = {}, opts = {}) {
  let envelope;
  try {
    envelope = await buildEnvelope(flags, opts);
  } catch (err) {
    return { ran: false, reason: 'build-error', code: EXIT.INCOMPLETE, findingsCount: 0 };
  }

  try {
    if (flags.json) {
      console.log(JSON.stringify(envelope, null, 2));
    } else if (!flags.quiet) {
      require('./scorecard.js').printMcpScan(envelope);
    }
  } catch {
    // Printing must never crash the process — the envelope/code is already
    // computed and is what matters for the exit-code contract.
  }

  return { ran: true, code: envelope.exitCode, findingsCount: envelope.findings.length };
}

module.exports = { scanMcp, buildEnvelope };
