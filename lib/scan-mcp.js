'use strict';

/**
 * MCP config scanner orchestrator (Phase 4 deliverable).
 *
 * This is the deliverable that wires lib/mcp/config-sources.js (discovery)
 * and lib/mcp/parsers/*.js (per-agent parsing) into the frozen `--json`
 * envelope Phases 5-8 build detectors on top of. Phase 4 ships with NO
 * detector loop — `findings` is ALWAYS `[]` here; only the envelope shape
 * and exit-code contract are frozen.
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
 * opts (for testing): { discoverAll, parsers, now } — never touches the
 * real filesystem or clock when injected.
 */
function buildEnvelope(flags, opts = {}) {
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

  return {
    schemaVersion: SCHEMA_VERSION,
    exitCode,
    generatedAt: now(),
    offline: true,
    sources,
    servers,
    findings: [],
    summary: { bySeverity: {}, byDetector: {} },
  };
}

/**
 * scanMcp(flags, opts) — the scan.js dispatch target for `scan --mcp`.
 * Builds the envelope, prints it (JSON or human), and returns
 * { ran:true, code, findingsCount } for lib/cli.js's exit-code
 * propagation. Never throws.
 */
function scanMcp(flags = {}, opts = {}) {
  let envelope;
  try {
    envelope = buildEnvelope(flags, opts);
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
