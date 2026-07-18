'use strict';

// ANSI color codes — zero dependencies
// Respect NO_COLOR (https://no-color.org/) and non-TTY output
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

const C = useColor ? {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
} : { reset: '', bold: '', dim: '', green: '', red: '', yellow: '', cyan: '', white: '' };

const PASS = `${C.green}\u2713${C.reset}`;
const FAIL = `${C.red}\u2717${C.reset}`;
const WARN = `${C.yellow}\u25c6${C.reset}`;
const DOT = `${C.dim}\u00b7${C.reset}`;

const LEVEL_LABELS = [
  'Exposed',
  'Basic',
  'Guarded',
  'Hardened',
  'Fortified',
];

const LEVEL_BAR_CHARS = [0, 5, 10, 15, 20];

function printHeader() {
  console.log('');
  console.log(`${C.bold}${C.cyan}  \u{1F512} LLM Safe Haven \u2014 Security Scorecard${C.reset}`);
  console.log('');
}

function printAgentSection(agent, detected, hardenResult, auditResult) {
  const icon = detected.found ? PASS : DOT;
  const version = detected.version ? ` ${C.dim}${detected.version}${C.reset}` : '';
  const tierLabel = agent.tier === 1 ? 'Full support' : agent.tier === 2 ? 'Solid support' : 'Advise only';

  console.log(`  ${icon} ${C.bold}${agent.name}${C.reset}${version} ${C.dim}(${tierLabel})${C.reset}`);

  if (!detected.found) return;

  // Show hardening actions
  if (hardenResult) {
    for (const action of hardenResult.actions) {
      console.log(`    ${PASS} ${action}`);
    }
    for (const warning of hardenResult.warnings) {
      console.log(`    ${WARN} ${C.yellow}${warning}${C.reset}`);
    }
  }

  // Show audit checks
  if (auditResult) {
    for (const check of auditResult.checks) {
      const icon = check.pass ? PASS : FAIL;
      console.log(`    ${icon} ${check.name} \u2014 ${C.dim}${check.detail}${C.reset}`);
    }
  }
}

function printEnvScan(envFiles) {
  console.log('');
  console.log(`  ${C.bold}Project scan:${C.reset}`);

  if (envFiles.length === 0) {
    console.log(`    ${PASS} No .env files found`);
  } else {
    console.log(`    ${FAIL} ${C.red}${envFiles.length} .env file(s) found:${C.reset}`);
    for (const f of envFiles.slice(0, 10)) {
      console.log(`      ${C.dim}${f}${C.reset}`);
    }
    if (envFiles.length > 10) {
      console.log(`      ${C.dim}...and ${envFiles.length - 10} more${C.reset}`);
    }
  }
}

function printLevel(level, caps = []) {
  const label = LEVEL_LABELS[level] || 'Unknown';
  const filled = LEVEL_BAR_CHARS[level] || 0;
  const empty = 20 - filled;
  const bar = '\u2588'.repeat(filled) + '\u2591'.repeat(empty);

  // BUG-6: Compute box width dynamically based on content
  const content = ` ${bar}  Level ${level}: ${label} `;
  const borderWidth = content.length;
  const horizontalBorder = '\u2500'.repeat(borderWidth);

  console.log('');
  console.log(`  ${C.bold}Security Level: ${level} of 4${C.reset}`);
  console.log(`  \u250C${horizontalBorder}\u2510`);
  console.log(`  \u2502${content}\u2502`);
  console.log(`  \u2514${horizontalBorder}\u2518`);

  // D-08/D-09: explain every active cap so a demoted level is never a
  // bare number \u2014 the reason string (built by computeSecurityLevel)
  // already carries the actionable hint, so it is printed verbatim.
  // Empty caps -> no extra lines (backward-compatible with the
  // install.js/scan.js callers that pass only `level`).
  // IN-01 defense-in-depth: cap.reason is built by computeSecurityLevel
  // from constants today, but it renders on the same hostile-report
  // surface — sanitize at the print site so a future reason that embeds
  // config-derived data can never inject terminal escapes.
  for (const cap of caps) {
    console.log(`  ${C.dim}Level capped at ${cap.cappedTo} (was ${cap.cappedFrom}): ${sanitizeForTerminal(cap.reason)}${C.reset}`);
  }
}

function printNextSteps(level, caps = []) {
  console.log('');
  console.log(`  ${C.bold}Next steps:${C.reset}`);

  // D-10: when an active MCP cap (findings or incomplete-scan) is why
  // the level is stuck below 3, mention resolving it BEFORE the
  // credential-proxy step — otherwise the operator chases the wrong
  // next action. Empty caps (or non-MCP caps) leave the message
  // unchanged, so install.js/scan.js callers passing only `level` are
  // unaffected.
  const hasMcpCap = caps.some((c) => c.id === 'mcp-findings' || c.id === 'mcp-incomplete');

  if (level < 1) {
    console.log(`    Run ${C.cyan}npx llm-safe-haven${C.reset} to install basic hooks`);
  } else if (level < 2) {
    console.log(`    Set up audit logging and remove .env files`);
  } else if (level < 3) {
    if (hasMcpCap) {
      console.log(`    Resolve MCP findings (${C.cyan}npx llm-safe-haven scan --mcp${C.reset}), then set up a credential proxy (see docs/credential-management.md)`);
    } else {
      console.log(`    Set up a credential proxy (see docs/credential-management.md)`);
    }
  } else if (level < 4) {
    console.log(`    Run agents in containers for full isolation`);
  } else {
    console.log(`    ${C.green}Maximum hardening achieved${C.reset}`);
  }

  console.log(`    Docs: ${C.dim}https://github.com/pleasedodisturb/llm-safe-haven${C.reset}`);
  console.log('');
}

// CR-01: strip C0 control chars, DEL, and C1 control chars so a hostile
// config-supplied server name (or any string derived from one, like a
// detector message) can never inject ANSI/OSC terminal escapes into the
// operator's terminal (CWE-150). MCP configs are attacker-controlled input
// per this tool's threat model; the report renderer is the single print
// choke point, so sanitization lives here. Replaced with U+FFFD so the
// operator SEES that something was stripped rather than it vanishing.
//
// Also neutralizes Unicode format/bidi controls (\p{Cf}: U+200B-200F
// zero-widths, U+202A-202E bidi embeddings/overrides like RLO, U+2066-
// U+2069 bidi isolates, U+FEFF, ...) — the same class this project's own
// tool-poisoning detector treats as hostile. An RLO in a server name can
// visually reorder a report line to spoof what the operator reads.
function sanitizeForTerminal(s) {
  return String(s == null ? '' : s).replace(/[\x00-\x1f\x7f-\x9f]|\p{Cf}/gu, '�');
}

// Frozen enums from the schema contract — derived here rather than
// re-listed as literals so a (hypothetical, additive) enum change can
// never silently desynchronize the renderer. Verified acyclic:
// mcp/base.js requires only fs.
const { SEVERITY, CONFIDENCE, EXIT, splitFindingsByConfidence } = require('./mcp/base.js');

/**
 * computeSecurityLevel(inputs) — the SINGLE source of truth for Security
 * Level math (SCOR-03). Both the human scorecard (lib/audit.js,
 * lib/install.js) and any future --json path MUST call this instead of
 * re-deriving the level inline — the duplicated inline math in
 * lib/audit.js (BUG-3: `result.agents` read from a still-being-built
 * object literal, a self-reference TDZ bug) is exactly the divergence
 * this function exists to prevent.
 *
 * inputs: {
 *   agentLevels: number[]   — per-agent audit levels (already computed)
 *   envFileCount: number    — count of tracked .env files found
 *   mcp: { ran, exitCode, verifiedCount, unverifiedCount }
 * }
 *
 * Semantics (D-06/D-07):
 *   - base = the highest agent level (0 if no agents), computed as a
 *     plain local BEFORE any return object is built — never read a
 *     partially-constructed object's own property (the BUG-3
 *     anti-pattern this replaces).
 *   - env-files ceiling: any tracked .env file caps the level at 1
 *     (D-06/D-09 — always paired with a complete, human-readable
 *     reason string).
 *   - MCP ceiling: an incomplete scan (mcp.ran === false OR
 *     mcp.exitCode === EXIT.INCOMPLETE) — and equally a MISSING or
 *     shapeless `mcp` input (WR-02: unknown MCP state is treated as
 *     not-ran, never as clean) — fails closed at ceiling 2 — an
 *     unfinished scan can never be presented as if it certified Level
 *     3+ (D-07/D-14, the locked security-gate-exit-codes rule).
 *     Otherwise, one or more VERIFIED MCP findings caps at ceiling 2.
 *     Only one of these two MCP caps is ever recorded — an incomplete
 *     scan's finding count is untrustworthy, so incomplete takes
 *     precedence over mcp-findings.
 *   - Unverified-only MCP findings NEVER cap the level (SCOR-02
 *     regression guard) — mcp.unverifiedCount is read by nothing here.
 *   - The final level is the min of base and every ceiling that
 *     actually fired (a ceiling only "fires" — and is recorded as a
 *     cap — when it is strictly below base; nothing to reduce
 *     otherwise).
 *
 * Pure: no I/O, no console output, no process.exit.
 */
function computeSecurityLevel({ agentLevels = [], envFileCount = 0, mcp } = {}) {
  // WR-02: fail CLOSED on absence — a caller that omits `mcp` (or passes
  // a shapeless object) has NOT proven the MCP scan ran, so "MCP state
  // unknown" is scored as an incomplete scan (ceiling 2), never silently
  // as "scanned and clean". `typeof mcp.ran === 'boolean'` is the shape
  // proof: both real producers (lib/audit.js getMcpInputs) always set it.
  const m = (mcp && typeof mcp.ran === 'boolean')
    ? mcp
    : { ran: false, exitCode: EXIT.INCOMPLETE, verifiedCount: 0, unverifiedCount: 0 };
  const base = agentLevels.length ? Math.max(0, ...agentLevels) : 0;
  const caps = [];
  const firedCeilings = [];

  // env-files cap: ceiling 1.
  if (envFileCount > 0) {
    const ceiling = 1;
    if (base > ceiling) {
      caps.push({
        id: 'env-files',
        cappedFrom: base,
        cappedTo: ceiling,
        reason: '.env file(s) present — remove tracked .env files to restore Level 2+',
      });
      firedCeilings.push(ceiling);
    }
  }

  // MCP cap: incomplete scan takes precedence over mcp-findings — only
  // one of the two is ever recorded (an unfinished scan's finding count
  // is untrustworthy).
  const mcpIncomplete = m.ran === false || m.exitCode === EXIT.INCOMPLETE;
  if (mcpIncomplete) {
    const ceiling = 2;
    if (base > ceiling) {
      caps.push({
        id: 'mcp-incomplete',
        cappedFrom: base,
        cappedTo: ceiling,
        reason: 'MCP scan could not complete — Level 3+ cannot be certified',
      });
      firedCeilings.push(ceiling);
    }
  } else if (m.verifiedCount > 0) {
    const ceiling = 2;
    if (base > ceiling) {
      caps.push({
        id: 'mcp-findings',
        cappedFrom: base,
        cappedTo: ceiling,
        reason: `${m.verifiedCount} MCP finding(s) — run npx llm-safe-haven scan --mcp for details`,
      });
      firedCeilings.push(ceiling);
    }
  }
  // mcp.unverifiedCount is intentionally never read above (SCOR-02).

  const level = firedCeilings.length ? Math.min(base, ...firedCeilings) : base;

  return { level, caps };
}

// Severity sort order (D-05): critical -> high -> medium -> low -> info.
const MCP_SEVERITY_ORDER = [
  SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW, SEVERITY.INFO,
].reduce((order, severity, index) => {
  order[severity] = index;
  return order;
}, {});

// Severity glyph mapping (D-05): critical/high = red, medium/low = yellow,
// info = dim. Reuses the SAME C color tokens as PASS/FAIL/WARN/DOT above —
// these are new glyphs (visually distinct from PASS/FAIL/WARN/DOT), never
// a new color palette, and never bypassing the useColor/NO_COLOR gate.
function mcpSeverityGlyph(severity) {
  if (severity === 'critical' || severity === 'high') return `${C.red}✖${C.reset}`;
  if (severity === 'medium' || severity === 'low') return `${C.yellow}◆${C.reset}`;
  return `${C.dim}●${C.reset}`;
}

// D-06: unverified findings ALWAYS render with this dim, neutral glyph —
// never the severity-colored red/yellow glyph above, regardless of
// severity. This is the "distinct fourth visual state" Phase 8 (SCOR-02)
// reuses.
const MCP_UNVERIFIED_GLYPH = `${C.dim}●${C.reset}`;

/**
 * printMcpAuditSection(envelope, mcp) — a COMPACT posture line for the
 * main scorecard (audit/install), sitting beside the .env block. `mcp`
 * is the already-computed { verifiedCount, unverifiedCount } produced by
 * lib/audit.js getMcpInputs (F8: accept the counts instead of
 * re-filtering); a caller that omits it (or passes a shapeless object)
 * gets a defensive re-derivation via the shared
 * splitFindingsByConfidence helper — never a throw. This is
 * deliberately NOT the full per-server report (printMcpScan owns that).
 * State precedence:
 *
 *   1. incomplete (envelope == null, or exitCode === EXIT.INCOMPLETE) —
 *      WARN/yellow, naming any unfinished sources and pointing at
 *      `scan --mcp` for detail. NOT mutually exclusive with the finding
 *      lines below (Phase 8 review F2): findings already produced before
 *      the scan failed are PARTIAL data — a floor, not a total — and
 *      must never be masked by the warning. When an incomplete envelope
 *      also carries verified/unverified findings, those count lines
 *      render IN ADDITION to the warning.
 *   2. verifiedCount > 0 — FAIL/red, the SCOR-01 "certified clean"
 *      gate line.
 *   3. unverifiedCount > 0 — dim/neutral via MCP_UNVERIFIED_GLYPH,
 *      NEVER red/yellow (D-06/SCOR-02 — an unverified-only scan must
 *      never look like a failure).
 *   4. clean — PASS/green (only when the scan completed).
 *
 * Every envelope-derived string (source agentId/scope, any name) is
 * passed through sanitizeForTerminal() before printing (T-08-01,
 * CWE-150) — the same choke point printMcpScan uses. Never throws;
 * findings/servers/sources default to [] on a missing/malformed
 * envelope.
 */
function printMcpAuditSection(envelope, mcp) {
  const findings = (envelope && envelope.findings) || [];
  const servers = (envelope && envelope.servers) || [];
  const sources = (envelope && envelope.sources) || [];

  // F8: the production callers pass getMcpInputs' already-derived counts;
  // the fallback re-derives through the SAME shared helper, so the
  // confidence-filter expression still exists in exactly one place.
  const { verifiedCount, unverifiedCount } =
    (mcp && typeof mcp.verifiedCount === 'number' && typeof mcp.unverifiedCount === 'number')
      ? mcp
      : splitFindingsByConfidence(findings);
  const incomplete = envelope == null || envelope.exitCode === EXIT.INCOMPLETE;
  const serverCount = servers.length;

  console.log('');
  console.log(`  ${C.bold}MCP scan:${C.reset}`);

  if (incomplete) {
    const unfinished = sources.filter((s) => s && s.status !== 'parsed' && s.status !== 'not-found');
    if (unfinished.length > 0) {
      const names = unfinished.map((s) => sanitizeForTerminal(s.agentId)).join(', ');
      console.log(`    ${WARN} ${C.yellow}MCP scan could not complete (${unfinished.length} source(s): ${names}) — run npx llm-safe-haven scan --mcp for details${C.reset}`);
    } else {
      console.log(`    ${WARN} ${C.yellow}MCP scan could not complete — run npx llm-safe-haven scan --mcp for details${C.reset}`);
    }
    // F2: findings produced BEFORE the scan failed are partial data (a
    // floor, not a total) — the warning must never mask them. Render the
    // same red/dim count lines the complete states use, after the WARN.
    if (verifiedCount > 0) {
      console.log(`    ${FAIL} ${C.red}${verifiedCount} MCP finding(s) — run npx llm-safe-haven scan --mcp for details${C.reset}`);
    }
    if (unverifiedCount > 0) {
      console.log(`    ${MCP_UNVERIFIED_GLYPH} ${C.dim}${unverifiedCount} unverified notice(s) — run scan --mcp --online to verify${C.reset}`);
    }
  } else if (verifiedCount > 0) {
    console.log(`    ${FAIL} ${C.red}${verifiedCount} MCP finding(s) — run npx llm-safe-haven scan --mcp for details${C.reset}`);
  } else if (unverifiedCount > 0) {
    console.log(`    ${MCP_UNVERIFIED_GLYPH} ${C.dim}${unverifiedCount} unverified notice(s) — run scan --mcp --online to verify${C.reset}`);
  } else {
    console.log(`    ${PASS} No MCP findings (${serverCount} server(s) checked)`);
  }
}

function sortFindingsBySeverity(findings) {
  return findings.slice().sort((a, b) => {
    const orderA = MCP_SEVERITY_ORDER[a.severity];
    const orderB = MCP_SEVERITY_ORDER[b.severity];
    return (orderA === undefined ? 5 : orderA) - (orderB === undefined ? 5 : orderB);
  });
}

function printMcpFindingLine(finding) {
  // IN-01 defense-in-depth: id and severity are internally-constructed
  // constants today, but they render interleaved with attacker-influenced
  // fields on the hostile-report surface — a future detector that
  // interpolates config data into an id must not regress silently.
  const label = sanitizeForTerminal(String(finding.severity).toUpperCase());
  const id = sanitizeForTerminal(finding.id);
  // CR-01: finding.message embeds the raw server.name from the scanned
  // (attacker-controlled) config — sanitize before it reaches the terminal.
  const msg = sanitizeForTerminal(finding.message);
  if (finding.confidence === CONFIDENCE.UNVERIFIED) {
    // D-06: dim/neutral only — no C.red/C.yellow anywhere on this line.
    console.log(`      ${MCP_UNVERIFIED_GLYPH} ${C.dim}${label} ${id} — ${msg}${C.reset}`);
  } else {
    console.log(`      ${mcpSeverityGlyph(finding.severity)} ${label} ${id} — ${msg}`);
  }
}

// Prints one server (or General) group's findings: verified findings first
// (severity-sorted, D-05), then — if any exist — a dim sub-line separator
// followed by unverified findings (also severity-sorted, D-06).
function printMcpFindingGroup(findings) {
  const verified = sortFindingsBySeverity(findings.filter((f) => f.confidence !== CONFIDENCE.UNVERIFIED));
  const unverified = sortFindingsBySeverity(findings.filter((f) => f.confidence === CONFIDENCE.UNVERIFIED));

  for (const finding of verified) printMcpFindingLine(finding);

  if (unverified.length > 0) {
    console.log(`      ${C.dim}unverified — run with --online to verify${C.reset}`);
    for (const finding of unverified) printMcpFindingLine(finding);
  }
}

/**
 * Human-readable presentation of the scan-mcp.js envelope (D-04..D-07,
 * MCPO-01). Findings are grouped per server under an
 * `agent › server-name (scope)` header, sorted critical -> high ->
 * medium -> low -> info within each group; findings with agentId:null
 * (tool-shadowing, typosquat/allowlist-unavailable) render in a final
 * General group (D-07). Unverified findings render in a distinct dim
 * style, never red/yellow (D-06). Non-parsed/non-not-found sources are
 * listed with their status so an exit-2 scan explains itself (D-07).
 *
 * Reads ONLY the frozen Finding fields (id/detector/severity/confidence/
 * agentId/scope/serverName/message) — never reaches back into
 * envelope.servers[] for raw env/args/headers/url values (T-07-06).
 * serverName and message are still DERIVED from the raw (hostile) config's
 * server.name, so every config-derived string is passed through
 * sanitizeForTerminal() before printing (CR-01, CWE-150).
 *
 * Never crashes on findings:[]/servers:[]/sources:[] (defensive defaults
 * below) and has no try/catch of its own — the caller in lib/scan-mcp.js
 * already wraps the printing call in a single point of catch.
 */
function printMcpScan(envelope) {
  const sources = (envelope && envelope.sources) || [];
  const servers = (envelope && envelope.servers) || [];
  const findings = (envelope && envelope.findings) || [];

  console.log('');
  console.log(`  ${C.bold}MCP server config scan:${C.reset}`);
  console.log(`    ${C.dim}${sources.length} source(s) checked, ${servers.length} server(s) discovered${C.reset}`);

  // The summary header mirrors the exit-code semantics (Phase 6 D-14 /
  // Phase 7 D-08): only confidence:verified findings count toward the red
  // FAIL line, exactly as only they produce exit 1. Unverified findings
  // get a SEPARATE dim, neutral notice line (D-06 style — never
  // red/yellow); an unverified-only scan exits 0 and accordingly shows no
  // red header at all.
  const { verifiedCount, unverifiedCount } = splitFindingsByConfidence(findings);

  if (findings.length === 0) {
    console.log(`    ${PASS} No MCP findings`);
  } else {
    if (verifiedCount > 0) {
      console.log(`    ${FAIL} ${C.red}${verifiedCount} finding(s)${C.reset}`);
    }
    if (unverifiedCount > 0) {
      console.log(`    ${C.dim}${unverifiedCount} unverified notice(s) — run with --online to verify${C.reset}`);
    }
    console.log('');

    // Group by (agentId, scope, serverName); agentId:null -> General (D-07).
    // Discovery order (first-seen) is used for group ordering — findings
    // already arrive in a deterministic order from the detector registry
    // (alphabetical by detector id), so this stays deterministic too.
    const groupsByKey = new Map();
    const generalGroup = [];

    for (const finding of findings) {
      if (finding.agentId === null || finding.agentId === undefined) {
        generalGroup.push(finding);
        continue;
      }
      const key = `${finding.agentId} ${finding.scope} ${finding.serverName}`;
      let group = groupsByKey.get(key);
      if (!group) {
        group = { agentId: finding.agentId, scope: finding.scope, serverName: finding.serverName, findings: [] };
        groupsByKey.set(key, group);
      }
      group.findings.push(finding);
    }

    // A Map preserves insertion order, so iterating groupsByKey.values()
    // IS the first-seen discovery order — no separate order array needed.
    // The General group is separate and stays last.
    for (const group of groupsByKey.values()) {
      const scopeLabel = group.scope ? ` (${sanitizeForTerminal(group.scope)})` : '';
      // CR-01: serverName is the raw server.name copied verbatim from the
      // hostile config — sanitize it (and, defensively, agentId/scope,
      // which flow through the same Finding fields) at the print boundary.
      console.log(`    ${C.bold}${sanitizeForTerminal(group.agentId)} › ${sanitizeForTerminal(group.serverName) || 'unknown'}${scopeLabel}${C.reset}`);
      printMcpFindingGroup(group.findings);
      console.log('');
    }

    if (generalGroup.length > 0) {
      console.log(`    ${C.bold}General${C.reset}`);
      printMcpFindingGroup(generalGroup);
      console.log('');
    }
  }

  // D-07: list any source whose status is neither 'parsed' nor 'not-found'
  // so an exit-2 scan explains itself.
  const unfinishedSources = sources.filter((s) => s && s.status !== 'parsed' && s.status !== 'not-found');
  if (unfinishedSources.length > 0) {
    console.log(`    ${C.dim}Sources that did not complete:${C.reset}`);
    for (const source of unfinishedSources) {
      // CR-01 defense-in-depth: these are produced by our own discovery
      // layer today, but they render on the same hostile-report surface.
      console.log(`      ${WARN} ${sanitizeForTerminal(source.agentId)} (${sanitizeForTerminal(source.scope)}) — ${sanitizeForTerminal(source.status)}`);
    }
  }

  console.log('');
}

module.exports = {
  printHeader,
  printAgentSection,
  printEnvScan,
  printLevel,
  printNextSteps,
  printMcpScan,
  printMcpAuditSection,
  computeSecurityLevel,
  sanitizeForTerminal,
  C, PASS, FAIL, WARN, DOT,
};
