'use strict';

/**
 * Tool-poisoning heuristics detector (Phase 5, MCPD-05).
 *
 * Static config files cannot see a live MCP server's tools/list response —
 * hidden-instruction tool descriptions are a runtime phenomenon this
 * detector structurally cannot observe. Every finding message carries
 * STATIC_HEURISTIC_NOTE, explicitly disclosing that this is a static
 * heuristic, not equivalent to live tools/list inspection (D-09).
 *
 * Tier 1 (always): scan every normalized string field (name, command,
 * args, env values, url, header values) for imperative-injection phrases
 * and invisible/bidi Unicode (\p{Cf}).
 *
 * Tier 2 (best-effort, npm-only in Phase 5 — Deferred: uvx/pip package
 * metadata): when server.command is npx/uvx and its package spec resolves
 * to a locally installed package (project node_modules/ or the npx
 * cache — PATH LOOKUP ONLY, never require()/exec/fetch the resolved
 * package, T-05-09), its package.json description is scanned with the
 * same Tier-1 rules. ANY resolution failure (unreadable, non-ok,
 * JSON.parse throw, no cache) returns null and is skipped SILENTLY — no
 * finding, no error, no exit-code change. This is a deliberate divergence
 * from the parsers' fail-closed readConfigSafe idiom (D-08; see
 * 05-PATTERNS.md) — Tier 2 is best-effort enrichment, not a required scan
 * step.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { Finding, SEVERITY, CONFIDENCE, readConfigSafe } = require('../base.js');

const id = 'tool-poisoning';
const requirement = 'MCPD-05';

const STATIC_HEURISTIC_NOTE = 'This is a static heuristic, not equivalent to live tools/list inspection.';

// Static, hand-authored regex literals only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-11). Seeded from
// published tool-poisoning-attack research and docs/threat-model.md
// incidents (hidden-instruction / exfiltration phrasing). [ASSUMED — seed
// list, not exhaustive; cheap to extend per CONTEXT.md discretion.]
const INJECTION_PHRASES = [
  /ignore (all )?previous instructions/i,
  /disregard (the )?(above|prior) instructions/i,
  /do not (tell|mention|inform) the user/i,
  /don'?t (tell|mention|inform) the user/i,
  /without (informing|telling|notifying) the user/i,
  /before (using|calling) this tool,? (you must|read|first)/i,
  /read\s+(~|\$HOME)?\/?\.(ssh|aws|npmrc|env)/i,
  /new (system )?instructions?:/i,
  /you are now (in|impersonating)/i,
  /override (your|the) (system|previous) (prompt|instructions)/i,
  /<IMPORTANT>/i,
  /silently (send|exfiltrate|transmit|forward)/i,
];

// Verified: catches bidi-control formatting characters, zero-width
// characters, word joiner, BOM, the Arabic Letter Mark, and the entire
// Unicode Tag block in ONE regex — all share Unicode General Category
// "Format" (Cf).
const INVISIBLE_UNICODE_RE = /\p{Cf}/u;

function hasInjectionPhrase(value) {
  return typeof value === 'string' && INJECTION_PHRASES.some((re) => re.test(value));
}

function hasInvisibleUnicode(value) {
  return typeof value === 'string' && INVISIBLE_UNICODE_RE.test(value);
}

/**
 * Collects every string value from a normalized server's fields that
 * Tier 1 scans: name, command, each arg, each env value, url, each
 * header value. Non-string values (already guaranteed absent by
 * normalizeServer(), but defended anyway) are dropped.
 */
function collectStringFields(server) {
  const values = [];
  if (typeof server.name === 'string') values.push(server.name);
  if (typeof server.command === 'string') values.push(server.command);
  for (const arg of Array.isArray(server.args) ? server.args : []) {
    if (typeof arg === 'string') values.push(arg);
  }
  for (const v of Object.values(server.env || {})) {
    if (typeof v === 'string') values.push(v);
  }
  if (typeof server.url === 'string') values.push(server.url);
  for (const v of Object.values(server.headers || {})) {
    if (typeof v === 'string') values.push(v);
  }
  return values;
}

function commandBasename(command) {
  if (typeof command !== 'string' || command === '') return null;
  return path.basename(command);
}

/**
 * Derives the npm package name from an npx/uvx-style args array: skips
 * leading flag tokens (and '--package'/'-p' plus its value, mirroring
 * unpinned-execution's leading-flag-skipping logic), then strips any
 * trailing @version/@tag suffix while preserving a leading @scope/.
 * Returns null if no candidate package-spec token is found.
 */
function derivePackageName(args) {
  const list = Array.isArray(args) ? args : [];
  for (let i = 0; i < list.length; i++) {
    const arg = list[i];
    if (typeof arg !== 'string') continue;
    if (arg === '--package' || arg === '-p') {
      i++; // skip the following value too
      continue;
    }
    if (arg.startsWith('-')) continue;
    const m = arg.match(/^(@[^/@\s]+\/)?([^@/\s]+)(@[^\s]+)?$/);
    if (!m) return arg;
    return `${m[1] || ''}${m[2]}`;
  }
  return null;
}

function safeExtractDescription(raw) {
  try {
    const pkg = JSON.parse(raw);
    return typeof pkg.description === 'string' ? pkg.description : null;
  } catch {
    return null;
  }
}

/**
 * Tier 2: best-effort, path-lookup-only local package description
 * resolution. ANY failure returns null (skip silently — D-08). Never
 * requires/execs/fetches the resolved package — readConfigSafe reads are
 * the only I/O performed.
 *
 * opts.cwd/opts.homedir default to process.cwd()/os.homedir() so tests
 * can inject deterministic tmpdir paths.
 */
function resolveLocalPackageDescription(pkgName, opts = {}) {
  if (!pkgName) return null;
  const cwd = opts.cwd || process.cwd();
  const homedir = opts.homedir || os.homedir();

  // 1. Project-local node_modules — the common, fast case.
  const localPkgJson = path.join(cwd, 'node_modules', ...pkgName.split('/'), 'package.json');
  const local = readConfigSafe(localPkgJson, opts);
  if (local.ok) {
    const description = safeExtractDescription(local.raw);
    if (description !== null) return description;
  }

  // 2. npx cache — scan hash directories for a matching package, bounded
  //    and read-only.
  const npxDir = path.join(homedir, '.npm', '_npx');
  let hashDirs;
  try {
    hashDirs = fs.readdirSync(npxDir);
  } catch {
    return null; // no npx cache — skip silently
  }
  for (const hash of hashDirs) {
    const candidatePkgJson = path.join(npxDir, hash, 'node_modules', ...pkgName.split('/'), 'package.json');
    const candidate = readConfigSafe(candidatePkgJson, opts);
    if (candidate.ok) {
      const description = safeExtractDescription(candidate.raw);
      if (description !== null) return description;
    }
  }
  return null; // unresolvable — no finding, no error (D-08)
}

function run(servers, context = {}) {
  const findings = [];

  for (const server of Array.isArray(servers) ? servers : []) {
    const values = collectStringFields(server);

    if (values.some(hasInjectionPhrase)) {
      findings.push(Finding({
        id: `${id}/injection-phrase`,
        detector: id,
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}" has a config field matching a known imperative-injection phrase. ${STATIC_HEURISTIC_NOTE}`,
      }));
    }

    if (values.some(hasInvisibleUnicode)) {
      findings.push(Finding({
        id: `${id}/invisible-unicode`,
        detector: id,
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}" has a config field containing invisible/bidi Unicode characters. ${STATIC_HEURISTIC_NOTE}`,
      }));
    }

    // Tier 2 (best-effort, npm-only): only attempted when the command is
    // npx/uvx — the package-spec-in-args shape this resolution assumes.
    const bin = commandBasename(server.command);
    if (bin === 'npx' || bin === 'uvx') {
      const pkgName = derivePackageName(server.args);
      const description = resolveLocalPackageDescription(pkgName, context);
      if (description !== null && (hasInjectionPhrase(description) || hasInvisibleUnicode(description))) {
        findings.push(Finding({
          id: `${id}/package-metadata`,
          detector: id,
          severity: SEVERITY.MEDIUM,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}"'s locally resolved package description contains a suspicious phrase or invisible Unicode. ${STATIC_HEURISTIC_NOTE}`,
        }));
      }
    }
  }

  return findings;
}

module.exports = { id, requirement, run };
