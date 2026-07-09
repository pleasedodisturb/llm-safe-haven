'use strict';

/**
 * Credential passthrough detector (Phase 5, MCPD-04).
 *
 * Grades MCP server `env` values by how they carry credentials:
 *   - an inlined literal that matches a known secret pattern is the real
 *     finding (critical) — SECRET_PATTERNS is REUSED (read-only require)
 *     from hooks/secret-guard.js per D-13, never re-implemented here.
 *   - a named interpolation token (`${env:NAME}` / `${input:NAME}`) is the
 *     RECOMMENDED clean pattern and yields zero findings (D-14).
 *   - an inlined literal that does not match a known pattern but is
 *     high-entropy, or sits under a sensitive-sounding key name, is a
 *     softer (high) finding — it might be a secret, might not.
 *   - a wildcard/whole-environment passthrough token (e.g. `*`) is only
 *     advisory (low) — it is a scoping smell, not evidence of a leak.
 *
 * D-15: findings NEVER carry the raw matched value — only the
 * SECRET_PATTERNS entry name and a maskedPreview() (first 4 chars +
 * '…[redacted]'). A dedicated regression test asserts no finding message
 * contains the raw secret substring.
 *
 * The "broad env inheritance" check is deliberately narrowed to visible
 * env-value tokens (a literal '*' or an explicit whole-env interpolation
 * token) because the frozen normalizeServer() shape (Phase 4) carries no
 * structural "inherits all host env vars" flag — RESEARCH.md Pitfall 3 /
 * Assumption A3. A config that inherits the shell environment implicitly
 * (by omitting `env` entirely) is invisible to a static parser and is out
 * of scope for this detector.
 */

const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');
const { SECRET_PATTERNS } = require('../../../hooks/secret-guard.js');

const id = 'credential-passthrough';
const requirement = 'MCPD-04';

// Static, hand-authored regex literals only — never build a RegExp from
// server-controlled data (ReDoS/injection defense, T-05-06).
const NAMED_INTERPOLATION_RE = /^\$\{(env|input):[A-Za-z_][A-Za-z0-9_]*\}$/;
const SENSITIVE_KEY_RE = /(token|secret|api[_-]?key|password|passwd|credential|private[_-]?key|auth)/i;
const BROAD_INHERITANCE_RE = /^\s*\*\s*$/;
const WHOLE_ENV_PASSTHROUGH_TOKENS = new Set(['${env:*}', '${input:*}']);

/**
 * Returns '[redacted]' for empty/non-string input, else the first 4 chars
 * of the value followed by '…[redacted]' — never the full value (D-15).
 */
function maskedPreview(value) {
  if (typeof value !== 'string' || value.length === 0) return '[redacted]';
  return `${value.slice(0, 4)}…[redacted]`;
}

function isCleanInterpolation(value) {
  return typeof value === 'string' && NAMED_INTERPOLATION_RE.test(value);
}

function isBroadInheritance(value) {
  if (typeof value !== 'string') return false;
  if (BROAD_INHERITANCE_RE.test(value)) return true;
  return WHOLE_ENV_PASSTHROUGH_TOKENS.has(value);
}

/**
 * High-entropy heuristic (D-05 "high" tier). Pinned thresholds — do not
 * loosen without re-running the boundary tests: length >= 20 AND at
 * least one lowercase, one uppercase, and one digit char, AND no ASCII
 * whitespace. The mixed-case-plus-digit requirement deliberately excludes
 * single-case hex/UUID-shaped values to cut false positives.
 */
function isHighEntropy(value) {
  return (
    value.length >= 20 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /[0-9]/.test(value) &&
    !/\s/.test(value)
  );
}

function run(servers, context = {}) {
  const findings = [];

  for (const server of Array.isArray(servers) ? servers : []) {
    const env = server.env || {};

    for (const [key, value] of Object.entries(env)) {
      if (typeof value !== 'string') continue;
      if (isCleanInterpolation(value)) continue;

      const secretMatch = SECRET_PATTERNS.find(({ pattern }) => pattern.test(value));
      if (secretMatch) {
        findings.push(Finding({
          id: `${id}/inlined-secret`,
          detector: id,
          severity: SEVERITY.CRITICAL,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}" env var "${key}" appears to contain an inlined ${secretMatch.name} (${maskedPreview(value)}) — replace with `
            + `\${env:${key}}\` interpolation instead of a raw literal.`,
        }));
        continue;
      }

      if (SENSITIVE_KEY_RE.test(key)) {
        findings.push(Finding({
          id: `${id}/sensitive-name-literal`,
          detector: id,
          severity: SEVERITY.HIGH,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}" env var "${key}" has a sensitive-sounding name but an inlined literal value (${maskedPreview(value)}) `
            + `— use \${env:${key}}\` or \${input:${key}}\` interpolation instead.`,
        }));
        continue;
      }

      if (isHighEntropy(value)) {
        findings.push(Finding({
          id: `${id}/high-entropy-literal`,
          detector: id,
          severity: SEVERITY.HIGH,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}" env var "${key}" is a high-entropy inlined literal (${maskedPreview(value)}) that may be a secret `
            + `— use named interpolation instead of a raw literal.`,
        }));
        continue;
      }

      if (isBroadInheritance(value)) {
        findings.push(Finding({
          id: `${id}/broad-inheritance`,
          detector: id,
          severity: SEVERITY.LOW,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}" env var "${key}" passes through the whole environment ("${value}") — consider scoping to named `
            + `interpolation instead of a wildcard passthrough.`,
        }));
      }
    }
  }

  return findings;
}

module.exports = { id, requirement, run };
