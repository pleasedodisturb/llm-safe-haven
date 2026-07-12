'use strict';

/**
 * Provenance attestation-presence detector (Phase 6, MCPD-02).
 *
 * For every npm-only server (D-08: commandBasename(server.command) ===
 * 'npx', deliberately NEVER 'uvx' here — unlike typosquat.js, this
 * detector does not gate on uvx at all), checks whether the resolved
 * package has an npm `dist.attestations` provenance attestation. This is
 * the first — and only — network-calling, async detector in the
 * codebase (D-09/D-11); every other Phase 5 detector's run() is
 * synchronous.
 *
 * Offline (default, context.online !== true): reports the distinct,
 * non-alarming provenance/unverified-offline state and makes ZERO
 * network calls. The code is structured so `fetchImpl` is never
 * referenced at all on this branch — not called-then-discarded, simply
 * unreachable — which is what makes "zero fetch attempts" a
 * unit-testable code-path property rather than a behavioral promise
 * (D-11, MCPO-04).
 *
 * Online: fetches https://registry.npmjs.org/<name>/<version-or-latest>
 * through a hardened, SSRF-safe, timeout-and-size-capped client (D-12)
 * and maps the result through the D-09 state machine:
 *   attestations present   -> no finding (clean)
 *   attestations absent    -> provenance/no-attestation   (low, verified)
 *   fetch failed (any way) -> provenance/fetch-failed      (info, unverified)
 *
 * This is a PRESENCE check only, never a cryptographic Sigstore
 * verification — every message says "has/lacks a provenance
 * attestation", never "verified authentic" (D-09).
 */

const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');
const { commandBasename, derivePackageName, isSafePackageName } = require('../npx-args.js');

const id = 'provenance';
const requirement = 'MCPD-02';

// D-12: pinned literal, NEVER config-derived or built from server/user
// input — this is the project's SSRF defense for the one outbound
// network call this phase introduces.
const REGISTRY_HOST = 'registry.npmjs.org';
// D-12: ~3s per-request timeout via AbortSignal.timeout(), no retries.
const FETCH_TIMEOUT_MS = 3000;
// D-12: mirrors lib/mcp/base.js MAX_CONFIG_SIZE — a compromised/MITM'd
// registry response must not be able to exhaust memory.
const MAX_RESPONSE_SIZE = 5 * 1024 * 1024;

/**
 * pkgName MUST already have passed isSafePackageName() (npx-args.js)
 * before this is called (D-12) — this function does not re-validate.
 * Host is the hardcoded literal above, never interpolated from config;
 * a single encodeURIComponent call per segment matches what npm's own
 * tooling emits for scoped names (06-RESEARCH.md, verified live).
 */
function buildRegistryUrl(pkgName, versionOrTag) {
  return `https://${REGISTRY_HOST}/${encodeURIComponent(pkgName)}/${encodeURIComponent(versionOrTag)}`;
}

/**
 * D-10: derives the version/tag to fetch from an npx args array —
 * mirrors the -p/--package-aware positional-scan discipline of
 * derivePackageName() (npx-args.js) but extracts the VERSION portion of
 * the spec instead of the name portion. Deliberately NOT extracted into
 * npx-args.js: this is provenance-specific (no other detector needs a
 * version, only a name). A pinned spec (name@version) fetches that
 * exact version; an unpinned spec (bare name, dist-tag, range, or
 * wildcard) fetches 'latest' — unpinnedness itself is never re-reported
 * here, that is MCPD-01's (unpinned-execution.js) finding.
 */
function deriveVersionOrTag(args) {
  const list = Array.isArray(args) ? args : [];
  let spec = null;

  for (let i = 0; i < list.length; i++) {
    const arg = list[i];
    if (typeof arg !== 'string') continue;
    if (arg === '--package' || arg === '-p') {
      spec = list[i + 1];
      break;
    }
    if (arg.startsWith('--package=')) {
      spec = arg.slice('--package='.length);
      break;
    }
    if (arg.startsWith('-')) continue;
    spec = arg;
    break;
  }

  if (typeof spec !== 'string') return 'latest';
  const m = spec.match(/^(@[^/@\s]+\/)?([^@/\s]+)(@([^\s]+))?$/);
  if (!m || !m[4]) return 'latest';
  return m[4];
}

/**
 * D-12 network-safety client. Every failure mode (throw/network error,
 * non-2xx incl. 404, response.text() throw, oversize body, JSON.parse
 * throw) collapses to the SAME { ok:false, reason:'fetch-failed' }
 * return — this function never throws past its own boundary.
 *
 * Pitfall 5: branch on !response.ok BEFORE attempting to parse the
 * body — fetch() does not throw on a 404, it resolves normally with
 * response.ok === false, and a 404 body is plain text ("Not Found"),
 * not JSON matching the expected shape. Falling through to parsing
 * would either throw on JSON.parse or silently read doc.dist as
 * undefined, misreporting a lookup failure as "no-attestation".
 */
async function fetchAttestationStatus(pkgName, versionOrTag, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(buildRegistryUrl(pkgName, versionOrTag), {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, reason: 'fetch-failed' };
  }

  if (!response || !response.ok) {
    return { ok: false, reason: 'fetch-failed' };
  }

  let text;
  try {
    text = await response.text();
  } catch {
    return { ok: false, reason: 'fetch-failed' };
  }
  if (typeof text !== 'string' || text.length > MAX_RESPONSE_SIZE) {
    return { ok: false, reason: 'fetch-failed' };
  }

  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'fetch-failed' };
  }

  return { ok: true, hasAttestation: !!(doc && doc.dist && doc.dist.attestations) };
}

/**
 * run() is async and returns Promise<Finding[]> — the ONLY async
 * detector in the codebase. index.js's runAll() awaits every detector
 * result (CR-01 fix), so this detector's findings are collected and a
 * rejection is contained by runAll()'s per-detector try/catch exactly
 * like a sync throw — the D-01 "never crashes the scan" guarantee holds
 * for async detectors too. The { id, requirement, run } shape is
 * unchanged, only run()'s return type widens to a Promise.
 */
async function run(servers, context = {}) {
  const findings = [];
  const online = context.online === true;

  for (const server of Array.isArray(servers) ? servers : []) {
    // D-08: npm-only. uvx and url-only servers produce nothing from this
    // detector.
    if (commandBasename(server.command) !== 'npx') continue;

    const args = Array.isArray(server.args) ? server.args : [];
    const pkgName = derivePackageName(args);
    if (!pkgName || !isSafePackageName(pkgName)) continue;

    if (!online) {
      // D-11 zero-network guarantee: context.fetchImpl is structurally
      // UNREACHABLE on this branch — never referenced, not even called
      // and discarded.
      findings.push(Finding({
        id: `${id}/unverified-offline`,
        detector: id,
        severity: SEVERITY.INFO,
        confidence: CONFIDENCE.UNVERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}"'s package "${pkgName}" provenance not checked (offline) — run with --online to verify.`,
      }));
      continue;
    }

    // Node 18-20's global fetch prints a one-time, cosmetic
    // ExperimentalWarning to stderr on first use in a process — stderr
    // only, never corrupts --json stdout output, and disappears
    // entirely on Node >=21. Documented, not worked around (no
    // process.emit monkey-patching — 06-RESEARCH.md Pitfall 1).
    const fetchImpl = context.fetchImpl || fetch;
    const versionOrTag = deriveVersionOrTag(args);
    const unpinned = versionOrTag === 'latest';
    const result = await fetchAttestationStatus(pkgName, versionOrTag, fetchImpl);

    if (!result.ok) {
      findings.push(Finding({
        id: `${id}/fetch-failed`,
        detector: id,
        severity: SEVERITY.INFO,
        confidence: CONFIDENCE.UNVERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}"'s package "${pkgName}" provenance lookup against the npm registry failed — could not determine whether it has a provenance attestation.`,
      }));
      continue;
    }

    if (!result.hasAttestation) {
      findings.push(Finding({
        id: `${id}/no-attestation`,
        detector: id,
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}"'s package "${pkgName}" lacks a provenance attestation${unpinned ? ' (checked against "latest" — the result applies to latest, not necessarily what npx actually resolved)' : ''}.`,
      }));
    }
    // attestations present -> no finding (clean).
  }

  return findings;
}

module.exports = { id, requirement, run };
