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
 * through a hardened, SSRF-safe, timeout-and-size-capped client (D-12).
 * Lookups are DEDUPED per pkg@ref (the same package configured in two
 * agents' configs is fetched once) and issued through a bounded worker
 * pool of FETCH_CONCURRENCY at a time (F6/D-12: bounded concurrency,
 * never one-request-per-server fan-out and never a serial crawl).
 * Findings order stays deterministic by server index regardless of
 * response arrival order. Results map through the D-09 state machine:
 *   attestations present   -> no finding (clean)
 *   attestations absent    -> provenance/no-attestation   (low, verified)
 *   fetch failed (any way) -> provenance/fetch-failed      (info, unverified)
 *
 * This is a PRESENCE check only, never a cryptographic Sigstore
 * verification — every message says "has/lacks a provenance
 * attestation", never "verified authentic" (D-09).
 */

const { Finding, SEVERITY, CONFIDENCE, MAX_CONFIG_SIZE } = require('../base.js');
const { commandBasename, derivePackageName, extractSpec, versionFromSpec, classifySpecSuffix, EXACT_SEMVER_RE, isSafePackageName } = require('../npx-args.js');

const id = 'provenance';
const requirement = 'MCPD-02';

// D-12: pinned literal, NEVER config-derived or built from server/user
// input — this is the project's SSRF defense for the one outbound
// network call this phase introduces.
const REGISTRY_HOST = 'registry.npmjs.org';
// D-12: ~3s per-request timeout via AbortSignal.timeout(), no retries.
const FETCH_TIMEOUT_MS = 3000;
// F6/D-12: at most this many registry requests in flight at once — a
// config with hundreds of servers must neither fan out into hundreds of
// parallel requests nor crawl serially at one 3s-timeout per server.
const FETCH_CONCURRENCY = 4;
// D-12: the response cap deliberately ALIASES base.js's MAX_CONFIG_SIZE
// (F9: it was a drift-prone twin literal) — a compromised/MITM'd
// registry response must not be able to exhaust memory. Enforced
// BEFORE/DURING the body read (WR-03): Content-Length is checked before
// any read, and a streamed body is aborted the moment the running byte
// count crosses the cap — never a check-after-full-buffering (the same
// class of bug readConfigSafe's fstat-before-read discipline avoids).
const MAX_RESPONSE_SIZE = MAX_CONFIG_SIZE;

/**
 * WR-03: size-capped body read over the web ReadableStream at
 * response.body (Node 18+ fetch), keeping a running BYTE count
 * (Uint8Array chunk lengths are bytes, never UTF-16 code units — F7)
 * and cancelling the stream as soon as it crosses MAX_RESPONSE_SIZE —
 * the cap bounds allocation, not just a post-hoc length check.
 *
 * F7: the old response.text() fallback for non-streaming doubles is
 * GONE — it buffered the entire body BEFORE any check (unbounded
 * allocation) and then compared .length in UTF-16 code units, which
 * undercounts multi-byte content by up to 3x. A response without a
 * streaming body now returns null (-> fetch-failed); test doubles
 * construct real streams via `new Response(json)` (a Node 18 global),
 * exactly like real fetch. Returns the body text, or null when
 * oversized/unreadable; throws are the caller's to contain.
 */
async function readBodyCapped(response) {
  const body = response.body;
  if (!body || typeof body.getReader !== 'function') return null;
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_RESPONSE_SIZE) {
      try { await reader.cancel(); } catch { /* already failed — nothing to release */ }
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

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
 * D-10: derives the version/tag to fetch from an npx args array — a
 * thin composition over the shared extractSpec()/versionFromSpec()/
 * classifySpecSuffix() pipeline (npx-args.js; WR-06/F8 consolidation:
 * the flag-scan loop AND the WR-02 suffix classification live there,
 * never re-copied here). Returns { ref, pinned }:
 *   exact semver (name@1.2.3, name@v1.2.3) -> { ref:'1.2.3', pinned:true }
 *     (v normalized away via EXACT_SEMVER_RE's capture group — the
 *     registry rejects v-prefixed versions; a non-semver 'exact' pin,
 *     i.e. a PyPI == suffix that has no business in an npx spec, is not
 *     a registry-fetchable path segment and falls through to 'latest')
 *   range/wildcard/partial (^ ~ > < = 1.x ...) -> { ref:'latest', pinned:false }
 *   dist-tag (next, beta, ...)              -> { ref:tag,     pinned:false }
 *   bare name (no suffix)                   -> { ref:'latest', pinned:false }
 * pinned:false makes the "checked against a floating ref" caveat render
 * on a no-attestation finding — unpinnedness itself is never re-reported
 * here, that is MCPD-01's (unpinned-execution.js) finding.
 */
function deriveVersionOrTag(args) {
  const suffix = versionFromSpec(extractSpec(args, 'npx'));
  if (suffix === null) return { ref: 'latest', pinned: false };
  const exact = EXACT_SEMVER_RE.exec(suffix);
  if (exact) return { ref: exact[1], pinned: true };
  if (classifySpecSuffix(suffix) === 'tag') return { ref: suffix, pinned: false };
  return { ref: 'latest', pinned: false };
}

/**
 * D-12 network-safety client. Every failure mode (throw/network error,
 * non-2xx incl. 404, oversize Content-Length, body-read throw, body
 * exceeding the cap mid-stream, JSON.parse throw) collapses to the SAME
 * { ok:false, reason:'fetch-failed' } return — this function never
 * throws past its own boundary.
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

  // WR-03: reject a declared-oversize response BEFORE reading any body
  // bytes. A missing/absent/lying Content-Length falls through to the
  // capped streaming read below — the cap holds either way.
  try {
    const headers = response.headers;
    const rawLength = headers && typeof headers.get === 'function' ? headers.get('content-length') : null;
    const declaredLength = rawLength === null || rawLength === undefined ? NaN : Number(rawLength);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_SIZE) {
      return { ok: false, reason: 'fetch-failed' };
    }
  } catch {
    return { ok: false, reason: 'fetch-failed' };
  }

  let text;
  try {
    text = await readBodyCapped(response);
  } catch {
    return { ok: false, reason: 'fetch-failed' };
  }
  if (text === null) {
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
 * F6: bounded-concurrency map, preserving result order by item index.
 * Zero-dep: workers pull the next unclaimed index until the list is
 * exhausted, so at most `limit` fn invocations are in flight at once.
 * fn rejections propagate to the caller's await — fetchAttestationStatus
 * never rejects past its own boundary, so run() keeps its no-throw
 * property.
 */
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  };
  const workers = [];
  for (let w = 0; w < Math.min(limit, items.length); w++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

/**
 * run() is async and returns Promise<Finding[]> — the ONLY async
 * detector in the codebase. index.js's runAll() awaits every detector
 * result (CR-01 fix), so this detector's findings are collected and a
 * rejection is contained by runAll()'s per-detector try/catch exactly
 * like a sync throw — the D-01 "never crashes the scan" guarantee holds
 * for async detectors too. The { id, requirement, run } shape is
 * unchanged, only run()'s return type widens to a Promise.
 *
 * F6 shape: a synchronous eligibility pass first (offline findings are
 * emitted directly there); online lookups are then deduped through a
 * per-run promise cache keyed `pkg@ref` — caching the PROMISE means two
 * servers resolving the same package share ONE in-flight request, not
 * just one cached result — and issued via mapWithConcurrency
 * (FETCH_CONCURRENCY at a time). Findings are emitted from the ordered
 * task list AFTER all lookups settle, so output order is deterministic
 * by server index regardless of response arrival order.
 */
async function run(servers, context = {}) {
  const findings = [];
  const online = context.online === true;

  // Pass 1 (synchronous): D-08 npm-only eligibility. uvx and url-only
  // servers produce nothing from this detector.
  const tasks = [];
  for (const server of Array.isArray(servers) ? servers : []) {
    if (commandBasename(server.command) !== 'npx') continue;

    const args = Array.isArray(server.args) ? server.args : [];
    // D-08: this detector is npx-only, so the npx flag grammar is passed
    // explicitly rather than re-deriving it from bin (F1).
    const pkgName = derivePackageName(args, 'npx');
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

    const { ref: versionOrTag, pinned } = deriveVersionOrTag(args);
    // WR-02: a dist-tag fetch (e.g. "next") resolves, but is still a
    // floating ref — the caveat must render for it too, not only for
    // 'latest'.
    tasks.push({ server, pkgName, versionOrTag, unpinned: !pinned });
  }

  if (!online) return findings;

  // Node 18-20's global fetch prints a one-time, cosmetic
  // ExperimentalWarning to stderr on first use in a process — stderr
  // only, never corrupts --json stdout output, and disappears
  // entirely on Node >=21. Documented, not worked around (no
  // process.emit monkey-patching — 06-RESEARCH.md Pitfall 1).
  const fetchImpl = context.fetchImpl || fetch;

  // F6: per-run promise cache — concurrent identical lookups share one
  // request. Per-RUN only, never module-level: attestation state must
  // not leak between scans.
  const lookupCache = new Map();
  const results = await mapWithConcurrency(tasks, FETCH_CONCURRENCY, (task) => {
    const key = `${task.pkgName}@${task.versionOrTag}`;
    if (!lookupCache.has(key)) {
      lookupCache.set(key, fetchAttestationStatus(task.pkgName, task.versionOrTag, fetchImpl));
    }
    return lookupCache.get(key);
  });

  for (let i = 0; i < tasks.length; i++) {
    const { server, pkgName, versionOrTag, unpinned } = tasks[i];
    const result = results[i];

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
        message: `Server "${server.name}"'s package "${pkgName}" lacks a provenance attestation${unpinned ? ` (checked against the floating ref "${versionOrTag}" — the result applies to what it pointed at during the scan, not necessarily what npx actually resolved)` : ''}.`,
      }));
    }
    // attestations present -> no finding (clean).
  }

  return findings;
}

module.exports = { id, requirement, run };
