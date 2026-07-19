'use strict';

/**
 * G-1372 — shared, idempotent fetch helper for the top-100 MCP research
 * pipeline. Node built-ins only (fs, path, crypto; `fetch` is Node >=18
 * built-in) — zero new deps, per CLAUDE.md.
 *
 * Every response (success, 404, and exhausted-retry) is cached under
 * snapshot/ keyed on a sha1 of the URL + a human-readable hint, so a
 * second run is fully offline/resumable after a rate-limit interruption.
 * Sequential requests only, small inter-request delay, exponential
 * backoff honoring HTTP 429 `Retry-After`. This module NEVER executes
 * fetched content — every response is treated as inert text/JSON.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SNAPSHOT_DIR = path.join(__dirname, 'snapshot');
const USER_AGENT =
  'llm-safe-haven-research/0.1 (+https://github.com/pleasedodisturb/llm-safe-haven; ' +
  'G-1372 top-100 MCP security research; static analysis only, no server execution)';
const INTER_REQUEST_DELAY_MS = 300;

function ensureSnapshotDir() {
  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Deterministic cache file path for a URL. Every fetch (hit, miss, or
 * exhausted-retry) is stored as ONE JSON envelope so re-runs never need
 * to distinguish "no cache file" from "cached negative result".
 */
function cachePathFor(url, hint) {
  const hash = crypto.createHash('sha1').update(url).digest('hex').slice(0, 16);
  const safeHint = (hint || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
  const name = safeHint ? `${hash}-${safeHint}.cache.json` : `${hash}.cache.json`;
  return path.join(SNAPSHOT_DIR, name);
}

function readCache(cachePath) {
  if (!fs.existsSync(cachePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(cachePath, 'utf8'));
  } catch {
    return null;
  }
}

function writeCache(cachePath, envelope) {
  ensureSnapshotDir();
  fs.writeFileSync(cachePath, JSON.stringify(envelope, null, 2));
}

/**
 * Trims a full npm registry package document (which embeds EVERY published
 * version's manifest, often megabytes for popular packages) down to just
 * the fields the research pipeline actually reads: readme text, the latest
 * version's manifest (version/bin/description only), and repo links. Kept
 * as a named `transform` so the exact same shrink applies identically on a
 * fresh fetch and on a cache re-read (single code path, see fetchCached).
 */
function trimNpmDoc(doc) {
  if (!doc || typeof doc !== 'object') return doc;
  const distTags = doc['dist-tags'] || {};
  const latest = distTags.latest;
  const fullManifest = latest && doc.versions && doc.versions[latest];
  const trimmedManifest = fullManifest
    ? { version: fullManifest.version, bin: fullManifest.bin, description: fullManifest.description }
    : undefined;
  return {
    name: doc.name,
    'dist-tags': { latest: latest || null },
    versions: trimmedManifest && latest ? { [latest]: trimmedManifest } : {},
    readme: doc.readme,
    readmeFilename: doc.readmeFilename,
    repository: doc.repository,
    homepage: doc.homepage,
  };
}

/**
 * fetchCached(url, opts)
 *   opts.json        - parse the response body as JSON
 *   opts.hint         - human-readable filename hint (for snapshot/ readability)
 *   opts.headers      - extra request headers
 *   opts.offlineOnly  - never touch the network; read cache or report missing
 *   opts.maxRetries   - default 5
 *   opts.transform    - (body) => body, applied to a successful JSON body
 *                       BEFORE it is cached, so cache-hit and fresh-fetch
 *                       return the identical (already-shrunk) shape
 *
 * Returns { fromCache, ok, status, body, url, error?, missing? }.
 * `body` is the parsed JSON value (opts.json) or raw text otherwise.
 * NEVER throws — network/parse failures come back as { ok:false, error }.
 */
async function fetchCached(url, opts = {}) {
  const cachePath = cachePathFor(url, opts.hint);
  const cached = readCache(cachePath);
  if (cached) {
    return { ...cached, fromCache: true };
  }

  if (opts.offlineOnly) {
    return { fromCache: false, ok: false, status: null, body: null, url, missing: true };
  }

  const maxRetries = opts.maxRetries ?? 5;
  let attempt = 0;
  let lastErrMessage;

  while (attempt <= maxRetries) {
    try {
      if (attempt > 0) {
        await sleep(INTER_REQUEST_DELAY_MS);
      }
      const res = await fetch(url, {
        headers: {
          'User-Agent': USER_AGENT,
          Accept: opts.json ? 'application/json' : 'text/plain, text/markdown, */*',
          ...(opts.headers || {}),
        },
      });

      if (res.status === 429 || res.status === 403) {
        attempt += 1;
        if (attempt > maxRetries) {
          const envelope = {
            ok: false,
            status: res.status,
            body: null,
            url,
            error: `rate-limited (${res.status}) after ${maxRetries} retries`,
          };
          writeCache(cachePath, envelope);
          return { ...envelope, fromCache: false };
        }
        const retryAfterHeader = Number(res.headers.get('retry-after'));
        const backoffMs = Number.isFinite(retryAfterHeader) && retryAfterHeader > 0
          ? retryAfterHeader * 1000
          : Math.min(2 ** attempt * 1000, 30000);
        await sleep(backoffMs);
        continue;
      }

      if (!res.ok) {
        // Non-retryable (404, etc) — cache the negative result so re-runs
        // don't re-fetch a permanent miss.
        const envelope = { ok: false, status: res.status, body: null, url };
        writeCache(cachePath, envelope);
        await sleep(INTER_REQUEST_DELAY_MS);
        return { ...envelope, fromCache: false };
      }

      const text = await res.text();
      let body = text;
      if (opts.json) {
        try {
          body = JSON.parse(text);
        } catch (err) {
          const envelope = { ok: false, status: res.status, body: null, url, error: `invalid-json: ${err.message}` };
          writeCache(cachePath, envelope);
          return { ...envelope, fromCache: false };
        }
        if (typeof opts.transform === 'function') {
          body = opts.transform(body);
        }
      }

      const envelope = { ok: true, status: res.status, body, url };
      writeCache(cachePath, envelope);
      await sleep(INTER_REQUEST_DELAY_MS);
      return { ...envelope, fromCache: false };
    } catch (err) {
      lastErrMessage = err.message;
      attempt += 1;
      await sleep(Math.min(2 ** attempt * 500, 8000));
    }
  }

  const envelope = { ok: false, status: null, body: null, url, error: lastErrMessage || 'unknown-error' };
  writeCache(cachePath, envelope);
  return { ...envelope, fromCache: false };
}

function sanitizeForHint(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * Canonical, single cache-key fetch of a package's full npm registry
 * document (trimmed via trimNpmDoc before caching). Every pipeline step
 * that needs npm registry data for the SAME package (selection's
 * entry-point check, README/snippet extraction) goes through this one
 * helper so they share exactly one snapshot/ cache entry per package
 * instead of re-fetching (and re-storing) the same document under
 * different hint strings.
 */
async function fetchNpmDoc(pkgName, offlineOnly) {
  return fetchCached(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`, {
    json: true,
    hint: `npmdoc-${sanitizeForHint(pkgName)}`,
    offlineOnly,
    transform: trimNpmDoc,
  });
}

module.exports = {
  fetchCached,
  SNAPSHOT_DIR,
  USER_AGENT,
  sleep,
  cachePathFor,
  trimNpmDoc,
  fetchNpmDoc,
  sanitizeForHint,
};
