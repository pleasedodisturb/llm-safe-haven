'use strict';

/**
 * G-1372 — Task 1: reproducible, mechanical Top-N MCP server selection.
 *
 * Methodology (locked, see 260719-img-TICKET.md §Methodology step 1 and
 * METHODOLOGY.md): union of
 *   (a) every ACTIVE server in the modelcontextprotocol/servers README's
 *       "Reference Servers" section (mechanically parsed from the raw
 *       README text — archived servers are excluded, they are explicitly
 *       unmaintained);
 *   (b) npm packages matching an MCP-server name/keyword heuristic,
 *       ranked by last-30-day downloads (the npm search API already
 *       returns `downloads.monthly` inline per result, so no separate
 *       downloads-API round trip is needed for this source).
 * Dedupe (source (a) wins ties), rank by monthly downloads (nulls last,
 * name as a final deterministic tiebreak), take top --limit (default 100).
 *
 * --verify: re-derive the SAME ranking from snapshot/ ONLY (no network —
 * every fetchCached() call below is opts.offlineOnly:true in this mode)
 * and assert byte-stable equality against the committed selection.json
 * (AC-4). A --verify run that finds an uncached URL simply gets a
 * `missing` result for that lookup — which reproduces deterministically
 * every time, because the snapshot/ cache is itself immutable input.
 *
 * Node built-ins only; `fetch` is the Node >=18 global.
 */

const fs = require('fs');
const path = require('path');
const { fetchCached, SNAPSHOT_DIR, fetchNpmDoc } = require('./lib-fetch.js');

const SELECTION_PATH = path.join(__dirname, 'selection.json');
const DATE_FILE = path.join(SNAPSHOT_DIR, 'selection-date.txt');

const REFERENCE_README_URL =
  'https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md';

const NPM_SEARCH_TERMS = ['mcp', 'mcp-server', 'modelcontextprotocol', 'mcp-client', 'mcp server'];

// Known false-positive class: "mcp" collides with Minecraft: Pocket/Bedrock
// Edition tooling ("mcpe", "mcp-*" mod loaders). Excluded so the pool isn't
// diluted with unrelated Minecraft packages.
const DENYLIST_RE = /\bmcpe\b|minecraft/i;

function looksLikeMcpServer(pkg) {
  const name = (pkg.name || '').toLowerCase();
  const description = pkg.description || '';
  if (DENYLIST_RE.test(name) || DENYLIST_RE.test(description)) return false;
  const nameMatch = /(^|[-_@./])mcp([-_./]|$)/.test(name) || /mcp[-_]?server|server[-_]?mcp/.test(name);
  const keywords = Array.isArray(pkg.keywords) ? pkg.keywords : [];
  const keywordMatch = keywords.some(k => /mcp|model[-_ ]?context[-_ ]?protocol/i.test(String(k)));
  return nameMatch || keywordMatch;
}

async function collectNpmSearchCandidates(offlineOnly) {
  const byKey = new Map();
  for (const term of NPM_SEARCH_TERMS) {
    const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(term)}&size=250`;
    const hint = `npm-search-${term.replace(/[^a-z0-9]+/gi, '_')}`;
    const res = await fetchCached(url, { json: true, hint, offlineOnly });
    if (!res.ok || !res.body || !Array.isArray(res.body.objects)) continue;

    for (const obj of res.body.objects) {
      const pkg = obj.package;
      if (!pkg || !pkg.name) continue;
      if (!looksLikeMcpServer(pkg)) continue;

      const key = pkg.name.toLowerCase();
      const monthlyDownloads =
        obj.downloads && typeof obj.downloads.monthly === 'number' ? obj.downloads.monthly : null;
      const repoUrl = (pkg.links && (pkg.links.repository || pkg.links.homepage)) || null;
      const existing = byKey.get(key);
      const isBetter =
        !existing ||
        (monthlyDownloads != null && (existing.monthlyDownloads == null || monthlyDownloads > existing.monthlyDownloads));
      if (isBetter) {
        byKey.set(key, {
          name: pkg.name,
          npmPackage: pkg.name,
          pypiPackage: null,
          monthlyDownloads,
          repoUrl,
          version: pkg.version || null,
          source: 'npm-search',
        });
      }
    }
  }
  return [...byKey.values()];
}

/**
 * Mechanically parses the "Reference Servers" bullet list out of the raw
 * README (archived servers, which live under a separate "### Archived"
 * heading, are intentionally excluded — they're unmaintained). For each
 * entry, derives an npm candidate name (`@modelcontextprotocol/server-
 * <slug>`) and confirms it via a real registry lookup; TS reference
 * servers resolve here. Python-only reference servers (Fetch, Git, Time)
 * fall back to a PyPI existence check (`mcp-server-<slug>`) since they
 * have no npm package at all — both checks are real, cached HTTP lookups,
 * never hardcoded.
 */
async function collectReferenceServers(offlineOnly) {
  const readmeRes = await fetchCached(REFERENCE_README_URL, { hint: 'mcp-servers-readme', offlineOnly });
  if (!readmeRes.ok || typeof readmeRes.body !== 'string') return [];

  const text = readmeRes.body;
  const sectionStart = text.indexOf('Reference Servers');
  const archivedStart = text.indexOf('### Archived');
  const section = sectionStart >= 0
    ? text.slice(sectionStart, archivedStart > sectionStart ? archivedStart : text.length)
    : '';

  const itemRe = /-\s+\*\*\[([^\]]+)]\(([^)]+)\)\*\*\s*-\s*(.+)/g;
  const items = [];
  let m;
  while ((m = itemRe.exec(section))) {
    items.push({ label: m[1].trim(), relPath: m[2].trim() });
  }

  const results = [];
  for (const item of items) {
    const slug = item.label.toLowerCase().replace(/\s+/g, '-');
    const npmCandidate = `@modelcontextprotocol/server-${slug}`;
    const npmDocRes = await fetchNpmDoc(npmCandidate, offlineOnly);

    let npmPackage = null;
    let pypiPackage = null;
    let version = null;
    let monthlyDownloads = null;

    if (npmDocRes.ok && npmDocRes.body && npmDocRes.body['dist-tags']) {
      npmPackage = npmCandidate;
      version = npmDocRes.body['dist-tags'].latest || null;
      const dlRes = await fetchCached(
        `https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(npmCandidate)}`,
        { json: true, hint: `refdl-${slug}`, offlineOnly },
      );
      if (dlRes.ok && dlRes.body && typeof dlRes.body.downloads === 'number') {
        monthlyDownloads = dlRes.body.downloads;
      }
    } else {
      const pypiCandidate = `mcp-server-${slug}`;
      const pypiRes = await fetchCached(
        `https://pypi.org/pypi/${encodeURIComponent(pypiCandidate)}/json`,
        { json: true, hint: `refdoc-pypi-${slug}`, offlineOnly },
      );
      if (pypiRes.ok && pypiRes.body) {
        pypiPackage = pypiCandidate;
        version = (pypiRes.body.info && pypiRes.body.info.version) || null;
      }
    }

    results.push({
      name: item.label,
      npmPackage,
      pypiPackage,
      monthlyDownloads,
      repoUrl: `https://github.com/modelcontextprotocol/servers/tree/main/${item.relPath.replace(/^\.\//, '')}`,
      version,
      source: 'reference-readme',
    });
  }
  return results;
}

// npm's own convention for prebuilt-binary optionalDependencies sub-packages
// (e.g. @azure/mcp-darwin-arm64) — these are never something a user installs
// directly as a server entry, they're transitive platform artifacts of a
// parent package that (if legitimate) already appears in the pool under its
// own name.
const PLATFORM_BINARY_RE = /-(darwin|linux|win32|android|freebsd)(-(arm64|x64|ia32|arm))?$/i;

/**
 * "Exposes a server entry point" heuristic refinement (ticket §Methodology
 * step 1): a real CLI-invokable MCP server has an npm `bin` entry — that's
 * what `npx <pkg>` actually runs. Filters out SDKs/frameworks/UI-adapter
 * libraries that merely match the name/keyword heuristic (e.g.
 * `@modelcontextprotocol/sdk`, `@mcp-ui/client`) without being directly
 * npx-runnable. Reference-README entries are always trusted (they are the
 * official reference implementations by definition). Insufficient registry
 * data (missing `versions` for the latest tag) is treated leniently — this
 * is a best-effort filter, not a hard requirement, so it never blocks a
 * candidate it can't evaluate.
 */
async function hasServerEntryPoint(entry, offlineOnly) {
  if (entry.source === 'reference-readme') return true;
  if (!entry.npmPackage) return false;
  const res = await fetchNpmDoc(entry.npmPackage, offlineOnly);
  if (!res.ok || !res.body) return false;
  const latestTag = res.body['dist-tags'] && res.body['dist-tags'].latest;
  const manifest = latestTag && res.body.versions && res.body.versions[latestTag];
  if (!manifest) return true; // can't evaluate — lenient default
  const bin = manifest.bin;
  if (!bin) return false;
  if (typeof bin === 'string') return bin.trim().length > 0;
  if (typeof bin === 'object') return Object.keys(bin).length > 0;
  return false;
}

async function buildRanking(referenceServers, npmSearchServers, limit, offlineOnly) {
  const byKey = new Map();
  for (const r of referenceServers) {
    const key = (r.npmPackage || r.pypiPackage || r.name).toLowerCase();
    byKey.set(key, r); // source (a) always wins a collision with (b)
  }
  for (const s of npmSearchServers) {
    const key = s.npmPackage.toLowerCase();
    if (!byKey.has(key)) byKey.set(key, s);
  }

  const merged = [...byKey.values()];
  merged.sort((a, b) => {
    const ad = a.monthlyDownloads == null ? -1 : a.monthlyDownloads;
    const bd = b.monthlyDownloads == null ? -1 : b.monthlyDownloads;
    if (bd !== ad) return bd - ad;
    // Codepoint compare, NOT localeCompare — localeCompare is ICU/locale
    // dependent, which would make the "deterministic tiebreak" (and --verify
    // byte-stability) vary across machines.
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });

  const final = [];
  for (const entry of merged) {
    if (final.length >= limit) break;
    if (entry.npmPackage && PLATFORM_BINARY_RE.test(entry.npmPackage)) continue;
    // eslint-disable-next-line no-await-in-loop -- sequential/polite by design
    const ok = await hasServerEntryPoint(entry, offlineOnly);
    if (!ok) continue;
    final.push(entry);
  }

  return final.map((entry, i) => ({
    rank: i + 1,
    name: entry.name,
    npmPackage: entry.npmPackage || null,
    pypiPackage: entry.pypiPackage || null,
    monthlyDownloads: entry.monthlyDownloads,
    repoUrl: entry.repoUrl,
    source: entry.source,
  }));
}

function parseArgs(argv) {
  const verify = argv.includes('--verify');
  let limit = 100;
  const limitEq = argv.find(a => a.startsWith('--limit='));
  if (limitEq) {
    limit = parseInt(limitEq.split('=')[1], 10);
  } else {
    const idx = argv.indexOf('--limit');
    if (idx >= 0 && argv[idx + 1]) limit = parseInt(argv[idx + 1], 10);
  }
  if (!Number.isFinite(limit) || limit <= 0) limit = 100;
  return { verify, limit };
}

async function main() {
  const { verify, limit } = parseArgs(process.argv.slice(2));
  const offlineOnly = verify;

  let snapshotDate;
  if (fs.existsSync(DATE_FILE)) {
    snapshotDate = fs.readFileSync(DATE_FILE, 'utf8').trim();
  } else if (!offlineOnly) {
    snapshotDate = new Date().toISOString().slice(0, 10);
    fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
    fs.writeFileSync(DATE_FILE, snapshotDate);
  } else {
    console.error('VERIFY FAILED: no snapshot/selection-date.txt — run a real (non --verify) selection first.');
    process.exitCode = 1;
    return;
  }

  const referenceServers = await collectReferenceServers(offlineOnly);
  const npmSearchServers = await collectNpmSearchCandidates(offlineOnly);
  const rankedRaw = await buildRanking(referenceServers, npmSearchServers, limit, offlineOnly);
  const ranking = rankedRaw.map(entry => ({
    ...entry,
    snapshotDate,
  }));

  if (verify) {
    if (!fs.existsSync(SELECTION_PATH)) {
      console.error('VERIFY FAILED: selection.json does not exist yet.');
      process.exitCode = 1;
      return;
    }
    const existing = JSON.parse(fs.readFileSync(SELECTION_PATH, 'utf8'));
    const existingStr = JSON.stringify(existing);
    const rebuiltStr = JSON.stringify(ranking);
    if (existingStr === rebuiltStr) {
      console.log(`VERIFY OK: ${ranking.length} servers, byte-stable order reproduced from snapshot/ offline.`);
    } else {
      console.error('VERIFY FAILED: rebuilt selection differs from the committed selection.json.');
      const max = Math.max(existing.length, ranking.length);
      for (let i = 0; i < max; i++) {
        const a = JSON.stringify(existing[i]);
        const b = JSON.stringify(ranking[i]);
        if (a !== b) {
          console.error(`First diff at index ${i}:\n  existing: ${a}\n  rebuilt:  ${b}`);
          break;
        }
      }
      process.exitCode = 1;
    }
    return;
  }

  fs.writeFileSync(SELECTION_PATH, JSON.stringify(ranking, null, 2));
  console.log(
    `Wrote selection.json with ${ranking.length} servers ` +
    `(reference-readme pool: ${referenceServers.length}, npm-search pool: ${npmSearchServers.length}).`,
  );
}

main().catch(err => {
  console.error('01-select.js failed:', err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
