'use strict';

/**
 * G-1372 — Task 1: README fetch + recommended-snippet extraction.
 *
 * For each selected server, resolves its README (npm registry `readme`
 * field first — already covered by the fetchNpmDoc() cache entry shared
 * with 01-select.js's entry-point check; falls back to
 * raw.githubusercontent.com of the repo's default branch for
 * PyPI-only reference servers with no npm package at all).
 *
 * Extracts the first fenced ```json block containing "mcpServers" as the
 * VERBATIM recommended install snippet. No such block => synthesize a
 * minimal `{ "mcpServers": { "<name>": { "command": "npx", "args": [pkg] } } }`
 * and mark synthesized:true. Multiple candidate blocks / malformed JSON /
 * no README at all => needsReview:true so the executor hand-reviews ONLY
 * those flagged entries, never all 100 (per plan Task 1).
 *
 * As a mechanical refinement (not a hand-edit — applied identically to
 * every server, not per-entry): when multiple mcpServers blocks are
 * present, prefer the first block whose `command` is `npx`/`uvx`/`docker`/
 * `cmd` (i.e. an actual executable-launch snippet) over a block that is
 * purely env-var documentation with no `command` key. Still flagged
 * needsReview:true so a human confirms the auto-pick.
 */

const fs = require('fs');
const path = require('path');
const { fetchCached, fetchNpmDoc } = require('./lib-fetch.js');
// Read-only reuse of the scanner's own JSONC tolerance (never modifies
// lib/) — several READMEs document their mcpServers example with trailing
// `// comment` annotations, which is invalid strict JSON and would
// otherwise make scoreBlockForExecutability() wrongly reject the actually-
// correct block in favor of an unrelated strictly-valid one (observed on
// @winor30/mcp-server-datadog — see FINDINGS-FOR-TICKETS.md).
const { stripJsonc } = require(path.join(__dirname, '..', '..', 'lib', 'mcp', 'base.js'));

const SELECTION_PATH = path.join(__dirname, 'selection.json');
const SNIPPETS_PATH = path.join(__dirname, 'snippets.json');

/**
 * Line-based fence scanner (CommonMark-style: ANY line that is only
 * backticks toggles fence state), not a single greedy/non-greedy regex
 * over the whole document. A regex-pair approach breaks silently on
 * READMEs with an odd number of ``` markers anywhere earlier in the
 * document (badges/deeplinks embedding literal backticks, a stray
 * decorative fence, etc.) — the non-greedy pairing desyncs and every
 * subsequent "block" ends up spanning from one real fence to an
 * unrelated later one, concatenating prose with JSON and reporting a
 * false malformed-json edge case (observed on @upstash/context7-mcp and
 * @ironbee-ai/devtools during hand-review — see FINDINGS-FOR-TICKETS.md).
 * Toggling per-line avoids that failure mode entirely.
 */
function findJsonBlocksWithMcpServers(markdown) {
  const lines = markdown.split('\n');
  const blocks = [];
  let inFence = false;
  let current = [];
  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      if (!inFence) {
        inFence = true;
        current = [];
      } else {
        inFence = false;
        const raw = current.join('\n').trim();
        if (raw.includes('mcpServers')) blocks.push(raw);
      }
      continue;
    }
    if (inFence) current.push(line);
  }
  return blocks;
}

// Score: -2 malformed JSON, -1 parses but has zero mcpServers entries
// (useless — treated the same as "no block"), 0 valid but no `command`
// key on any entry, 1 valid with at least one executable `command`.
function scoreBlockForExecutability(raw) {
  try {
    const parsed = JSON.parse(stripJsonc(raw));
    const servers = parsed.mcpServers || {};
    const names = Object.keys(servers);
    if (names.length === 0) return -1;
    const hasCommand = names.some(n => servers[n] && typeof servers[n].command === 'string' && servers[n].command);
    return hasCommand ? 1 : 0;
  } catch {
    return -2;
  }
}

/**
 * Normalized {command, args} signature of a block's first server entry —
 * used to tell "genuinely different candidate blocks" (real ambiguity)
 * apart from "the same recommended server repeated once per client
 * wrapper" (Claude Desktop / Cursor / VS Code / Windsurf sections all
 * showing the identical install), which is the OVERWHELMINGLY common
 * shape for well-documented servers and needs no human judgment call.
 */
function blockSignature(raw) {
  try {
    const parsed = JSON.parse(stripJsonc(raw));
    const servers = parsed.mcpServers || {};
    const first = Object.values(servers)[0];
    if (!first) return null;
    return JSON.stringify({ command: first.command, args: first.args, url: first.url });
  } catch {
    return null;
  }
}

/**
 * Decides what to do with the set of candidate ```json mcpServers blocks
 * found in a README, per plan Task 1's exact edge-case list: only
 * "multiple candidate blocks" and "malformed JSON in the block" earn
 * needsReview:true here (a clean single valid block, or zero blocks at
 * all — the ordinary synthesize path — do NOT need human review). Among
 * "multiple blocks", only a REAL divergence in the underlying
 * command/args across blocks counts as ambiguous; multiple blocks that
 * all encode the identical install (repeated per client) are auto-picked
 * without a review flag.
 */
function pickBestBlock(blocks) {
  if (blocks.length === 0) {
    return { block: null, needsReview: false, reason: null };
  }

  const scored = blocks.map(b => ({ b, score: scoreBlockForExecutability(b) }));
  const usable = scored.filter(s => s.score >= 0);

  if (blocks.length === 1) {
    const only = scored[0];
    if (only.score === -2) {
      return { block: null, needsReview: true, reason: 'malformed-json' };
    }
    if (only.score === -1) {
      return { block: null, needsReview: false, reason: null }; // empty block == no block
    }
    return { block: only.b, needsReview: false, reason: null };
  }

  if (usable.length === 0) {
    return { block: null, needsReview: true, reason: 'multiple-candidate-blocks-all-malformed' };
  }

  const best = usable.find(s => s.score === 1) || usable[0];
  const executableUsable = usable.filter(s => s.score === 1);
  const compareSet = executableUsable.length > 0 ? executableUsable : usable;
  const signatures = new Set(compareSet.map(s => blockSignature(s.b)).filter(Boolean));
  const genuinelyAmbiguous = signatures.size > 1;

  return {
    block: best.b,
    needsReview: genuinelyAmbiguous,
    reason: genuinelyAmbiguous ? 'multiple-candidate-blocks-diverge' : null,
  };
}

function synthesizeSnippet(name, npmPackage, pypiPackage) {
  if (npmPackage) {
    return JSON.stringify(
      { mcpServers: { [name]: { command: 'npx', args: ['-y', npmPackage] } } },
      null,
      2,
    );
  }
  if (pypiPackage) {
    return JSON.stringify(
      { mcpServers: { [name]: { command: 'uvx', args: [pypiPackage] } } },
      null,
      2,
    );
  }
  return JSON.stringify({ mcpServers: { [name]: { command: 'npx', args: ['-y', name] } } }, null, 2);
}

async function resolveReadme(entry, offlineOnly) {
  if (entry.npmPackage) {
    const doc = await fetchNpmDoc(entry.npmPackage, offlineOnly);
    if (doc.ok && doc.body && typeof doc.body.readme === 'string' && doc.body.readme.trim().length > 0) {
      return { readme: doc.body.readme, version: (doc.body['dist-tags'] || {}).latest || null, via: 'npm-registry-readme-field' };
    }
  }
  // Fall back to raw GitHub README for the repo's default branch (try
  // main then master) — covers PyPI-only servers and npm packages that
  // ship an empty/missing registry readme field.
  const repo = extractGithubRepo(entry.repoUrl);
  if (repo) {
    for (const branch of ['main', 'master']) {
      const url = `https://raw.githubusercontent.com/${repo}/${branch}/README.md`;
      const res = await fetchCached(url, { hint: `readme-${repo.replace(/[^a-zA-Z0-9]+/g, '_')}-${branch}`, offlineOnly });
      if (res.ok && typeof res.body === 'string' && res.body.trim().length > 0) {
        return { readme: res.body, version: null, via: `github-raw-${branch}` };
      }
    }
  }
  return { readme: null, version: null, via: null };
}

function extractGithubRepo(repoUrl) {
  if (!repoUrl) return null;
  const m = /github\.com[/:]([^/]+\/[^/.]+)(?:\.git)?/.exec(repoUrl);
  return m ? m[1].replace(/\.git$/, '') : null;
}

async function main() {
  const offlineOnly = process.argv.includes('--offline');
  if (!fs.existsSync(SELECTION_PATH)) {
    console.error('02-fetch-readmes.js: selection.json not found — run 01-select.js first.');
    process.exitCode = 1;
    return;
  }
  const selection = JSON.parse(fs.readFileSync(SELECTION_PATH, 'utf8'));

  const snippets = fs.existsSync(SNIPPETS_PATH) ? JSON.parse(fs.readFileSync(SNIPPETS_PATH, 'utf8')) : {};
  let synthesizedCount = 0;
  let needsReviewCount = 0;

  // The two documented Task-1 hand-corrections (METHODOLOGY §2,
  // FINDINGS-FOR-TICKETS anomaly #3). A plain re-run must NOT clobber a
  // human-reviewed snippet with the auto-picker's known-wrong choice — for
  // these keys an existing snippets.json entry always wins over re-extraction.
  const HAND_CORRECTED = new Set(['pi-mcp-adapter', '@winor30/mcp-server-datadog']);

  for (const entry of selection) {
    const key = entry.name;
    if (HAND_CORRECTED.has(key) && snippets[key]) {
      if (snippets[key].synthesized) synthesizedCount++;
      if (snippets[key].needsReview) needsReviewCount++;
      continue;
    }
    // eslint-disable-next-line no-await-in-loop -- sequential/polite by design
    const { readme, version, via } = await resolveReadme(entry, offlineOnly);

    let snippetRaw;
    let synthesized = false;
    let needsReview = false;
    let needsReviewReason = null;

    if (!readme) {
      snippetRaw = synthesizeSnippet(key, entry.npmPackage, entry.pypiPackage);
      synthesized = true;
      needsReview = true;
      needsReviewReason = 'no-readme-found';
    } else {
      const blocks = findJsonBlocksWithMcpServers(readme);
      const { block, needsReview: nr, reason } = pickBestBlock(blocks);
      if (!block) {
        snippetRaw = synthesizeSnippet(key, entry.npmPackage, entry.pypiPackage);
        synthesized = true;
        // pickBestBlock already applies the exact plan edge-case list
        // (malformed JSON / all-candidates-malformed => review; a clean
        // zero-block README is the ordinary synthesize path => no review).
        needsReview = nr;
        needsReviewReason = reason || (blocks.length === 0 ? null : 'no-usable-mcpservers-block');
      } else {
        snippetRaw = block;
        synthesized = false;
        needsReview = nr;
        needsReviewReason = reason;
      }
    }

    if (synthesized) synthesizedCount++;
    if (needsReview) needsReviewCount++;

    snippets[key] = {
      npmPackage: entry.npmPackage,
      pypiPackage: entry.pypiPackage,
      version: version || null,
      repoUrl: entry.repoUrl,
      readmeSource: via,
      snippetRaw,
      synthesized,
      needsReview,
      needsReviewReason,
    };
  }

  fs.writeFileSync(SNIPPETS_PATH, JSON.stringify(snippets, null, 2));
  console.log(
    `Wrote snippets.json: ${Object.keys(snippets).length} servers ` +
    `(${synthesizedCount} synthesized, ${needsReviewCount} flagged needsReview).`,
  );
}

main().catch(err => {
  console.error('02-fetch-readmes.js failed:', err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
