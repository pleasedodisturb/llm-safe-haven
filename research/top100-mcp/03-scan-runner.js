'use strict';

/**
 * G-1372 — Task 2: batch fixture builder + real `scan --mcp` runner +
 * mechanical envelope merge into dataset.json.
 *
 * NEVER executes any scanned server's code — this spawns llm-safe-haven's
 * OWN scanner (a static config parser) against synthetic `.mcp.json`
 * fixtures built from the verbatim/synthesized snippets in snippets.json.
 * No `npx <candidate>`, no MCP handshake, ever.
 *
 * Isolation (see plan <interfaces>): each batch gets a fresh OS-tmp dir
 * used as BOTH the child's cwd (so claude-code project-scope discovery
 * finds only the fixture .mcp.json) and an empty HOME (so user/local
 * scope discovery — <HOME>/.claude.json — can never see the executor's
 * real config). claude-code discovery is additionally gated on
 * commandExists('claude'), which is a PATH-based `which` lookup,
 * independent of HOME, so the isolated child still discovers correctly.
 *
 * Every batch's raw envelope is cached under snapshot/ keyed by a hash of
 * the batch's fixture content, so a re-run skips batches already scanned
 * (resumable; avoids repeating --online registry.npmjs.org provenance
 * lookups for a batch that already succeeded).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

// Read-only reuse of the scanner's own JSONC tolerance to turn a snippet's
// (possibly comment-annotated) verbatim text back into a real object for
// fixture assembly — never modifies lib/.
const { stripJsonc } = require(path.join(__dirname, '..', '..', 'lib', 'mcp', 'base.js'));

const REPO_ROOT = path.join(__dirname, '..', '..');
const BIN_PATH = path.join(REPO_ROOT, 'bin', 'llm-safe-haven.js');
const SNAPSHOT_DIR = path.join(__dirname, 'snapshot');
const SELECTION_PATH = path.join(__dirname, 'selection.json');
const SNIPPETS_PATH = path.join(__dirname, 'snippets.json');
const DATASET_PATH = path.join(__dirname, 'dataset.json');
const FINDINGS_PATH = path.join(__dirname, 'FINDINGS-FOR-TICKETS.md');
const PKG_VERSION = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')).version;

const BATCH_SIZE = 10;

function sanitizeKey(s) {
  return String(s).replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 60);
}

function parseSnippetServers(snippetRaw) {
  try {
    const parsed = JSON.parse(stripJsonc(snippetRaw));
    return parsed.mcpServers && typeof parsed.mcpServers === 'object' && !Array.isArray(parsed.mcpServers)
      ? parsed.mcpServers
      : null;
  } catch {
    return null;
  }
}

let anomalyBuffer = [];
function appendAnomaly(text) {
  anomalyBuffer.push(text);
}

function flushAnomalies() {
  if (anomalyBuffer.length === 0) return;
  const existing = fs.existsSync(FINDINGS_PATH) ? fs.readFileSync(FINDINGS_PATH, 'utf8') : '';
  const marker = '_(populated by `03-scan-runner.js` as it runs — see below)_';
  const block = anomalyBuffer.map((a, i) => `\n### Scan anomaly ${i + 1}\n\n${a}\n`).join('\n');
  let updated;
  if (existing.includes(marker)) {
    updated = existing.replace(marker, `${marker}\n${block}`);
  } else {
    updated = `${existing}\n${block}`;
  }
  fs.writeFileSync(FINDINGS_PATH, updated);
  anomalyBuffer = [];
}

/**
 * Builds batches of ~BATCH_SIZE selected servers. Every server's mcpServers
 * entry/entries are re-keyed under a unique deterministic `s0NN__<name>`
 * id (NN = rank) before merging into the shared batch fixture — this
 * keeps findings unambiguously joinable back to a single dataset entry
 * AND prevents two unrelated servers that happen to share a display name
 * (e.g. two "Memory" servers) from triggering a FALSE tool-shadowing
 * name-collision that wouldn't exist in the real world. A snippet whose
 * mcpServers block defines more than one entry (e.g. a bundled companion
 * server) has ALL of its entries injected under the same rank prefix —
 * that mirrors exactly what a user pasting the verbatim snippet would
 * get, and every entry still joins back to the one profiled server.
 */
function buildBatches(selection, snippets) {
  const batches = [];
  for (let i = 0; i < selection.length; i += BATCH_SIZE) {
    const slice = selection.slice(i, i + BATCH_SIZE);
    const batchIndex = Math.floor(i / BATCH_SIZE);
    const mcpServers = {};
    const perRankNames = {};

    for (const entry of slice) {
      const rankTag = `s${String(entry.rank).padStart(3, '0')}`;
      const snip = snippets[entry.name];
      const servers = snip ? parseSnippetServers(snip.snippetRaw) : null;
      const names = [];

      if (servers && Object.keys(servers).length > 0) {
        for (const [origKey, def] of Object.entries(servers)) {
          const injected = `${rankTag}__${sanitizeKey(origKey)}`;
          mcpServers[injected] = def;
          names.push(injected);
        }
      }

      if (names.length === 0) {
        appendAnomaly(
          `**Batch ${batchIndex}, rank ${entry.rank} (\`${entry.name}\`)** — its snippet ` +
          `produced zero parseable \`mcpServers\` entries (stripJsonc+JSON.parse failed on ` +
          `the stored snippetRaw), so it was excluded from the scan fixture entirely. This ` +
          `should not happen — every snippets.json entry is expected to hold either a ` +
          `verbatim or synthesized valid block. snippetRaw:\n\n\`\`\`json\n${snip ? snip.snippetRaw : 'MISSING'}\n\`\`\``,
        );
      }
      perRankNames[entry.rank] = names;
    }

    batches.push({ batchIndex, entries: slice, mcpServers, perRankNames });
  }
  return batches;
}

/**
 * Runs ONE batch through the real scanner in an isolated tmp cwd+HOME.
 * Caches the raw result (envelope + exit status + stderr) under snapshot/
 * keyed by a hash of the batch's fixture content — a re-run with the same
 * fixture content skips straight to the cached result (resumable, and
 * avoids repeating --online registry lookups for an already-scanned
 * batch).
 */
function runBatch(batch, offlineOnly) {
  const contentHash = crypto.createHash('sha1').update(JSON.stringify(batch.mcpServers)).digest('hex').slice(0, 12);
  const cachePath = path.join(SNAPSHOT_DIR, `scan-batch-${batch.batchIndex}-${contentHash}.cache.json`);

  if (fs.existsSync(cachePath)) {
    return JSON.parse(fs.readFileSync(cachePath, 'utf8'));
  }
  if (offlineOnly) {
    return { envelope: null, status: null, stderr: '', spawnError: null, parseError: null, missing: true };
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'g1372-batch-'));
  const cwdDir = path.join(tmpRoot, 'cwd');
  const homeDir = path.join(tmpRoot, 'home');
  fs.mkdirSync(cwdDir, { recursive: true });
  fs.mkdirSync(homeDir, { recursive: true });
  fs.writeFileSync(path.join(cwdDir, '.mcp.json'), JSON.stringify({ mcpServers: batch.mcpServers }, null, 2));

  let stdout = '';
  let stderr = '';
  let status = null;
  let spawnError = null;

  try {
    stdout = execFileSync('node', [BIN_PATH, 'scan', '--mcp', '--json', '--online'], {
      cwd: cwdDir,
      env: { ...process.env, HOME: homeDir },
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
      timeout: 120000,
    });
    status = 0;
  } catch (err) {
    stdout = err.stdout ? err.stdout.toString('utf8') : '';
    stderr = err.stderr ? err.stderr.toString('utf8') : (err.message || String(err));
    status = typeof err.status === 'number' ? err.status : null;
    if (!stdout) spawnError = err.message || String(err);
  } finally {
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    } catch {
      // best-effort cleanup of our own tmp dir; never fatal
    }
  }

  let envelope = null;
  let parseError = null;
  if (stdout) {
    try {
      envelope = JSON.parse(stdout);
    } catch (err) {
      parseError = err.message;
    }
  }

  const result = { envelope, status, stderr, spawnError, parseError };
  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  fs.writeFileSync(cachePath, JSON.stringify(result, null, 2));
  return result;
}

function deriveProvenance(findings, hadNpxOrUvxCommand) {
  const relevant = findings.filter(f => f.detector === 'provenance');
  if (relevant.some(f => f.id.endsWith('/no-attestation'))) return 'lacks-attestation';
  if (relevant.some(f => f.id.endsWith('/fetch-failed'))) return 'unverified-fetch-failed';
  if (relevant.some(f => f.id.endsWith('/unverified-offline'))) return 'unverified-offline';
  if (!hadNpxOrUvxCommand) return 'not-applicable';
  // provenance.js: "attestations present -> no finding (clean)" — the
  // absence of any provenance finding for an npx/uvx-resolvable server
  // that WAS checked (--online) means it has one.
  return 'has-attestation';
}

async function main() {
  const offlineOnly = process.argv.includes('--offline');
  if (!fs.existsSync(SELECTION_PATH) || !fs.existsSync(SNIPPETS_PATH)) {
    console.error('03-scan-runner.js: selection.json/snippets.json missing — run 01/02 first.');
    process.exitCode = 1;
    return;
  }

  const selection = JSON.parse(fs.readFileSync(SELECTION_PATH, 'utf8'));
  const snippets = JSON.parse(fs.readFileSync(SNIPPETS_PATH, 'utf8'));
  const batches = buildBatches(selection, snippets);

  const serversByRank = new Map();
  let incompleteBatchCount = 0;

  for (const batch of batches) {
    // eslint-disable-next-line no-await-in-loop -- sequential/isolated by design
    const result = runBatch(batch, offlineOnly);

    if (!result.envelope) {
      incompleteBatchCount++;
      appendAnomaly(
        `**Batch ${batch.batchIndex} — scan did not complete.**\n\n` +
        `- ranks in this batch: ${batch.entries.map(e => e.rank).join(', ')}\n` +
        `- exit status: ${result.status}\n` +
        `- spawnError: ${result.spawnError || 'none'}\n` +
        `- parseError: ${result.parseError || 'none'}\n` +
        `- stderr (truncated): ${(result.stderr || '').slice(0, 2000)}\n`,
      );
      for (const entry of batch.entries) {
        serversByRank.set(entry.rank, { entry, findings: [], servers: [], scanIncomplete: true });
      }
      continue;
    }

    const envelope = result.envelope;
    if (envelope.exitCode === 2) {
      incompleteBatchCount++;
      appendAnomaly(
        `**Batch ${batch.batchIndex} — envelope reported exitCode 2 (incomplete).**\n\n` +
        `- ranks in this batch: ${batch.entries.map(e => e.rank).join(', ')}\n` +
        `- envelope.error: ${envelope.error || 'none'}\n` +
        `- sources: ${JSON.stringify(envelope.sources)}\n`,
      );
    }

    for (const entry of batch.entries) {
      const injectedNames = new Set(batch.perRankNames[entry.rank] || []);
      const servers = (envelope.servers || []).filter(s => injectedNames.has(s.name));
      const findings = (envelope.findings || []).filter(f => injectedNames.has(f.serverName));
      serversByRank.set(entry.rank, {
        entry,
        findings,
        servers,
        scanIncomplete: envelope.exitCode === 2,
      });
    }
  }

  flushAnomalies();

  const datasetServers = [];
  for (const entry of selection) {
    const snip = snippets[entry.name] || {};
    const rec = serversByRank.get(entry.rank) || { findings: [], servers: [], scanIncomplete: true };
    const hadNpxOrUvx = rec.servers.some(s => s.command === 'npx' || s.command === 'uvx');
    datasetServers.push({
      rank: entry.rank,
      name: entry.name,
      npmPackage: entry.npmPackage,
      pypiPackage: entry.pypiPackage,
      version: snip.version || null,
      monthlyDownloads: entry.monthlyDownloads,
      repoUrl: entry.repoUrl,
      source: entry.source,
      snippetRaw: snip.snippetRaw || null,
      synthesized: !!snip.synthesized,
      needsReview: !!snip.needsReview,
      scanIncomplete: !!rec.scanIncomplete,
      findings: rec.findings.map(f => ({
        id: f.id,
        detector: f.detector,
        severity: f.severity,
        confidence: f.confidence,
        message: f.message,
      })),
      provenance: rec.scanIncomplete ? 'scan-incomplete' : deriveProvenance(rec.findings, hadNpxOrUvx),
    });
  }

  const dataset = {
    snapshotDate: selection[0] ? selection[0].snapshotDate : null,
    pinnedCommit: '9be47145400310292307f047242d637d82b36c72',
    scannerVersion: PKG_VERSION,
    incompleteBatchCount,
    servers: datasetServers,
  };

  fs.writeFileSync(DATASET_PATH, JSON.stringify(dataset, null, 2));
  console.log(
    `Wrote dataset.json: ${datasetServers.length} servers across ${batches.length} batches ` +
    `(${incompleteBatchCount} batch(es) incomplete).`,
  );
}

main().catch(err => {
  console.error('03-scan-runner.js failed:', err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
