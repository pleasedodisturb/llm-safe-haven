# Methodology — Top-100 public MCP server security scan (G-1372)

This directory is research output, not a shipped package (it is not in `package.json`
`files` and is never installed via `npx llm-safe-haven`). It documents, reproduces, and
scans the recommended installation configuration for the 100 most-used public MCP servers,
using llm-safe-haven's own `scan --mcp` detector suite (v0.3.1, 8 detectors) — the exact
tool this repo ships.

## 1. Selection (Task 1 — `01-select.js`)

**Snapshot date:** 2026-07-19 (see `snapshot/selection-date.txt`; every non-`--verify` run
before that file exists stamps the current date, and every run after reuses it so
`--verify` is byte-stable forever).

**Repo commit pinned for the scan phase (Task 2):** `9be47145400310292307f047242d637d82b36c72`
(`v0.3.1`, `main`, produced by `git rev-parse HEAD` at the start of this ticket).

**Node version:** the pipeline requires Node >=18 (repo's own `engines.node`); `fetch` is
the Node global (no HTTP client dependency). Executed here on Node v26.5.0.

### Union of two sources

**(a) Reference servers** — mechanically parsed from the raw
`modelcontextprotocol/servers` README's "Reference Servers" section
(`https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md`), i.e.
the `- **[Name](path)** - description` bullet list up to (excluding) the `### Archived`
heading. **Deviation from the ticket's literal wording:** the ticket describes source (a)
as "every server in the … README (reference + community lists)". As of this snapshot date,
the upstream README no longer embeds a community server list at all — it was migrated
out to `https://registry.modelcontextprotocol.io/`, and the README explicitly redirects
readers there. The registry has no popularity/download signal and is not npm-centric (many
entries are remote-only services with no installable package), so it cannot supply a
reproducible "ranked by downloads" ordering on its own; it was evaluated and rejected as a
primary source for that reason. Source (a) here therefore contributes only the ~7 actively
maintained reference servers (Everything, Fetch, Filesystem, Git, Memory, Sequential
Thinking, Time) — the small, official, always-legitimate set the ticket's own wording
anticipates ("GitHub stars as tiebreak for non-npm" already assumes a small non-npm
subset). This is a Rule 1 auto-fix (the described source no longer exists in that form) —
documented here rather than silently substituted.

For each reference server: derive an npm candidate `@modelcontextprotocol/server-<slug>`
and confirm it via a real `registry.npmjs.org` lookup (TypeScript reference servers
resolve here — Everything, Filesystem, Memory, Sequential Thinking). Python-only reference
servers (Fetch, Git, Time) have no npm package; fall back to a PyPI existence check
(`mcp-server-<slug>` via `pypi.org/pypi/<name>/json` — Fetch/Git/Time all resolve). Every
check is a real, cached HTTP lookup — nothing here is hardcoded.

**(b) npm search** — `registry.npmjs.org/-/v1/search` queried with 5 terms (`mcp`,
`mcp-server`, `modelcontextprotocol`, `mcp-client`, `mcp server`), `size=250` each,
filtered by a name/keyword heuristic (`/(^|[-_@./])mcp([-_./]|$)/` or an `mcp`/
`model-context-protocol` keyword, minus a Minecraft-collision denylist for `mcpe`/
`minecraft`). The npm search API returns `downloads.monthly` inline per result — used
directly as the ranking signal, avoiding a second per-package round trip to
`api.npmjs.org/downloads/point/last-month/<pkg>` (that endpoint IS used for source (a),
where there is no search result to read the figure from — matching the ticket's exact API
for that path).

**Entry-point refinement.** The ticket's own wording for source (b) is "npm packages
matching MCP-server heuristics (keyword/name contains 'mcp', exposes a server entry
point)". The name/keyword filter alone over-admits SDKs/frameworks/UI-adapter libraries
that are not directly `npx`-runnable servers (`@modelcontextprotocol/sdk`, `@mcp-ui/client`,
`@ai-sdk/mcp`). `01-select.js` walks the downloads-sorted candidate pool and, for each one
(reference-README entries are always trusted, they're official by definition), fetches
the package's full registry document and requires a non-empty `bin` field on the latest
published version — "exposes a server entry point" is exactly what `npx <pkg>` needs to
find something to execute. Platform-specific prebuilt-binary sub-packages (npm's own
`<pkg>-<darwin|linux|win32|android>[-<arch>]` convention, e.g. `@azure/mcp-darwin-arm64`)
are excluded outright before the registry check — they are never installed directly.
Insufficient registry data is treated leniently (never punishes a candidate the check
can't evaluate).

### Ranking and dedup

Union → dedupe by package name (source (a) wins a collision with (b)) → sort by monthly
downloads descending (`null` sorts last; package name is the final deterministic tiebreak)
→ walk the sorted list applying the entry-point/platform-binary filters until `--limit`
(default 100) servers are collected.

### Reproducibility (AC-4)

Every HTTP response (npm search pages, registry package documents — trimmed to just the
fields the pipeline reads: readme text, the latest version's `{version, bin, description}`,
repository/homepage links — READMEs, PyPI lookups) is cached to `snapshot/` keyed by a
SHA1 of the URL plus a human-readable hint, as one JSON envelope covering both hits and
negative results (404s, exhausted retries) so a second run never re-fetches anything —
including permanent misses. `node 01-select.js --verify` re-derives the identical ranked
list reading `snapshot/` **only** (every fetch call is `offlineOnly:true`, and any URL not
already cached resolves to a deterministic "missing" result rather than a network call) and
asserts byte-for-byte JSON equality against the committed `selection.json`. Verified locally
after every run in this ticket (`VERIFY OK: 100 servers, byte-stable order reproduced from
snapshot/ offline`).

### Exact commands to reproduce

```bash
cd research/top100-mcp
node 01-select.js --limit 100      # writes selection.json (network; resumable via snapshot/)
node 01-select.js --verify         # re-derives from snapshot/ only, asserts byte-stable order
node 02-fetch-readmes.js           # writes snippets.json (network; resumable via snapshot/)
node 03-scan-runner.js             # writes dataset.json (spawns the real scanner; no network beyond --online provenance lookups)
node 04-aggregate.js               # writes stats.json
```

## 2. Snippet extraction (Task 1 — `02-fetch-readmes.js`)

For each selected server: README resolved from the npm registry document's `readme` field
first (shares the exact same cache entry `01-select.js` already populated for the
entry-point check — one fetch per package across the whole pipeline), falling back to
`raw.githubusercontent.com/<owner>/<repo>/{main,master}/README.md` when the registry
readme is empty (common — many packages ship "see GitHub" placeholders) or the package has
no npm presence at all (PyPI-only reference servers).

The README is scanned for fenced code blocks containing the substring `mcpServers`, using
a **line-based fence scanner** (any line that is only backticks toggles fence state) rather
than a single regex spanning the whole document. A regex-pair approach silently desyncs
the moment a README contains an odd number of ``` markers anywhere earlier in the document
(a stray decorative fence, a badge with embedded backticks) — every subsequent "block" then
spans from one real fence to an unrelated later one, concatenating prose with JSON and
reporting a false `malformed-json`. This was observed and fixed during this ticket (see
`FINDINGS-FOR-TICKETS.md`).

Blocks are parsed tolerant of JSONC-style trailing `// comments` (reusing the scanner's
own `lib/mcp/base.js` `stripJsonc()` — read-only import, never modifies `lib/`) since
several READMEs document their example with inline comments, which is invalid strict JSON
and would otherwise make the wrong (but strictly-parseable) block win over the actually
correct one.

**Selection among multiple blocks:** the first block with an executable `command` wins by
default. A block set only earns `needsReview:true` when the underlying `{command, args,
url}` signature of the candidate blocks **genuinely diverges** (different servers,
different transports, different pinning) — not merely because a server documents the same
install once per client wrapper (Claude Desktop / Cursor / VS Code / Windsurf sections
showing an identical snippet is the overwhelmingly common case for well-documented servers
and needs no human judgment call). No block at all (or all candidates malformed) →
synthesize the minimal `{ "mcpServers": { "<name>": { "command": "npx"|"uvx", "args": [...] } } }`
form and mark `synthesized:true`. No README found at all also earns `needsReview:true` per
the plan's exact edge-case list.

Two `needsReview:true` entries were hand-corrected after inspection (both are genuine
README-content edge cases, not extraction bugs in the general case — full detail and repro
in `FINDINGS-FOR-TICKETS.md`):

- `pi-mcp-adapter` — its README's "Quick Start" section demonstrates configuring a
  third-party example server (`chrome-devtools-mcp`), not itself. Corrected to the
  synthesized minimal form.
- `@winor30/mcp-server-datadog` — its README leads with an unrelated leftover
  `@modelcontextprotocol/server-github` boilerplate block (a copy-paste artifact) before
  its own real Datadog snippet later in the document. Corrected to the package's own
  verbatim block (transcribed from the same README, JSONC comments preserved as originally
  written).

## 3. Scanning (Task 2 — `03-scan-runner.js`)

Batches of ~10 servers become one synthetic `.mcp.json` (`project` scope). Every entry's
name is rewritten to a unique deterministic id (`s001__<pkg>`, …) before merging into the
batch file, so findings are unambiguously joinable back to a source server AND no
false `tool-shadowing` name-collision is induced by two unrelated servers happening to pick
the same display name (`Filesystem`, `Memory`, etc.).

**Isolation.** Each batch runs in a fresh OS-tmp directory as both `cwd` (project-scope
`.mcp.json` discovery) and an isolated, empty `HOME` (`env.HOME`) so `user`/`local` scope
discovery — which reads `<HOME>/.claude.json` — can never see the executor's real config.
Discovery for the `claude-code` agent additionally gates on `commandExists('claude')`,
which shells out to `which claude` — PATH-based and independent of `HOME`, so the isolated
child still discovers the fixture correctly as long as the `claude` CLI is on `PATH`
(verified locally: `/Users/pleasedodisturb/.local/bin/claude`). Spawned via
`execFileSync('node', [<repoRoot>/bin/llm-safe-haven.js, 'scan', '--mcp', '--json',
'--online'], { cwd, env, maxBuffer })`. After parsing stdout, only `envelope.servers` /
`envelope.findings` whose name/`serverName` is in that batch's injected set are kept
(belt-and-suspenders against any wider config leaking through discovery).

`--online` is passed per batch (host-pinned `registry.npmjs.org` provenance lookups only,
exactly what `docs/mcp-security.md` §4 documents as `--online`'s entire footprint).

Exit codes `0` (clean) and `1` (verified findings) are both normal outcomes. Exit `2`
(incomplete/build-error) is recorded as an anomaly in `FINDINGS-FOR-TICKETS.md` together
with the batch's `error`/source statuses and stderr — never silently treated as clean.
Every batch spawn is wrapped in try/catch; a crash is an anomaly, not fatal, and the run is
resumable (a batch whose result is already cached is skipped on re-run).

## 4. Cross-set tool-shadowing analysis (Task 2 — `04-aggregate.js`)

Best-effort, from README tool tables where tool names are statically visible in the
snippet/README text — no code execution, no live `tools/list` introspection (this scanner
never does that, see fidelity limits below). Servers where tool names are not statically
recoverable are skipped and counted as skipped, not silently omitted.

## 5. Disclosure policy (locked, ticket §Methodology step 5)

Aggregate statistics are always publishable. A named server may appear in `DRAFT.md`
**only** for an objectively-public fact about its recommended install: an unpinned
version spec, a missing provenance attestation, a plain-HTTP endpoint. Anything resembling
an actual exploitable defect unique to one server is never named in the draft — it is
aggregated/anonymized and recorded under a "Private appendix candidates" section for
maintainer notification instead. When unsure, aggregate. This self-review runs against
`stats.json`'s `disclosureCandidates` list before `DRAFT.md` is finalized (Task 3).

## 6. Fidelity honesty (ticket §Methodology step 6)

This research inherits the scanner's own honest limitations verbatim — `docs/mcp-security.md`
§5 is the canonical statement and `DRAFT.md`'s fidelity-limits section mirrors it:

- **No `tools/list` introspection.** Every finding here comes from a static parse of the
  recommended install config, never a live connection to any of the 100 servers.
- **`provenance` checks attestation presence, not authenticity.** "Has an attestation"
  means the package was published through npm's provenance pipeline — it says nothing
  about whether the code inside is safe.
- **Edit-distance `typosquat` cannot catch combosquats.** A plausible new name that isn't a
  near-miss of a known package (the `easy-day-js` case in `threat-model.md`) is a
  documented, tested blind spot, not something this run additionally catches.
- **`tool-poisoning` here is the same static heuristic** as the shipped detector — config
  strings and, best-effort, a locally-resolved `package.json` description. Nothing about
  a server's actual runtime tool descriptions.

## 7. Known selection-heuristic limitations

Documented here rather than silently patched around, per the ticket's "detector feedback
loop, not detector fix" instruction (these are dataset-collection observations, not
scanner bugs — see `FINDINGS-FOR-TICKETS.md` for the scanner-relevant subset):

- The name/keyword heuristic still admits a handful of general-purpose MCP
  frameworks/adapters whose README examples are self-referential scaffolding rather than a
  single canonical server config (`mcp-framework`, `mcp-use` and its `@mcp-use/*`
  siblings, `fastmcp`). These are legitimate `npx`/`bin`-bearing packages that satisfy
  every mechanical filter; distinguishing "framework users configure servers with" from
  "server you install" would require semantic classification out of scope for a
  mechanical selection pipeline. Their entries are correctly marked `synthesized:true`
  where no single literal `mcpServers` snippet exists in the README (their examples are
  Python/JS code samples embedding a config dict, not standalone JSON).
