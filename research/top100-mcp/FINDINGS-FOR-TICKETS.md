# G-1372 — Detector/pipeline anomalies for ticket filing

Per ticket AC-3: every false positive, crash, parse failure, or detection gap surfaced by
the run is recorded here for the user to file as its own Linear ticket (team G, parent
G-507). **Zero tickets is a suspicious outcome** — this file states explicitly if the run
was clean; it is not, so this section is populated below.

## Private appendix (do not publish) — maintainer notification candidates

Per the disclosure policy (Methodology §5): anything resembling an exploitable defect
unique to one server is aggregated/anonymized in `DRAFT.md` and listed here instead, for
private maintainer notification rather than public naming.

_(populated after `04-aggregate.js`'s `disclosureCandidates` are reviewed in Task 3 — see
the "Private appendix candidates" section below this line once populated)_

---

## Pipeline anomalies (Task 1 — selection / README extraction)

### 1. Regex fence-pairing desyncs on READMEs with an odd \`\`\` count earlier in the document

**Found during:** Task 1, `02-fetch-readmes.js` initial implementation.
**Symptom:** A single greedy/non-greedy regex scanning a whole README for fenced blocks
silently mispairs open/close markers the moment the document contains an odd number of
\`\`\` occurrences anywhere earlier (a stray decorative fence, certain badge markup). Every
subsequent "block" then spans from one real fence to an unrelated later one, concatenating
HTML/prose with JSON and producing a false `malformed-json` classification for content
that is, in fact, valid.
**Repro:** `@upstash/context7-mcp` and `@ironbee-ai/devtools` npm registry READMEs both
reproduce this with the naive regex (verified interactively via `fetchNpmDoc()` + the old
regex during this session — both READMEs contain a perfectly valid `mcpServers` block that
the regex-pair approach mis-scoped as malformed).
**Fix applied here:** `02-fetch-readmes.js`'s `findJsonBlocksWithMcpServers()` uses a
line-based fence scanner (any line consisting only of backticks toggles fence state,
matching CommonMark semantics) instead of a whole-document regex pair. This is a Task-1
pipeline fix, not a scanner (`lib/`) change — out of scope for a Linear ticket unless a
future contributor wants the same tolerant-fence logic added to a shipped Markdown-parsing
surface (none currently exists in `lib/`).
**Ticket-worthy?** No — this is research-pipeline code (`research/top100-mcp/`), not
shipped scanner code. Documented here for transparency per the anomaly-capture
requirement, not filed as a G ticket.

### 2. JSONC trailing-comment blocks rejected by strict `JSON.parse`, letting an unrelated stricter block win

**Found during:** Task 1, hand-review of `@winor30/mcp-server-datadog` (flagged
`multiple-candidate-blocks-diverge`).
**Symptom:** The package's own correct recommended snippet includes `// Optional` trailing
comments (invalid strict JSON). Before applying `stripJsonc()`, `JSON.parse` rejected that
block outright, so the "first executable" auto-pick fell through to an unrelated (and
apparently leftover/copy-paste) `@modelcontextprotocol/server-github` example earlier in
the same README — a real misattribution risk for any server whose README uses JSONC-style
comments in its example.
**Fix applied here:** `02-fetch-readmes.js` now parses candidate blocks through the
scanner's own `lib/mcp/base.js` `stripJsonc()` (read-only `require`, `lib/` untouched)
before `JSON.parse`, so comment-annotated blocks are correctly recognized as valid/usable
JSON for scoring and signature-divergence comparison.
**Residual risk:** `stripJsonc()`-tolerant scoring fixed the *validity* check, but the
*first-position* tie-break can still auto-pick an unrelated-but-earlier block when a README
literally contains leftover template boilerplate ahead of its real snippet (see finding #3
below) — that class of error requires human judgment, which is exactly what the
`needsReview:true` flag exists for; it is not a scanner bug.
**Ticket-worthy?** No — research-pipeline code, not shipped scanner code.

### 3. Two `needsReview:true` entries had a genuinely misattributed auto-picked snippet (hand-corrected)

**Found during:** Task 1, hand-review pass over all 41 `needsReview:true` entries.

- **`pi-mcp-adapter`** — its README's "Quick Start" section illustrates the tool's own
  config-adapter purpose using a *third-party example server* (`chrome-devtools-mcp`) as
  sample payload. The auto-picker correctly found the only valid `mcpServers` block in the
  README, but that block genuinely does not describe `pi-mcp-adapter` itself. Corrected to
  the synthesized minimal `npx pi-mcp-adapter` form (no self-referential snippet exists in
  the README to substitute instead).
- **`@winor30/mcp-server-datadog`** — README leads with an unrelated leftover
  `@modelcontextprotocol/server-github` block (likely a forgotten template artifact from a
  scaffolding tool) *before* its own real Datadog snippet appears later in the same
  document. Corrected to the package's own verbatim block (transcribed from later in the
  same README, JSONC comments preserved as originally written).

**Ticket-worthy?** No — both are README-content quirks in third-party packages, not
scanner or pipeline defects. Recorded here as the anomaly-capture requirement calls for,
and as an example of exactly the class of case the `needsReview:true` human-review gate
exists to catch (it worked as designed both times).

## Scan anomalies (Task 2 — `03-scan-runner.js`)

_(populated by `03-scan-runner.js` as it runs — see below)_
