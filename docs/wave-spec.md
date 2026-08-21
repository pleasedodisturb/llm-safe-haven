# Authoring a Wave Spec

A step-by-step reference for adding a new supply-chain wave (a new Shai-Hulud-lineage
attack, a new worm, a new campaign) to `llm-safe-haven`'s traversal engine. Written for
someone doing this under time pressure — possibly you at 2am during a live incident,
possibly an automated agent triggered off a Linear ticket.

---

## What a wave spec is

The traversal engine (`lib/traverse/`) is data-driven: IOC data lives in a versioned JSON
file under `manifests/waves/`, and the same engine code walks the filesystem, classifies
files, and matches every wave's IOCs against them. **A new wave is a spec plus tests, not
a new scanner.** Before this engine existed, each wave got its own hand-rolled bash
script (`scripts/scan-shai-hulud-may2026.sh`, `scripts/scan-miasma-june2026.sh`,
`scripts/scan-g747-may22.sh`) — three independent implementations of the same
enumerate-classify-match logic, each with its own traversal bugs. Migrating those three
legacy scanners onto the wave-spec architecture is tracked separately as **G-1490**; they
still work standalone today (see the header comment in each file) and are not touched by
this doc. `scripts/scan-chaindrop-aug2026.sh`, the current bundled scanner, is retrofitted
onto `manifests/waves/chaindrop-aug2026.json` in plan 17-14.

If you're adding a wave, you are writing a new file under `manifests/waves/`, not a new
`.sh` file.

---

## Field reference

Every field that can appear in a wave-spec JSON file. `fileMarkers` through `bounds` are
the eleven sections `lib/traverse/wave-spec.js`'s `REQUIRED_SECTIONS` demands — a spec
missing any of them fails validation with a reason naming the missing section.
`specVersion`, `wave`, `updated`, `description`, and `sources` are optional metadata (not
required by the validator, but every bundled spec carries them, and you should too).

| Field | Type | Required | What the engine does with it |
|-------|------|----------|-------------------------------|
| `specVersion` | number | optional (recommended) | Read by `loadWaveSpec`/`validateWaveSpec`. Must be a member of `SUPPORTED_SPEC_VERSIONS` (currently `[1]`) or the whole spec fails closed — see specVersion policy below. |
| `wave` | string | optional | Free-text identifier for the wave (e.g. `"chaindrop-aug2026"`), not read by the validator. Used in log lines and for humans to identify which file they're looking at. |
| `updated` | string | optional | Free-text ISO date, documentation only. |
| `description` | string | optional | Free-text summary, documentation only. Subject to the same string-hygiene rule as every other spec string (no newline/CR/NUL). |
| `sources` | string[] | optional | Vendor writeup URLs. Documentation only — not read by the engine — but the authoring checklist below requires at least two independent ones. |
| `fileMarkers` | object | **required** | `fileMarkers.fail` (string[]) is an exact-filename FAIL list, checked against every file the `all-files` class walks. `fileMarkers.warnOnly` (string[], optional) is the same but WARN severity. `fileMarkers.variantPattern` (object, optional) describes a glob-matched family of renamed payload variants, with `globs`, `sizeThresholdBytes`, and `excludeExactNames` (so a name already in `fail` isn't double-reported) — FAIL when a variant carries a `knownBadHashes` match or is `>= sizeThresholdBytes`, WARN otherwise. |
| `knownBadHashes` | array of `{ sha256, description, sizeBytes }` | **required** | Definitive hash matches, checked by the targeted hash-candidate tier — see the `hashCandidateMaxBytes` bound below for why this tier is not capped at the bulk-scan size. `sha256` must be a 64-character hex string or the spec fails validation. |
| `poisonedVersions` | object mapping package name → version string[] | **required** | Cross-checked against lockfiles (`lockfiles` class) and installed `node_modules` (`family-packages` class). FAIL only fires on a listed version — mere presence of the package at a pre-attack version is not an IOC. |
| `compromisedFamily` | string[] | **required** | The package names the `family-packages` class walks `node_modules` looking for, cross-referenced against `poisonedVersions` for the actual FAIL condition. Family presence alone is informational, not a finding. |
| `markerStrings` | string[] | **required** | Literal strings (C2 domains, IPs, wallet addresses, dead-drop description text) grepped for by the `marker-config` class (extension-allowlisted per `spec.classes['bulk-content'].fileGlobs`, size-capped by `bulkReadCapBytes`, and — per the tiering rule below — never `.gitignore`-pruned, for every allow-listed name, not just `.env`/`.env.*`/`.npmrc`). |
| `installMarker` | object with `filename`, `pattern`, `jsPattern`, `prune`, `note` | **required** | Drives the `no-prune` class — a regex (POSIX `pattern` for the bash-era ground truth, `jsPattern` for the engine) matched against `filename` (typically `package.json`) with **no directory prune at all**, including inside `node_modules`. This is deliberately the widest-scoped check in the taxonomy. |
| `persistence` | object with `claudeSettings`, `vscodeTasks` sub-objects | **required** | Drives the `agent-config` class: glob-matched `.claude/settings*.json` / `.vscode/tasks.json` files checked against `commandPattern` / `triggerPattern` + `failPattern`. Like `installMarker.pattern`/`jsPattern`, `claudeSettings.commandPattern` and `vscodeTasks.failPattern` are POSIX ERE for the bash-era ground truth; the engine consumes the required `jsCommandPattern` / `jsFailPattern` siblings instead, because a JS `RegExp` does not understand a POSIX bracket class such as `[[:space:]]` (G-1482). `triggerPattern` has no POSIX-class dependency and needs no `js*` counterpart. This is the AI-agent persistence-hook detection — the vector most of the 2026 waves actually use for re-execution (see `docs/supply-chain-defense.md`). |
| `lockfiles` | string[] | **required** | Filenames the `lockfiles` class matches (`package-lock.json`, `yarn.lock`, etc.), scanned for `poisonedVersions` entries. |
| `staticPaths` | string[] | **required** | Fixed, non-walked paths (typically under `$HOME`) checked directly for existence — persistence artifacts that don't live inside a project tree (systemd units, LaunchAgents, the two `$HOME/.claude/settings*.json` paths). |
| `classes` | object | **required** | Declares, per targeted-class name, its directory-prune scope (`pruneCommon`, a custom array, or none), whether it walks into `node_modules` (`includesNodeModules`), and (for `bulk-content`) its file-extension allowlist and size cap. This is the ground truth the engine's `FILE_CLASSES` prune-scope table in `lib/traverse/index.js` formalizes. Must be a plain object or the spec fails validation. |
| `bounds` | object | **required** | Numeric limits — see the Bounds section below. Every value except the free-text `note` key must be a positive safe integer or the spec fails validation. |

Every string anywhere in the spec — value *or* object key — is checked for embedded
newline, carriage-return, or NUL bytes (`lib/traverse/wave-spec.js`'s hygiene rule) and
for `__proto__`/`constructor`/`prototype` keys (prototype-pollution rule), because spec
scalars later get written into results-directory list files and bash array
interpolations. A spec that fails either check is rejected with a reason naming the exact
path.

---

## specVersion policy

- `specVersion` is an integer, currently `1` (`SUPPORTED_SPEC_VERSIONS = [1]` in
  `lib/traverse/wave-spec.js`).
- The engine refuses an unknown or malformed `specVersion` — missing, wrong type
  (`"1"` as a string does NOT coerce), or a number not in `SUPPORTED_SPEC_VERSIONS` — and
  reports it as an **incomplete scan (exit 2)**, never a clean one. A spec that fails to
  load is not "no IOCs to check"; it's "the scanner could not run."
- **Adding a new optional field to the spec format does NOT bump `specVersion`.** A field
  the current validator doesn't yet know about is simply ignored — additive changes are
  backward compatible.
- **Changing the meaning or type of an EXISTING field DOES bump `specVersion`,** and
  requires updating `SUPPORTED_SPEC_VERSIONS` and every validator rule that depends on the
  old shape. Do this rarely — it is a breaking change to every spec file already on disk.

---

## Tiering rules

There is no gitignore-consulting tier. Every class `FILE_CLASSES` (`lib/traverse/index.js`)
lists is targeted — always runs, NEVER pruned by `.gitignore`: `all-files`, `no-prune`,
`lockfiles`, `family-packages`, `agent-config`, `marker-config`, `env-secrets`, and (as data
only, see below) `bulk-content`.

**`.gitignore` is attacker-controlled input.** In a compromised repository, nothing stops an
attacker from adding a line to `.gitignore` that hides their own payload from a
gitignore-aware scanner. That is precisely why every check this engine runs — filenames,
hashes, poisoned versions, persistence hooks, `.env` discovery, and marker-string scanning
— runs regardless of `.gitignore`.

**2026-08-07 revision — the gitignore-delegated bulk tier is retired, and the former
`git-ignore.js` traverse module (deleted 2026-08-07, Phase 17 D-13) is removed.** The
original design put ordinary source-file marker-string scanning
(`.js`/`.mjs`/`.ts`/`.json`/`.sh`/`.yml`/`.md`/`.lock`/etc — the `bulk-content` allowlist)
behind a gitignore-prunable `bulk-content` class, consulting the former `git-ignore.js`
module's `isBulkEligible()` to decide what to skip, with only the credential-bearing
subset (`.env`/`.env.*`/`.npmrc`, `marker-config`) kept targeted. Human
review of the retrofit (plan 17-14, G-1482) rejected this as a real detection regression,
not an acceptable trade-off — the pre-retrofit bash scanner never consulted `.gitignore`
for *any* of its marker-string allowlist, not just credential files, and deciding what a
supply-chain scanner does NOT read by consulting a file inside the repository being
scanned is an attacker-addressable blind spot in its own right. Measured cost of removing
the tier: nothing (a full `$HOME` scan went from 11,040 ms to 7,862-10,714 ms afterward,
because `bulk-content`'s allowlist was narrow to begin with); the tier was never the
scanner's worst-case protection anyway — the locked 60s / 1,000,000-file budget backstop
provides that independently, and when it bites the scan exits 2, visibly incomplete,
rather than silently narrowing what was read.

The fix: `lib/traverse/classify.js`'s `isMarkerConfigMember` was widened to cover every
name `spec.classes['bulk-content'].fileGlobs` lists, not just the credential-file subset,
restoring exact bash parity. `classify()` can no longer assign the `bulk-content` class to
anything, so `git-ignore.js` — the module that supplied the gitignore resolver, and its
only consumer — was deleted entirely, along with its two `lib/traverse/engine.js` call
sites and its test file `git-ignore-source.test.js` (also deleted 2026-08-07). `classify()`'s
`ctx` parameter no longer accepts an `ignore` field at all. `tests/traverse/zero-git-subprocess.test.js` is
the committed proof, against a real engine run, that no `child_process.spawnSync` call
happens anywhere in this engine any more.

`spec.classes['bulk-content'].fileGlobs` is KEPT (not deleted, not renamed) as the data
source `marker-config`'s widened predicate reads from — renaming or removing it is a wave
spec schema change requiring a `specVersion` bump (17-04's validator is fail-closed with a
versioned `specVersion` plus a three-way drift guard), and the field's role changed from
"the bulk-tier allowlist" to "the full marker-string allowlist, all of it targeted" without
any change to its shape. `bulkReadCapBytes` still applies uniformly to every marker-string
candidate (targeted reads share the exact same size-cap code path bulk reads used to, in
`lib/traverse/read-pool.js`), so it continues to control the marker-string scan's read cost.
See `lib/traverse/classify.js`'s module header, `.planning/phases/17-.../17-08-SUMMARY.md`
and `17-10-SUMMARY.md`'s superseded notes, and the 17-14 plan summary for the full history.

**Moving a check into a gitignore-prunable tier is a security downgrade and requires
explicit review**, not a routine refactor — this is exactly what the 2026-08-07 revision
above reverted, and there is no longer a gitignore-prunable tier to move a check into at
all. If a scan needs to run faster, lower `bulkReadCapBytes` instead (it bounds the
marker-string scan's per-file read cost directly).

---

## Bounds

`bounds` carries three byte-size limits, all currently defined in
`manifests/waves/chaindrop-aug2026.json` and validated as positive safe integers by
`lib/traverse/wave-spec.js`:

| Bound | Value | What it excludes |
|-------|-------|-------------------|
| `bulkReadCapBytes` | `262144` (256 KiB) | Files at or above this size are excluded from the marker-string scan (`marker-config`; applies uniformly regardless of tier — see the 2026-08-07 tiering revision above). |
| `hashCandidateMaxBytes` | `1048576` (1 MiB) | Files at or above this size are excluded from the targeted known-bad-hash candidate selection. |
| `variantSizeThresholdBytes` | `204800` (200 KiB) | Not a scan-eligibility bound — controls the `fileMarkers.variantPattern` FAIL-vs-WARN split (`>=` this size and unmatched by a known hash → WARN, not FAIL). |

**Before merging a new wave, check its real payload size against `hashCandidateMaxBytes`.**
This is not hypothetical: the ChainDrop stage-2 harvester (`Math_Symbol.js`) is **727,680
bytes** — comfortably over the 256 KiB bulk-content cap and the reason
`hashCandidateMaxBytes` exists as a *separate, larger* bound from `bulkReadCapBytes` in
the first place. If your new wave's payload is bigger than 1,048,576 bytes, the current
`hashCandidateMaxBytes` won't catch it either, and the bound needs to move (with a
`specVersion` review, since it's a shared value) — not the payload silently going
undetected.

Both byte bounds **exclude** files at or above the threshold; they do not truncate and
read a prefix. This matches the semantics of the `find -size -256k` / `find -size -1024k`
predicates the pre-engine bash scanner used — those are block-rounded exclusive bounds,
which is why `262144` and `1048576` (exact powers of 1024, not "256000"/"1000000") were
chosen: they are the smallest values that are a strict superset of what the bash scanner
read, so the engine may read slightly *more* than the old scanner did, never less. Losing
coverage is the one unacceptable outcome of this migration.

---

## Authoring checklist

Work through this in order. Every step has a concrete, copy-pasteable action.

1. **Source IOCs from at least two independent vendor writeups** (Socket, Wiz,
   StepSecurity, Snyk, Microsoft, Kodem, Aikido, Chainguard, etc.) and record both URLs in
   the spec's `sources` array.
2. **Add poisoned versions to both the wave spec AND the doc-referenced manifest** — for
   ChainDrop that's `manifests/chaindrop-poisoned-versions.json`, kept in permanent parity
   with the spec by `tests/chaindrop-spec-parity.test.js` (three-way drift guard, D-10: the
   manifest is not generated from the spec, the two are cross-validated).
3. **Validate the new spec:**
   ```bash
   node scripts/validate-wave-spec.js manifests/waves/<your-new-wave>.json
   ```
   This must print a line starting with `OK` before you go any further. A `FAIL` line
   names the exact field to fix.
4. **Add one corpus case per new IOC type** in `tests/helpers/chaindrop-corpus.js`, with
   both its expected verdict AND its expected finding count — presence-only assertions
   cannot distinguish "detected once" from "detected twice by two different code paths."
5. **Run the full detection-parity + spec-parity suites:**
   ```bash
   node --test tests/chaindrop-parity.test.js tests/chaindrop-spec-parity.test.js
   ```
6. **Confirm the repo's own self-root scan still comes back ALL CLEAR.** A wave spec that
   makes `llm-safe-haven`'s own source tree "detected" is a false positive that will fire
   on every consumer's install of this tool, not just yours:
   ```bash
   npx llm-safe-haven scan --supply-chain
   ```

---

## Worked example

A minimal, complete spec for a fictional wave (`example-fictional-wave.json`) — short
enough to copy, rename, and edit as a starting point for a real one.

```json
{
  "specVersion": 1,
  "wave": "example-fictional-wave",
  "updated": "2026-08-07",
  "description": "Fictional worked example for docs/wave-spec.md — not a real wave.",
  "sources": [
    "https://example.com/vendor-writeup-one",
    "https://example.com/vendor-writeup-two"
  ],
  "fileMarkers": {
    "fail": ["evil_payload.js"],
    "warnOnly": ["setup_stage1.mjs"],
    "variantPattern": {
      "globs": ["evil_*.js"],
      "sizeThresholdBytes": 204800,
      "excludeExactNames": ["evil_payload.js"],
      "note": "Renamed variants of evil_payload.js."
    }
  },
  "knownBadHashes": [
    {
      "sha256": "0000000000000000000000000000000000000000000000000000000000000",
      "description": "evil_payload.js definitive hash.",
      "sizeBytes": 12345
    }
  ],
  "poisonedVersions": {
    "example-package": ["9.9.9"]
  },
  "compromisedFamily": ["example-package"],
  "markerStrings": ["evil-c2.example.com"],
  "installMarker": {
    "filename": "package.json",
    "pattern": "\"preinstall\"[[:space:]]*:[[:space:]]*\"node[[:space:]]+setup_stage1\\.mjs\"",
    "jsPattern": "\"preinstall\"\\s*:\\s*\"node\\s+setup_stage1\\.mjs\"",
    "prune": "none",
    "note": "Runs with no directory prune, per D-25."
  },
  "persistence": {
    "claudeSettings": {
      "paths": ["*/.claude/settings.json", "*/.claude/settings.local.json"],
      "commandPattern": "setup_stage1|evil_payload|node[[:space:]]+-e",
      "jsCommandPattern": "setup_stage1|evil_payload|node\\s+-e",
      "note": "Glob-matched during the walk (agent-config class)."
    },
    "vscodeTasks": {
      "path": "*/.vscode/tasks.json",
      "triggerPattern": "\"runOn\"\\s*:\\s*\"folderOpen\"",
      "failPattern": "setup_stage1|evil_payload",
      "jsFailPattern": "setup_stage1|evil_payload"
    }
  },
  "lockfiles": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
  "staticPaths": ["$HOME/.claude/settings.json", "$HOME/.claude/settings.local.json"],
  "classes": {
    "pruneCommon": [".git", "target", "dist", "build", ".next", ".nuxt", "*/.claude/worktrees"],
    "all-files": { "prune": "pruneCommon", "includesNodeModules": true, "note": "Filename markers." },
    "no-prune": { "prune": [], "includesNodeModules": true, "note": "Install-marker check." },
    "lockfiles": { "prune": "pruneCommon", "includesNodeModules": false, "note": "Lockfile scan." },
    "family-packages": { "prune": ["*/.claude/worktrees"], "includesNodeModules": true, "note": "Installed-family check." },
    "agent-config": { "prune": "pruneCommon", "includesNodeModules": false, "note": "Persistence hooks." },
    "bulk-content": {
      "prune": "pruneCommon",
      "includesNodeModules": false,
      "excludeCache": true,
      "fileGlobs": ["*.js", "*.mjs", "*.json", "*.sh"],
      "sizeCapBytes": 262144,
      "note": "Marker-string sweep."
    }
  },
  "bounds": {
    "bulkReadCapBytes": 262144,
    "hashCandidateMaxBytes": 1048576,
    "variantSizeThresholdBytes": 204800,
    "note": "Same defaults as every other bundled wave — do not invent new numbers without reviewing the whole spec set."
  }
}
```
