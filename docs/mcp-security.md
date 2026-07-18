# MCP Security

**MCP server configs are now a first-class attack surface.** The June 2026 Hades wave
(Wave G) targeted MCP server packages directly instead of general npm/PyPI dependencies
— see [Real Incidents](#7-real-incidents) below. `scan --mcp` is a static config scanner
built to catch the failure modes those incidents exploited, before you run the server.

This is not a live-connection scanner. It reads the config files your agents load at
startup and reasons about what's declared there. Section 5 spells out exactly what that
means you're NOT getting.

---

## 1. What `scan --mcp` covers

`scan --mcp` discovers and parses MCP server configs across **5 agents**: Claude Code,
Cursor, Windsurf, Cline, and Continue.dev. For Claude Code specifically, it reads all
**3 config scopes**:

| Scope | Path | Notes |
|-------|------|-------|
| `user` | `~/.claude.json` (top-level `mcpServers`) | Applies to every project |
| `local` | `~/.claude.json` (project-nested `projects[<cwd>].mcpServers`) | Same file, per-project section |
| `project` | `<project>/.mcp.json` | Committed to the repo, shared with collaborators |

Cursor, Windsurf, Cline, and Continue.dev each contribute their own global/project config
paths through the same discovery layer.

**Offline-first by default.** Every detector runs against the parsed config text alone —
zero network calls unless you pass `--online` (see [Section 4](#4-offline-vs---online)).
This is a static config scan: no server process is started, no `tools/list` request is
sent, nothing on your machine actually connects to any MCP server to produce a finding.

## 2. Quickstart

```bash
npx llm-safe-haven scan --mcp             # Human-readable report, offline
npx llm-safe-haven scan --mcp --json      # Machine-readable output for CI
npx llm-safe-haven scan --mcp --online    # Opt in to registry provenance checks
```

Exit codes (a security gate must never report "clean" when the scan didn't finish):

| Code | Meaning |
|------|---------|
| `0` | Clean — scan completed, no findings |
| `1` | Findings — scan completed, at least one verified finding |
| `2` | Error or incomplete — the scan could not finish (parse failure, unreadable config); never treated as clean |

## 3. Detector reference

Eight detectors run on every scan. Each one's honest limitation is listed alongside what
it catches — read [Section 5](#5-fidelity-limits-honestly) for the full picture.

| Detector | Rule IDs | Severity | Confidence | What it catches | One limitation |
|----------|----------|----------|------------|------------------|-----------------|
| `credential-passthrough` | `inlined-secret`, `broad-inheritance`, `sensitive-name-literal` | critical / high / low | verified | Env values matching a known secret pattern (critical), high-entropy or sensitive-key-named literals (high), wildcard/whole-env passthrough tokens (low, advisory) | Only sees explicit `env` blocks — a config that implicitly inherits the shell environment by omitting `env` entirely is invisible to a static parser |
| `insecure-endpoint` | `plain-http`, `wildcard-bind`, `unauthenticated-transport` | high / high / medium | verified | Plain `http://` remote transport, wildcard/any-interface bind hosts (`0.0.0.0`, `[::]`), remote endpoints with no recognized auth header | Only checks that *an* auth header name is present — it can't tell if the token behind it is valid or the transport is otherwise trustworthy |
| `provenance` | `unverified-offline`, `fetch-failed`, `no-attestation` | info / info / low | unverified / unverified / verified | Whether a resolved npm package has a `dist.attestations` provenance record (only meaningful with `--online`) | Presence-only — never a cryptographic Sigstore verification. Findings say "has/lacks attestation", never claim the package's authenticity was verified |
| `scope-breadth` | `unscoped-broad-capability` | info | verified | Servers that look filesystem/shell/terminal-capable per a narrow allowlist AND declare no explicit path-bounding argument | Deliberately narrow allowlist — false negatives are accepted by design; a capable server this detector doesn't recognize simply isn't flagged |
| `tool-poisoning` | `injection-phrase`, `invisible-unicode`, `package-metadata` | medium | verified | Imperative-injection phrases and invisible/bidi Unicode in config strings; for npx/uvx servers, the same checks against a locally-resolved package's `package.json` description | Static heuristic over config-adjacent text only — structurally cannot see a live server's `tools/list` response |
| `tool-shadowing` | `name-collision` | medium | verified | The same server `name` resolving to a different `(command, args, url)` signature across agents/scopes | Static server-name collision proxy, not verified tool-level shadowing at the MCP protocol layer |
| `typosquat` | `allowlist-unavailable`, `near-known-name`, `scope-confusion` | info / high / high | unverified / verified / verified | Package names within edit-distance threshold of a known-good allowlist entry; bare names claiming a scope that belongs to a different known publisher | Edit-distance cannot catch combosquats — see [easy-day-js](#5-fidelity-limits-honestly) below |
| `unpinned-execution` | `{npx\|uvx}-no-version`, `url-no-version-binding` | medium | verified | npx/uvx servers invoked without an exact version pin (bare name, `@latest`/`@next`/`@canary`, floating ranges); remote URLs with no version/integrity binding | Only checks that a pin exists syntactically — doesn't verify the pinned version itself is safe or unmodified |

## 4. Offline vs `--online`

By default, `scan --mcp` makes **zero network calls**. Detectors that would need a
network round-trip (provenance lookups, allowlist freshness) degrade to a fourth,
honest state instead of guessing: **unverified**. Unverified findings render dim (not
severity-colored), never cap your Security Level, and carry a
`run with --online to verify` sub-line.

`--online` opts you into exactly one thing:

> `--online` Opt in to network calls for provenance checks on `scan --mcp`
> (transmits package names to registry.npmjs.org, opt-in only).

That's the whole privacy footprint: package names, sent to `registry.npmjs.org`, only
when you pass the flag. No config contents, no file paths, no telemetry, nothing else
leaves your machine.

## 5. Fidelity limits, honestly

This is the section that matters most if you're deciding how much to trust a clean scan.

**`scan --mcp` is a static config scanner, not a live-connection scanner.** It never
starts an MCP server process and never inspects a live `tools/list` response. Concretely:

- **No `tools/list` introspection.** A server whose config looks clean but whose runtime
  tool descriptions carry hidden instructions is invisible to this scanner — that's a
  runtime phenomenon a static parser structurally cannot observe.
- **`tool-poisoning` is a static heuristic**, not equivalent to live `tools/list`
  inspection. It scans config strings (and, best-effort, a locally-resolved
  `package.json` description) for injection phrases and invisible Unicode — nothing
  more.
- **`provenance` checks attestation *presence*, not authenticity.** A package that
  "has an attestation" was published through npm's provenance pipeline; it does not mean
  the code inside it is safe. We deliberately say "has/lacks attestation," and never
  claim the package's contents were cryptographically checked — those are different
  claims, and conflating them is exactly the overstatement this section exists to
  prevent.
- **Edit-distance cannot catch combosquats.** `typosquat` flags names that are a small
  edit away from a *known* name. It cannot flag a plausible *new* name that isn't a
  near-miss of anything in the allowlist — a combosquat, not a typosquat. The
  [Mastra `easy-day-js` attack](threat-model.md#june-2026--mastra-ai-npm-supply-chain-attack-via-easy-day-js-typosquat-june-17)
  is the textbook case: `easy-day-js` isn't a one-character edit of any known package
  name, it's a plausible-sounding new name for a date library, and no edit-distance
  threshold would have flagged it. We ship a regression fixture
  (`tests/mcp/fixtures/detectors/typosquat/combosquat.json`) that asserts this exact
  miss produces zero findings — we test our own blind spot rather than pretend it
  doesn't exist.

If you need live introspection or semantic classification of a server's actual tool
descriptions, `scan --mcp` is not that tool (yet) — live introspection is on the
roadmap. If you're tracking it, watch the
[project issues](https://github.com/pleasedodisturb/llm-safe-haven/issues).

## 6. Scorecard gating

A clean `scan --mcp` run is a prerequisite for **Security Level 3 (Hardened)**. MCP
scan state feeds three commands, each with its own exit-code contract — here are the
exact semantics, so you gate CI on the right one:

**`scan --mcp` — the CI gate for MCP findings.**

| Code | Meaning |
|------|---------|
| `0` | Clean — scan completed, no verified findings (unverified-only notices are exit `0`) |
| `1` | At least one **verified** finding |
| `2` | Error or incomplete — the scan did not finish |

**`audit` — the CI gate for overall posture.**

| Code | Meaning |
|------|---------|
| `0` | Security Level 2+ (and the in-process MCP scan completed) |
| `1` | Security Level below 2 (scan completed) |
| `2` | The MCP scan `audit` runs in-process did not complete — a pass/fail verdict built on an unfinished scan would not be trustworthy, so `audit` refuses to emit one |

Verified MCP findings demote the Security Level (rules below) and therefore block
Level 3+, but they do **not** by themselves fail `audit`'s exit code — a Level 2 setup
with verified MCP findings still exits `0` from `audit`. If you want CI to fail on MCP
findings, gate on `scan --mcp` (exit `1`), not on `audit`.

**`install` — informational, never a gate.** The default `npx llm-safe-haven` run
prints the same scorecard through the same level pipeline, but its exit code carries no
gating signal. CI gating belongs to `audit` (level + incomplete-scan) and `scan --mcp`
(findings).

The Security Level rules, in priority order:

1. **An incomplete MCP scan caps the level at 2** — and, as of the table above, fails
   `audit` with exit `2`. An unfinished scan (parse error, unreadable config) is never
   treated as clean, because you don't actually know what it would have found.
2. **A verified MCP finding caps the level at 2** — regardless of severity, a verified
   finding means the scan found something concrete to fix.
3. **Unverified findings never cap the level.** An offline-degraded "unverified" result
   (e.g. provenance not checked because you didn't pass `--online`) is informational,
   not a gate — the scan didn't fail, it just didn't check everything it could.
4. **The existing `.env`-exposure cap (Level 1) is independent.** If both the `.env`
   cap and an MCP cap are active, both reasons render — they don't override each other.

The Security Level line names the specific cause and the command to run for details, so
an upgrading user never sees a bare number drop with no explanation.

## 7. Real incidents

`scan --mcp`'s detectors map directly to incidents already documented in the
[threat model](threat-model.md):

- [Mini Shai-Hulud Wave G: Hades MCP-Targeting](threat-model.md#june-2026--mini-shai-hulud-wave-g-hades-mcp-targeting-june-9)
  — malicious packages impersonating popular MCP server libraries. Motivates
  `unpinned-execution` and `typosquat`.
- [Agentjacking: Sentry MCP Event Injection → AI Agent RCE](threat-model.md#june-2026--agentjacking-sentry-mcp-event-injection--ai-agent-rce-june-12)
  — an MCP server returning attacker-controlled context that an agent trusted and acted
  on. Motivates `tool-poisoning`'s injection-phrase heuristic.
- [Mastra AI npm Supply Chain Attack via easy-day-js Typosquat](threat-model.md#june-2026--mastra-ai-npm-supply-chain-attack-via-easy-day-js-typosquat-june-17)
  — the combosquat this scanner honestly cannot catch (Section 5). Cited here, not
  hidden, because knowing the blind spot is part of using this tool responsibly.
  See also the [Supply Chain Defense Guide](supply-chain-defense.md) for the full
  attack-chain writeup.
- [June MCP-Server "Insecure Default" Wave](threat-model.md#june-2026--june-mcp-server-insecure-default-wave-june-1826)
  — servers shipping with plain-HTTP transport, wildcard binds, and no auth by default.
  Motivates `insecure-endpoint`.
- [MCP Design Flaw: Zero-Click Prompt Injection in IDEs, 9 of 11 Registries Poisoned](threat-model.md#april-2026--mcp-design-flaw-zero-click-prompt-injection-in-ides-9-of-11-registries-poisoned)
  — malicious MCP STDIO servers silently registered into local config with no user
  approval. Motivates config-level scanning as a whole, plus `scope-breadth`.
- [MCP Servers as Universal Attack Surface](threat-model.md#march-2025--mcp-servers-as-universal-attack-surface)
  — the original 2025 documentation of tool shadowing, cross-server tool injection, and
  server impersonation. Motivates `tool-shadowing` and `credential-passthrough`.

None of these incidents are hypothetical — every one is a real, sourced disclosure in
the threat model. If you're deciding whether `scan --mcp` is worth running, this is the
threat class it exists to catch a slice of, honestly documented limitations and all.

---

## Further Reading

- [Threat Model: OWASP Agentic Top 10 for Solo Devs](threat-model.md) — all 30+ incidents,
  including the six above
- [Supply Chain Defense Guide](supply-chain-defense.md) — npm worm case studies, the
  `scan --supply-chain` IOC scanner
- [Credential Management](credential-management.md) — why env vars fail, credential
  proxy architecture (the `credential-passthrough` detector's design analog)
