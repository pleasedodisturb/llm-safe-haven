# We scanned the top 100 public MCP servers' own install instructions. 90 fail the first check.

_(Draft — G-1372. Not published. Publishing/HN timing is a separate ticket, G-386.)_

## The install snippet is the attack surface

On June 9, 2026, StepSecurity and BleepingComputer disclosed "Hades MCP-targeting" — the
seventh wave of the Mini Shai-Hulud npm supply chain campaign, and the first to directly
target the MCP server ecosystem instead of general-purpose npm/PyPI packages. The attacker
published malicious packages impersonating popular MCP server libraries for Claude Code,
Cursor, and GitHub Copilot integrations. A developer who installs a compromised MCP server
doesn't just add a risky dependency — they hand the attacker a seat inside their coding
agent's own tool-execution loop.

Nine days later, a second, unrelated cluster of advisories landed: the "June MCP-Server
Insecure Default Wave" (June 18–26). `mcp-pinot` shipped with no auth and a public bind
(CVSS 10.0, full cluster read/write). `dbt-mcp` leaked access and refresh tokens over an
unauthenticated endpoint. `backpropagate` shipped an `--auth` flag that was a documented
no-op — the backend never read the environment variable the flag was supposed to set. Five
CVEs, one pattern: the server's *default*, out-of-the-box configuration — the thing its own
README tells you to paste — was the vulnerability.

That's the premise of this research: **`scan --mcp` reads configs, not packages.** So we
pointed it at the one thing every MCP server author controls and every user copies
verbatim — the recommended install snippet in the README — for the 100 most-downloaded
public MCP servers, and counted what came back.

## Headline numbers

Out of 100 servers, using llm-safe-haven's own 8-detector `scan --mcp` suite (v0.3.1)
against each server's own recommended install snippet:

- **90 recommend an unpinned install** — `npx <package>` (or `uvx`) with no version, SHA,
  or lockfile binding. Anyone who copy-pastes the README's own instructions gets whatever
  the latest published version happens to be on the day they run it — exactly the
  distribution channel Hades MCP-targeting abused.
- **38 of the npm-resolvable servers lack a provenance attestation** — no Sigstore-backed
  proof the package came from the CI pipeline its source repo claims, checked live against
  the npm registry (`--online`).
- **22 servers' recommended snippets inline a literal credential-shaped value** (env vars
  named like `API_KEY`/`TOKEN`/`SECRET` set to a literal string, usually a placeholder like
  `YOUR_API_KEY`) instead of an interpolated reference — a habit that trains users to paste
  real secrets straight into a JSON file that regularly gets committed to a repo.
- Two servers' recommended snippets show the June "Insecure Default" wave's failure shape
  directly: one remote-transport config with **no recognized authentication header** on
  its endpoints, and one filesystem/shell-capable local server with **no bounded path
  argument** — the exact pattern behind that wave's CVEs, just caught before install
  instead of after.
- **32 of the 100 had no literal `mcpServers` block in their README at all** — no
  copy-pasteable snippet, just a bare package name. Their line in this dataset is a
  synthesized minimal form (`npx -y <package>`), flagged `synthesized:true` throughout, and
  none of the headline detector counts above are inflated by inventing arguments those
  packages never actually documented.

Full methodology, the exact commands to reproduce this, and every source consulted:
`METHODOLOGY.md` in this directory.

## Per-detector breakdown

**`unpinned-execution` — 90/100.** The dominant finding by a wide margin, and the most
avoidable: pin a version or a full git SHA (both count as pinned as of v0.3.1 — a floating
`@latest`/`@next`/`@canary` tag, or nothing at all, does not).

**`provenance` — 38/89 npm-resolvable servers lack an attestation** (11 servers in the
dataset don't resolve to an npm package at all — Docker-only or remote-URL-only
recommended installs, PyPI-only reference servers — and provenance is `not-applicable`
for those). Remember what this number does and doesn't mean: `has-attestation` means the
package was published through npm's own provenance pipeline. It is *not* a claim that the
code inside was audited or is safe — see the fidelity-limits section below.

**`insecure-endpoint` — 1/100.** Both hits come from a single server's recommended
multi-server example: two HTTPS endpoints (the server's own remote transport, plus a
third-party service endpoint shown in the same example block) with no recognized
authentication header configured. Notably, neither hit is plain-HTTP — in this dataset
the remote-transport failure mode is skipped authentication, not skipped TLS, mirroring
the exact failure mode behind `mcp-pinot`/`dbt-mcp` above. Remote-transport snippets are
rare in the top 100, so read this as a shape, not a rate.

**`credential-passthrough` — 22/100.** All 22 are the `sensitive-name-literal` rule
(inlined literal value for a sensitive-sounding env var name) — none triggered the
`inlined-secret` (a value that looks like an actual live credential) or `broad-inheritance`
rules. In every case we inspected, the literal value is a documentation placeholder
(`YOUR_API_KEY`, `<YOUR_TOKEN>`), not a real leaked credential. The finding is about the
*pattern* the README teaches, not a specific leak: a JSON config file that says "put your
real API key right here" is a config file that regularly ends up committed to a repo with
the real key still in it.

**`scope-breadth` — 1/100.** One filesystem/shell-capable server recommends no bounded
path argument in its default snippet. This detector is deliberately narrow by design (a
small allowlist, false negatives accepted) — a low count here is expected, not reassuring.

**`tool-poisoning` / `tool-shadowing` — 0/100.** No injection-phrase or invisible-Unicode
hits in any config-adjacent string across 100 servers. The tool-shadowing zero deserves an
asterisk: the scan fixtures rewrite every server to a unique generated name (so two
unrelated servers can't collide merely by both calling themselves `filesystem`), which
also makes a within-batch name collision structurally impossible — that zero is by
construction, not a measurement. Read both alongside the fidelity limits below — this
detector is a static heuristic over config text, not a live `tools/list` inspection, so a
clean result here says nothing about a server's actual runtime tool descriptions.

**`typosquat` — 5/100, and all five are a confirmed detector false positive**, not five
real typosquats. `@ui5/mcp-server`, `@cap-js/mcp-server`, `@launchdarkly/mcp-server`,
`@hubspot/mcp-server`, and `@browserstack/mcp-server` were each flagged
`scope-confusion` because the allowlist's one `@sentry/mcp-server` entry seeds `mcp-server`
as a "known" name half — and `mcp-server` turns out to be a generic leaf name that SAP,
LaunchDarkly, HubSpot, and BrowserStack all independently and legitimately chose for their
own official package. We're naming this as a detector bug, not a finding about any of
those five vendors — every one of them is a real, official, first-party integration. Full
repro filed for ticketing in `FINDINGS-FOR-TICKETS.md`. This is exactly the kind of thing
running your own detector at 25x the normal dogfood scale is supposed to surface (see
G-1368, caught the same way one scale-order down).

## Cross-set tool-shadowing

We did not compute a tool-name collision count across the 100-server set. Tool names are
not statically recoverable from a recommended-install-snippet scrape — that would require
parsing each server's own README tool-reference table, a different (and much larger)
per-server extraction task than collecting one JSON snippet. Every server in this dataset
is counted as skipped rather than reporting a fabricated collision figure. `tool-shadowing`
findings above are the scanner's own static server-NAME collision proxy only (within each
fixture batch), never a verified tool-level shadowing check at the protocol layer.

## How this was collected (short version)

`selection.json` — top 100 by last-30-day npm downloads, union of the official
`modelcontextprotocol/servers` reference implementations and an npm-search MCP-server
heuristic (name/keyword match plus a real "does it have a `bin` entry" executable check).
`snippets.json` — each server's own recommended `mcpServers` JSON block, extracted verbatim
from its README (or synthesized, flagged, when no such block exists). `dataset.json` — the
real `scan --mcp --json --online` envelope run against fixtures built from those snippets,
merged mechanically by server name — every finding above traces back to an actual scan
output, never hand-typed. Full detail, exact commands, and every documented deviation from
the original methodology: `METHODOLOGY.md`.

## What this can't see (read this before trusting a clean scan)

This is the same honesty section `docs/mcp-security.md` §5 carries for the shipped tool,
because this research ran the exact same static analysis with the exact same blind spots:

- **No `tools/list` introspection.** Every number above comes from parsing a config file
  — README text turned into a synthetic `.mcp.json` — never a live connection to any of
  the 100 servers. A server whose config looks clean but whose runtime tool descriptions
  carry hidden instructions is invisible to this entire methodology, not just to our
  scanner.
- **`provenance` means attestation presence, not code safety.** "Has an attestation" means
  the package was published through npm's provenance pipeline. It says nothing about
  whether the code inside is safe — we deliberately never claim the package's contents
  were cryptographically checked or its authenticity confirmed, and neither should you
  read it that way.
- **Edit-distance `typosquat` cannot catch a combosquat**, and the false-positive class we
  found above (a generic name legitimately reused by five different vendors) is the mirror
  image of that same edit-distance approach's other failure mode: a plausible new name
  that ISN'T close to anything known — the [`easy-day-js` attack on Mastra AI](../../docs/threat-model.md#june-2026--mastra-ai-npm-supply-chain-attack-via-easy-day-js-typosquat-june-17)
  — would sail through undetected. Neither this run nor the shipped tool catches it.
- **This is a documentation snapshot, not a live posture check.** A server can change its
  recommended snippet the day after this snapshot date; a package can lose its attestation
  on a later release. Re-run the scan against your own actual configured servers, not this
  dataset, to know your own current exposure.

## Check your own setup

Everything above comes from the same tool you can run against your own machine right now:

```bash
npx llm-safe-haven scan --mcp
```

Add `--online` to also check provenance attestations for any npx/uvx-resolvable servers you
have configured, and `--json` for a CI-friendly machine-readable report.
