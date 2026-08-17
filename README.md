# LLM Safe Haven

[![Socket Badge](https://socket.dev/api/badge/npm/package/llm-safe-haven)](https://socket.dev/npm/package/llm-safe-haven)
[![npm version](https://img.shields.io/npm/v/llm-safe-haven.svg)](https://www.npmjs.com/package/llm-safe-haven)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Harden your AI coding agent in 60 seconds.

```bash
npx llm-safe-haven
```

## What It Does

Detects your installed agents, installs security hooks, and scores your setup:

```
LLM Safe Haven -- Security Scorecard

  Detected agents:
    + Claude Code    -- Level 3 (hooks + audit + sandbox)
    + Cursor         -- Level 1 (ignore files + advice)
    . Windsurf       -- not installed

  Security Level: 2 of 4
  +--------------------------------------+
  | ##########..........  Level 2: Guarded |
  +--------------------------------------+
```

## Supported Agents

| Agent | Tier | What It Configures |
|-------|------|--------------------|
| Claude Code | Full | Hooks (bash-firewall, secret-guard, config-guard, audit-logger), settings.json, sandbox, audit logging |
| Cursor | Solid | .cursorignore, workspace trust guidance |
| Windsurf | Solid | .codeiumignore, limitation warnings |
| Cline | Solid | .clineignore |
| Continue.dev | Solid | .continueignore |
| Aider | Solid | .aiderignore, .env warnings |
| Codex CLI | Solid | .codexignore, sandbox guidance |

## Commands

```bash
npx llm-safe-haven               # Install hooks and harden (default)
npx llm-safe-haven audit          # Check security posture (0 clean / 1 findings / 2 a scan didn't finish)
npx llm-safe-haven audit --json   # Machine-readable for CI
npx llm-safe-haven scan           # Find exposed .env files (0 none / 1 found / 2 scan didn't finish)
npx llm-safe-haven scan --supply-chain  # Scan for ChainDrop/Shai-Hulud IOCs (macOS/Linux)
npx llm-safe-haven scan --mcp     # Scan MCP server configs (5 agents) -- the CI gate for MCP findings
npx llm-safe-haven scan --mcp --json    # Scan MCP server configs (JSON output)
npx llm-safe-haven scan --mcp --online  # Opt in to registry provenance checks
npx llm-safe-haven update         # Update hooks to latest
npx llm-safe-haven --dry-run      # Preview without changing anything
```

### Exit codes

Every scanning command uses the same three-valued contract:

| Code | Meaning |
|------|---------|
| `0` | Clean — the scan completed and found nothing |
| `1` | Findings — something was observed that you need to act on |
| `2` | The scan did not finish — treat as unknown, never as clean |

**An incomplete scan is never reported as clean.** A finding takes precedence over
incompleteness: if a `.env` was actually observed, that is exit `1` even when other paths
could not be read, because what was seen is a fact regardless of what was missed.

> **⚠ Behaviour change — if you gate CI on `scan`, read this.**
> `scan` previously exited `0` even when it found tracked `.env` files, while printing them
> as a red `✗`. It now exits `1`, as the table above says it should. Any pipeline treating
> `scan`'s `0` as "the command ran OK" rather than "nothing was found" will start failing —
> correctly. Use `--json` (on `audit`) or check for `1` explicitly if you need to distinguish
> "found something" from "could not run".

#### Zero default scan roots

`scan`, `audit`, `install`, and `scan --supply-chain` all resolve their scan scope from the same
six default directory names under `$HOME` (`Projects`, `Developer`, `Code`, `src`, `repos`,
`workspace`), or from `LSH_ROOTS` if you set it. A machine where **none** of the six exist used to
report a silent all-clear — the scan examined zero bytes and still printed a green check.

Now, when zero default roots resolve:

- if the current directory looks like a project (it contains a `.git` entry or a `package.json`),
  that directory becomes the sole scan root. Exactly one line is printed to stderr noting the
  fallback, and the exit code follows findings as usual.
- otherwise, the run is reported incomplete and exits `2` — never a silent `0`.

A machine with one or more of the six default roots present is unaffected: no new stderr line, no
exit-code change, byte-identical output to before this change.

> **⚠ Behaviour change — if you run any of these commands in a container or CI runner whose code
> lives outside `~/{Projects,Developer,Code,src,repos,workspace}`, read this.**
> A container or CI runner whose working directory is not itself a project (no `.git`, no
> `package.json`) will now exit `2` where it previously exited `0`. This is intentional: an exit
> code of `0` is supposed to mean "the scan ran and found nothing" — it never meant "the scan ran
> nowhere." If you hit this, either set `LSH_ROOTS` to the directory you want scanned, or run the
> command from that directory.

## Security Levels

| Level | Name | What It Means |
|-------|------|---------------|
| 0 | Exposed | No hardening |
| 1 | Basic | Hooks installed |
| 2 | Guarded | + Audit logging + no .env files |
| 3 | Hardened | + Credential proxy + deny rules + clean MCP scan |
| 4 | Fortified | + Container isolation + network restrictions |

## Go Deeper

- [Threat Model](docs/threat-model.md) -- OWASP Agentic Top 10 for solo devs (30+ real incidents)
- [Supply Chain Defense](docs/supply-chain-defense.md) -- npm worm case studies + the `scan --supply-chain` IOC scanners
- [MCP Security](docs/mcp-security.md) -- 8 detectors for MCP server configs, offline-first, honest fidelity limits
- [Claude Code Hardening](docs/hardening/claude-code.md) -- Full guide with hooks, sandbox, permissions
- [Cursor Hardening](docs/hardening/cursor.md) -- 7 CVEs documented, hardening steps
- [Windsurf Hardening](docs/hardening/windsurf.md) -- Honest assessment of limitations
- [Devin Hardening](docs/hardening/devin.md) -- Cloud agent security model
- [GitHub Copilot Hardening](docs/hardening/github-copilot.md) -- 4 modes, 5 CVEs
- [Aider Hardening](docs/hardening/aider.md) -- No sandbox, but minimal attack surface
- [Credential Management](docs/credential-management.md) -- Why env vars fail, proxy architecture
- [Testing & Detection](docs/testing.md) -- Canary tokens, honeypots, incident response
- [References](docs/references.md) -- 64+ curated security resources

## Why This Exists

In April 2026, three AI coding agents leaked secrets through a single prompt injection.
We hit the same problems, filed issues, built solutions, and documented everything.

Key issues from our investigation:
- [anthropics/claude-code#52471](https://github.com/anthropics/claude-code/issues/52471) -- Sandbox blocks credential managers

## Project Status

Early but active. `llm-safe-haven` is pre-1.0, published on npm, and under regular
development — adoption is still small and growing. The strength today is depth over
reach: a [threat model](docs/threat-model.md) tracking 30+ real-world incidents against
the AI-agent toolchain, hardening guides for seven agents, and a supply-chain scanner
built against actual attack waves. If you use it, feedback and issues are genuinely
valued and shape the roadmap.

## Security

`llm-safe-haven` is itself a security tool, so its own supply-chain integrity is treated
as safety-critical. Found a vulnerability? Please report it privately — see
[SECURITY.md](SECURITY.md) for the coordinated-disclosure process (do **not** open a
public issue for security problems).

## Governance

Maintained by [@pleasedodisturb](https://github.com/pleasedodisturb) as the sole
maintainer and final decision-maker on scope, releases, and security response. Decisions
are made in the open via GitHub issues and pull requests; contributions are welcome (see
below) and reviewed by the maintainer. As the project grows, governance and additional
maintainers will be formalized here.

## Contributing

Add a new agent module: create `lib/agents/your-agent.js` implementing the standard
interface (detect, harden, audit). See [lib/agents/cursor.js](lib/agents/cursor.js)
for a template.

## License

[MIT](LICENSE)
