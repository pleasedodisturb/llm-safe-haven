# LLM Safe Haven

[![Socket Badge](https://socket.dev/api/badge/npm/package/llm-safe-haven)](https://socket.dev/npm/package/llm-safe-haven)
[![npm version](https://img.shields.io/npm/v/llm-safe-haven.svg)](https://www.npmjs.com/package/llm-safe-haven)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Harden your AI coding agent in 60 seconds. Zero dependencies, offline by default, nothing written outside your agent's own config.

```bash
npx llm-safe-haven
```

It detects your installed agents, installs security hooks, scans for exposed secrets and risky MCP servers, and scores the result:

```
LLM Safe Haven -- Security Scorecard

  Detected agents:
    + Claude Code    -- Level 3 (hooks + audit + sandbox)
    + Cursor         -- Level 1 (ignore files + advice)
    . Windsurf       -- not installed

  Security Level: 2 of 4
```

## Commands

```bash
npx llm-safe-haven               # Install hooks and harden (default)
npx llm-safe-haven --dry-run      # Preview without changing anything
npx llm-safe-haven audit          # Check security posture (0 clean / 1 findings / 2 a scan didn't finish)
npx llm-safe-haven audit --json   # Machine-readable for CI
npx llm-safe-haven scan           # Find exposed .env files (0 none / 1 found / 2 scan didn't finish)
npx llm-safe-haven scan --supply-chain  # Scan for ChainDrop/Shai-Hulud IOCs (macOS/Linux)
npx llm-safe-haven scan --mcp     # Scan MCP server configs (10 agents) -- the CI gate for MCP findings
npx llm-safe-haven scan --mcp --json    # Scan MCP server configs (JSON output)
npx llm-safe-haven scan --mcp --online  # Opt in to registry provenance checks
npx llm-safe-haven update         # Update hooks to latest
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — the scan completed and found nothing |
| `1` | Findings — act on them (for `audit`: also a completed posture below Level 2) |
| `2` | The scan did not finish — unknown, never clean |

An incomplete scan is never reported as clean, and a real finding beats incompleteness. Gate CI on the **exit status** — not on `audit --json`'s `overallLevel` alone, because an incomplete scan is capped *at* 2, the same value as the Level-2 pass threshold. The full contract — including what changed for `scan` in v0.7 and what happens when none of the default scan roots exist — is in [Exit Codes and Scan Scope](docs/exit-codes.md).

## Security Levels

| Level | Name | What It Means |
|-------|------|---------------|
| 0 | Exposed | No hardening |
| 1 | Basic | Hooks installed |
| 2 | Guarded | + Audit logging + no .env files |
| 3 | Hardened | + Credential proxy + deny rules + clean MCP scan |
| 4 | Fortified | + Container isolation + network restrictions |

## Supported Agents

`llm-safe-haven` detects and hardens 16 agents. The tier says what the tool **actually configures today** — not how much we care, and never more than the vendor's own docs support. **Full** wires the agent's hook system. **Solid** writes an ignore file the agent's documentation says it honours. **Advise** means no repo-local control we can depend on, so you get detection and guidance. Ignore files are best-effort context exclusion, not a hard secret boundary — every Solid-tier guide says so.

| Agent | Tier | What It Configures |
|-------|------|--------------------|
| Claude Code | **Full** | Hooks (bash-firewall, secret-guard, config-guard, audit-logger), `settings.json` wiring, SHA256 hook-integrity verification, audit-log freshness check |
| Cursor | Solid | `.cursorignore`; workspace-trust + auto-run guidance |
| Windsurf | Solid | `.codeiumignore`; limitation warnings (no sandbox, no hooks) |
| Cline | Solid | `.clineignore` |
| Continue.dev | Solid | `.continueignore`; config API-key warning |
| Gemini CLI | Solid | `.geminiignore`; config-review guidance |
| Aider | Solid | `.aiderignore`; project `.env` key scan — _deprecated: unmaintained upstream_ |
| GitHub Copilot | Advise | `.copilotignore` is inert (Copilot's real exclusions live server-side); reads VS Code workspace trust |
| Codex CLI | Advise | `.codexignore` + sandbox/approval guidance — has a Claude-Code-style hook system we don't wire yet (nearest path to a second **Full**) |
| Goose | Advise | `.gooseignore`; `config.yaml` review — its docs name `.gitignore`, not this file |
| Antigravity | Advise | `.antigravityignore` — its docs name `.gitignore`, not this file |
| Augment | Advise | Guidance only (no ignore-file mechanism) |
| Amazon Q | Advise | IAM / AWS access guidance — _deprecated: AWS ends support for the IDE plugins and paid subscriptions 2027-04-30 (superseded by Kiro)_ |
| JetBrains AI | Advise | Guidance only (settings are an opaque IDE blob) |
| Replit Agent | Advise | Guidance only (code executes off-machine) |
| Zed AI | Advise | Guidance only (tool permissions are user-scope) |

The Solid/Advise line is a codified rule, not a judgment call: `computeExpectedTier()` in `lib/agents/base.js` grades every module, and a meta-test fails CI on a mis-tier. Roadmap: Codex CLI to **Full**, then the other agents with Claude-Code-compatible hooks (OpenHands, Droid, CodeBuddy, Crush, Trae), and `pi` for **Solid**.

## Go Deeper

- [Threat Model](docs/threat-model.md) — OWASP Agentic Top 10 for solo devs, 30+ real incidents
- [Supply Chain Defense](docs/supply-chain-defense.md) — npm worm case studies + the `scan --supply-chain` IOC scanners
- [MCP Security](docs/mcp-security.md) — 8 detectors for MCP server configs, offline-first, honest fidelity limits
- [Exit Codes and Scan Scope](docs/exit-codes.md) — the 0/1/2 contract, zero-root behaviour, `audit --json` gating
- Hardening guides: [Claude Code](docs/hardening/claude-code.md) · [Cursor](docs/hardening/cursor.md) · [Windsurf](docs/hardening/windsurf.md) · [GitHub Copilot](docs/hardening/github-copilot.md) · [Aider](docs/hardening/aider.md) · [Devin](docs/hardening/devin.md) (advisory only — Devin runs off-machine, so there is no `lib/agents/` module)
- [Credential Management](docs/credential-management.md) — why env vars fail, proxy architecture
- [Testing & Detection](docs/testing.md) — canary tokens, honeypots, incident response
- [Quick Start](docs/guides/quick-start.md) — the 60-second path, with real captured output
- [References](docs/references.md) — 120+ curated security resources

## Project

**Why.** In April 2026, three AI coding agents leaked secrets through a single prompt injection ([the "Comment and Control" incident](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026)). Building defences against that ran straight into platform limits — e.g. [anthropics/claude-code#52471](https://github.com/anthropics/claude-code/issues/52471), where the macOS sandbox blocks the Unix sockets credential managers rely on — so we built the fixes and documented everything.

**Status.** Pre-1.0, on npm with SLSA provenance, under regular development; adoption is small and growing. The strength is depth over reach: a threat model tracking 30+ real incidents, hardening guides for six agents, a supply-chain scanner built against actual attack waves, and a doc-drift guard that fails CI when these pages stop matching the code.

**Security.** This is itself a security tool, so its own supply chain is treated as safety-critical. Report vulnerabilities privately per [SECURITY.md](SECURITY.md) — never in a public issue.

**Governance.** Maintained by [@pleasedodisturb](https://github.com/pleasedodisturb) as sole maintainer and final decision-maker; decisions happen in the open via issues and PRs. Contributions are welcome — to add an agent, create `lib/agents/<your-agent>.js` implementing `detect`, `harden`, `audit` (see [lib/agents/cursor.js](lib/agents/cursor.js)). Cross-agent working contract: [AGENTS.md](AGENTS.md).

**License.** [MIT](LICENSE)
